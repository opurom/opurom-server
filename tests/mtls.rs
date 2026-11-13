//! R8 mutual TLS tests over real sockets: a CA-signed server chain, trusted
//! and untrusted client certificates, a static fingerprint deny list, ALPN
//! negotiation and the operator-facing diagnostics. R9 uses a real h2 client
//! where ALPN selects `h2`. All certificates and private keys are generated
//! in memory with rcgen; none are checked in.

mod support;

use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::tls::{self, MtlsOptions};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SigningKey,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use support::h2::{exchange, Identity as H2Identity, RequestSpec};

static NONCE: AtomicU64 = AtomicU64::new(0);

const REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const HEALTH_BODY: &str = "{\"ok\":true}";
const DEMO_HEALTH_BODY: &str = "{\"ok\":true,\"app\":\"opurom-server-demo\",\"version\":\"0.2.0\"}";

/// One generated client identity. The chain PEM may contain the issuing CA.
#[derive(Clone)]
struct ClientIdentity {
    chain_pem: String,
    key_pem: String,
    fingerprint: String,
}

/// A CA, a CA-signed server chain, two trusted clients and one untrusted one.
struct Pki {
    ca_pem: String,
    ca_der: Vec<u8>,
    server_chain_pem: String,
    server_key_pem: String,
    trusted_client: ClientIdentity,
    other_trusted_client: ClientIdentity,
    untrusted_client: ClientIdentity,
}

/// Generate CA -> server certificate and CA -> client certificate chains.
fn pki() -> Pki {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "opurom R8 test CA");
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let (server_cert, server_key) = signed_leaf(
        &issuer,
        "localhost",
        tls::DEFAULT_TLS_NAMES
            .iter()
            .map(|name| name.to_string())
            .collect(),
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let (client_cert, client_key) = signed_leaf(
        &issuer,
        "trusted-client",
        vec!["trusted.example".to_string()],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let (other_cert, other_key) = signed_leaf(
        &issuer,
        "other-trusted-client",
        vec!["other.example".to_string()],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let (untrusted_cert, untrusted_key) = self_signed_client("untrusted-client");

    let ca_pem = ca_cert.pem();
    Pki {
        ca_der: ca_cert.der().as_ref().to_vec(),
        ca_pem: ca_pem.clone(),
        server_chain_pem: format!("{}{}", server_cert.pem(), ca_pem),
        server_key_pem: server_key.serialize_pem(),
        trusted_client: signed_identity(&client_cert, &client_key, &ca_pem),
        other_trusted_client: signed_identity(&other_cert, &other_key, &ca_pem),
        untrusted_client: signed_identity(&untrusted_cert, &untrusted_key, ""),
    }
}

/// A leaf certificate signed by the test CA.
fn signed_leaf<S: SigningKey>(
    issuer: &Issuer<'_, S>,
    common_name: &str,
    names: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(names).expect("leaf parameters");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(eku);
    params.use_authority_key_identifier_extension = true;
    let key = KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, issuer).expect("leaf certificate");
    (cert, key)
}

/// A self-signed client certificate that the server's CA does not trust.
fn self_signed_client(common_name: &str) -> (rcgen::Certificate, KeyPair) {
    let mut params =
        CertificateParams::new(vec!["untrusted.example".to_string()]).expect("client parameters");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let key = KeyPair::generate().expect("untrusted client key");
    let cert = params.self_signed(&key).expect("untrusted client cert");
    (cert, key)
}

fn signed_identity(cert: &rcgen::Certificate, key: &KeyPair, ca_pem: &str) -> ClientIdentity {
    let der = cert.der().as_ref().to_vec();
    ClientIdentity {
        chain_pem: format!("{}{}", cert.pem(), ca_pem),
        key_pem: key.serialize_pem(),
        fingerprint: tls::fingerprint_of(&der),
    }
}

fn demo_router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, HEALTH_BODY)
    });
    router
}

fn h2_identity(identity: &ClientIdentity) -> H2Identity {
    H2Identity {
        chain_pem: identity.chain_pem.clone(),
        key_pem: identity.key_pem.clone(),
    }
}

/// Start an mTLS server with the CA-signed server chain and a deny list.
fn start_mtls_server(pki: &Pki, revoked: &[String]) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let options = MtlsOptions {
        client_ca_pem: pki.ca_pem.as_bytes().to_vec(),
        revoked: revoked.to_vec(),
        ..MtlsOptions::default()
    };
    let config = tls::config_from_pem_bytes(
        pki.server_chain_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        Some(&options),
    )
    .expect("mTLS server configuration");
    let server = Server::bind_tls(
        "127.0.0.1:0",
        demo_router(),
        MiddlewareChain::new(),
        1024 * 1024,
        Some(config),
    )
    .expect("mTLS server binds");
    let (addr, shutdown) = server.spawn().expect("mTLS server spawns");
    (addr.port(), shutdown)
}

/// Start the R7 single-sided TLS server with its self-signed certificate.
fn start_single_sided_tls_server() -> (u16, Vec<u8>, Arc<std::sync::atomic::AtomicBool>) {
    let server = Server::bind_tls(
        "127.0.0.1:0",
        demo_router(),
        MiddlewareChain::new(),
        1024 * 1024,
        None,
    )
    .expect("single-sided TLS server binds");
    let certificate_der = server
        .tls_config()
        .expect("the server has a TLS configuration")
        .certificate_der()
        .to_vec();
    let (addr, shutdown) = server.spawn().expect("single-sided TLS server spawns");
    (addr.port(), certificate_der, shutdown)
}

fn client_config(
    root_der: &[u8],
    identity: Option<&ClientIdentity>,
    alpn: &[&str],
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .expect("trust anchor");
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut config = match identity {
        Some(identity) => {
            let certs = rustls_pemfile::certs(&mut BufReader::new(identity.chain_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .expect("client certificate chain");
            let key = rustls_pemfile::private_key(&mut BufReader::new(identity.key_pem.as_bytes()))
                .expect("client private key")
                .expect("client PRIVATE KEY block");
            builder
                .with_client_auth_cert(certs, key)
                .expect("client identity")
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|value| value.as_bytes().to_vec()).collect();
    config
}

/// One real TLS connection. Returns the HTTP answer and the ALPN protocol
/// rustls selected on the client side, or the I/O/handshake diagnostic.
fn https_request(
    port: u16,
    root_der: &[u8],
    identity: Option<&ClientIdentity>,
    alpn: &[&str],
    request: &str,
) -> Result<(String, Option<String>), String> {
    let config = client_config(root_der, identity, alpn);
    let server_name = ServerName::try_from("localhost").expect("server name");
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| format!("client connection: {}", err))?;
    let socket =
        TcpStream::connect(("127.0.0.1", port)).map_err(|err| format!("connect: {}", err))?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(5)));
    let mut stream = StreamOwned::new(connection, socket);
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("write: {}", err))?;
    stream.flush().map_err(|err| format!("flush: {}", err))?;
    let selected_alpn = stream
        .conn
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|err| format!("read: {}", err))?;
    Ok((String::from_utf8_lossy(&raw).into_owned(), selected_alpn))
}

fn refused(result: Result<(String, Option<String>), String>) -> String {
    match result {
        Ok((answer, _)) => panic!("the handshake must be refused, got: {}", answer),
        Err(err) => err,
    }
}

#[test]
fn trusted_client_certificate_completes_a_real_mtls_handshake() {
    let pki = pki();
    let (port, shutdown) = start_mtls_server(&pki, &[]);
    let (answer, alpn) = https_request(
        port,
        &pki.ca_der,
        Some(&pki.trusted_client),
        &["http/1.1"],
        REQUEST,
    )
    .expect("a CA-signed client certificate completes mTLS");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(answer.ends_with(HEALTH_BODY), "{}", answer);
    println!(
        "[R8 mTLS] trusted client accepted; selected ALPN: {:?}",
        alpn
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn missing_client_certificate_is_refused() {
    let pki = pki();
    let (port, shutdown) = start_mtls_server(&pki, &[]);
    let err = refused(https_request(
        port,
        &pki.ca_der,
        None,
        &["h2", "http/1.1"],
        REQUEST,
    ));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    println!("[R8 mTLS] client with no certificate refused: {}", err);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn untrusted_self_signed_client_certificate_is_refused() {
    let pki = pki();
    let (port, shutdown) = start_mtls_server(&pki, &[]);
    let err = refused(https_request(
        port,
        &pki.ca_der,
        Some(&pki.untrusted_client),
        &["h2", "http/1.1"],
        REQUEST,
    ));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    println!(
        "[R8 mTLS] self-signed untrusted client certificate refused: {}",
        err
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn revoked_but_trusted_certificate_is_refused_and_a_non_revoked_one_succeeds() {
    let pki = pki();
    let revoked = vec![pki.trusted_client.fingerprint.clone()];
    let (port, shutdown) = start_mtls_server(&pki, &revoked);
    let err = refused(https_request(
        port,
        &pki.ca_der,
        Some(&pki.trusted_client),
        &["h2"],
        REQUEST,
    ));
    assert!(
        err.to_ascii_lowercase().contains("revoked"),
        "the diagnostic must name the revocation: {}",
        err
    );
    let (answer, _) = https_request(
        port,
        &pki.ca_der,
        Some(&pki.other_trusted_client),
        &["http/1.1"],
        REQUEST,
    )
    .expect("a non-revoked CA-signed client certificate succeeds");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    println!(
        "[R8 mTLS] revoked fingerprint {} refused; a non-revoked trusted certificate succeeded",
        pki.trusted_client.fingerprint
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn revocation_ignores_a_client_supplied_fingerprint_header() {
    let pki = pki();
    let revoked = vec![pki.trusted_client.fingerprint.clone()];
    let (port, shutdown) = start_mtls_server(&pki, &revoked);
    let spoofed = format!(
        "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Client-Cert-Fingerprint: {}\r\nConnection: close\r\n\r\n",
        pki.other_trusted_client.fingerprint
    );
    let err = refused(https_request(
        port,
        &pki.ca_der,
        Some(&pki.trusted_client),
        &["h2"],
        &spoofed,
    ));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    println!(
        "[R8 mTLS] a spoofed fingerprint header did not bypass the deny list: {}",
        err
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn alpn_advertises_h2_and_http_1_1_and_reports_selection() {
    assert_eq!(tls::ALPN_PROTOCOLS, &["h2", "http/1.1"]);
    let pki = pki();
    let (port, shutdown) = start_mtls_server(&pki, &[]);
    let identity = h2_identity(&pki.trusted_client);
    for (offered, expected) in [
        (vec!["h2"], "h2"),
        (vec!["http/1.1"], "http/1.1"),
        (vec!["h2", "http/1.1"], "h2"),
    ] {
        if expected == "h2" {
            let (selected, answers) = exchange(
                port,
                &pki.ca_der,
                Some(&identity),
                vec![RequestSpec::get("/health")],
            )
            .expect("an h2 client completes mTLS and the h2 handshake");
            assert_eq!(selected.as_deref(), Some(expected), "{:?}", offered);
            assert_eq!(answers[0].status, 200);
            assert_eq!(answers[0].body, HEALTH_BODY.as_bytes());
            println!(
                "[R8/R9 ALPN] offered {:?} -> selected {}; server answers HTTP/2",
                offered, expected
            );
        } else {
            let (answer, selected) = https_request(
                port,
                &pki.ca_der,
                Some(&pki.trusted_client),
                &offered,
                REQUEST,
            )
            .expect("the TLS handshake succeeds");
            assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
            assert_eq!(selected.as_deref(), Some(expected), "{:?}", offered);
            println!(
                "[R8 ALPN] offered {:?} -> selected {}; server answers HTTP/1.1",
                offered, expected
            );
        }
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn single_sided_tls_without_alpn_stays_byte_identical() {
    let (port, certificate_der, shutdown) = start_single_sided_tls_server();
    let (answer, alpn) = https_request(port, &certificate_der, None, &[], REQUEST)
        .expect("R7 single-sided TLS still accepts a client with no certificate");
    let expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        HEALTH_BODY.len(),
        HEALTH_BODY
    );
    assert_eq!(answer, expected);
    assert_eq!(alpn, None);
    println!("[R8] single-sided TLS with no ALPN: byte-identical HTTP/1.1 answer");
    shutdown.store(true, Ordering::Relaxed);
}

/// A unique temporary directory removed on every test exit path.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "opurom-server-r8-mtls-{}-{}-{}",
            tag,
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temporary directory");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A demo server process killed and cleaned up on every test exit path.
struct DemoServer {
    child: Child,
    port: u16,
    stderr_path: PathBuf,
}

impl DemoServer {
    fn spawn(tag: &str, envs: &[(&str, &str)]) -> DemoServer {
        let port = free_port();
        let stderr_path = std::env::temp_dir().join(format!(
            "opurom-server-r8-mtls-{}-{}-{}.stderr",
            tag,
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let stderr_file = fs::File::create(&stderr_path).expect("stderr file");
        let mut command = Command::new(env!("CARGO_BIN_EXE_opurom-server"));
        command
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        for name in [
            "OPR_PORT",
            "OPR_RATE_LIMIT",
            "OPR_LOG_JSON",
            "OPR_AUTH_TOKEN",
            "OPR_CORS",
            "OPR_ETAG",
            "OPR_TLS",
            "OPR_TLS_CERT",
            "OPR_TLS_KEY",
            "OPR_KEEPALIVE",
            "OPR_WEBSOCKET",
            "OPR_MTLS",
            "OPR_CLIENT_CA",
            "OPR_REVOKED",
            "OPR_CRL_FILE",
            "OPR_OCSP_FILE",
        ] {
            command.env_remove(name);
        }
        for (name, value) in envs {
            command.env(name, value);
        }
        let child = command.spawn().expect("demo server spawns");
        let server = DemoServer {
            child,
            port,
            stderr_path,
        };
        assert!(server.wait_ready(), "demo server did not start");
        server
    }

    fn wait_ready(&self) -> bool {
        for _ in 0..300 {
            if self.stderr().contains("listening on https://") {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn wait_for<F: Fn(&str) -> bool>(&self, predicate: F) -> Option<String> {
        for _ in 0..300 {
            let text = self.stderr();
            if predicate(&text) {
                return Some(text);
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    }
}

impl Drop for DemoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.stderr_path);
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("free port binding");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

#[test]
fn opr_mtls_alone_enables_tls_and_requires_a_client_certificate() {
    let pki = pki();
    let dir = TempDir::new("mtls-only");
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    fs::write(&ca_path, &pki.ca_pem).expect("CA PEM written");
    fs::write(&cert_path, &pki.server_chain_pem).expect("server chain PEM written");
    fs::write(&key_path, &pki.server_key_pem).expect("server key PEM written");

    // DemoServer::spawn removes every OPR_* variable before applying this
    // list, so OPR_TLS is genuinely absent here.
    let server = DemoServer::spawn(
        "mtls-only",
        &[
            ("OPR_MTLS", "1"),
            ("OPR_CLIENT_CA", ca_path.to_str().expect("UTF-8 path")),
            ("OPR_TLS_CERT", cert_path.to_str().expect("UTF-8 path")),
            ("OPR_TLS_KEY", key_path.to_str().expect("UTF-8 path")),
        ],
    );
    let (answer, _) = https_request(
        server.port,
        &pki.ca_der,
        Some(&pki.trusted_client),
        &["http/1.1"],
        REQUEST,
    )
    .expect("OPR_MTLS alone serves HTTPS to a trusted client");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    let err = refused(https_request(server.port, &pki.ca_der, None, &[], REQUEST));
    println!(
        "[R8 mTLS] OPR_MTLS alone enabled TLS; no-certificate client refused: {}",
        err
    );
}

#[test]
fn demo_server_reports_alpn_and_mtls_refusal_diagnostics() {
    let pki = pki();
    let dir = TempDir::new("demo");
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    fs::write(&ca_path, &pki.ca_pem).expect("CA PEM written");
    fs::write(&cert_path, &pki.server_chain_pem).expect("server chain PEM written");
    fs::write(&key_path, &pki.server_key_pem).expect("server key PEM written");

    let server = DemoServer::spawn(
        "logs",
        &[
            ("OPR_TLS", "1"),
            ("OPR_MTLS", "1"),
            ("OPR_TLS_CERT", cert_path.to_str().expect("UTF-8 path")),
            ("OPR_TLS_KEY", key_path.to_str().expect("UTF-8 path")),
            ("OPR_CLIENT_CA", ca_path.to_str().expect("UTF-8 path")),
            ("OPR_LOG_JSON", "1"),
        ],
    );

    let (selected, answers) = exchange(
        server.port,
        &pki.ca_der,
        Some(&h2_identity(&pki.trusted_client)),
        vec![RequestSpec::get("/health")],
    )
    .expect("the trusted h2 client completes the demo server handshake");
    assert_eq!(selected.as_deref(), Some("h2"));
    assert_eq!(answers[0].status, 200);
    assert_eq!(answers[0].body, DEMO_HEALTH_BODY.as_bytes());

    let text = server
        .wait_for(|text| text.contains("\"alpn\""))
        .expect("the structured log reports ALPN");
    let line = text
        .lines()
        .find(|line| line.starts_with('{'))
        .expect("one JSON request log line");
    let value: Value = serde_json::from_str(line).expect("valid JSON log line");
    assert_eq!(value["alpn"], "h2");
    assert_eq!(value["method"], "GET");
    assert_eq!(value["path"], "/health");
    assert_eq!(value["status"], 200);
    println!("[R8 structured log] {}", line);

    let missing = refused(https_request(
        server.port,
        &pki.ca_der,
        None,
        &["h2"],
        REQUEST,
    ));
    let text = server
        .wait_for(|text| text.matches("mTLS handshake refused").count() >= 1)
        .expect("a missing certificate writes a clear diagnostic");
    assert!(text.contains("OPR_CLIENT_CA"), "{}", text);
    println!("[R8 mTLS] missing certificate diagnostic: {}", missing);

    let untrusted = refused(https_request(
        server.port,
        &pki.ca_der,
        Some(&pki.untrusted_client),
        &["h2"],
        REQUEST,
    ));
    let text = server
        .wait_for(|text| text.matches("mTLS handshake refused").count() >= 2)
        .expect("an untrusted certificate writes a clear diagnostic");
    assert!(text.contains("client certificate"), "{}", text);
    println!("[R8 mTLS] untrusted certificate diagnostic: {}", untrusted);
}
