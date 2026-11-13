//! R7 TLS tests: a real handshake over a real socket, the self-signed
//! fallback, the fingerprint log line and the clear error paths.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::{body_cap, logging, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::tls;

static NONCE: AtomicU64 = AtomicU64::new(0);

/// A demo server process killed and cleaned up on every test exit path.
struct DemoServer {
    child: Child,
    port: u16,
    stderr_path: PathBuf,
}

impl DemoServer {
    fn spawn(tag: &str, envs: &[(&str, &str)]) -> DemoServer {
        let port = free_port();
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let stderr_path = std::env::temp_dir().join(format!(
            "opurom-server-r7-tls-{}-{}-{}.stderr",
            tag,
            std::process::id(),
            nonce
        ));
        let stderr_file = fs::File::create(&stderr_path).expect("stderr file");

        let mut command = Command::new(env!("CARGO_BIN_EXE_opurom-server"));
        command
            .arg(port.to_string())
            .env_remove("OPR_PORT")
            .env_remove("OPR_RATE_LIMIT")
            .env_remove("OPR_LOG_JSON")
            .env_remove("OPR_AUTH_TOKEN")
            .env_remove("OPR_CORS")
            .env_remove("OPR_ETAG")
            .env_remove("OPR_TLS")
            .env_remove("OPR_TLS_CERT")
            .env_remove("OPR_TLS_KEY")
            .env_remove("OPR_MTLS")
            .env_remove("OPR_CLIENT_CA")
            .env_remove("OPR_REVOKED")
            .env_remove("OPR_CRL_FILE")
            .env_remove("OPR_OCSP_FILE")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        for (key, value) in envs {
            command.env(key, value);
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

    /// Wait until the startup line appears in the stderr log.
    fn wait_ready(&self) -> bool {
        for _ in 0..200 {
            if self.stderr().contains("listening on") {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
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

/// A router with one JSON route.
fn demo_router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router
}

/// Start a TLS server on an ephemeral port and return its address and the
/// DER bytes of its certificate.
fn start_tls() -> (u16, Vec<u8>, Arc<std::sync::atomic::AtomicBool>) {
    let mut chain = MiddlewareChain::new();
    chain.push(logging());
    chain.push(body_cap(1024 * 1024));
    let server = Server::bind_tls("127.0.0.1:0", demo_router(), chain, 1024 * 1024, None)
        .expect("TLS server binds");
    let certificate_der = server
        .tls_config()
        .expect("the server has a TLS configuration")
        .certificate_der()
        .to_vec();
    let (addr, shutdown) = server.spawn().expect("TLS server spawns");
    (addr.port(), certificate_der, shutdown)
}

/// A rustls client that trusts the given certificate as its only anchor.
fn client_with_trust_anchor(cert_der: Vec<u8>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der))
        .expect("the certificate is a valid trust anchor");
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Connect over TLS with a real handshake and read the whole answer.
fn https_request(port: u16, cert_der: Vec<u8>, request: &str) -> Result<String, String> {
    let config = client_with_trust_anchor(cert_der);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| format!("client connection: {}", err))?;
    let socket =
        TcpStream::connect(("127.0.0.1", port)).map_err(|err| format!("connect: {}", err))?;
    let mut stream = rustls::StreamOwned::new(connection, socket);
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("write: {}", err))?;
    stream.flush().map_err(|err| format!("flush: {}", err))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|err| format!("read: {}", err))?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

#[test]
fn tls_handshake_succeeds_over_a_real_socket() {
    let (port, certificate_der, shutdown) = start_tls();
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let answer = https_request(port, certificate_der, request).expect("the TLS handshake succeeds");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(answer.ends_with("{\"ok\":true}"), "{}", answer);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn tls_client_without_the_anchor_is_rejected() {
    let (port, _certificate_der, shutdown) = start_tls();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let connection =
        rustls::ClientConnection::new(Arc::new(config), server_name).expect("client connection");
    let socket = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let outcome = stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush());
    // The untrusted certificate is refused, so the write fails or the read
    // returns no HTTP answer at all.
    let answer = match outcome {
        Ok(()) => {
            let mut raw = Vec::new();
            let _ = stream.read_to_end(&mut raw);
            String::from_utf8_lossy(&raw).into_owned()
        }
        Err(_) => String::new(),
    };
    assert!(
        !answer.starts_with("HTTP/1.1 200 OK"),
        "an untrusted certificate must not serve a request: {}",
        answer
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn self_signed_certificate_has_a_fingerprint_and_no_key_leak() {
    let config = tls::self_signed_config().expect("self-signed certificate");
    assert!(config.is_self_signed());
    let fingerprint = config.fingerprint();
    assert_eq!(fingerprint.len(), 32 * 3 - 1, "{}", fingerprint);
    assert!(
        fingerprint
            .split(':')
            .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit())),
        "{}",
        fingerprint
    );

    let rendered = format!("{:?}", config);
    assert!(rendered.contains(fingerprint), "{}", rendered);
    assert!(!rendered.contains("PRIVATE KEY"), "{}", rendered);
}

#[test]
fn an_unreadable_certificate_file_is_a_clear_error() {
    let error = tls::config_from_pem_files(
        Path::new("/nonexistent/opurom-cert.pem"),
        Path::new("/nonexistent/opurom-key.pem"),
    )
    .expect_err("a missing certificate file is an error");
    let message = error.to_string();
    assert!(
        message.contains("cannot read the TLS certificate"),
        "{}",
        message
    );
}

#[test]
fn a_certificate_without_a_key_names_the_missing_variable() {
    // The environment is process-wide, so this test runs alone in its own
    // process through the demo server instead of changing it here.
    let dir = temp_dir("halfpair");
    let cert_path = dir.join("cert.pem");
    fs::write(&cert_path, certificate_pem()).expect("cert written");

    let port = free_port();
    let output = Command::new(env!("CARGO_BIN_EXE_opurom-server"))
        .arg(port.to_string())
        .env_remove("OPR_PORT")
        .env("OPR_TLS", "1")
        .env("OPR_TLS_CERT", &cert_path)
        .env_remove("OPR_TLS_KEY")
        .output()
        .expect("demo server runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the server must not start");
    assert!(
        stderr.contains("OPR_TLS_KEY is missing"),
        "the error must name the missing variable: {}",
        stderr
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_mismatched_certificate_and_key_pair_is_a_clear_error() {
    let dir = temp_dir("mismatch");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(&cert_path, certificate_pem()).expect("cert written");
    fs::write(&key_path, key_pem()).expect("key written");

    // A certificate that does not match the key must not start a server.
    let error = tls::config_from_pem_files(&cert_path, &key_path).expect_err("mismatched pair");
    let message = error.to_string();
    assert!(message.contains("do not form a usable pair"), "{}", message);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_corrupt_certificate_pem_is_a_clear_error() {
    let dir = temp_dir("corrupt");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n",
    )
    .expect("cert written");
    fs::write(&key_path, key_pem()).expect("key written");

    let error =
        tls::config_from_pem_files(&cert_path, &key_path).expect_err("a corrupt PEM is an error");
    let message = error.to_string();
    assert!(
        message.contains("not a valid PEM chain")
            || message.contains("no CERTIFICATE block")
            || message.contains("do not form a usable pair"),
        "{}",
        message
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_demo_server_logs_the_fingerprint_and_not_the_key() {
    let server = DemoServer::spawn("fingerprint", &[("OPR_TLS", "1")]);
    let mut stderr = String::new();
    for _ in 0..200 {
        stderr = server.stderr();
        if stderr.contains("listening on https://") {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(stderr.contains("listening on https://"), "{}", stderr);
    assert!(
        stderr.contains("TLS certificate SHA-256 fingerprint"),
        "{}",
        stderr
    );
    assert!(
        !stderr.contains("PRIVATE KEY") && !stderr.contains("BEGIN "),
        "the private key must never be logged: {}",
        stderr
    );
}

#[test]
fn the_demo_server_reports_a_bad_certificate_pair_and_exits() {
    let dir = temp_dir("badpair");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(&cert_path, certificate_pem()).expect("cert written");
    fs::write(&key_path, key_pem()).expect("key written");

    let port = free_port();
    let output = Command::new(env!("CARGO_BIN_EXE_opurom-server"))
        .arg(port.to_string())
        .env_remove("OPR_PORT")
        .env("OPR_TLS", "1")
        .env("OPR_TLS_CERT", &cert_path)
        .env("OPR_TLS_KEY", &key_path)
        .output()
        .expect("demo server runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the server must not start");
    assert!(
        stderr.contains("do not form a usable pair"),
        "the error must name the problem: {}",
        stderr
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn plain_http_stays_byte_identical_without_opr_tls() {
    let server = DemoServer::spawn("plain", &[]);
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).expect("connect");
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    let answer = String::from_utf8_lossy(&raw).into_owned();
    let body = "{\"ok\":true,\"app\":\"opurom-server-demo\",\"version\":\"0.2.0\"}";
    assert_eq!(
        answer,
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    );
}

/// A unique temporary directory for one test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "opurom-tls-{}-{}-{}",
        name,
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// The PEM of a generated certificate.
fn certificate_pem() -> String {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let key = rcgen::KeyPair::generate().expect("key");
    params.self_signed(&key).expect("self-sign").pem()
}

/// The PEM of a generated private key that does not match [`certificate_pem`].
fn key_pem() -> String {
    rcgen::KeyPair::generate().expect("key").serialize_pem()
}
