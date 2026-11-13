//! Environment-variable integration for `OPR_CRL_FILE` and
//! `OPR_OCSP_FILE`. All PEM and DER files are generated inside this crate's
//! ignored `target/` directory at test runtime and removed afterwards.

#[path = "support/status_fixture.rs"]
mod status_fixture;

use std::ffi::OsString;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::tls;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use status_fixture::{fixture as make_fixture, ClientIdentity, Fixture};

const REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const HEALTH_BODY: &str = "{\"ok\":true}";
const OPR_VARS: &[&str] = &[
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
];

static NONCE: AtomicU64 = AtomicU64::new(0);

/// Remove all opt-in variables for this one-test binary and restore them.
struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn isolate() -> EnvGuard {
        let saved = OPR_VARS
            .iter()
            .map(|&name| (name, std::env::var_os(name)))
            .collect();
        for name in OPR_VARS {
            std::env::remove_var(name);
        }
        EnvGuard { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// A unique temporary directory inside the ignored crate-local target tree.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "opurom-server-r10-{}-{}-{}",
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

fn demo_router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, HEALTH_BODY)
    });
    router
}

fn client_config(root_der: &[u8], identity: &ClientIdentity) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .expect("trust anchor");
    let certs = rustls_pemfile::certs(&mut BufReader::new(identity.chain_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .expect("client certificate chain");
    let key = rustls_pemfile::private_key(&mut BufReader::new(identity.key_pem.as_bytes()))
        .expect("client private key")
        .expect("client PRIVATE KEY block");
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .expect("client identity");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

fn https_request(port: u16, root_der: &[u8], identity: &ClientIdentity) -> Result<String, String> {
    let config = client_config(root_der, identity);
    let server_name = ServerName::try_from("localhost").expect("server name");
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| format!("client connection: {}", err))?;
    let socket =
        TcpStream::connect(("127.0.0.1", port)).map_err(|err| format!("connect: {}", err))?;
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(5)));
    let mut stream = StreamOwned::new(connection, socket);
    stream
        .write_all(REQUEST.as_bytes())
        .map_err(|err| format!("write: {}", err))?;
    stream.flush().map_err(|err| format!("flush: {}", err))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|err| format!("read: {}", err))?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

fn refused(result: Result<String, String>) -> String {
    match result {
        Ok(answer) => panic!("the handshake must be refused, got: {}", answer),
        Err(err) => err,
    }
}

fn start_env_server(config: tls::TlsConfig) -> (u16, Arc<AtomicBool>) {
    let server = Server::bind_tls(
        "127.0.0.1:0",
        demo_router(),
        MiddlewareChain::new(),
        1024 * 1024,
        Some(config),
    )
    .expect("environment-configured mTLS server binds");
    let (addr, shutdown) = server.spawn().expect("mTLS server spawns");
    (addr.port(), shutdown)
}

#[test]
fn crl_and_ocsp_env_files_configure_mtls() {
    let _env = EnvGuard::isolate();
    let pki: Fixture = make_fixture();
    let dir = TempDir::new("env");
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    let crl_path = dir.path().join("client.crl");
    let ocsp_path = dir.path().join("client.ocsp");
    fs::write(&cert_path, pki.server_chain_pem.as_bytes()).expect("server PEM written");
    fs::write(&key_path, pki.server_key_pem.as_bytes()).expect("server key written");
    fs::write(&crl_path, pki.crl_revokes_other.as_slice()).expect("CRL DER written");
    fs::write(&ocsp_path, pki.ocsp_good.as_slice()).expect("OCSP DER written");

    std::env::set_var("OPR_MTLS", "1");
    std::env::set_var("OPR_CLIENT_CA", pki.ca_pem.as_str());
    std::env::set_var("OPR_TLS_CERT", cert_path.as_os_str());
    std::env::set_var("OPR_TLS_KEY", key_path.as_os_str());
    std::env::set_var("OPR_CRL_FILE", crl_path.as_os_str());
    std::env::set_var("OPR_OCSP_FILE", ocsp_path.as_os_str());

    let config = tls::config_from_env().expect("environment TLS configuration");
    assert!(config.requires_client_auth());
    let (port, shutdown) = start_env_server(config);
    let answer = https_request(port, &pki.ca_der, &pki.trusted)
        .expect("a good client with both local status files completes mTLS");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(answer.ends_with(HEALTH_BODY), "{}", answer);

    fs::remove_file(&ocsp_path).expect("OCSP DER file removed");
    let missing_ocsp = refused(https_request(port, &pki.ca_der, &pki.trusted));
    fs::write(&ocsp_path, pki.ocsp_good.as_slice()).expect("OCSP DER file restored");
    fs::remove_file(&crl_path).expect("CRL DER file removed");
    let missing_crl = refused(https_request(port, &pki.ca_der, &pki.trusted));

    println!(
        "[env] both local files accepted; missing OCSP={}, missing CRL={}",
        missing_ocsp, missing_crl
    );
    shutdown.store(true, Ordering::Relaxed);
}
