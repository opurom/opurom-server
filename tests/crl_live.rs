//! Live CRL retrieval over a loopback HTTP distribution point. A real mTLS
//! server, a real HTTP/1.1 CRL server on 127.0.0.1:0 and rcgen fixtures prove
//! the fetch, the URL-keyed cache, the refresh interval, the local-file
//! precedence and fail-closed behaviour. Request counts are measured from the
//! HTTP server, not estimated.

#[path = "support/status_fixture.rs"]
mod status_fixture;

use std::ffi::OsString;
use std::fs;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::tls;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use status_fixture::{fixture as make_fixture, fixture_with_crl_dp, ClientIdentity, Fixture};

const REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const HEALTH_BODY: &str = "{\"ok\":true}";
const TTL_SECS: &str = "0.2";
const EXPIRE_WAIT: Duration = Duration::from_millis(320);

const OPR_VARS: &[&str] = &[
    "OPR_MTLS",
    "OPR_CLIENT_CA",
    "OPR_REVOKED",
    "OPR_CRL_FILE",
    "OPR_CRL_URL",
    "OPR_CRL_TTL_SECS",
    "OPR_OCSP_FILE",
];

static ENV_LOCK: Mutex<()> = Mutex::new(());
static NONCE: AtomicU64 = AtomicU64::new(0);

/// The tests in this binary share process-global environment variables.
struct EnvGuard(Vec<(&'static str, Option<OsString>)>);

impl EnvGuard {
    fn isolate() -> (MutexGuard<'static, ()>, EnvGuard) {
        let lock = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let saved = OPR_VARS
            .iter()
            .map(|&name| (name, std::env::var_os(name)))
            .collect();
        for name in OPR_VARS {
            std::env::remove_var(name);
        }
        (lock, EnvGuard(saved))
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
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
                "opurom-server-crl-live-{}-{}-{}",
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

/// One loopback HTTP/1.1 distribution point that serves the same DER CRL on
/// every request and counts the requests it accepted.
struct CrlServer {
    url: String,
    requests: Arc<AtomicUsize>,
    body: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl CrlServer {
    fn start(der: &[u8]) -> CrlServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback CRL listener binds");
        let port = listener.local_addr().expect("loopback address").port();
        let requests = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(Mutex::new(der.to_vec()));
        let stop = Arc::new(AtomicBool::new(false));
        let counted = Arc::clone(&requests);
        let served = Arc::clone(&body);
        let stopping = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let mut request = [0u8; 1024];
                        let _ = stream.read(&mut request);
                        let reply = {
                            let body = served.lock().unwrap_or_else(PoisonError::into_inner);
                            let mut out = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            out.extend_from_slice(&body);
                            out
                        };
                        let _ = stream.write_all(&reply);
                    }
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        CrlServer {
            url: format!("http://127.0.0.1:{}/crl/client.crl", port),
            requests,
            body,
            stop,
            handle: Some(handle),
        }
    }

    fn set_body(&self, der: &[u8]) {
        *self.body.lock().unwrap_or_else(PoisonError::into_inner) = der.to_vec();
    }

    fn count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn shutdown(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.stop.store(true, Ordering::SeqCst);
            handle.join().expect("CRL server thread stops");
        }
    }
}

impl Drop for CrlServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn demo_router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, HEALTH_BODY)
    });
    router
}

fn set_mtls_env(pki: &Fixture) {
    std::env::set_var("OPR_MTLS", "1");
    std::env::set_var("OPR_CLIENT_CA", pki.ca_pem.as_str());
    std::env::set_var(tls::CRL_TTL_SECS_ENV, TTL_SECS);
}

/// Build the mTLS listener from the environment, so `OPR_CRL_URL` and
/// `OPR_CRL_TTL_SECS` go through the production configuration path.
fn env_server(pki: &Fixture) -> (u16, Arc<AtomicBool>) {
    let options = tls::MtlsOptions::from_env()
        .expect("mTLS options from the environment")
        .expect("OPR_MTLS=1 configures mTLS");
    let config = tls::config_from_pem_bytes(
        pki.server_chain_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        Some(&options),
    )
    .expect("TLS configuration with the live CRL source");
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

fn accepted(result: Result<String, String>) {
    let answer = result.expect("a good client certificate completes mTLS");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(answer.ends_with(HEALTH_BODY), "{}", answer);
}

#[test]
fn live_crl_url_fetches_caches_refreshes_and_fails_closed() {
    let (_lock, _env) = EnvGuard::isolate();
    let pki = make_fixture();
    let mut crl_server = CrlServer::start(&pki.crl_revokes_other);
    set_mtls_env(&pki);
    std::env::set_var(tls::CRL_URL_ENV, crl_server.url.as_str());

    let (port, shutdown) = env_server(&pki);
    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let first = crl_server.count();
    assert_eq!(first, 1, "the first handshake fetches the CRL once");

    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let cached = crl_server.count();
    assert_eq!(cached, first, "the second handshake uses the fresh cache");

    thread::sleep(EXPIRE_WAIT);
    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let refreshed = crl_server.count();
    assert_eq!(refreshed, first + 1, "an expired cache refetches once");

    crl_server.shutdown();
    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let offline_cached = crl_server.count();
    assert_eq!(
        offline_cached, refreshed,
        "a fresh cached CRL verifies with the distribution point gone"
    );

    thread::sleep(EXPIRE_WAIT);
    let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    let offline_expired = crl_server.count();
    assert_eq!(
        offline_expired, refreshed,
        "an expired cache with no distribution point refuses the handshake"
    );
    println!(
        "[live CRL] measured requests: first={}, after cached handshake={}, after TTL refresh={}, cached with server down={}, expired with server down={} (refused: {})",
        first, cached, refreshed, offline_cached, offline_expired, err
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn live_crl_without_cache_and_without_server_fails_closed() {
    let (_lock, _env) = EnvGuard::isolate();
    let pki = make_fixture();
    let mut crl_server = CrlServer::start(&pki.crl_revokes_other);
    let url = crl_server.url.clone();
    crl_server.shutdown();
    set_mtls_env(&pki);
    std::env::set_var(tls::CRL_URL_ENV, url);

    let (port, shutdown) = env_server(&pki);
    let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    assert_eq!(crl_server.count(), 0, "no request reached the closed port");
    println!(
        "[live CRL] no cache and no server: requests={}, refused: {}",
        crl_server.count(),
        err
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn live_crl_url_keeps_signature_freshness_and_serial_checks() {
    let (_lock, _env) = EnvGuard::isolate();
    let pki = make_fixture();
    for (label, der) in [
        ("revoked serial", pki.crl_revokes_trusted.clone()),
        ("stale nextUpdate", pki.crl_stale.clone()),
        ("bad signature", pki.crl_tampered.clone()),
    ] {
        let crl_server = CrlServer::start(&der);
        set_mtls_env(&pki);
        std::env::set_var(tls::CRL_URL_ENV, crl_server.url.as_str());
        let (port, shutdown) = env_server(&pki);
        let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
        assert!(!err.contains("HTTP/1.1 200"), "{}", err);
        assert_eq!(crl_server.count(), 1, "{} fetched once", label);
        println!(
            "[live CRL] {} refused with {} fetched request",
            label,
            crl_server.count()
        );
        shutdown.store(true, Ordering::Relaxed);
    }
}

#[test]
fn crl_file_takes_precedence_over_crl_url() {
    let (_lock, _env) = EnvGuard::isolate();
    let pki = make_fixture();
    // The URL serves a CRL that revokes the trusted client; the local file
    // keeps it accepted, and no HTTP request is made.
    let crl_server = CrlServer::start(&pki.crl_revokes_trusted);
    let dir = TempDir::new("file-wins");
    let crl_path = dir.path().join("client.crl");
    fs::write(&crl_path, &pki.crl_revokes_other).expect("local CRL DER written");
    set_mtls_env(&pki);
    std::env::set_var(tls::CRL_URL_ENV, crl_server.url.as_str());
    std::env::set_var(tls::CRL_FILE_ENV, crl_path.as_os_str());

    let (port, shutdown) = env_server(&pki);
    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let with_file = crl_server.count();
    assert_eq!(with_file, 0, "a local CRL file wins over the URL");

    fs::remove_file(&crl_path).expect("local CRL DER removed");
    let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    let after_removal = crl_server.count();
    assert_eq!(
        after_removal, 0,
        "a configured local file stays required even when a URL is set"
    );
    println!(
        "[live CRL] local file precedence: requests with file={}, after file removal={} (refused: {})",
        with_file, after_removal, err
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn crl_url_from_certificate_extension_fetches_and_caches() {
    let (_lock, _env) = EnvGuard::isolate();
    let crl_server = CrlServer::start(&[]);
    // The trusted client carries a CRL Distribution Points extension naming
    // exactly this loopback URL.
    let pki = fixture_with_crl_dp(&crl_server.url);
    crl_server.set_body(&pki.crl_revokes_other);
    set_mtls_env(&pki);
    std::env::set_var(tls::CRL_URL_ENV, "cert");

    let (port, shutdown) = env_server(&pki);
    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let first = crl_server.count();
    assert_eq!(first, 1, "the certificate extension drives one fetch");
    accepted(https_request(port, &pki.ca_der, &pki.trusted));
    let cached = crl_server.count();
    assert_eq!(cached, first, "the extension URL cache key is stable");
    println!(
        "[live CRL] certificate extension: first={}, after cached handshake={}",
        first, cached
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn invalid_crl_url_or_ttl_is_a_startup_error() {
    let (_lock, _env) = EnvGuard::isolate();
    std::env::set_var("OPR_MTLS", "1");
    std::env::set_var("OPR_CLIENT_CA", "-----BEGIN CERTIFICATE-----");
    std::env::set_var(tls::CRL_URL_ENV, "http://127.0.0.1:1/crl");

    std::env::set_var(tls::CRL_TTL_SECS_ENV, "abc");
    let err = tls::MtlsOptions::from_env().expect_err("a non-numeric TTL is refused");
    assert!(err.to_string().contains(tls::CRL_TTL_SECS_ENV), "{}", err);

    std::env::set_var(tls::CRL_TTL_SECS_ENV, "0");
    let err = tls::MtlsOptions::from_env().expect_err("a zero TTL is refused");
    assert!(err.to_string().contains(tls::CRL_TTL_SECS_ENV), "{}", err);

    std::env::remove_var(tls::CRL_TTL_SECS_ENV);
    std::env::set_var(tls::CRL_URL_ENV, "https://ca.example/crl");
    let err = tls::MtlsOptions::from_env().expect_err("an HTTPS URL is refused");
    assert!(err.to_string().contains("HTTPS"), "{}", err);
}
