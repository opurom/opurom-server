//! R10 certificate-status tests over real mTLS sockets. All status fixtures
//! are generated in memory by rcgen; the required sources are in-memory DER
//! bytes or local DER files under this crate's ignored `target/` directory.
//! No live OCSP responder is contacted and no private key is checked in.

#[path = "support/status_fixture.rs"]
mod status_fixture;

use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use opurom_server::cert_status::{StatusSource, MAX_STATUS_DER_BYTES};
use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::tls::{self, MtlsOptions};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use status_fixture::{fixture as make_fixture, ClientIdentity, Fixture};

const REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const HEALTH_BODY: &str = "{\"ok\":true}";

static NONCE: AtomicU64 = AtomicU64::new(0);
static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn shared_fixture() -> &'static Fixture {
    FIXTURE.get_or_init(make_fixture)
}

fn crl_source(bytes: Vec<u8>) -> StatusSource {
    StatusSource::in_memory(tls::CRL_FILE_ENV, bytes)
}

fn ocsp_source(bytes: Vec<u8>) -> StatusSource {
    StatusSource::in_memory(tls::OCSP_FILE_ENV, bytes)
}

fn demo_router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, HEALTH_BODY)
    });
    router
}

fn start_server(
    pki: &Fixture,
    crl: Option<StatusSource>,
    ocsp: Option<StatusSource>,
) -> (u16, Arc<AtomicBool>) {
    let options = MtlsOptions {
        client_ca_pem: pki.ca_pem.as_bytes().to_vec(),
        crl,
        ocsp,
        ..MtlsOptions::default()
    };
    let config = tls::config_from_pem_bytes(
        pki.server_chain_pem.as_bytes(),
        pki.server_key_pem.as_bytes(),
        Some(&options),
    )
    .expect("mTLS server configuration with status sources");
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

fn accepted(result: Result<String, String>) -> String {
    let answer = result.expect("a good client certificate completes mTLS");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(answer.ends_with(HEALTH_BODY), "{}", answer);
    answer
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

#[test]
fn crl_revoked_serial_is_refused_and_good_client_is_accepted() {
    let pki = shared_fixture();
    let (port, shutdown) =
        start_server(pki, Some(crl_source(pki.crl_revokes_trusted.clone())), None);
    let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    accepted(https_request(port, &pki.ca_der, &pki.other));
    println!(
        "[R10 CRL] revoked serial refused; a non-revoked trusted serial accepted: {}",
        err
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn crl_stale_or_tampered_der_fails_closed() {
    let pki = shared_fixture();
    for (label, der) in [
        ("stale nextUpdate", pki.crl_stale.clone()),
        ("bad signature", pki.crl_tampered.clone()),
    ] {
        let (port, shutdown) = start_server(pki, Some(crl_source(der)), None);
        let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
        assert!(!err.contains("HTTP/1.1 200"), "{}", err);
        println!("[R10 CRL] {} failed closed: {}", label, err);
        shutdown.store(true, Ordering::Relaxed);
    }
}

#[test]
fn crl_malformed_or_oversized_der_fails_closed() {
    let pki = shared_fixture();
    for (label, der) in [
        ("malformed", vec![0x30, 0x00]),
        ("oversized", vec![0u8; MAX_STATUS_DER_BYTES + 1]),
    ] {
        let (port, shutdown) = start_server(pki, Some(crl_source(der)), None);
        let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
        assert!(!err.contains("HTTP/1.1 200"), "{}", err);
        println!("[R10 CRL] {} DER failed closed: {}", label, err);
        shutdown.store(true, Ordering::Relaxed);
    }
}

#[test]
fn ocsp_good_status_is_accepted_and_revoked_status_is_refused() {
    let pki = shared_fixture();
    let (good_port, good_shutdown) =
        start_server(pki, None, Some(ocsp_source(pki.ocsp_good.clone())));
    accepted(https_request(good_port, &pki.ca_der, &pki.trusted));
    good_shutdown.store(true, Ordering::Relaxed);

    let (bad_port, bad_shutdown) =
        start_server(pki, None, Some(ocsp_source(pki.ocsp_revoked.clone())));
    let err = refused(https_request(bad_port, &pki.ca_der, &pki.trusted));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    println!("[R10 OCSP] good accepted; revoked refused: {}", err);
    bad_shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn ocsp_unknown_and_wrong_serial_fail_closed() {
    let pki = shared_fixture();
    for (label, der) in [
        ("unknown status", pki.ocsp_unknown.clone()),
        ("no matching serial", pki.ocsp_other_serial.clone()),
    ] {
        let (port, shutdown) = start_server(pki, None, Some(ocsp_source(der)));
        let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
        assert!(!err.contains("HTTP/1.1 200"), "{}", err);
        println!("[R10 OCSP] {} failed closed: {}", label, err);
        shutdown.store(true, Ordering::Relaxed);
    }
}

#[test]
fn ocsp_stale_or_tampered_response_fails_closed() {
    let pki = shared_fixture();
    for (label, der) in [
        ("stale nextUpdate", pki.ocsp_stale.clone()),
        ("bad signature", pki.ocsp_tampered.clone()),
    ] {
        let (port, shutdown) = start_server(pki, None, Some(ocsp_source(der)));
        let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
        assert!(!err.contains("HTTP/1.1 200"), "{}", err);
        println!("[R10 OCSP] {} failed closed: {}", label, err);
        shutdown.store(true, Ordering::Relaxed);
    }
}

#[test]
fn ocsp_empty_env_value_fails_closed() {
    let pki = shared_fixture();
    let source = StatusSource::unavailable(tls::OCSP_FILE_ENV, "OPR_OCSP_FILE is empty");
    let (port, shutdown) = start_server(pki, None, Some(source));
    let err = refused(https_request(port, &pki.ca_der, &pki.trusted));
    assert!(!err.contains("HTTP/1.1 200"), "{}", err);
    println!("[R10 OCSP] empty required source failed closed: {}", err);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn ocsp_unavailable_or_malformed_file_fails_closed() {
    let pki = shared_fixture();
    let dir = TempDir::new("ocsp-file");
    let path = dir.path().join("response.der");
    let source = StatusSource::file(tls::OCSP_FILE_ENV, path.clone());
    let (port, shutdown) = start_server(pki, None, Some(source));

    let missing = refused(https_request(port, &pki.ca_der, &pki.trusted));
    fs::write(&path, &pki.ocsp_good).expect("good OCSP DER file written");
    accepted(https_request(port, &pki.ca_der, &pki.trusted));

    fs::remove_file(&path).expect("good OCSP DER file removed");
    let unavailable = refused(https_request(port, &pki.ca_der, &pki.trusted));
    fs::write(&path, [0x30, 0x00]).expect("malformed OCSP DER file written");
    let malformed = refused(https_request(port, &pki.ca_der, &pki.trusted));
    fs::write(&path, vec![0u8; MAX_STATUS_DER_BYTES + 1]).expect("oversized OCSP DER file written");
    let oversized = refused(https_request(port, &pki.ca_der, &pki.trusted));

    println!(
        "[R10 OCSP] missing={}, unavailable={}, malformed={}, oversized={}",
        missing, unavailable, malformed, oversized
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn crl_and_ocsp_sources_are_both_required() {
    let pki = shared_fixture();
    for (crl, ocsp, should_accept, label) in [
        (
            pki.crl_revokes_other.clone(),
            pki.ocsp_good.clone(),
            true,
            "both good",
        ),
        (
            pki.crl_revokes_other.clone(),
            pki.ocsp_revoked.clone(),
            false,
            "OCSP revoked",
        ),
        (
            pki.crl_revokes_trusted.clone(),
            pki.ocsp_good.clone(),
            false,
            "CRL revoked",
        ),
    ] {
        let (port, shutdown) = start_server(pki, Some(crl_source(crl)), Some(ocsp_source(ocsp)));
        let result = https_request(port, &pki.ca_der, &pki.trusted);
        if should_accept {
            accepted(result);
        } else {
            let err = refused(result);
            assert!(!err.contains("HTTP/1.1 200"), "{}", err);
            println!(
                "[R10 status] {} refused when both sources are required",
                label
            );
        }
        shutdown.store(true, Ordering::Relaxed);
    }
}

#[test]
fn r9_mtls_response_bytes_are_identical_without_status_sources() {
    let pki = shared_fixture();
    let (port, shutdown) = start_server(pki, None, None);
    let answer = https_request(port, &pki.ca_der, &pki.trusted)
        .expect("R9 mTLS still accepts a trusted client");
    let expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        HEALTH_BODY.len(),
        HEALTH_BODY
    );
    assert_eq!(answer, expected);
    println!("[R10 status] no status sources: byte-identical R9 mTLS answer");
    shutdown.store(true, Ordering::Relaxed);
}
