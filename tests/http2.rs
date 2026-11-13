//! HTTP/2 tests over the real TLS listener: concurrent h2 client streams,
//! request/response flow control, stream isolation and graceful GOAWAY.

mod support;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opurom_server::http::{Request, Response};
use opurom_server::middleware::{body_cap, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::server::Server;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, StreamOwned};
use support::h2::{exchange, RequestSpec};

const LARGE_BODY_BYTES: usize = 256 * 1024;
const LARGE_REQUEST_BYTES: usize = 128 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const SETTINGS_FRAME: u8 = 4;
const PING_FRAME: u8 = 6;
const GOAWAY_FRAME: u8 = 7;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const CLIENT_SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];
const SETTINGS_ACK: &[u8] = &[0, 0, 0, 4, 1, 0, 0, 0, 0];

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

static BIND_LOCK: Mutex<()> = Mutex::new(());

/// Restore process-wide environment variables after a server binds.
struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn apply(envs: &[(&'static str, &str)]) -> EnvGuard {
        let saved = OPR_VARS
            .iter()
            .map(|&name| (name, std::env::var_os(name)))
            .collect();
        for &name in OPR_VARS {
            std::env::remove_var(name);
        }
        for &(name, value) in envs {
            std::env::set_var(name, value);
        }
        EnvGuard { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, previous) in &self.saved {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// An in-process TLS server. Setting its shutdown flag and connecting once
/// wakes the detached accept loop so no thread outlives the test.
struct TestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    shutdown: Arc<AtomicBool>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
    }
}

fn start_server(envs: &[(&'static str, &str)], router: Router) -> TestServer {
    let _bind_guard = BIND_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let env_guard = EnvGuard::apply(envs);
    let mut chain = MiddlewareChain::new();
    chain.push(Arc::new(|request: &mut Request| {
        if request.path == "/blocked" {
            Some(Response::error(418, "blocked"))
        } else {
            None
        }
    }));
    chain.push(body_cap(MAX_BODY_BYTES));
    let server = Server::bind_tls("127.0.0.1:0", router, chain, MAX_BODY_BYTES, None)
        .expect("TLS server binds");
    drop(env_guard);
    let cert_der = server
        .tls_config()
        .expect("the server has TLS")
        .certificate_der()
        .to_vec();
    let (addr, shutdown) = server.spawn().expect("TLS server spawns");
    TestServer {
        addr,
        cert_der,
        shutdown,
    }
}

fn large_body() -> Vec<u8> {
    (0..LARGE_BODY_BYTES)
        .map(|index| b'a' + (index % 26) as u8)
        .collect()
}

fn router() -> Router {
    let large = String::from_utf8(large_body()).expect("large body is ASCII");
    let mut router = Router::new();
    router.get("/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router.get("/items/:id", |request: &mut Request| {
        let id = request.param("id").unwrap_or_default();
        Response::json_text(
            200,
            &format!("{{\"id\":\"{}\",\"query\":\"{}\"}}", id, request.query),
        )
    });
    router.post("/echo", |request: &mut Request| {
        Response::text(200, request.body_str().unwrap_or_default())
    });
    router.get("/large", move |_request: &mut Request| {
        Response::text(200, &large)
    });
    router.get("/panic", |_request: &mut Request| {
        panic!("intentional h2 stream failure")
    });
    router
}

fn with_dev_headers(spec: RequestSpec) -> RequestSpec {
    spec.with_header("Authorization", "Bearer devtoken")
        .with_header("Origin", "https://app.example")
}

#[test]
fn h2_concurrent_streams_share_one_tls_connection() {
    let server = start_server(
        &[
            ("OPR_AUTH_TOKEN", "devtoken"),
            ("OPR_CORS", "https://app.example"),
            ("OPR_ETAG", "1"),
        ],
        router(),
    );
    let requests = vec![
        with_dev_headers(RequestSpec::get("/health")),
        with_dev_headers(RequestSpec::get("/items/42?q=one")),
        with_dev_headers(RequestSpec::new("POST", "/echo").with_body(b"hello h2".to_vec())),
        with_dev_headers(
            RequestSpec::new("OPTIONS", "/health")
                .with_header("Access-Control-Request-Method", "GET"),
        ),
        with_dev_headers(RequestSpec::get("/blocked")),
    ];
    let (alpn, answers) = exchange(server.addr.port(), &server.cert_der, None, requests)
        .expect("one h2 connection serves every concurrent stream");
    assert_eq!(alpn.as_deref(), Some("h2"));
    assert_eq!(
        answers
            .iter()
            .map(|answer| answer.status)
            .collect::<Vec<_>>(),
        vec![200, 200, 200, 204, 418]
    );
    assert_eq!(answers[0].body, b"{\"ok\":true}");
    assert_eq!(answers[0].header("content-length"), Some("11"));
    assert!(answers[0].header("etag").is_some());
    assert_eq!(
        answers[0].header("access-control-allow-origin"),
        Some("https://app.example")
    );
    assert_eq!(answers[1].body, b"{\"id\":\"42\",\"query\":\"q=one\"}");
    assert_eq!(answers[2].body, b"hello h2");
    assert!(answers[3].body.is_empty());
    assert_eq!(
        answers[3].header("access-control-allow-methods"),
        Some("GET, POST, PUT, DELETE, OPTIONS")
    );
    assert_eq!(answers[4].body, b"{\"error\":\"blocked\"}");
    println!(
        "[h2] one TLS connection, {} concurrent streams: GET /health=200, GET /items/42=200, POST /echo=200, OPTIONS /health=204, GET /blocked=418; ALPN=h2",
        answers.len()
    );
}

#[test]
fn h2_large_body_flow_control_isolates_failed_stream() {
    let server = start_server(&[], router());
    let posted = (0..LARGE_REQUEST_BYTES)
        .map(|index| b'0' + (index % 10) as u8)
        .collect::<Vec<u8>>();
    let requests = vec![
        RequestSpec::get("/large"),
        RequestSpec::get("/panic"),
        RequestSpec::new("POST", "/echo").with_body(posted.clone()),
        RequestSpec::get("/health"),
    ];
    let (alpn, answers) = exchange(server.addr.port(), &server.cert_der, None, requests)
        .expect("large bodies and a failed stream keep the h2 connection usable");
    assert_eq!(alpn.as_deref(), Some("h2"));
    assert_eq!(
        answers
            .iter()
            .map(|answer| answer.status)
            .collect::<Vec<_>>(),
        vec![200, 500, 200, 200]
    );
    assert_eq!(answers[0].body, large_body());
    assert_eq!(answers[1].body, b"{\"error\":\"handler_panic\"}");
    assert_eq!(answers[2].body, posted);
    assert_eq!(answers[3].body, b"{\"ok\":true}");
    println!(
        "[h2] {} KiB response and {} KiB request crossed flow-control windows; GET /large=200, GET /panic=500, POST /echo=200, GET /health=200 on one connection",
        LARGE_BODY_BYTES / 1024,
        LARGE_REQUEST_BYTES / 1024
    );
}

#[derive(Debug)]
struct Frame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn read_frame<R: Read>(reader: &mut R) -> std::io::Result<Frame> {
    let mut header = [0u8; 9];
    reader.read_exact(&mut header)?;
    let length = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    Ok(Frame {
        kind: header[3],
        flags: header[4],
        stream_id,
        payload,
    })
}

fn rustls_h2_config(cert_der: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("self-signed certificate is a trust anchor");
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

#[test]
fn h2_shutdown_sends_graceful_goaway() {
    let server = start_server(&[], router());
    let socket = TcpStream::connect(server.addr).expect("TLS socket connects");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let connection =
        rustls::ClientConnection::new(Arc::new(rustls_h2_config(&server.cert_der)), server_name)
            .expect("client connection");
    let mut tls = StreamOwned::new(connection, socket);
    tls.write_all(H2_PREFACE).expect("write h2 preface");
    tls.write_all(CLIENT_SETTINGS).expect("write SETTINGS");
    tls.flush().expect("flush h2 preface and SETTINGS");

    let mut shutdown_requested = false;
    let mut initial_goaway = false;
    for _ in 0..64 {
        let frame = read_frame(&mut tls).expect("read an h2 frame");
        if frame.kind == SETTINGS_FRAME && frame.flags & 1 == 0 {
            tls.write_all(SETTINGS_ACK).expect("write SETTINGS ACK");
            tls.flush().expect("flush SETTINGS ACK");
            if !shutdown_requested {
                server.shutdown.store(true, Ordering::Relaxed);
                shutdown_requested = true;
            }
        } else if frame.kind == PING_FRAME && frame.flags & 1 == 0 {
            assert_eq!(frame.payload.len(), 8);
            let mut pong = vec![0, 0, 8, PING_FRAME, 1, 0, 0, 0, 0];
            pong.extend_from_slice(&frame.payload);
            tls.write_all(&pong).expect("write PING ACK");
            tls.flush().expect("flush PING ACK");
        } else if frame.kind == GOAWAY_FRAME {
            assert_eq!(frame.stream_id, 0);
            assert!(frame.payload.len() >= 8);
            assert_eq!(&frame.payload[4..8], &[0, 0, 0, 0]);
            let last_stream_id = u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]) & 0x7fff_ffff;
            if last_stream_id == 0x7fff_ffff {
                initial_goaway = true;
                continue;
            }
            assert!(initial_goaway, "the final GOAWAY follows the initial one");
            assert_eq!(last_stream_id, 0);
            println!(
                "[h2] shutdown sent initial GOAWAY(last_stream_id=2^31-1, NO_ERROR), accepted PING ACK, then final GOAWAY(last_stream_id=0, NO_ERROR)"
            );
            return;
        }
    }
    panic!("the server did not complete a graceful GOAWAY exchange");
}
