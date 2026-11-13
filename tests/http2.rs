//! HTTP/2 tests over the real TLS listener: concurrent h2 client streams,
//! request/response flow control, stream isolation, client RST_STREAM and
//! graceful GOAWAY.

mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
const DATA_FRAME: u8 = 0;
const HEADERS_FRAME: u8 = 1;
const RST_STREAM_FRAME: u8 = 3;
const SETTINGS_FRAME: u8 = 4;
const PING_FRAME: u8 = 6;
const GOAWAY_FRAME: u8 = 7;
const END_STREAM_FLAG: u8 = 1;
const END_HEADERS_FLAG: u8 = 4;
const RST_CANCEL: u32 = 8;
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

/// Build one raw h2 frame, with the reserved bit of the stream id cleared.
fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut bytes = Vec::with_capacity(9 + length);
    bytes.extend_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    bytes.push(kind);
    bytes.push(flags);
    bytes.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// HPACK literal header field without indexing, with a new (unindexed) name.
/// shortcut: one-byte lengths fit every test header, add HPACK integer
/// continuation when a name or value reaches 127 bytes.
fn literal_header(name: &str, value: &str) -> Vec<u8> {
    let mut bytes = vec![0x00];
    bytes.push(name.len() as u8);
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(value.len() as u8);
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

fn request_frame(stream_id: u32, method: &str, path: &str, end_stream: bool) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in [
        (":method", method),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", path),
    ] {
        block.extend_from_slice(&literal_header(name, value));
    }
    let flags = if end_stream {
        END_HEADERS_FLAG | END_STREAM_FLAG
    } else {
        END_HEADERS_FLAG
    };
    frame(HEADERS_FRAME, flags, stream_id, &block)
}

fn data_frame(stream_id: u32, payload: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = if end_stream { END_STREAM_FLAG } else { 0 };
    frame(DATA_FRAME, flags, stream_id, payload)
}

fn reset_frame(stream_id: u32, reason: u32) -> Vec<u8> {
    frame(RST_STREAM_FRAME, 0, stream_id, &reason.to_be_bytes())
}

/// Open a raw h2 connection and acknowledge the server's SETTINGS.
fn raw_h2_connection(server: &TestServer) -> StreamOwned<rustls::ClientConnection, TcpStream> {
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
    for _ in 0..64 {
        let received = read_frame(&mut tls).expect("read an h2 frame");
        if received.kind == SETTINGS_FRAME && received.flags & 1 == 0 {
            tls.write_all(SETTINGS_ACK).expect("write SETTINGS ACK");
            tls.flush().expect("flush SETTINGS ACK");
            return tls;
        }
        if received.kind == PING_FRAME && received.flags & 1 == 0 {
            let mut pong = vec![0, 0, 8, PING_FRAME, 1, 0, 0, 0, 0];
            pong.extend_from_slice(&received.payload);
            tls.write_all(&pong).expect("write PING ACK");
            tls.flush().expect("flush PING ACK");
        }
    }
    panic!("the server did not send its SETTINGS frame");
}

#[derive(Default)]
struct Exchange {
    bodies: BTreeMap<u32, Vec<u8>>,
    stream_frames: Vec<(u32, u8)>,
    ended: Vec<u32>,
    goaway: bool,
}

/// Drive the connection until `until` reaches END_STREAM, keeping SETTINGS
/// and PING acknowledged and recording every per-stream frame.
fn collect_frames<R: Read + Write>(tls: &mut R, until: u32) -> Exchange {
    let mut exchange = Exchange::default();
    for _ in 0..256 {
        let received = read_frame(tls).expect("read an h2 frame");
        match received.kind {
            SETTINGS_FRAME if received.flags & 1 == 0 => {
                tls.write_all(SETTINGS_ACK).expect("write SETTINGS ACK");
                tls.flush().expect("flush SETTINGS ACK");
            }
            PING_FRAME if received.flags & 1 == 0 => {
                let mut pong = vec![0, 0, 8, PING_FRAME, 1, 0, 0, 0, 0];
                pong.extend_from_slice(&received.payload);
                tls.write_all(&pong).expect("write PING ACK");
                tls.flush().expect("flush PING ACK");
            }
            GOAWAY_FRAME => exchange.goaway = true,
            HEADERS_FRAME | DATA_FRAME | RST_STREAM_FRAME => {
                exchange
                    .stream_frames
                    .push((received.stream_id, received.kind));
                if received.kind == DATA_FRAME {
                    exchange
                        .bodies
                        .entry(received.stream_id)
                        .or_default()
                        .extend_from_slice(&received.payload);
                }
                if received.flags & END_STREAM_FLAG != 0 {
                    exchange.ended.push(received.stream_id);
                }
            }
            _ => {}
        }
        if exchange.ended.contains(&until) || exchange.goaway {
            return exchange;
        }
    }
    panic!("stream {} did not finish a response", until);
}

fn health_body() -> &'static [u8] {
    b"{\"ok\":true}"
}

#[test]
fn h2_rst_stream_cancels_stream_and_keeps_others_serving() {
    let dispatched = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&dispatched);
    let mut cancelled_router = Router::new();
    cancelled_router.get("/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    cancelled_router.post("/cancelled", move |_request: &mut Request| {
        counter.fetch_add(1, Ordering::SeqCst);
        Response::text(200, "cancelled work ran")
    });
    let server = start_server(&[], cancelled_router);
    let mut tls = raw_h2_connection(&server);

    // One TLS write per batch: h2 applies the reset before it hands the
    // request to the app, so the cancelled handler can never be dispatched.
    let frames = [
        request_frame(1, "POST", "/cancelled", false),
        data_frame(1, b"discard me", true),
        reset_frame(1, RST_CANCEL),
        request_frame(3, "GET", "/health", true),
    ]
    .concat();
    tls.write_all(&frames)
        .expect("write cancelled stream and healthy request");
    tls.flush()
        .expect("flush cancelled stream and healthy request");
    let exchange = collect_frames(&mut tls, 3);
    assert!(
        !exchange.goaway,
        "a client reset must not tear down the connection"
    );
    assert!(
        !exchange.stream_frames.iter().any(|(id, _)| *id == 1),
        "a cancelled stream sends no HEADERS, DATA or RST_STREAM"
    );
    assert_eq!(
        exchange.bodies.get(&3).map(Vec::as_slice),
        Some(health_body())
    );
    assert_eq!(
        dispatched.load(Ordering::SeqCst),
        0,
        "a cancelled stream stops work before dispatch"
    );

    // An open body (no END_STREAM) is the common cancellation timing: the
    // reset must wake the parked reader and stop work just the same.
    let frames = [
        request_frame(5, "POST", "/cancelled", false),
        data_frame(5, b"half a body", false),
        reset_frame(5, RST_CANCEL),
        request_frame(7, "GET", "/health", true),
    ]
    .concat();
    tls.write_all(&frames)
        .expect("write open-body cancellation and healthy request");
    tls.flush()
        .expect("flush open-body cancellation and healthy request");
    let exchange = collect_frames(&mut tls, 7);
    assert!(
        !exchange.goaway,
        "an open-body reset is not a connection error"
    );
    assert!(
        !exchange.stream_frames.iter().any(|(id, _)| *id == 5),
        "a cancelled open-body stream sends no frames"
    );
    assert_eq!(
        exchange.bodies.get(&7).map(Vec::as_slice),
        Some(health_body())
    );
    assert_eq!(
        dispatched.load(Ordering::SeqCst),
        0,
        "an open-body cancellation stops work before dispatch"
    );

    // A duplicate reset on the now-closed stream is ignored deterministically.
    let frames = [
        reset_frame(1, RST_CANCEL),
        request_frame(9, "GET", "/health", true),
    ]
    .concat();
    tls.write_all(&frames)
        .expect("write duplicate reset and request");
    tls.flush().expect("flush duplicate reset and request");
    let exchange = collect_frames(&mut tls, 9);
    assert!(!exchange.goaway, "a reset on a closed stream is ignored");
    assert!(
        !exchange.stream_frames.iter().any(|(id, _)| *id == 1),
        "a closed stream stays silent"
    );
    assert_eq!(
        exchange.bodies.get(&9).map(Vec::as_slice),
        Some(health_body())
    );
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    println!(
        "[h2] RST_STREAM(CANCEL) on a finished and an open body stopped streams 1 and 5 with no handler call, no response and no GOAWAY; streams 3, 7 and 9 served 200 on one connection"
    );
}

#[test]
fn h2_rst_stream_unknown_and_closed_streams_are_ignored() {
    let server = start_server(&[], router());
    let mut tls = raw_h2_connection(&server);

    // Opening stream 5 first implicitly closes the never-opened ids 1 and 3.
    tls.write_all(&request_frame(5, "GET", "/health", true))
        .expect("write first health request");
    tls.flush().expect("flush first health request");
    let exchange = collect_frames(&mut tls, 5);
    assert!(!exchange.goaway);
    assert_eq!(
        exchange.bodies.get(&5).map(Vec::as_slice),
        Some(health_body())
    );

    let frames = [
        reset_frame(1, RST_CANCEL),
        reset_frame(3, RST_CANCEL),
        reset_frame(5, RST_CANCEL),
        reset_frame(5, RST_CANCEL),
        request_frame(7, "GET", "/health", true),
    ]
    .concat();
    tls.write_all(&frames)
        .expect("write unknown and closed stream resets");
    tls.flush().expect("flush unknown and closed stream resets");
    let exchange = collect_frames(&mut tls, 7);
    assert!(
        !exchange.goaway,
        "resets on unknown or closed streams must not be a connection error"
    );
    assert!(
        !exchange
            .stream_frames
            .iter()
            .any(|(_, kind)| *kind == RST_STREAM_FRAME),
        "the server must not echo a client reset"
    );
    assert_eq!(
        exchange.bodies.get(&7).map(Vec::as_slice),
        Some(health_body())
    );

    // A later stream proves the connection kept serving after all four resets.
    tls.write_all(&request_frame(9, "GET", "/health", true))
        .expect("write final health request");
    tls.flush().expect("flush final health request");
    let exchange = collect_frames(&mut tls, 9);
    assert!(!exchange.goaway);
    assert_eq!(
        exchange.bodies.get(&9).map(Vec::as_slice),
        Some(health_body())
    );
    println!(
        "[h2] four RST_STREAM frames on unknown (1, 3) and closed (5) streams were ignored; streams 7 and 9 served 200 with no GOAWAY"
    );
}
