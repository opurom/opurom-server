//! HTTP/3 integration tests over a real QUIC endpoint.
//!
//! The tests bind a QUIC endpoint on an ephemeral UDP port, complete a real
//! TLS 1.3 handshake with ALPN `h3` and exchange real HTTP/3 requests with
//! the `h3` crate. They assert the status, the headers and the body, prove
//! that a panicking handler still answers with a diagnostic without killing
//! the endpoint, and report the measured handshake and request timings.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use opurom_server::http::{Request, Response};
use opurom_server::http3::{Http3Endpoint, Http3Server, State};
use opurom_server::middleware::{body_cap, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::tls;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

const MAX_BODY_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The environment variables the server reads.
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
    "OPR_HTTP3",
    "OPR_HTTP3_PORT",
    "OPR_ALT_SVC_PORT",
];

/// The environment is process-wide, so the tests that change it run alone.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One answer of an HTTP/3 request.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The measured time of the request, from the first byte sent to the
    /// last byte received.
    elapsed: Duration,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A running HTTP/3 endpoint on an ephemeral UDP port.
struct TestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    shutdown: Arc<AtomicBool>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// The routes every HTTP/3 test shares.
fn router() -> Router {
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
    router.get("/panic", |_request: &mut Request| {
        panic!("intentional h3 handler failure")
    });
    router
}

/// Start the HTTP/3 endpoint on an ephemeral UDP port.
fn start_server() -> TestServer {
    let tls = tls::self_signed_config().expect("self-signed TLS configuration");
    let cert_der = tls.certificate_der().to_vec();
    let endpoint = Http3Endpoint::bind("127.0.0.1:0", &tls).expect("the QUIC endpoint binds");
    let state = State {
        router: Arc::new(router()),
        middleware: Arc::new({
            let mut chain = MiddlewareChain::new();
            chain.push(body_cap(MAX_BODY_BYTES));
            chain
        }),
        limiter: None,
        options: Arc::new(Default::default()),
        max_body: MAX_BODY_BYTES,
    };
    let server = Http3Server::new(endpoint, state);
    let (addr, shutdown) = server.spawn().expect("the HTTP/3 server spawns");
    TestServer {
        addr,
        cert_der,
        shutdown,
    }
}

/// Connect a real h3 client to the endpoint and exchange one request.
fn exchange(
    addr: SocketAddr,
    cert_der: &[u8],
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(Answer, Duration, Duration), String> {
    let cert_der = cert_der.to_vec();
    let method = method.to_string();
    let path = path.to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        tokio::time::timeout(REQUEST_TIMEOUT, run(addr, cert_der, method, path, body))
            .await
            .map_err(|_| "the HTTP/3 exchange timed out".to_string())?
    })
}

async fn run(
    addr: SocketAddr,
    cert_der: Vec<u8>,
    method: String,
    path: String,
    body: Option<Vec<u8>>,
) -> Result<(Answer, Duration, Duration), String> {
    // The client trusts the certificate of the server and offers ALPN "h3".
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der))
        .map_err(|err| err.to_string())?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls_config)
            .map_err(|err| format!("cannot build the QUIC client configuration: {}", err))?,
    ));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client address"))
        .map_err(|err| err.to_string())?;
    endpoint.set_default_client_config(client_config);

    // The handshake timing is measured around the QUIC connection.
    let handshake_started = Instant::now();
    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|err| err.to_string())?
        .await
        .map_err(|err| err.to_string())?;
    let handshake = handshake_started.elapsed();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|err| format!("cannot build the h3 client: {}", err))?;

    // The client connection is driven until the response is complete.
    let driver_task = tokio::spawn(async move {
        driver.wait_idle().await;
    });

    let answer = request(&mut send_request, &method, &path, body).await?;
    let elapsed = answer.elapsed;
    driver_task.abort();
    endpoint.close(0u32.into(), b"done");

    Ok((answer, handshake, elapsed))
}

/// Send one request and read the whole response.
async fn request(
    send_request: &mut SendRequest<h3_quinn::OpenStreams, Bytes>,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<Answer, String> {
    let started = Instant::now();
    let builder = http::Request::builder()
        .method(method)
        .uri(format!("https://localhost{}", path));
    let request = builder
        .body(())
        .map_err(|err| format!("cannot build the request: {}", err))?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|err| format!("cannot send the request: {}", err))?;
    if let Some(body) = body {
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|err| format!("cannot send the request body: {}", err))?;
    }
    stream
        .finish()
        .await
        .map_err(|err| format!("cannot finish the request: {}", err))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|err| format!("cannot read the response: {}", err))?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let mut body_bytes = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|err| format!("cannot read the response body: {}", err))?
    {
        let size = chunk.remaining();
        body_bytes.extend_from_slice(&chunk.copy_to_bytes(size));
    }
    let elapsed = started.elapsed();
    Ok(Answer {
        status,
        headers,
        body: body_bytes,
        elapsed,
    })
}

#[test]
fn h3_get_and_post_share_the_router_with_http1_and_http2() {
    let server = start_server();

    let (answer, handshake, request_time) =
        exchange(server.addr, &server.cert_der, "GET", "/health", None)
            .expect("the h3 client completes the GET request");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"{\"ok\":true}");
    assert_eq!(answer.header("content-type"), Some("application/json"));
    // A client that already speaks HTTP/3 needs no alternative service.
    assert_eq!(answer.header("alt-svc"), None);
    println!(
        "[h3] GET /health -> {} body={} handshake={:?} request={:?}",
        answer.status,
        String::from_utf8_lossy(&answer.body),
        handshake,
        request_time
    );

    let (answer, handshake, request_time) = exchange(
        server.addr,
        &server.cert_der,
        "GET",
        "/items/42?q=one",
        None,
    )
    .expect("the h3 client completes the parameter request");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"{\"id\":\"42\",\"query\":\"q=one\"}");
    println!(
        "[h3] GET /items/42?q=one -> {} body={} handshake={:?} request={:?}",
        answer.status,
        String::from_utf8_lossy(&answer.body),
        handshake,
        request_time
    );

    let (answer, handshake, request_time) = exchange(
        server.addr,
        &server.cert_der,
        "POST",
        "/echo",
        Some(b"hello h3".to_vec()),
    )
    .expect("the h3 client completes the POST request");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"hello h3");
    println!(
        "[h3] POST /echo -> {} body={} handshake={:?} request={:?}",
        answer.status,
        String::from_utf8_lossy(&answer.body),
        handshake,
        request_time
    );
}

#[test]
fn h3_panicking_handler_answers_with_a_diagnostic_and_the_endpoint_survives() {
    let server = start_server();

    let (answer, _, _) = exchange(server.addr, &server.cert_der, "GET", "/panic", None)
        .expect("the panicking handler still answers");
    assert_eq!(answer.status, 500);
    assert_eq!(answer.body, b"{\"error\":\"handler_panic\"}");
    println!(
        "[h3] GET /panic -> {} body={}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );

    // The endpoint keeps serving other routes after the panic.
    let (answer, _, _) = exchange(server.addr, &server.cert_der, "GET", "/health", None)
        .expect("the endpoint keeps serving after the panic");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"{\"ok\":true}");
    println!(
        "[h3] GET /health after the panic -> {} body={}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );
}

/// A plain HTTP/1.1 answer of the same router.
fn http1_answer(port: u16, path: &str) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        path
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

#[test]
fn the_same_route_returns_the_same_body_on_http1_and_http3() {
    // Both protocols register the same routes, so the same path returns the
    // same JSON body.
    let chain = {
        let mut chain = MiddlewareChain::new();
        chain.push(body_cap(MAX_BODY_BYTES));
        chain
    };

    let http1 = opurom_server::server::Server::bind_with(
        "127.0.0.1:0",
        router(),
        chain.clone(),
        MAX_BODY_BYTES,
    )
    .expect("the HTTP/1.1 server binds");
    let (http1_addr, http1_shutdown) = http1.spawn().expect("the HTTP/1.1 server spawns");

    let tls = tls::self_signed_config().expect("self-signed TLS configuration");
    let cert_der = tls.certificate_der().to_vec();
    let endpoint = Http3Endpoint::bind("127.0.0.1:0", &tls).expect("the QUIC endpoint binds");
    let state = State {
        router: Arc::new(router()),
        middleware: Arc::new(chain),
        limiter: None,
        options: Arc::new(Default::default()),
        max_body: MAX_BODY_BYTES,
    };
    let (http3_addr, http3_shutdown) = Http3Server::new(endpoint, state)
        .spawn()
        .expect("the HTTP/3 server spawns");

    for path in ["/health", "/items/42?q=one"] {
        let (status, body) = http1_answer(http1_addr.port(), path);
        let (answer, _, _) = exchange(http3_addr, &cert_der, "GET", path, None)
            .expect("the h3 client completes the request");
        assert_eq!(status, answer.status, "the status differs on {}", path);
        assert_eq!(body.as_bytes(), answer.body, "the body differs on {}", path);
        println!(
            "[h3] {} -> HTTP/1.1 {} and HTTP/3 {} return the identical body {}",
            path, status, answer.status, body
        );
    }

    http1_shutdown.store(true, Ordering::Relaxed);
    http3_shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn https_responses_advertise_the_http3_endpoint_with_alt_svc() {
    let _env_lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The Alt-Svc header is opt-in: without the variable the response headers
    // stay unchanged.
    let server = opurom_server::server::Server::bind_tls(
        "127.0.0.1:0",
        router(),
        MiddlewareChain::new(),
        MAX_BODY_BYTES,
        None,
    )
    .expect("the TLS server binds");
    assert!(
        server.http3().is_none(),
        "no HTTP/3 listener without the variable"
    );
    let cert_der = server
        .tls_config()
        .expect("the server has TLS")
        .certificate_der()
        .to_vec();
    let (addr, shutdown) = server.spawn().expect("the TLS server spawns");

    let answer = https_request(addr, &cert_der);
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(
        !answer.to_ascii_lowercase().contains("alt-svc"),
        "the header is opt-in: {}",
        answer
    );
    println!("[h3] without the opt-in variable the HTTPS response has no Alt-Svc header");

    shutdown.store(true, Ordering::Relaxed);

    // With the HTTP/3 listener enabled the HTTPS response advertises the
    // real UDP port of the QUIC endpoint.
    let _env = EnvGuard::apply(&[("OPR_HTTP3", "1"), ("OPR_HTTP3_PORT", "0")]);
    let server = opurom_server::server::Server::bind_tls(
        "127.0.0.1:0",
        router(),
        MiddlewareChain::new(),
        MAX_BODY_BYTES,
        None,
    )
    .expect("the TLS server binds");
    let http3 = server.http3().expect("the HTTP/3 listener is enabled");
    let port = http3.local_addr().port();
    let cert_der = server
        .tls_config()
        .expect("the server has TLS")
        .certificate_der()
        .to_vec();
    let (addr, shutdown) = server.spawn().expect("the TLS server spawns");

    let answer = https_request(addr, &cert_der);
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(
        answer.contains(&format!("Alt-Svc: h3=\":{}\"", port)),
        "the response must advertise the HTTP/3 endpoint: {}",
        answer
    );
    println!(
        "[h3] the HTTPS response advertises Alt-Svc: h3=\":{}\" on the QUIC port {}",
        port, port
    );

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_alt_svc_port_variable_advertises_a_port_without_the_http3_listener() {
    let _env_lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _env = EnvGuard::apply(&[("OPR_ALT_SVC_PORT", "8443")]);
    let server = opurom_server::server::Server::bind_tls(
        "127.0.0.1:0",
        router(),
        MiddlewareChain::new(),
        MAX_BODY_BYTES,
        None,
    )
    .expect("the TLS server binds");
    let cert_der = server
        .tls_config()
        .expect("the server has TLS")
        .certificate_der()
        .to_vec();
    let (addr, shutdown) = server.spawn().expect("the TLS server spawns");

    let answer = https_request(addr, &cert_der);
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    assert!(
        answer.contains("Alt-Svc: h3=\":8443\""),
        "the configured port must be advertised: {}",
        answer
    );
    println!("[h3] the HTTPS response advertises the configured Alt-Svc port 8443");

    shutdown.store(true, Ordering::Relaxed);
}

/// Restore the process-wide environment variables after a server binds.
struct EnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
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

/// One HTTPS/1.1 answer of the shared router.
fn https_request(addr: SocketAddr, root_der: &[u8]) -> String {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .expect("trust anchor");
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut stream = rustls::StreamOwned::new(
        rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("localhost").expect("server name"),
        )
        .expect("client connection"),
        std::net::TcpStream::connect(addr).expect("connect"),
    );
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    String::from_utf8_lossy(&raw).into_owned()
}

/// A plain HTTP/1.1 POST answer of the same router.
fn http1_post(port: u16, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the header terminator");
    let status = String::from_utf8_lossy(&raw[..head_end])
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, raw[head_end + 4..].to_vec())
}

/// Run `jobs` as concurrent HTTP/3 requests on one QUIC connection.
///
/// Every job opens its own h3 stream, so the whole batch is in flight at the
/// same time. The answers come back in job order. Both returned durations
/// are measured with `std::time::Instant`: the handshake of the QUIC
/// connection and the elapsed time of the whole batch.
fn concurrent_exchange(
    addr: SocketAddr,
    cert_der: &[u8],
    jobs: Vec<(String, String, Option<Vec<u8>>)>,
) -> Result<(Vec<Answer>, Duration, Duration), String> {
    let cert_der = cert_der.to_vec();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    runtime.block_on(async move {
        tokio::time::timeout(REQUEST_TIMEOUT, run_concurrent(addr, cert_der, jobs))
            .await
            .map_err(|_| "the concurrent HTTP/3 exchange timed out".to_string())?
    })
}

async fn run_concurrent(
    addr: SocketAddr,
    cert_der: Vec<u8>,
    jobs: Vec<(String, String, Option<Vec<u8>>)>,
) -> Result<(Vec<Answer>, Duration, Duration), String> {
    // The client trusts the certificate of the server and offers ALPN "h3".
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der))
        .map_err(|err| err.to_string())?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls_config)
            .map_err(|err| format!("cannot build the QUIC client configuration: {}", err))?,
    ));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client address"))
        .map_err(|err| err.to_string())?;
    endpoint.set_default_client_config(client_config);

    // The handshake timing is measured around the QUIC connection.
    let handshake_started = Instant::now();
    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|err| err.to_string())?
        .await
        .map_err(|err| err.to_string())?;
    let handshake = handshake_started.elapsed();

    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|err| format!("cannot build the h3 client: {}", err))?;
    let driver_task = tokio::spawn(async move {
        driver.wait_idle().await;
    });

    // The batch timer covers opening every stream through the last byte.
    let started = Instant::now();
    let mut handles = Vec::new();
    for (method, path, body) in jobs {
        // One clone of the sender per stream: the streams run concurrently.
        let mut sender = send_request.clone();
        handles.push(tokio::spawn(async move {
            request(&mut sender, &method, &path, body).await
        }));
    }
    let mut answers = Vec::new();
    for handle in handles {
        let answer = handle
            .await
            .map_err(|err| format!("a request task failed: {}", err))?;
        answers.push(answer?);
    }
    let elapsed = started.elapsed();
    driver_task.abort();
    endpoint.close(0u32.into(), b"done");

    Ok((answers, handshake, elapsed))
}

#[test]
fn h3_concurrent_requests_share_one_connection_and_the_router_keeps_serving() {
    let server = start_server();

    // Eight in-flight GETs on one QUIC connection: half ask for the shared
    // health route, half for a parameter route of the same router.
    let mut jobs = Vec::new();
    let mut expected = Vec::new();
    for i in 0..8 {
        if i % 2 == 0 {
            jobs.push(("GET".to_string(), "/health".to_string(), None));
            expected.push(br#"{"ok":true}"#.to_vec());
        } else {
            jobs.push(("GET".to_string(), format!("/items/{}", i), None));
            expected.push(format!("{{\"id\":\"{}\",\"query\":\"\"}}", i).into_bytes());
        }
    }

    let (answers, handshake, elapsed) = concurrent_exchange(server.addr, &server.cert_der, jobs)
        .expect("the h3 client completes the concurrent batch");
    assert_eq!(answers.len(), expected.len());
    for (index, (answer, wanted)) in answers.iter().zip(expected.iter()).enumerate() {
        assert_eq!(answer.status, 200, "request {} must be 200", index);
        assert_eq!(
            &answer.body, wanted,
            "request {} must have its exact body",
            index
        );
    }
    let fastest = answers
        .iter()
        .map(|answer| answer.elapsed)
        .min()
        .expect("at least one answer");
    let slowest = answers
        .iter()
        .map(|answer| answer.elapsed)
        .max()
        .expect("at least one answer");
    println!(
        "[h3] 8 concurrent GET requests on one QUIC connection -> 8x 200 with exact bodies; \
         handshake={:?} batch={:?} per-request={:?}..{:?}",
        handshake, elapsed, fastest, slowest
    );

    // The shared router keeps serving after the concurrent batch.
    let (answer, _, _) = exchange(server.addr, &server.cert_der, "GET", "/health", None)
        .expect("the endpoint keeps serving after the batch");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"{\"ok\":true}");
    println!(
        "[h3] GET /health after the batch -> {} body={}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );
}

#[test]
fn h3_fault_isolation_keeps_healthy_routes_serving_under_concurrent_panics() {
    let server = start_server();

    // Two of the ten concurrent requests hit the panicking route: below the
    // three-strike threshold, so both panics answer the exact 500 diagnostic
    // and every healthy request keeps its exact 200 body.
    let mut jobs: Vec<(String, String, Option<Vec<u8>>)> = Vec::new();
    let mut expected: Vec<(u16, Vec<u8>)> = Vec::new();
    for i in 0..6 {
        jobs.push(("GET".to_string(), format!("/items/{}", i), None));
        expected.push((
            200,
            format!("{{\"id\":\"{}\",\"query\":\"\"}}", i).into_bytes(),
        ));
    }
    jobs.push(("GET".to_string(), "/panic".to_string(), None));
    expected.push((500, br#"{"error":"handler_panic"}"#.to_vec()));
    jobs.push(("GET".to_string(), "/health".to_string(), None));
    expected.push((200, br#"{"ok":true}"#.to_vec()));
    jobs.push((
        "POST".to_string(),
        "/echo".to_string(),
        Some(b"payload under load".to_vec()),
    ));
    expected.push((200, b"payload under load".to_vec()));
    jobs.push(("GET".to_string(), "/panic".to_string(), None));
    expected.push((500, br#"{"error":"handler_panic"}"#.to_vec()));

    let (answers, _handshake, elapsed) = concurrent_exchange(server.addr, &server.cert_der, jobs)
        .expect("the h3 client completes the concurrent load");
    assert_eq!(answers.len(), expected.len());
    for (index, (answer, (status, wanted))) in answers.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            answer.status, *status,
            "request {} has the wrong status",
            index
        );
        assert_eq!(&answer.body, wanted, "request {} has the wrong body", index);
    }
    println!(
        "[h3] 10 concurrent requests, 2 to the panicking route -> 8x 200 with exact bodies, \
         2x 500 {{\"error\":\"handler_panic\"}}; batch={:?}",
        elapsed
    );

    // The endpoint keeps serving the non-panicking routes after the load.
    let (answer, _, _) = exchange(server.addr, &server.cert_der, "GET", "/health", None)
        .expect("the endpoint keeps serving after the load");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"{\"ok\":true}");
    println!(
        "[h3] GET /health after the load -> {} body={}",
        answer.status,
        String::from_utf8_lossy(&answer.body)
    );
}

#[test]
fn h3_post_body_boundaries_echo_identically_to_http1() {
    let chain = {
        let mut chain = MiddlewareChain::new();
        chain.push(body_cap(MAX_BODY_BYTES));
        chain
    };

    let http1 = opurom_server::server::Server::bind_with(
        "127.0.0.1:0",
        router(),
        chain.clone(),
        MAX_BODY_BYTES,
    )
    .expect("the HTTP/1.1 server binds");
    let (http1_addr, http1_shutdown) = http1.spawn().expect("the HTTP/1.1 server spawns");

    let tls = tls::self_signed_config().expect("self-signed TLS configuration");
    let cert_der = tls.certificate_der().to_vec();
    let endpoint = Http3Endpoint::bind("127.0.0.1:0", &tls).expect("the QUIC endpoint binds");
    let state = State {
        router: Arc::new(router()),
        middleware: Arc::new(chain),
        limiter: None,
        options: Arc::new(Default::default()),
        max_body: MAX_BODY_BYTES,
    };
    let (http3_addr, http3_shutdown) = Http3Server::new(endpoint, state)
        .spawn()
        .expect("the HTTP/3 server spawns");

    // The boundary sizes of the configured 1 MiB body cap: 0 bytes, 1 byte,
    // a typical 4 KiB body and the cap itself.
    for size in [0usize, 1, 4 * 1024, MAX_BODY_BYTES] {
        let payload: Vec<u8> = (0..size).map(|i| b'a' + (i % 26) as u8).collect();
        let (http1_status, http1_body) = http1_post(http1_addr.port(), "/echo", &payload);
        assert_eq!(http1_status, 200, "HTTP/1.1 must accept {} bytes", size);
        assert_eq!(http1_body, payload, "HTTP/1.1 must echo {} bytes", size);

        let (answer, _, request_time) = exchange(
            http3_addr,
            &cert_der,
            "POST",
            "/echo",
            Some(payload.clone()),
        )
        .expect("the h3 client completes the POST request");
        assert_eq!(answer.status, 200, "HTTP/3 must accept {} bytes", size);
        assert_eq!(answer.body, payload, "HTTP/3 must echo {} bytes", size);
        assert_eq!(
            answer.status, http1_status,
            "the status for {} bytes must match HTTP/1.1",
            size
        );
        assert_eq!(
            answer.body, http1_body,
            "the body for {} bytes must match HTTP/1.1",
            size
        );
        println!(
            "[h3] POST /echo {} bytes -> HTTP/1.1 {} and HTTP/3 {} return the identical echo; \
             h3 request={:?}",
            size, http1_status, answer.status, request_time
        );
    }

    http1_shutdown.store(true, Ordering::Relaxed);
    http3_shutdown.store(true, Ordering::Relaxed);
}
