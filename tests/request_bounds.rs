//! Loopback TCP tests for the HTTP/1.1 request bounds: the body cap, the
//! header block cap, read timeouts and pipelined requests.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use opurom_server::http::{Method, Request, Response, MAX_BODY_BYTES, MAX_HEADER_BYTES};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::{Server, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS};

/// One parsed HTTP answer.
#[derive(Debug)]
struct Answer {
    status_line: String,
    status: u16,
    connection: Option<String>,
    body: String,
}

/// Start a real server on an ephemeral loopback port.
fn start(idle: Duration, keep_alive: bool) -> (u16, Arc<AtomicBool>) {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router.route(Method::Get, "/one", |_request: &mut Request| {
        Response::json_text(200, "{\"n\":1}")
    });
    router.route(Method::Get, "/two", |_request: &mut Request| {
        Response::json_text(200, "{\"n\":2}")
    });
    router.route(Method::Post, "/upload", |_request: &mut Request| {
        Response::json_text(201, "{\"uploaded\":true}")
    });

    let mut server = Server::bind_with(
        "127.0.0.1:0",
        router,
        MiddlewareChain::new(),
        MAX_BODY_BYTES,
    )
    .expect("server binds")
    .with_idle_timeout(idle)
    .with_max_connections(DEFAULT_MAX_CONNECTIONS);
    if keep_alive {
        server = server.with_keep_alive();
    }
    let (addr, shutdown) = server.spawn().expect("server spawns");
    (addr.port(), shutdown)
}

/// Connect with a client-side read timeout so a stalled test cannot hang.
fn connect(port: u16, timeout: Duration) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(timeout))
        .expect("client read timeout");
    stream
}

/// Build one complete request with a `Content-Length` body.
fn request_bytes(method: &str, path: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n{}\r\n",
        method,
        path,
        body.len(),
        headers
    )
    .into_bytes();
    raw.extend_from_slice(body);
    raw
}

/// Parse one answer from `raw`, returning it and the bytes it consumed.
fn parse_one(raw: &[u8]) -> Option<(Answer, usize)> {
    let separator = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..separator]).into_owned();
    let length = head
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let used = separator + 4 + length;
    if raw.len() < used {
        return None;
    }
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default().to_string();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let connection = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("connection")
            .then(|| value.trim().to_string())
    });
    let body = String::from_utf8_lossy(&raw[separator + 4..used]).into_owned();
    Some((
        Answer {
            status_line,
            status,
            connection,
            body,
        },
        used,
    ))
}

/// Read `count` complete answers, keeping bytes that belong to later answers.
fn read_answers(stream: &mut TcpStream, count: usize) -> Vec<Answer> {
    let mut raw = Vec::new();
    let mut answers = Vec::new();
    let mut buffer = [0u8; 4096];
    while answers.len() < count {
        while let Some((answer, used)) = parse_one(&raw) {
            raw.drain(..used);
            answers.push(answer);
            if answers.len() == count {
                return answers;
            }
        }
        let read = stream.read(&mut buffer).expect("read answer");
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
    }
    answers
}

fn read_answer(stream: &mut TcpStream) -> Answer {
    read_answers(stream, 1)
        .pop()
        .unwrap_or_else(|| panic!("no complete HTTP answer"))
}

#[test]
fn oversized_body_is_rejected_with_413() {
    let (port, shutdown) = start(Duration::from_secs(5), false);
    let mut stream = connect(port, Duration::from_secs(5));
    let body = vec![b'x'; MAX_BODY_BYTES + 1];
    let raw = request_bytes("POST", "/upload", "", &body);
    stream.write_all(&raw).expect("write request");

    let answer = read_answer(&mut stream);
    assert_eq!(answer.status_line, "HTTP/1.1 413 Payload Too Large");
    assert_eq!(answer.status, 413);
    assert_eq!(answer.body, "{\"error\":\"payload_too_large\"}");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn oversized_header_block_is_rejected_with_431() {
    let (port, shutdown) = start(Duration::from_secs(5), false);
    let mut stream = connect(port, Duration::from_secs(5));
    let line = format!("X-Pad: {}\r\n", "a".repeat(1024));
    let mut raw = String::from("GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for _ in 0..(MAX_HEADER_BYTES / line.len() + 2) {
        raw.push_str(&line);
    }
    raw.push_str("\r\n");
    // The server answers before the last chunk lands, so a broken pipe is fine.
    for chunk in raw.as_bytes().chunks(4096) {
        if stream.write_all(chunk).is_err() {
            break;
        }
    }

    let answer = read_answer(&mut stream);
    assert_eq!(
        answer.status_line,
        "HTTP/1.1 431 Request Header Fields Too Large"
    );
    assert_eq!(answer.status, 431);
    assert_eq!(answer.body, "{\"error\":\"header_block_too_large\"}");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn unterminated_oversized_header_line_is_bounded() {
    let (port, shutdown) = start(Duration::from_secs(5), false);
    let mut stream = connect(port, Duration::from_secs(2));
    // No CRLF: the byte cap must stop the parser without waiting for a newline.
    let raw = format!(
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: {}",
        "a".repeat(MAX_HEADER_BYTES + 1)
    );
    let _ = stream.write_all(raw.as_bytes());

    let started = Instant::now();
    let answer = read_answer(&mut stream);
    assert_eq!(answer.status, 431);
    assert_eq!(answer.body, "{\"error\":\"header_block_too_large\"}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the cap must fire before the idle timeout"
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn slow_incomplete_request_times_out_without_blocking_other_requests() {
    let (port, shutdown) = start(Duration::from_millis(200), false);
    let mut slow = connect(port, Duration::from_secs(3));
    slow.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .expect("write partial request");

    // A different connection is served while the first one is stalled.
    let mut fast = connect(port, Duration::from_secs(3));
    let raw = request_bytes("GET", "/health", "", &[]);
    fast.write_all(&raw).expect("write complete request");
    let fast_answer = read_answer(&mut fast);
    assert_eq!(fast_answer.status, 200);
    assert_eq!(fast_answer.body, "{\"ok\":true}");

    let started = Instant::now();
    let slow_answer = read_answer(&mut slow);
    assert_eq!(slow_answer.status_line, "HTTP/1.1 408 Request Timeout");
    assert_eq!(slow_answer.status, 408);
    assert_eq!(slow_answer.body, "{\"error\":\"request_timeout\"}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the stalled request must not outlive its timeout"
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn pipelined_requests_get_two_ordered_responses() {
    let (port, shutdown) = start(Duration::from_secs(5), true);
    let mut stream = connect(port, Duration::from_secs(5));
    let mut raw = Vec::new();
    raw.extend_from_slice(&request_bytes(
        "GET",
        "/one",
        "Connection: keep-alive\r\n",
        &[],
    ));
    raw.extend_from_slice(&request_bytes(
        "GET",
        "/two",
        "Connection: keep-alive\r\n",
        &[],
    ));
    stream.write_all(&raw).expect("write pipelined requests");

    let answers = read_answers(&mut stream, 2);
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0].status, 200);
    assert_eq!(answers[1].status, 200);
    assert_eq!(answers[0].body, "{\"n\":1}");
    assert_eq!(answers[1].body, "{\"n\":2}");
    assert_eq!(answers[0].connection.as_deref(), Some("keep-alive"));
    assert_eq!(answers[1].connection.as_deref(), Some("keep-alive"));
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn malformed_bounded_requests_do_not_panic() {
    let (port, shutdown) = start(Duration::from_millis(300), false);

    // A declared body that never arrives: the drain stops at EOF and the
    // server answers 413 without allocating the declared length.
    let mut huge = connect(port, Duration::from_secs(3));
    let declared = format!(
        "POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        usize::MAX
    );
    huge.write_all(declared.as_bytes())
        .expect("write oversized declaration");
    huge.shutdown(std::net::Shutdown::Write)
        .expect("half-close the write side");
    let answer = read_answer(&mut huge);
    assert_eq!(answer.status, 413);
    assert_eq!(answer.body, "{\"error\":\"payload_too_large\"}");

    // Invalid UTF-8 in a header line is a 400, not a panic.
    let mut bad_utf8 = connect(port, Duration::from_secs(3));
    bad_utf8
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Bad: \xff\r\n\r\n")
        .expect("write invalid header");
    let answer = read_answer(&mut bad_utf8);
    assert_eq!(answer.status, 400);

    // The same server still serves a normal request.
    let mut healthy = connect(port, Duration::from_secs(3));
    let raw = request_bytes("GET", "/health", "", &[]);
    healthy.write_all(&raw).expect("write healthy request");
    let answer = read_answer(&mut healthy);
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, "{\"ok\":true}");

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn request_limits_are_configurable_constants() {
    assert_eq!(MAX_BODY_BYTES, 1024 * 1024);
    assert_eq!(MAX_HEADER_BYTES, 64 * 1024);
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(30));
    assert_eq!(DEFAULT_MAX_CONNECTIONS, 256);
}
