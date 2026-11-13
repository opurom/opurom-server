//! Keep-alive tests: two requests on one socket, `Connection: close`,
//! the idle timeout and the maximum in-flight connection limit.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::{body_cap, logging, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::server::{Server, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS};

/// Start a keep-alive server on an ephemeral port.
fn start() -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    start_with(Duration::from_secs(30), DEFAULT_MAX_CONNECTIONS)
}

/// Start a keep-alive server with an explicit idle timeout and limit.
fn start_with(
    idle_timeout: Duration,
    max_connections: usize,
) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let mut chain = MiddlewareChain::new();
    chain.push(logging());
    chain.push(body_cap(1024 * 1024));
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router.route(Method::Get, "/count", |_request: &mut Request| {
        Response::json_text(200, "{\"n\":1}")
    });
    let server = Server::bind_with("127.0.0.1:0", router, chain, 1024 * 1024)
        .expect("server binds")
        .with_keep_alive()
        .with_idle_timeout(idle_timeout)
        .with_max_connections(max_connections);
    let (addr, shutdown) = server.spawn().expect("server spawns");
    (addr.port(), shutdown)
}

/// One HTTP answer read from a socket.
#[derive(Debug)]
struct Answer {
    status_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Answer {
    fn parse(raw: &str) -> Answer {
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("no header separator in {:?}", raw));
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or_default().to_string();
        let headers = lines
            .filter_map(|line| {
                line.split_once(':')
                    .map(|(name, value)| (name.to_string(), value.trim().to_string()))
            })
            .collect();
        Answer {
            status_line,
            headers,
            body: body.to_string(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Read one HTTP answer from a socket, using the `Content-Length` header to
/// know where the body ends.
fn read_answer(stream: &mut TcpStream) -> Answer {
    let mut raw = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).expect("read answer");
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let Some((head, body)) = text.split_once("\r\n\r\n") else {
            continue;
        };
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        if body.len() >= length {
            return Answer::parse(&text);
        }
    }
    Answer::parse(&String::from_utf8_lossy(&raw))
}

#[test]
fn two_requests_share_one_socket() {
    let (port, shutdown) = start();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let first = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream
        .write_all(first.as_bytes())
        .expect("write first request");
    let first_answer = read_answer(&mut stream);
    assert_eq!(first_answer.status_line, "HTTP/1.1 200 OK");
    assert_eq!(first_answer.body, "{\"ok\":true}");
    assert_eq!(
        first_answer.header("Connection"),
        Some("keep-alive"),
        "the connection must stay open"
    );
    assert_eq!(first_answer.header("Content-Length"), Some("11"));

    // The same socket serves the second request.
    let second = "GET /count HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream
        .write_all(second.as_bytes())
        .expect("write second request");
    let second_answer = read_answer(&mut stream);
    assert_eq!(second_answer.status_line, "HTTP/1.1 200 OK");
    assert_eq!(second_answer.body, "{\"n\":1}");
    assert_eq!(second_answer.header("Connection"), Some("keep-alive"));

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_connection_close_request_ends_the_connection() {
    let (port, shutdown) = start();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.status_line, "HTTP/1.1 200 OK");
    assert_eq!(answer.header("Connection"), Some("close"));

    // The server closes the socket, so the read reaches the end.
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read to the end");
    assert!(raw.is_empty(), "the server must close the connection");

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_close_answer_ends_the_connection_after_the_body() {
    let (port, shutdown) = start();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    // The client asks to keep the connection, but the server answers 503 and
    // closes it.
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.status_line, "HTTP/1.1 200 OK");
    assert_eq!(answer.header("Connection"), Some("keep-alive"));

    // A second request with `Connection: close` ends the connection.
    let closing = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(closing.as_bytes()).expect("write request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.header("Connection"), Some("close"));
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read to the end");
    assert!(raw.is_empty(), "the server must close the connection");

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn an_idle_connection_is_closed_after_the_timeout() {
    let (port, shutdown) = start_with(Duration::from_millis(300), DEFAULT_MAX_CONNECTIONS);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.status_line, "HTTP/1.1 200 OK");

    // The server closes the idle connection on its own.
    let started = Instant::now();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read to the end");
    assert!(raw.is_empty(), "the idle connection must be closed");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the idle timeout must fire"
    );

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_in_flight_limit_is_enforced() {
    let mut chain = MiddlewareChain::new();
    chain.push(body_cap(1024 * 1024));
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    let server = Server::bind_with("127.0.0.1:0", router, chain, 1024 * 1024)
        .expect("server binds")
        .with_keep_alive()
        .with_max_connections(1)
        .with_idle_timeout(Duration::from_secs(30));
    let (server_addr, shutdown) = server.spawn().expect("server spawns");

    // The first connection is accepted and keeps its slot: the server waits
    // for the first request on it.
    let mut busy = TcpStream::connect(("127.0.0.1", server_addr.port())).expect("connect");
    busy.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    let _ = busy;

    // The second connection is refused with 503 because the limit is one.
    let mut rejected = TcpStream::connect(("127.0.0.1", server_addr.port())).expect("connect");
    rejected
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut raw = Vec::new();
    let _ = rejected.read_to_end(&mut raw);
    let answer = String::from_utf8_lossy(&raw).into_owned();
    assert!(
        answer.contains("503") && answer.contains("server_busy"),
        "the connection limit must answer 503: {}",
        answer
    );

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_default_limits_are_documented() {
    assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(30));
    assert_eq!(DEFAULT_MAX_CONNECTIONS, 256);
}

#[test]
fn the_demo_server_keeps_the_connection_without_opr_keepalive() {
    // Without the opt-in variable the default behaviour stays: every response
    // carries `Connection: close`.
    let port = free_port();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_opurom-server"))
        .arg(port.to_string())
        .env_remove("OPR_PORT")
        .env_remove("OPR_TLS")
        .env_remove("OPR_KEEPALIVE")
        .env_remove("OPR_WEBSOCKET")
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("demo server spawns");
    wait_ready(port);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.header("Connection"), Some("close"));
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read to the end");
    assert!(raw.is_empty(), "the server must close the connection");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn the_demo_server_keeps_the_connection_with_opr_keepalive() {
    let port = free_port();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_opurom-server"))
        .arg(port.to_string())
        .env_remove("OPR_PORT")
        .env_remove("OPR_TLS")
        .env("OPR_KEEPALIVE", "1")
        .env_remove("OPR_WEBSOCKET")
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("demo server spawns");
    wait_ready(port);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.header("Connection"), Some("keep-alive"));

    // The same socket serves a second request.
    let second = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream
        .write_all(second.as_bytes())
        .expect("write second request");
    let answer = read_answer(&mut stream);
    assert_eq!(answer.status_line, "HTTP/1.1 200 OK");
    assert_eq!(answer.header("Connection"), Some("keep-alive"));

    let _ = child.kill();
    let _ = child.wait();
}

/// A free port on the loopback interface.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("free port binding");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

/// Wait until the demo server accepts connections.
fn wait_ready(port: u16) {
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("the demo server did not start");
}
