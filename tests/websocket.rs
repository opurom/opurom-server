//! R7 WebSocket tests: the RFC 6455 handshake, text and binary frames,
//! ping/pong, close frames and fragmentation, all over a real socket.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::{body_cap, logging, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::websocket::{
    accept_key, client::WebSocketClient, encode_frame, Opcode, WsMessage, MAX_FRAME_PAYLOAD,
};

/// Start a WebSocket-capable server on an ephemeral port.
fn start(router: Router) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let mut chain = MiddlewareChain::new();
    chain.push(logging());
    chain.push(body_cap(1024 * 1024));
    let server = Server::bind_with("127.0.0.1:0", router, chain, 1024 * 1024)
        .expect("server binds")
        .with_websocket();
    let (addr, shutdown) = server.spawn().expect("server spawns");
    (addr.port(), shutdown)
}

/// A router with one JSON route.
fn demo_router() -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router
}

/// Send a raw HTTP upgrade request and read the raw answer.
fn raw_upgrade(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write request");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut raw = Vec::new();
    let mut buffer = [0u8; 1024];
    // Read until the end of the header block.
    loop {
        let read = stream.read(&mut buffer).expect("read answer");
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

#[test]
fn the_handshake_answers_the_documented_accept_value() {
    let (port, shutdown) = start(demo_router());
    // The key and the expected accept value from RFC 6455 section 1.3.
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        key
    );
    let answer = raw_upgrade(port, &request);
    assert!(
        answer.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{}",
        answer
    );
    assert!(answer.contains("Upgrade: websocket\r\n"), "{}", answer);
    assert!(answer.contains("Connection: Upgrade\r\n"), "{}", answer);
    assert!(
        answer.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"),
        "{}",
        answer
    );
    assert_eq!(accept_key(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_request_without_the_upgrade_headers_is_a_normal_request() {
    let (port, shutdown) = start(demo_router());
    let answer = raw_upgrade(
        port,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{}", answer);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_text_frame_round_trips_over_a_real_socket() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    client.send_text("hello opurom").expect("send text");
    match client.recv().expect("receive text") {
        WsMessage::Text(text) => assert_eq!(text, "hello opurom"),
        other => panic!("expected a text message, got {:?}", other),
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_binary_frame_round_trips_over_a_real_socket() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    let payload = vec![0u8, 1, 2, 3, 255, 254, 128];
    client.send_binary(&payload).expect("send binary");
    match client.recv().expect("receive binary") {
        WsMessage::Binary(data) => assert_eq!(data, payload),
        other => panic!("expected a binary message, got {:?}", other),
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_ping_is_answered_with_a_pong() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    client.send_ping(b"keepalive").expect("send ping");
    match client.recv().expect("receive pong") {
        WsMessage::Pong(payload) => assert_eq!(payload, b"keepalive"),
        other => panic!("expected a pong, got {:?}", other),
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_close_frame_carries_the_status_code_and_reason() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    client.send_close(1000, "bye").expect("send close");
    match client.recv().expect("receive close") {
        WsMessage::Close { code, reason } => {
            assert_eq!(code, 1000);
            assert_eq!(reason, "bye");
        }
        other => panic!("expected a close message, got {:?}", other),
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_fragmented_message_is_reassembled() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");

    // A text frame split into a start frame and one continuation frame.
    let first = encode_frame(Opcode::Text, b"hello ", false, Some([1, 2, 3, 4]));
    let second = encode_frame(Opcode::Continuation, b"world", true, Some([5, 6, 7, 8]));
    client.write_frames(&[first, second]);
    match client.recv().expect("receive the reassembled message") {
        WsMessage::Text(text) => assert_eq!(text, "hello world"),
        other => panic!("expected a text message, got {:?}", other),
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_binary_message_split_into_three_fragments_is_reassembled() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    let frames = [
        encode_frame(Opcode::Binary, b"one", false, Some([1, 1, 1, 1])),
        encode_frame(Opcode::Continuation, b"two", false, Some([2, 2, 2, 2])),
        encode_frame(Opcode::Continuation, b"three", true, Some([3, 3, 3, 3])),
    ];
    client.write_frames(&frames);
    match client.recv().expect("receive the reassembled message") {
        WsMessage::Binary(data) => assert_eq!(data, b"onetwothree"),
        other => panic!("expected a binary message, got {:?}", other),
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_server_rejects_a_frame_larger_than_the_limit() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    // A frame header that claims more than the limit is refused before any
    // buffer is allocated for it.
    let mut header = vec![0x81, 127];
    header.extend_from_slice(&((MAX_FRAME_PAYLOAD as u64) + 1).to_be_bytes());
    client.write_frames(&[header]);
    let outcome = client.recv();
    assert!(outcome.is_err(), "an oversized frame must be refused");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_server_rejects_an_unmasked_client_frame() {
    let (port, shutdown) = start(demo_router());
    let mut client = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect("the handshake succeeds");
    // A server-to-client frame is never masked, so the server refuses it.
    client.write_frames(&[encode_frame(Opcode::Text, b"unmasked", true, None)]);
    let outcome = client.recv();
    assert!(outcome.is_err(), "an unmasked client frame must be refused");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_client_refuses_a_wrong_accept_value() {
    // A fake server that answers the handshake with a wrong accept value.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        let answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
        let _ = stream.write_all(answer.as_bytes());
    });

    let error = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect_err("a wrong accept value must be refused");
    assert!(
        error.to_string().contains("Sec-WebSocket-Accept"),
        "{}",
        error
    );
    handle.join().expect("the fake server finishes");
}

#[test]
fn the_client_refuses_a_non_101_answer() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        let answer = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.write_all(answer.as_bytes());
    });

    let error = WebSocketClient::connect(&format!("127.0.0.1:{}", port), "/ws")
        .expect_err("a non-101 answer must be refused");
    assert!(error.to_string().contains("404"), "{}", error);
    handle.join().expect("the fake server finishes");
}
