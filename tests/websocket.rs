//! WebSocket tests: the RFC 6455 handshake, text and binary frames,
//! ping/pong, close frames, fragmentation and room broadcasts, all over a real
//! socket.

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
use opurom_server::{MAX_ROOMS, MAX_ROOM_MEMBERS};
use serde_json::{json, Value};

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

fn connect(port: u16) -> WebSocketClient {
    let client = WebSocketClient::connect(&format!("127.0.0.1:{port}"), "/ws")
        .expect("the handshake succeeds");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout is set");
    client
}

fn send_control(client: &mut WebSocketClient, control: &Value) {
    client
        .send_text(&control.to_string())
        .expect("send control");
}

fn recv_json(client: &mut WebSocketClient) -> Value {
    match client.recv().expect("receive JSON frame") {
        WsMessage::Text(text) => serde_json::from_str(&text).expect("valid JSON"),
        other => panic!("expected a text message, got {:?}", other),
    }
}

fn expect_ack(client: &mut WebSocketClient, kind: &str, room: &str) {
    let frame = recv_json(client);
    assert_eq!(frame["type"].as_str(), Some(kind));
    assert_eq!(frame["room"].as_str(), Some(room));
}

fn expect_error(client: &mut WebSocketClient, code: &str) -> Value {
    let frame = recv_json(client);
    assert_eq!(frame["type"].as_str(), Some("error"));
    assert_eq!(frame["error"].as_str(), Some(code));
    assert!(frame["message"]
        .as_str()
        .is_some_and(|message| !message.is_empty()));
    frame
}

fn expect_broadcast(client: &mut WebSocketClient, room: &str, payload: &Value) {
    let frame = recv_json(client);
    assert_eq!(frame["type"].as_str(), Some("broadcast"));
    assert_eq!(frame["room"].as_str(), Some(room));
    assert_eq!(&frame["payload"], payload);
}

fn assert_no_message(client: &mut WebSocketClient) {
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("short read timeout is set");
    let outcome = client.recv();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout is restored");
    let unexpected = outcome.ok();
    assert!(unexpected.is_none(), "unexpected frame: {:?}", unexpected);
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

#[test]
fn three_members_receive_the_same_broadcast_payload() {
    let (port, shutdown) = start(demo_router());
    let mut clients = [connect(port), connect(port), connect(port)];
    for client in clients.iter_mut() {
        send_control(client, &json!({"type":"join","room":"trio"}));
    }
    for client in clients.iter_mut() {
        expect_ack(client, "joined", "trio");
    }
    let payload = json!({"seq":7,"text":"all three"});
    send_control(
        &mut clients[1],
        &json!({"type":"broadcast","room":"trio","payload":payload.clone()}),
    );
    for client in clients.iter_mut() {
        expect_broadcast(client, "trio", &payload);
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn a_room_broadcast_excludes_a_non_member() {
    let (port, shutdown) = start(demo_router());
    let mut alice = connect(port);
    let mut bob = connect(port);
    let mut outsider = connect(port);
    send_control(&mut alice, &json!({"type":"join","room":"design"}));
    send_control(&mut bob, &json!({"type":"join","room":"design"}));
    send_control(&mut outsider, &json!({"type":"join","room":"lobby"}));
    expect_ack(&mut alice, "joined", "design");
    expect_ack(&mut bob, "joined", "design");
    expect_ack(&mut outsider, "joined", "lobby");

    let payload = json!({"seq":1,"text":"ship it"});
    send_control(
        &mut alice,
        &json!({"type":"broadcast","room":"design","payload":payload.clone()}),
    );
    expect_broadcast(&mut alice, "design", &payload);
    expect_broadcast(&mut bob, "design", &payload);
    assert_no_message(&mut outsider);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn leaving_a_room_stops_delivery_but_keeps_the_connection_alive() {
    let (port, shutdown) = start(demo_router());
    let mut alice = connect(port);
    let mut bob = connect(port);
    for client in [&mut alice, &mut bob] {
        send_control(client, &json!({"type":"join","room":"design"}));
        expect_ack(client, "joined", "design");
    }
    send_control(&mut bob, &json!({"type":"leave","room":"design"}));
    expect_ack(&mut bob, "left", "design");

    let first = json!({"seq":1});
    send_control(
        &mut alice,
        &json!({"type":"broadcast","room":"design","payload":first.clone()}),
    );
    expect_broadcast(&mut alice, "design", &first);
    assert_no_message(&mut bob);

    send_control(&mut bob, &json!({"type":"join","room":"design"}));
    expect_ack(&mut bob, "joined", "design");
    let second = json!({"seq":2});
    send_control(
        &mut alice,
        &json!({"type":"broadcast","room":"design","payload":second.clone()}),
    );
    expect_broadcast(&mut alice, "design", &second);
    expect_broadcast(&mut bob, "design", &second);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn malformed_controls_return_errors_and_keep_other_clients_connected() {
    let (port, shutdown) = start(demo_router());
    let mut alice = connect(port);
    let mut bob = connect(port);
    send_control(&mut bob, &json!({"type":"join","room":"design"}));
    expect_ack(&mut bob, "joined", "design");

    let cases = [
        (json!({"type":"frobnicate"}), "unknown_control_type"),
        (json!({"type":"join"}), "invalid_control"),
        (json!({"type":"join","room":"bad room"}), "invalid_room"),
        (
            json!({"type":"broadcast","room":"design"}),
            "invalid_control",
        ),
        (
            json!({"type":"broadcast","room":"missing","payload":{"seq":99}}),
            "unknown_room",
        ),
    ];
    for (control, code) in cases {
        send_control(&mut alice, &control);
        let frame = expect_error(&mut alice, code);
        if code == "unknown_control_type" {
            assert!(frame["message"]
                .as_str()
                .is_some_and(|message| message.contains("frobnicate")));
        }
    }
    assert_no_message(&mut bob);

    send_control(&mut alice, &json!({"type":"join","room":"design"}));
    expect_ack(&mut alice, "joined", "design");
    let payload = json!({"seq":42,"text":"survived"});
    send_control(
        &mut alice,
        &json!({"type":"broadcast","room":"design","payload":payload.clone()}),
    );
    expect_broadcast(&mut alice, "design", &payload);
    expect_broadcast(&mut bob, "design", &payload);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_room_cap_is_enforced_without_closing_the_connection() {
    let (port, shutdown) = start(demo_router());
    let mut client = connect(port);
    for index in 0..MAX_ROOMS {
        let room = format!("room-{index}");
        send_control(&mut client, &json!({"type":"join","room":room.clone()}));
        expect_ack(&mut client, "joined", &room);
    }
    send_control(&mut client, &json!({"type":"join","room":"overflow"}));
    expect_error(&mut client, "room_limit");

    let payload = json!({"seq":"after-cap"});
    send_control(
        &mut client,
        &json!({"type":"broadcast","room":"room-0","payload":payload.clone()}),
    );
    expect_broadcast(&mut client, "room-0", &payload);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn the_member_cap_is_enforced_without_closing_the_connection() {
    let (port, shutdown) = start(demo_router());
    let mut clients: Vec<WebSocketClient> = (0..=MAX_ROOM_MEMBERS).map(|_| connect(port)).collect();
    let (members, extra) = clients.split_at_mut(MAX_ROOM_MEMBERS);
    for client in members.iter_mut() {
        send_control(client, &json!({"type":"join","room":"packed"}));
        expect_ack(client, "joined", "packed");
    }
    send_control(&mut extra[0], &json!({"type":"join","room":"packed"}));
    expect_error(&mut extra[0], "member_limit");

    let payload = json!({"seq":32,"text":"packed"});
    send_control(
        &mut members[0],
        &json!({"type":"broadcast","room":"packed","payload":payload.clone()}),
    );
    for client in members.iter_mut() {
        expect_broadcast(client, "packed", &payload);
    }
    assert_no_message(&mut extra[0]);

    send_control(&mut extra[0], &json!({"type":"join","room":"spare"}));
    expect_ack(&mut extra[0], "joined", "spare");
    let spare_payload = json!({"seq":33,"text":"spare"});
    send_control(
        &mut extra[0],
        &json!({"type":"broadcast","room":"spare","payload":spare_payload.clone()}),
    );
    expect_broadcast(&mut extra[0], "spare", &spare_payload);
    shutdown.store(true, Ordering::Relaxed);
}
