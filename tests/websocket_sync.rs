//! Server-side change events over the existing WebSocket room hub.
//!
//! Subscribers join a model by name and receive one compact event for every
//! accepted write. The wire bytes and the event order are locked here so a
//! generated service and a runtime adapter can reproduce the same protocol.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use opurom_server::http::{Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::serde_json::json;
use opurom_server::server::Server;
use opurom_server::websocket::client::WebSocketClient;
use opurom_server::websocket::WsMessage;
use opurom_server::RoomHub;

/// A service whose write routes publish through one shared hub, exactly like
/// the handlers that `opurom-serverc` lowers.
fn spawn_change_service() -> (u16, Arc<RoomHub>, Arc<std::sync::atomic::AtomicBool>) {
    let rooms = Arc::new(RoomHub::default());
    let mut router = Router::new();
    let create_rooms = Arc::clone(&rooms);
    router.post("/todos", move |_request: &mut Request| {
        create_rooms.publish_change("Todo", "insert", &json!(7));
        Response::json_text(201, "{\"ok\":true}")
    });
    let batch_rooms = Arc::clone(&rooms);
    router.post("/todos/batch", move |_request: &mut Request| {
        batch_rooms.publish_change("Todo", "insert", &json!(8));
        batch_rooms.publish_change("Todo", "update", &json!(8));
        Response::json_text(201, "{\"ok\":true}")
    });
    let other_rooms = Arc::clone(&rooms);
    router.post("/posts", move |_request: &mut Request| {
        other_rooms.publish_change("Post", "insert", &json!(9));
        Response::json_text(201, "{\"ok\":true}")
    });
    router.get("/health", |_request: &mut Request| {
        Response::json_text(200, "{}")
    });

    let server = Server::bind_with("127.0.0.1:0", router, MiddlewareChain::new(), 1024 * 1024)
        .expect("server binds")
        .with_websocket()
        .with_rooms(Arc::clone(&rooms));
    let (addr, shutdown) = server.spawn().expect("server spawns");
    (addr.port(), rooms, shutdown)
}

/// One HTTP write, with the unchanged response bytes.
fn post(port: u16, path: &str) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).expect("read answer");
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 201"), "{answer}");
    assert!(answer.contains("{\"ok\":true}"), "{answer}");
}

/// Subscribe to one model and consume the deterministic acknowledgement.
fn subscribe(port: u16, model: &str, timeout: Duration) -> WebSocketClient {
    let mut client =
        WebSocketClient::connect(&format!("127.0.0.1:{port}"), "/ws").expect("websocket connects");
    client
        .set_read_timeout(Some(timeout))
        .expect("read timeout");
    client
        .send_text(&format!("{{\"type\":\"subscribe\",\"model\":\"{model}\"}}"))
        .expect("subscribe frame");
    match client.recv().expect("subscribe ack") {
        WsMessage::Text(ack) => assert_eq!(
            ack,
            format!("{{\"model\":\"{model}\",\"type\":\"subscribed\"}}")
        ),
        other => panic!("unexpected subscribe answer: {other:?}"),
    }
    client
}

fn next_text(client: &mut WebSocketClient) -> String {
    match client.recv().expect("change frame") {
        WsMessage::Text(text) => text,
        other => panic!("unexpected frame: {other:?}"),
    }
}

/// Subscribe, write, collect: run twice and the bytes must be identical.
fn one_round() -> Vec<String> {
    let (port, rooms, shutdown) = spawn_change_service();
    // No subscribers yet: publishing is a silent, counted no-op.
    assert_eq!(rooms.publish_change("Todo", "insert", &json!(1)), 0);

    let mut first = subscribe(port, "Todo", Duration::from_millis(500));
    let mut second = subscribe(port, "Todo", Duration::from_millis(500));
    post(port, "/todos");
    let event = "{\"id\":7,\"model\":\"Todo\",\"op\":\"insert\",\"type\":\"change\"}";
    assert_eq!(next_text(&mut first), event);
    assert_eq!(next_text(&mut second), event);

    // Multiple writes keep completion order; no coalescing.
    post(port, "/todos/batch");
    let ordered = vec![
        "{\"id\":8,\"model\":\"Todo\",\"op\":\"insert\",\"type\":\"change\"}".to_string(),
        "{\"id\":8,\"model\":\"Todo\",\"op\":\"update\",\"type\":\"change\"}".to_string(),
    ];
    assert_eq!(vec![next_text(&mut first), next_text(&mut first)], ordered);
    assert_eq!(
        vec![next_text(&mut second), next_text(&mut second)],
        ordered
    );

    // A subscriber of another model hears nothing.
    let mut unrelated = subscribe(port, "Post", Duration::from_millis(200));
    post(port, "/posts");
    assert_eq!(
        next_text(&mut unrelated),
        "{\"id\":9,\"model\":\"Post\",\"op\":\"insert\",\"type\":\"change\"}"
    );
    let leaked = first.recv();
    assert!(leaked.is_err(), "no cross-model event, got {leaked:?}");
    assert!(second.recv().is_err(), "no cross-model event");

    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    ordered
}

#[test]
fn subscribers_receive_ordered_model_change_events() {
    let first = one_round();
    let second = one_round();
    assert_eq!(first, second, "two runs must emit identical bytes");
}
