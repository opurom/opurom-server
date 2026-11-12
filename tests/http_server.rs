//! Integration tests: a real server on an ephemeral port, exercised over TCP.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::{body_cap, logging, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::server::Server;

/// One HTTP answer.
#[derive(Clone, Debug)]
struct Answer {
    status: u16,
    body: String,
}

/// Start a server on an ephemeral port with the given router.
fn start(router: Router) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let mut chain = MiddlewareChain::new();
    chain.push(logging());
    chain.push(body_cap(1024 * 1024));
    let server =
        Server::bind_with("127.0.0.1:0", router, chain, 1024 * 1024).expect("server binds");
    let (addr, shutdown) = server.spawn().expect("server spawns");
    (addr.port(), shutdown)
}

/// Send one request and read the whole answer.
fn request(port: u16, method: &str, path: &str, body: &str) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let payload = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        method,
        path,
        body.len(),
        body
    );
    stream.write_all(payload.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header separator in {:?}", text));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    Answer {
        status,
        body: body.to_string(),
    }
}

/// A CRUD router backed by an in-process store (no database needed).
fn crud_router() -> Router {
    let store: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let next_id = Arc::new(AtomicU32::new(1));

    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true,\"app\":\"test\",\"version\":\"0.2.0\"}")
    });

    let list_store = Arc::clone(&store);
    router.route(Method::Get, "/todos", move |_request: &mut Request| {
        let guard = list_store.lock().unwrap();
        let items: Vec<String> = guard
            .iter()
            .map(|(id, title)| format!("{{\"id\":{},\"title\":\"{}\"}}", id, title))
            .collect();
        Response::json_text(200, &format!("[{}]", items.join(",")))
    });

    let create_store = Arc::clone(&store);
    let create_id = Arc::clone(&next_id);
    router.route(Method::Post, "/todos", move |request: &mut Request| {
        let title = request
            .json()
            .ok()
            .and_then(|value| {
                value
                    .get("title")
                    .and_then(|title| title.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let id = create_id.fetch_add(1, Ordering::Relaxed) as u64;
        let mut guard = create_store.lock().unwrap();
        guard.push((id, title.clone()));
        Response::json_text(201, &format!("{{\"id\":{},\"title\":\"{}\"}}", id, title))
    });

    let get_store = Arc::clone(&store);
    router.route(Method::Get, "/todos/:id", move |request: &mut Request| {
        let id = request.param("id").and_then(|raw| raw.parse::<u64>().ok());
        let guard = get_store.lock().unwrap();
        match id.and_then(|id| guard.iter().find(|(row, _)| *row == id)) {
            Some((id, title)) => {
                Response::json_text(200, &format!("{{\"id\":{},\"title\":\"{}\"}}", id, title))
            }
            None => Response::error(404, "not_found"),
        }
    });

    let update_store = Arc::clone(&store);
    router.route(Method::Put, "/todos/:id", move |request: &mut Request| {
        let id = request.param("id").and_then(|raw| raw.parse::<u64>().ok());
        let title = request
            .json()
            .ok()
            .and_then(|value| {
                value
                    .get("title")
                    .and_then(|title| title.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let mut guard = update_store.lock().unwrap();
        match id.and_then(|id| {
            guard
                .iter_mut()
                .find(|(row, _)| *row == id)
                .map(|(_, stored)| *stored = title.clone())
        }) {
            Some(_) => Response::json_text(
                200,
                &format!(
                    "{{\"id\":{},\"title\":\"{}\"}}",
                    id.unwrap_or_default(),
                    title
                ),
            ),
            None => Response::error(404, "not_found"),
        }
    });

    let delete_store = Arc::clone(&store);
    router.route(
        Method::Delete,
        "/todos/:id",
        move |request: &mut Request| {
            let id = request.param("id").and_then(|raw| raw.parse::<u64>().ok());
            let mut guard = delete_store.lock().unwrap();
            let before = guard.len();
            guard.retain(|(row, _)| Some(*row) != id);
            if guard.len() == before {
                Response::error(404, "not_found")
            } else {
                Response::json_text(200, "{\"deleted\":true}")
            }
        },
    );

    router
}

#[test]
fn health_endpoint_answers_json() {
    let (port, shutdown) = start(crud_router());
    let answer = request(port, "GET", "/health", "");
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.body,
        "{\"ok\":true,\"app\":\"test\",\"version\":\"0.2.0\"}"
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn crud_lifecycle_over_tcp() {
    let (port, shutdown) = start(crud_router());

    let created = request(port, "POST", "/todos", "{\"title\":\"write tests\"}");
    assert_eq!(created.status, 201);
    assert!(
        created.body.contains("\"title\":\"write tests\""),
        "{}",
        created.body
    );

    let listed = request(port, "GET", "/todos", "");
    assert_eq!(listed.status, 200);
    assert!(listed.body.starts_with('['), "{}", listed.body);
    assert!(listed.body.contains("write tests"), "{}", listed.body);

    let fetched = request(port, "GET", "/todos/1", "");
    assert_eq!(fetched.status, 200);
    assert!(fetched.body.contains("\"id\":1"), "{}", fetched.body);

    let updated = request(port, "PUT", "/todos/1", "{\"title\":\"write more tests\"}");
    assert_eq!(updated.status, 200);
    assert!(
        updated.body.contains("write more tests"),
        "{}",
        updated.body
    );

    let deleted = request(port, "DELETE", "/todos/1", "");
    assert_eq!(deleted.status, 200);
    assert_eq!(deleted.body, "{\"deleted\":true}");

    let gone = request(port, "GET", "/todos/1", "");
    assert_eq!(gone.status, 404);
    assert_eq!(gone.body, "{\"error\":\"not_found\"}");

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn unknown_path_is_404_json() {
    let (port, shutdown) = start(crud_router());
    let answer = request(port, "GET", "/does-not-exist", "");
    assert_eq!(answer.status, 404);
    assert_eq!(answer.body, "{\"error\":\"not_found\"}");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn wrong_method_is_405_json() {
    let (port, shutdown) = start(crud_router());
    let answer = request(port, "PUT", "/todos", "{}");
    assert_eq!(answer.status, 405);
    assert_eq!(answer.body, "{\"error\":\"method_not_allowed\"}");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn body_over_one_mib_is_413() {
    let (port, shutdown) = start(crud_router());
    let oversized = "x".repeat(1024 * 1024 + 1);
    let answer = request(port, "POST", "/todos", &oversized);
    assert_eq!(answer.status, 413);
    assert_eq!(answer.body, "{\"error\":\"payload_too_large\"}");
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn body_at_one_mib_is_accepted() {
    let (port, shutdown) = start(crud_router());
    let payload = "x".repeat(1024 * 1024);
    let answer = request(port, "POST", "/todos", &payload);
    assert_eq!(answer.status, 201);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn panicking_handler_is_isolated_and_then_disabled() {
    let mut router = Router::new();
    router.route(Method::Get, "/boom", |_request: &mut Request| {
        panic!("handler exploded");
    });
    router.route(Method::Get, "/alive", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    let (port, shutdown) = start(router);

    for _ in 0..2 {
        let answer = request(port, "GET", "/boom", "");
        assert_eq!(answer.status, 500);
        assert_eq!(answer.body, "{\"error\":\"handler_panic\"}");
    }

    // The third consecutive panic disables the route.
    let third = request(port, "GET", "/boom", "");
    assert_eq!(third.status, 500);
    let fourth = request(port, "GET", "/boom", "");
    assert_eq!(fourth.status, 503);
    assert_eq!(fourth.body, "{\"error\":\"route_disabled\"}");

    // Other routes keep serving.
    let alive = request(port, "GET", "/alive", "");
    assert_eq!(alive.status, 200);
    assert_eq!(alive.body, "{\"ok\":true}");

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn router_matches_path_parameters() {
    let mut router = Router::new();
    router.route(
        Method::Get,
        "/users/:user/posts/:post",
        |request: &mut Request| {
            Response::json_text(
                200,
                &format!(
                    "{{\"user\":\"{}\",\"post\":\"{}\"}}",
                    request.param("user").unwrap_or_default(),
                    request.param("post").unwrap_or_default()
                ),
            )
        },
    );
    let (port, shutdown) = start(router);

    let answer = request(port, "GET", "/users/ada/posts/42", "");
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, "{\"user\":\"ada\",\"post\":\"42\"}");

    let missing = request(port, "GET", "/users/ada/posts", "");
    assert_eq!(missing.status, 404);

    shutdown.store(true, Ordering::Relaxed);
}
