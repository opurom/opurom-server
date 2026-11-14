//! Bearer authentication and the structured list query over a real loopback
//! TCP socket. One in-process demo-style server is shared by the tests; the
//! auth gate is configured with an env-independent `AuthOptions` value, and
//! the `/todos` route renders the paginated envelope with `ListQuery`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use opurom_server::http::{Request, Response};
use opurom_server::middleware::{AuthOptions, MiddlewareChain};
use opurom_server::query::{ListQuery, DEFAULT_LIMIT, MAX_LIMIT, MAX_OFFSET};
use opurom_server::router::Router;
use opurom_server::serde_json::{self, Value as Json};
use opurom_server::server::Server;

const TOKEN: &str = "s3cret-token";

/// One parsed HTTP answer.
#[derive(Debug)]
struct Answer {
    status: u16,
    body: String,
}

impl Answer {
    fn parse(raw: &[u8]) -> Answer {
        let text = String::from_utf8_lossy(raw).into_owned();
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

    fn json(&self) -> Json {
        serde_json::from_str(&self.body).expect("valid JSON body")
    }
}

/// Send one request and read the whole answer over a fresh connection.
fn request(port: u16, method: &str, path: &str, token: Option<&str>) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut payload = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(token) = token {
        payload.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    payload.push_str("Connection: close\r\n\r\n");
    stream.write_all(payload.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    Answer::parse(&raw)
}

/// A router with an open `/health` and a `/todos` list backed by a seeded
/// in-memory store. Titles are deliberately out of insertion order so the
/// sorted answers are easy to assert.
fn router() -> Router {
    let store: Arc<Mutex<BTreeMap<i64, Json>>> = Arc::new(Mutex::new(BTreeMap::new()));
    {
        let mut guard = store.lock().unwrap();
        for (id, title) in [(1, "delta"), (2, "alpha"), (3, "charlie"), (4, "bravo")] {
            let mut row = serde_json::Map::new();
            row.insert("id".to_string(), Json::from(id));
            row.insert("title".to_string(), Json::from(title));
            guard.insert(id, Json::Object(row));
        }
    }

    let mut router = Router::new();
    router.get("/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router.get("/todos", move |request: &mut Request| {
        let query = match ListQuery::parse(&request.query) {
            Ok(query) => query,
            Err(err) => return err.response(),
        };
        let guard = store.lock().unwrap();
        let rows: Vec<Json> = guard.values().cloned().collect();
        Response::json(200, &query.apply(rows))
    });
    router
}

/// Bind the shared server with an env-independent bearer-token gate.
fn start() -> (u16, Arc<std::sync::atomic::AtomicBool>) {
    let mut chain = MiddlewareChain::new();
    chain.push(opurom_server::middleware::body_cap(1024 * 1024));
    let server = Server::bind_with("127.0.0.1:0", router(), chain, 1024 * 1024)
        .expect("server binds")
        .with_auth(AuthOptions::new(TOKEN));
    let (addr, shutdown) = server.spawn().expect("server spawns");
    (addr.port(), shutdown)
}

fn titles(answer: &Answer) -> Vec<String> {
    answer.json()["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|item| item["title"].as_str().expect("title").to_string())
        .collect()
}

#[test]
fn authenticated_vs_unauthenticated_and_wrong_token() {
    let (port, shutdown) = start();

    // Health stays open without a credential.
    let open = request(port, "GET", "/health", None);
    assert_eq!(open.status, 200);
    assert_eq!(open.body, "{\"ok\":true}");

    // A protected list route refuses a missing token.
    let missing = request(port, "GET", "/todos", None);
    assert_eq!(missing.status, 401);
    assert_eq!(missing.body, "{\"error\":\"unauthorized\"}");

    // A wrong token is refused with the same body.
    let wrong = request(port, "GET", "/todos", Some("not-the-token"));
    assert_eq!(wrong.status, 401);
    assert_eq!(wrong.body, "{\"error\":\"unauthorized\"}");

    // A token that only shares a prefix is still wrong.
    let prefix = request(port, "GET", "/todos", Some("s3cret"));
    assert_eq!(prefix.status, 401);

    // The matching token is accepted.
    let valid = request(port, "GET", "/todos", Some(TOKEN));
    assert_eq!(valid.status, 200);

    // A protected route answers after a rejected request on another socket.
    let after = request(port, "GET", "/todos?limit=1", Some(TOKEN));
    assert_eq!(after.status, 200);

    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn malformed_and_out_of_bounds_query_values_are_400() {
    let (port, shutdown) = start();
    let cases = [
        ("?limit=-1", "{\"error\":\"negative_limit\"}"),
        ("?limit=abc", "{\"error\":\"invalid_limit\"}"),
        ("?limit=", "{\"error\":\"invalid_limit\"}"),
        ("?limit=1.5", "{\"error\":\"invalid_limit\"}"),
        ("?limit=1001", "{\"error\":\"limit_too_large\"}"),
        ("?offset=-1", "{\"error\":\"negative_offset\"}"),
        ("?offset=9x", "{\"error\":\"invalid_offset\"}"),
        ("?offset=1000001", "{\"error\":\"offset_too_large\"}"),
        ("?order=sideways", "{\"error\":\"invalid_order\"}"),
    ];
    for (query, body) in cases {
        let answer = request(port, "GET", &format!("/todos{query}"), Some(TOKEN));
        assert_eq!(answer.status, 400, "{query}");
        assert_eq!(answer.body, body, "{query}");
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn boundary_values_are_accepted() {
    let (port, shutdown) = start();
    // limit at the minimum and maximum, offset at the maximum: all valid 200s.
    for query in [
        "?limit=1".to_string(),
        format!("?limit={MAX_LIMIT}"),
        format!("?offset={MAX_OFFSET}"),
        "?limit=0".to_string(),
    ] {
        let answer = request(port, "GET", &format!("/todos{query}"), Some(TOKEN));
        assert_eq!(answer.status, 200, "{query}");
        let envelope = answer.json();
        assert!(envelope["total"].is_number(), "{query}");
    }
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn envelope_carries_total_count_limit_and_offset() {
    let (port, shutdown) = start();
    let answer = request(port, "GET", "/todos?limit=2&offset=1", Some(TOKEN));
    assert_eq!(answer.status, 200);
    let envelope = answer.json();
    assert_eq!(envelope["total"], Json::from(4));
    assert_eq!(envelope["count"], Json::from(2));
    assert_eq!(envelope["limit"], Json::from(2));
    assert_eq!(envelope["offset"], Json::from(1));
    // Default page size when `limit` is absent.
    let default = request(port, "GET", "/todos", Some(TOKEN));
    assert_eq!(default.json()["limit"], Json::from(DEFAULT_LIMIT as u64));
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn ordering_is_stable_across_repeated_calls() {
    let (port, shutdown) = start();
    let first = request(port, "GET", "/todos?sort=title&order=asc", Some(TOKEN));
    assert_eq!(titles(&first), vec!["alpha", "bravo", "charlie", "delta"]);
    let body = first.body.clone();
    for _ in 0..5 {
        let again = request(port, "GET", "/todos?sort=title&order=asc", Some(TOKEN));
        assert_eq!(again.body, body, "ordering must be deterministic");
    }
    let descending = request(port, "GET", "/todos?sort=title&order=desc", Some(TOKEN));
    assert_eq!(
        titles(&descending),
        vec!["delta", "charlie", "bravo", "alpha"]
    );
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn filter_sorts_and_pages_together() {
    let (port, shutdown) = start();
    // Every title contains an 'a' or 'b'; q=ra matches "bravo" and "charlie".
    // Every title contains an 'a'; q=a keeps all four and pages one.
    let filtered = request(
        port,
        "GET",
        "/todos?q=a&sort=title&order=asc&limit=1",
        Some(TOKEN),
    );
    assert_eq!(filtered.status, 200);
    let envelope = filtered.json();
    assert_eq!(envelope["total"], Json::from(4));
    assert_eq!(envelope["count"], Json::from(1));
    assert_eq!(titles(&filtered), vec!["alpha"]);

    let narrower = request(port, "GET", "/todos?q=ch", Some(TOKEN));
    assert_eq!(narrower.json()["total"], Json::from(1));
    assert_eq!(titles(&narrower), vec!["charlie"]);

    let none = request(port, "GET", "/todos?q=zzz", Some(TOKEN));
    assert_eq!(none.json()["total"], Json::from(0));
    assert_eq!(titles(&none), Vec::<String>::new());
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn other_routes_keep_serving_after_a_rejected_request() {
    let (port, shutdown) = start();
    let rejected = request(port, "GET", "/todos?limit=nope", Some(TOKEN));
    assert_eq!(rejected.status, 400);
    let unauthorized = request(port, "GET", "/todos", None);
    assert_eq!(unauthorized.status, 401);

    // The open health route and a valid list request answer normally.
    let health = request(port, "GET", "/health", None);
    assert_eq!(health.status, 200);
    assert_eq!(health.body, "{\"ok\":true}");
    let listed = request(port, "GET", "/todos?limit=1", Some(TOKEN));
    assert_eq!(listed.status, 200);
    shutdown.store(true, Ordering::Relaxed);
}

#[test]
fn disabled_auth_leaves_every_route_open() {
    let mut chain = MiddlewareChain::new();
    chain.push(opurom_server::middleware::body_cap(1024 * 1024));
    let defaults = AuthOptions::default();
    assert!(!defaults.is_enabled());
    let server = Server::bind_with("127.0.0.1:0", router(), chain, 1024 * 1024)
        .expect("server binds")
        .with_auth(defaults);
    let (addr, shutdown) = server.spawn().expect("server spawns");
    let answer = request(addr.port(), "GET", "/todos", None);
    assert_eq!(answer.status, 200, "{}", answer.body);
    shutdown.store(true, Ordering::Relaxed);
}
