//! `opurom-server` - a small demo server for smoke testing the runtime.
//!
//! Usage:
//!   opurom-server [port]
//!   OPR_PORT=9000 opurom-server
//!
//! The demo serves `/health`, `/ssr` and an in-memory `/todos` collection with
//! the five CRUD verbs, so the runtime can be exercised without a database.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use opurom_server::http::{Method, Request, Response};
use opurom_server::middleware::{body_cap, logging, MiddlewareChain};
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::ssr::ssr_html;

const DEMO_IR: &str = r##"{
  "ir": "0.1",
  "app": "Counter",
  "state": [ { "name": "count", "type": "int", "init": 0 } ],
  "tree": {
    "id": 0,
    "kind": "Column",
    "props": { "gap": 8, "padding": 16, "align": "center" },
    "children": [
      { "id": 1, "kind": "Text", "props": { "value": "Count: {count}", "size": 24 }, "children": [], "events": {} }
    ],
    "events": {}
  },
  "theme": { "mode": "system", "accent": "#4F46E5", "radius": 12 }
}"##;

fn main() {
    let port: u16 = std::env::var("OPR_PORT")
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .or_else(|| {
            std::env::args()
                .nth(1)
                .and_then(|raw| raw.trim().parse().ok())
        })
        .unwrap_or(8787);

    let router = demo_router();
    let mut chain = MiddlewareChain::new();
    chain.push(logging());
    chain.push(body_cap(1024 * 1024));

    let addr = format!("127.0.0.1:{}", port);
    let server = match Server::bind_from_env(&addr, router, chain, 1024 * 1024) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("opurom-server: cannot start on {}: {}", addr, err);
            std::process::exit(1);
        }
    };
    match server.tls_config() {
        Some(config) => eprintln!(
            "opurom-server demo listening on https://{} (TLS certificate SHA-256 fingerprint {})",
            addr,
            config.fingerprint()
        ),
        None => eprintln!("opurom-server demo listening on http://{}", addr),
    }
    server.serve();
}

/// Demo routes: `/health`, `/ssr` and an in-memory `/todos` collection.
fn demo_router() -> Router {
    let mut router = Router::new();
    let todos: Arc<Mutex<BTreeMap<i64, serde_json::Value>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let next_id = Arc::new(AtomicU64::new(1));

    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(
            200,
            "{\"ok\":true,\"app\":\"opurom-server-demo\",\"version\":\"0.2.0\"}",
        )
    });

    let ssr_ir = DEMO_IR.to_string();
    router.route(Method::Get, "/ssr", move |_request: &mut Request| {
        Response::html(200, &ssr_html(&ssr_ir, ""))
    });

    let list_store = Arc::clone(&todos);
    router.route(Method::Get, "/todos", move |_request: &mut Request| {
        let guard = match list_store.lock() {
            Ok(guard) => guard,
            Err(_) => return Response::error(503, "store_locked"),
        };
        let items: Vec<String> = guard.values().map(json_to_string).collect();
        Response::json_text(200, &format!("[{}]", items.join(",")))
    });

    let create_store = Arc::clone(&todos);
    let create_id = Arc::clone(&next_id);
    router.route(Method::Post, "/todos", move |request: &mut Request| {
        let mut guard = match create_store.lock() {
            Ok(guard) => guard,
            Err(_) => return Response::error(503, "store_locked"),
        };
        let body = match request.json() {
            Ok(value) => value,
            Err(_) => return Response::error(400, "invalid_json"),
        };
        let id = create_id.fetch_add(1, Ordering::Relaxed) as i64;
        let mut item = match body.as_object() {
            Some(object) => object.clone(),
            None => serde_json::Map::new(),
        };
        item.insert("id".to_string(), serde_json::Value::from(id));
        let value = serde_json::Value::Object(item);
        guard.insert(id, value.clone());
        Response::json_text(201, &json_to_string(&value))
    });

    let get_store = Arc::clone(&todos);
    router.route(Method::Get, "/todos/:id", move |request: &mut Request| {
        let guard = match get_store.lock() {
            Ok(guard) => guard,
            Err(_) => return Response::error(503, "store_locked"),
        };
        match request.param("id").and_then(|raw| raw.parse::<i64>().ok()) {
            Some(id) => match guard.get(&id) {
                Some(value) => Response::json_text(200, &json_to_string(value)),
                None => Response::error(404, "not_found"),
            },
            None => Response::error(404, "not_found"),
        }
    });

    let update_store = Arc::clone(&todos);
    router.route(Method::Put, "/todos/:id", move |request: &mut Request| {
        let mut guard = match update_store.lock() {
            Ok(guard) => guard,
            Err(_) => return Response::error(503, "store_locked"),
        };
        let id = match request.param("id").and_then(|raw| raw.parse::<i64>().ok()) {
            Some(id) => id,
            None => return Response::error(404, "not_found"),
        };
        let body = match request.json() {
            Ok(value) => value,
            Err(_) => return Response::error(400, "invalid_json"),
        };
        let mut item = match guard.get(&id) {
            Some(value) => value.as_object().cloned().unwrap_or_default(),
            None => return Response::error(404, "not_found"),
        };
        if let Some(object) = body.as_object() {
            for (key, value) in object {
                item.insert(key.clone(), value.clone());
            }
        }
        let value = serde_json::Value::Object(item);
        guard.insert(id, value.clone());
        Response::json_text(200, &json_to_string(&value))
    });

    let delete_store = Arc::clone(&todos);
    router.route(
        Method::Delete,
        "/todos/:id",
        move |request: &mut Request| {
            let mut guard = match delete_store.lock() {
                Ok(guard) => guard,
                Err(_) => return Response::error(503, "store_locked"),
            };
            match request.param("id").and_then(|raw| raw.parse::<i64>().ok()) {
                Some(id) if guard.remove(&id).is_some() => {
                    Response::json_text(200, "{\"deleted\":true}")
                }
                _ => Response::error(404, "not_found"),
            }
        },
    );

    router
}

/// Serialize a JSON value deterministically.
fn json_to_string(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}
