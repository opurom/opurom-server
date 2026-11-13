//! HEAD resolves against a GET route: the answer repeats the GET headers and
//! rejects the body, and a HEAD-only path still answers 404.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use opurom_server::http::{Method, Request, Response};
use opurom_server::router::Router;
use opurom_server::server::{request_for, Server};

fn body_of(router: &Router, method: Method, path: &str) -> Response {
    let mut request = request_for(method, path, "");
    router.handle(&mut request)
}

fn router() -> Router {
    let mut router = Router::new();
    router.get("/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });
    router
}

#[test]
fn head_resolves_the_get_route_without_the_body() {
    let router = router();
    let get = body_of(&router, Method::Get, "/health");
    let head = body_of(&router, Method::Head, "/health");
    assert_eq!(get.status, 200);
    assert_eq!(head.status, 200);
    assert_eq!(head.headers, get.headers, "HEAD repeats the GET headers");
    assert_eq!(
        head.body, get.body,
        "the transport drops the body, not the router, so the length stays exact"
    );
    assert_eq!(get.body_string(), "{\"ok\":true}");
}

#[test]
fn head_keeps_get_only_routes_and_unknown_paths_unchanged() {
    let router = router();
    let post_only = body_of(&router, Method::Head, "/health");
    assert_eq!(post_only.status, 200);
    assert_eq!(
        body_of(&router, Method::Head, "/missing").status,
        404,
        "an unknown path stays 404 for HEAD"
    );
    assert_eq!(
        body_of(&router, Method::Post, "/health").status,
        405,
        "a POST on a GET route stays 405"
    );
}

#[test]
fn head_over_a_socket_carries_the_get_content_length_and_no_body() {
    let server = Server::bind_with(
        "127.0.0.1:0",
        router(),
        opurom_server::middleware::MiddlewareChain::new(),
        1024 * 1024,
    )
    .expect("server binds")
    .with_keep_alive();
    let (addr, shutdown) = server.spawn().expect("server spawns");
    let mut stream = TcpStream::connect(("127.0.0.1", addr.port())).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    stream
        .write_all(b"HEAD /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read answer");
    shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header separator in {:?}", raw));
    assert!(head.starts_with("HTTP/1.1 200 OK"), "status line: {head}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("content-length: 11")),
        "HEAD advertises the GET length: {head}"
    );
    assert!(body.is_empty(), "HEAD sends no body, got {body:?}");
}
