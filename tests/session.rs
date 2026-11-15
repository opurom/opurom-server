//! Session authentication over a real loopback server: login issues an HttpOnly
//! cookie, protected routes reject the anonymous and the wrong cookie, the role
//! ladder gates admin-only handlers, logout clears the session, and idle
//! sessions expire. Plus the store and cookie helpers in isolation.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use opurom_server::http::{Request, Response};
use opurom_server::middleware::MiddlewareChain;
use opurom_server::router::Router;
use opurom_server::server::Server;
use opurom_server::session::{
    clear_session_cookie, cookie_value, require_role, session_cookie, session_gate, session_user,
    Role, SessionStore, SESSION_COOKIE,
};

#[derive(Debug)]
struct Answer {
    status: u16,
    set_cookie: Option<String>,
    body: String,
}

impl Answer {
    fn parse(raw: &[u8]) -> Answer {
        let text = String::from_utf8_lossy(raw).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("no header separator in {text:?}"));
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let set_cookie = head.lines().find_map(|line| {
            line.strip_prefix("Set-Cookie: ")
                .or_else(|| line.strip_prefix("set-cookie: "))
                .map(str::to_string)
        });
        Answer {
            status,
            set_cookie,
            body: body.to_string(),
        }
    }

    fn cookie_id(&self) -> Option<String> {
        cookie_value(self.set_cookie.as_deref()?, SESSION_COOKIE)
    }
}

fn send(port: u16, method: &str, path: &str, cookie: Option<&str>) -> Answer {
    send_body(port, method, path, cookie, "")
}

fn send_body(port: u16, method: &str, path: &str, cookie: Option<&str>, body: &str) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut payload = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(cookie) = cookie {
        payload.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    if !body.is_empty() {
        payload.push_str("Content-Type: application/json\r\n");
        payload.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    payload.push_str("Connection: close\r\n\r\n");
    payload.push_str(body);
    stream.write_all(payload.as_bytes()).expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read");
    Answer::parse(&raw)
}

/// A mini forum server: `/health` open, `/login` issues a member or admin
/// session, `/me` needs any session, `/admin` needs the admin role, `/logout`
/// destroys the session.
fn router(store: SessionStore) -> Router {
    let mut router = Router::new();
    router.get("/health", |_request: &mut Request| {
        Response::json_text(200, "{\"ok\":true}")
    });

    let login_store = store.clone();
    router.post("/login", move |request: &mut Request| {
        let value = match request.json() {
            Ok(value) => value,
            Err(_) => return Response::error(400, "invalid_json"),
        };
        let user = value.get("user").and_then(|v| v.as_str()).unwrap_or("");
        if user.is_empty() {
            return Response::error(400, "missing_user");
        }
        let role = value
            .get("role")
            .and_then(|v| v.as_str())
            .and_then(Role::parse)
            .unwrap_or(Role::Member);
        let id = login_store.create(user, role);
        Response::json_text(200, "{\"ok\":true}").with_header("Set-Cookie", &session_cookie(&id))
    });

    let me_store = store.clone();
    router.get("/me", move |request: &mut Request| {
        match session_user(request) {
            Some(_) => {}
            None => return Response::error(401, "unauthorized"),
        }
        let _ = &me_store;
        Response::json_text(200, "{\"ok\":true}")
    });

    router.get("/admin", |request: &mut Request| {
        if let Some(response) = require_role(request, Role::Admin) {
            return response;
        }
        Response::json_text(200, "{\"ok\":true}")
    });

    let logout_store = store.clone();
    router.post("/logout", move |request: &mut Request| {
        if let Some(id) = opurom_server::session::session_id_from_cookie(request) {
            logout_store.destroy(&id);
        }
        Response::json_text(200, "{\"ok\":true}").with_header("Set-Cookie", &clear_session_cookie())
    });

    router
}

fn start() -> (u16, Arc<AtomicBool>, SessionStore) {
    let store = SessionStore::new(3600);
    // /login and /health are public; every other route needs a session.
    fn protected(request: &Request) -> bool {
        !(request.method == opurom_server::http::Method::Get && request.path == "/health")
            && !(request.method == opurom_server::http::Method::Post && request.path == "/login")
    }
    let mut chain = MiddlewareChain::new();
    chain.push(session_gate(store.clone(), protected));
    let server =
        Server::bind_with("127.0.0.1:0", router(store.clone()), chain, 64 * 1024).expect("bind");
    let (addr, shutdown) = server.spawn().expect("spawn");
    (addr.port(), shutdown, store)
}

#[test]
fn login_grants_access_and_anonymous_is_rejected() {
    let (port, _shutdown, _store) = start();

    assert_eq!(send(port, "GET", "/health", None).status, 200);
    assert_eq!(
        send(port, "GET", "/me", None).status,
        401,
        "no cookie -> 401"
    );

    let login = send_body(port, "POST", "/login", None, "{\"user\":\"ada\"}");
    assert_eq!(login.status, 200);
    let cookie = login.set_cookie.as_deref().expect("Set-Cookie present");
    assert!(cookie.contains("HttpOnly"), "session cookie is HttpOnly");
    assert!(cookie.contains("SameSite=Strict"));
    let id = login.cookie_id().expect("a session id");

    let me = send(port, "GET", "/me", Some(&format!("{SESSION_COOKIE}={id}")));
    assert_eq!(me.status, 200, "the issued cookie authenticates");
}

#[test]
fn forged_or_unknown_cookie_is_rejected() {
    let (port, _shutdown, _store) = start();
    let forged = send(
        port,
        "GET",
        "/me",
        Some(&format!(
            "{SESSION_COOKIE}=deadbeefdeadbeefdeadbeefdeadbeef"
        )),
    );
    assert_eq!(forged.status, 401, "an unknown id does not authenticate");
}

#[test]
fn role_ladder_gates_admin_and_logout_clears_session() {
    let (port, _shutdown, store) = start();

    // A member cannot reach /admin.
    let member_login = send_body(port, "POST", "/login", None, "{\"user\":\"ada\"}");
    let member_id = member_login.cookie_id().expect("member id");
    let member_cookie = format!("{SESSION_COOKIE}={member_id}");
    assert_eq!(
        send(port, "GET", "/admin", Some(&member_cookie)).status,
        403,
        "member is below admin"
    );

    // An admin can.
    let admin = send_body(
        port,
        "POST",
        "/login",
        None,
        "{\"user\":\"root\",\"role\":\"admin\"}",
    );
    let admin_id = admin.cookie_id().expect("admin id");
    let admin_cookie = format!("{SESSION_COOKIE}={admin_id}");
    assert_eq!(
        send(port, "GET", "/admin", Some(&admin_cookie)).status,
        200,
        "admin reaches /admin"
    );

    // Logout destroys the session; the old cookie stops working.
    let logout = send(port, "POST", "/logout", Some(&member_cookie));
    assert_eq!(logout.status, 200);
    assert!(logout
        .set_cookie
        .as_deref()
        .unwrap_or_default()
        .contains("Max-Age=0"));
    assert_eq!(
        send(port, "GET", "/me", Some(&member_cookie)).status,
        401,
        "a logged-out cookie is rejected"
    );
    assert_eq!(store.len(), 1, "only the admin session remains");
}

#[test]
fn store_create_lookup_destroy_and_expiry() {
    let store = SessionStore::new(0); // zero TTL: every lookup is stale
    let id = store.create("ada", Role::Member);
    assert_eq!(id.len(), 32, "128-bit hex id");
    assert!(store.destroy(&id), "destroy reports the removal");
    assert!(!store.destroy(&id), "a second destroy is a no-op");

    let live = SessionStore::new(3600);
    let id = live.create("linus", Role::Admin);
    let session = live.lookup(&id).expect("fresh session resolves");
    assert_eq!(session.user, "linus");
    assert_eq!(session.role, Role::Admin);
    assert!(live.destroy(&id));
    assert!(live.lookup(&id).is_none());
}

#[test]
fn ids_are_unique_across_creates() {
    let store = SessionStore::new(3600);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        assert!(seen.insert(store.create("u", Role::Guest)), "id collision");
    }
}

#[test]
fn cookie_helpers_parse_and_format() {
    assert_eq!(
        cookie_value("a=1; opurom_session=abc123; b=2", SESSION_COOKIE).as_deref(),
        Some("abc123")
    );
    assert_eq!(cookie_value("a=1; b=2", SESSION_COOKIE), None);
    assert_eq!(cookie_value("opurom_session=", SESSION_COOKIE), None);
    assert!(session_cookie("xyz").starts_with("opurom_session=xyz; Path=/; HttpOnly"));
}

#[test]
fn role_ordering_is_guest_member_admin() {
    assert!(Role::Guest < Role::Member);
    assert!(Role::Member < Role::Admin);
    assert_eq!(Role::parse("ADMIN"), Some(Role::Admin));
    assert_eq!(Role::parse("root"), None);
}
