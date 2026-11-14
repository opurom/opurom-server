//! The ordered HTTP middleware pipeline over real loopback TCP: request-id,
//! access log, conditional GET (ETag/304), gzip and Cache-Control. Each layer
//! is asserted independently and the ordering is observable from the output.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use flate2::read::GzDecoder;
use opurom_server::middleware::{
    access_log_line, etag_for, if_none_match_matches, request_id, GZIP_THRESHOLD_BYTES,
    RESPONSE_STAGES,
};
use opurom_server::serde_json::{self, Value as Json};
use opurom_server::{MiddlewareChain, Request};

const HEALTH_BODY: &str = "{\"ok\":true,\"app\":\"opurom-server-demo\",\"version\":\"0.2.0\"}";
const CACHE_CONTROL: &str = "public, max-age=60";

static NONCE: AtomicU64 = AtomicU64::new(0);

/// A demo server process killed and cleaned up on every test exit path.
struct DemoServer {
    child: Child,
    port: u16,
    stderr_path: PathBuf,
    stdout_path: PathBuf,
}

impl DemoServer {
    fn spawn(tag: &str, envs: &[(&str, &str)]) -> DemoServer {
        let port = free_port();
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let stderr_path = std::env::temp_dir().join(format!(
            "opurom-server-pipeline-{}-{}-{}.stderr",
            tag,
            std::process::id(),
            nonce
        ));
        let stdout_path = std::env::temp_dir().join(format!(
            "opurom-server-pipeline-{}-{}-{}.stdout",
            tag,
            std::process::id(),
            nonce
        ));
        let stderr_file = File::create(&stderr_path).expect("stderr file");
        let stdout_file = File::create(&stdout_path).expect("stdout file");

        let mut command = Command::new(env!("CARGO_BIN_EXE_opurom-server"));
        command
            .arg(port.to_string())
            .env_remove("OPR_PORT")
            .env_remove("OPR_RATE_LIMIT")
            .env_remove("OPR_LOG_JSON")
            .env_remove("OPR_AUTH_TOKEN")
            .env_remove("OPR_CORS")
            .env_remove("OPR_ETAG")
            .env_remove("OPR_CACHE_CONTROL")
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        for (key, value) in envs {
            command.env(key, value);
        }
        let child = command.spawn().expect("demo server spawns");
        let server = DemoServer {
            child,
            port,
            stderr_path,
            stdout_path,
        };
        assert!(
            server.wait_ready(),
            "demo server did not print its startup line"
        );
        server
    }

    fn wait_ready(&self) -> bool {
        for _ in 0..200 {
            if self.stderr().contains("listening on") {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn stdout(&self) -> String {
        fs::read_to_string(&self.stdout_path).unwrap_or_default()
    }

    fn json_log_lines(&self) -> Vec<String> {
        self.stderr()
            .lines()
            .filter(|line| line.starts_with('{'))
            .map(str::to_string)
            .collect()
    }

    fn wait_for_json_lines(&self, count: usize) -> Vec<String> {
        for _ in 0..200 {
            let lines = self.json_log_lines();
            if lines.len() >= count {
                return lines;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.json_log_lines()
    }
}

impl Drop for DemoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.stderr_path);
        let _ = fs::remove_file(&self.stdout_path);
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("free port binding");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

fn raw_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut payload = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        method,
        path,
        body.len()
    );
    for (name, value) in headers {
        payload.push_str(name);
        payload.push_str(": ");
        payload.push_str(value);
        payload.push_str("\r\n");
    }
    payload.push_str("\r\n");
    stream.write_all(payload.as_bytes()).expect("write request");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    raw
}

#[derive(Debug)]
struct Answer {
    status_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn parse(raw: &[u8]) -> Answer {
        let separator = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("header separator");
        let head = String::from_utf8_lossy(&raw[..separator]);
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
            body: raw[separator + 4..].to_vec(),
        }
    }

    fn status(&self) -> u16 {
        self.status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn vary_has(answer: &Answer, field: &str) -> bool {
    answer.header("Vary").is_some_and(|raw| {
        raw.split(',')
            .any(|value| value.trim().eq_ignore_ascii_case(field))
    })
}

fn gunzip(body: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(body);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).expect("gzip decodes");
    decoded
}

fn title_for_body_len(target: usize) -> String {
    // The list envelope for one item: {"count":1,"items":[{"id":1,"title":""}],
    // "limit":50,"offset":0,"total":1}. The fixed wrapper length is 54.
    "x".repeat(target - 54)
}

fn expected_todo_list(title: &str) -> String {
    format!(
        "{{\"count\":1,\"items\":[{{\"id\":1,\"title\":\"{}\"}}],\"limit\":50,\"offset\":0,\"total\":1}}",
        title
    )
}

fn post_todo(port: u16, title: &str) -> Answer {
    let body = format!("{{\"title\":\"{}\"}}", title);
    let answer = Answer::parse(&raw_request(port, "POST", "/todos", &[], body.as_bytes()));
    assert_eq!(answer.status(), 201, "{}", answer.body_str());
    answer
}

// --- Library-level assertions: each stage and the log shape are testable
// --- without a socket, in addition to the TCP round-trips below.

#[test]
fn response_stage_order_is_declared_and_etag_precedes_gzip() {
    // The documented order is a fixed, explicit contract.
    assert_eq!(
        RESPONSE_STAGES,
        ["alt-svc", "cors", "cache-control", "etag", "gzip"]
    );
    // ETag before gzip means the validator is the hash of the uncompressed
    // body, so it does not depend on whether the client accepts gzip.
    let expected = etag_for(HEALTH_BODY.as_bytes());
    let server = DemoServer::spawn("order", &[("OPR_ETAG", "1")]);
    let plain = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    let gz = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Accept-Encoding", "gzip")],
        b"",
    ));
    assert_eq!(plain.header("ETag"), Some(expected.as_str()));
    assert_eq!(gz.header("ETag"), Some(expected.as_str()));
}

#[test]
fn access_log_line_fields_are_present_and_ordered() {
    let line = access_log_line("GET", "/health", 200, 7, Some("req-1"));
    assert!(!line.contains('\n'));
    // serde_json renders object keys in a fixed, stable (sorted) order, so the
    // same request always yields the same key sequence: duration_ms, method,
    // path, request_id, status. Assert both presence and that stable order.
    let positions: Vec<usize> = [
        "\"duration_ms\"",
        "\"method\"",
        "\"path\"",
        "\"request_id\"",
        "\"status\"",
    ]
    .iter()
    .map(|field| {
        line.find(field)
            .unwrap_or_else(|| panic!("missing field {field} in {line}"))
    })
    .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted, "fields out of order: {line}");
    // The same inputs serialize to the same bytes, every call.
    assert_eq!(
        line,
        access_log_line("GET", "/health", 200, 7, Some("req-1"))
    );
    let value: Json = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(value["method"], "GET");
    assert_eq!(value["path"], "/health");
    assert_eq!(value["status"], 200);
    assert_eq!(value["duration_ms"], 7);
    assert_eq!(value["request_id"], "req-1");
    // An unassigned id is rendered as the "-" placeholder, never omitted.
    let none = access_log_line("GET", "/x", 200, 0, None);
    assert_eq!(
        serde_json::from_str::<Json>(&none).unwrap()["request_id"],
        "-"
    );
}

#[test]
fn request_id_layer_reuses_valid_ids_and_mints_stable_ones() {
    let layer = request_id();
    // An inbound valid id is kept verbatim so a caller can correlate traces.
    let mut reused = Request {
        path: "/health".to_string(),
        headers: vec![("X-Request-Id".to_string(), "caller-supplied".to_string())],
        ..Request::default()
    };
    assert!(layer(&mut reused).is_none());
    assert_eq!(reused.header("X-Request-Id"), Some("caller-supplied"));

    // A missing id is minted; two requests never collide.
    let mut first = Request::default();
    let mut second = Request::default();
    layer(&mut first);
    layer(&mut second);
    let first_id = first.header("X-Request-Id").expect("minted id").to_string();
    let second_id = second
        .header("X-Request-Id")
        .expect("minted id")
        .to_string();
    assert_ne!(first_id, second_id);
    assert!(first_id.starts_with("req-"));

    // A malformed inbound id (header injection attempt) is replaced, not echoed.
    let mut hostile = Request {
        headers: vec![(
            "X-Request-Id".to_string(),
            "bad value\r\nX-Evil: 1".to_string(),
        )],
        ..Request::default()
    };
    layer(&mut hostile);
    let replaced = hostile.header("X-Request-Id").expect("minted id");
    assert!(replaced.starts_with("req-"));
    assert!(!replaced.contains(['\r', '\n', ' ']));
}

#[test]
fn malformed_if_none_match_never_matches() {
    let etag = etag_for(b"body");
    // Garbage validators fail to match, which keeps a 200 rather than erroring.
    for raw in ["not-an-etag", "\"", "W/", "", ",,", "W/\"bad\""] {
        assert!(!if_none_match_matches(raw, &etag), "{raw}");
    }
    assert!(if_none_match_matches(&etag, &etag));
    assert!(if_none_match_matches("*", &etag));
}

#[test]
fn empty_chain_leaves_request_untouched() {
    let mut request = Request {
        path: "/health".to_string(),
        ..Request::default()
    };
    let chain = MiddlewareChain::new();
    assert!(chain.apply(&mut request).is_none());
    assert_eq!(request.header("X-Request-Id"), None);
}

// --- End-to-end assertions over real loopback TCP.

#[test]
fn gzip_round_trips_and_sets_vary_without_changing_etag() {
    let server = DemoServer::spawn("gzip-vary", &[("OPR_ETAG", "1")]);
    let title = title_for_body_len(GZIP_THRESHOLD_BYTES + 1);
    post_todo(server.port, &title);
    let expected = expected_todo_list(&title);

    let plain = Answer::parse(&raw_request(server.port, "GET", "/todos", &[], b""));
    assert_eq!(plain.status(), 200);
    assert_eq!(plain.body_str(), expected);
    assert_eq!(plain.header("Content-Encoding"), None);
    assert_eq!(plain.header("Vary"), None);

    let compressed = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[("Accept-Encoding", "gzip")],
        b"",
    ));
    assert_eq!(compressed.status(), 200);
    assert_eq!(compressed.header("Content-Encoding"), Some("gzip"));
    assert!(vary_has(&compressed, "Accept-Encoding"));
    assert!(compressed.body.starts_with(&[0x1f, 0x8b]));
    // The ETag is computed before compression, so it equals the plain body hash.
    assert_eq!(compressed.header("ETag"), plain.header("ETag"));
    assert_eq!(
        compressed.header("ETag"),
        Some(etag_for(expected.as_bytes()).as_str())
    );
    // Decompressing recovers exactly the plain bytes.
    assert_eq!(gunzip(&compressed.body), plain.body);
    assert_eq!(gunzip(&compressed.body), expected.as_bytes());
}

#[test]
fn etag_is_stable_and_304_has_empty_body_then_other_routes_serve() {
    let server = DemoServer::spawn("etag-304", &[("OPR_ETAG", "1")]);
    let first = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(first.status(), 200);
    let etag = first.header("ETag").expect("ETag header").to_string();
    assert_eq!(etag, etag_for(first.body.as_slice()));

    // Same request => same ETag, deterministically.
    let again = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(again.header("ETag"), Some(etag.as_str()));

    let not_modified = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", etag.as_str())],
        b"",
    ));
    assert_eq!(not_modified.status(), 304);
    assert!(not_modified.body.is_empty());
    assert_eq!(not_modified.header("Content-Length"), Some("0"));
    assert_eq!(not_modified.header("ETag"), Some(etag.as_str()));

    // A mismatching validator answers 200 with the full body.
    let mismatch = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", "\"0000000000000000\"")],
        b"",
    ));
    assert_eq!(mismatch.status(), 200);
    assert_eq!(mismatch.body_str(), HEALTH_BODY);
    assert_eq!(mismatch.header("ETag"), Some(etag.as_str()));

    // A malformed validator is handled gracefully: 200, not 500.
    let malformed = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", "W/\"garbage\"")],
        b"",
    ));
    assert_eq!(malformed.status(), 200);
    assert_eq!(malformed.body_str(), HEALTH_BODY);

    // Another route still serves after the 304 on this connection.
    let ssr = Answer::parse(&raw_request(server.port, "GET", "/ssr", &[], b""));
    assert_eq!(ssr.status(), 200);
    assert!(
        ssr.header("ETag").is_some(),
        "a body route also gets a validator"
    );
}

#[test]
fn conditional_get_on_a_gzip_eligible_body_keeps_a_bodyless_304() {
    let server = DemoServer::spawn("etag-gzip-304", &[("OPR_ETAG", "1")]);
    let title = title_for_body_len(GZIP_THRESHOLD_BYTES + 1);
    post_todo(server.port, &title);
    let first = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[("Accept-Encoding", "gzip")],
        b"",
    ));
    assert_eq!(first.header("Content-Encoding"), Some("gzip"));
    let etag = first.header("ETag").expect("ETag").to_string();

    let not_modified = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[
            ("Accept-Encoding", "gzip"),
            ("If-None-Match", etag.as_str()),
        ],
        b"",
    ));
    assert_eq!(not_modified.status(), 304);
    assert!(not_modified.body.is_empty());
    assert_eq!(not_modified.header("Content-Encoding"), None);
    assert_eq!(not_modified.header("ETag"), Some(etag.as_str()));
    assert!(vary_has(&not_modified, "Accept-Encoding"));
}

#[test]
fn cache_control_is_configurable_on_success_and_absent_by_default() {
    // Default: no Cache-Control header is added.
    let default = DemoServer::spawn("no-cache-control", &[]);
    let plain = Answer::parse(&raw_request(default.port, "GET", "/health", &[], b""));
    assert_eq!(plain.header("Cache-Control"), None);

    // Configured: the value rides on the 2xx and the 304.
    let server = DemoServer::spawn(
        "cache-control",
        &[("OPR_ETAG", "1"), ("OPR_CACHE_CONTROL", CACHE_CONTROL)],
    );
    let get = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(get.status(), 200);
    assert_eq!(get.header("Cache-Control"), Some(CACHE_CONTROL));
    let etag = get.header("ETag").expect("ETag").to_string();

    let not_modified = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", etag.as_str())],
        b"",
    ));
    assert_eq!(not_modified.status(), 304);
    assert_eq!(not_modified.header("Cache-Control"), Some(CACHE_CONTROL));

    // An error response stays uncached even with Cache-Control configured.
    let missing = Answer::parse(&raw_request(server.port, "GET", "/nope", &[], b""));
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.header("Cache-Control"), None);
}

#[test]
fn structured_access_log_carries_request_id_and_reused_id() {
    let server = DemoServer::spawn("access-log", &[("OPR_LOG_JSON", "1")]);
    // A caller-supplied id must appear verbatim in the access log.
    let supplied = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("X-Request-Id", "trace-abc")],
        b"",
    ));
    assert_eq!(supplied.status(), 200);
    assert_eq!(supplied.header("X-Request-Id"), Some("trace-abc"));

    let lines = server.wait_for_json_lines(1);
    let value: Json = serde_json::from_str(&lines[0]).expect("valid JSON access log");
    assert_eq!(value["method"], "GET");
    assert_eq!(value["path"], "/health");
    assert_eq!(value["status"], 200);
    assert!(value["duration_ms"].is_u64(), "{}", lines[0]);
    assert_eq!(value["request_id"], "trace-abc");
    // The plain logging layer stays silent when JSON logging is on.
    assert!(!server.stderr().contains("[opurom-server] ->"));
    assert!(server.stdout().is_empty());
}

#[test]
fn minted_request_id_is_logged_but_not_echoed_to_keep_defaults_byte_identical() {
    let server = DemoServer::spawn("mint-id", &[("OPR_LOG_JSON", "1")]);
    let answer = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(answer.status(), 200);
    // No id was supplied, so the response is unmodified (no echo header).
    assert_eq!(answer.header("X-Request-Id"), None);

    let lines = server.wait_for_json_lines(1);
    let value: Json = serde_json::from_str(&lines[0]).expect("valid JSON access log");
    let logged = value["request_id"].as_str().expect("logged id");
    assert!(logged.starts_with("req-"), "{logged}");
    // Two requests mint distinct ids, so the log can tell them apart.
    let _second = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    let lines = server.wait_for_json_lines(2);
    let second_id = serde_json::from_str::<Json>(&lines[1]).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(logged, second_id);
}
