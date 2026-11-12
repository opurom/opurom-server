//! R5 opt-in HTTP features over real TCP: auth, gzip, ETag, CORS and defaults.

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
    constant_time_eq, cors_origin_from_env_value, etag_for, GZIP_THRESHOLD_BYTES,
};
use opurom_server::serde_json::{self, Value as Json};

const HEALTH_BODY: &str = "{\"ok\":true,\"app\":\"opurom-server-demo\",\"version\":\"0.2.0\"}";
const CORS_ORIGIN: &str = "https://app.example";

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
            "opurom-server-r5-{}-{}-{}.stderr",
            tag,
            std::process::id(),
            nonce
        ));
        let stdout_path = std::env::temp_dir().join(format!(
            "opurom-server-r5-{}-{}-{}.stdout",
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

    fn wait_for_plain_lines(&self, count: usize) {
        for _ in 0..200 {
            let lines = self
                .stderr()
                .lines()
                .filter(|line| line.starts_with("[opurom-server] ->"))
                .count();
            if lines >= count {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
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

/// One parsed HTTP answer with the body kept as bytes for gzip checks.
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

    fn header_count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .count()
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

fn expected_todo_list(title: &str) -> String {
    format!("[{{\"id\":1,\"title\":\"{}\"}}]", title)
}

fn title_for_body_len(target: usize) -> String {
    "x".repeat(target - expected_todo_list("").len())
}

fn post_todo(port: u16, title: &str, headers: &[(&str, &str)]) -> Answer {
    let body = format!("{{\"title\":\"{}\"}}", title);
    let answer = Answer::parse(&raw_request(
        port,
        "POST",
        "/todos",
        headers,
        body.as_bytes(),
    ));
    assert_eq!(answer.status(), 201, "{}", answer.body_str());
    answer
}

fn json_statuses(lines: &[String]) -> Vec<u64> {
    let mut statuses: Vec<u64> = lines
        .iter()
        .map(|line| {
            let value: Json = serde_json::from_str(line).expect("valid JSON log line");
            assert_eq!(value["method"], "GET");
            assert_eq!(value["path"], "/health");
            assert!(value["elapsed_ms"].is_u64(), "{}", line);
            value["status"].as_u64().expect("numeric status")
        })
        .collect();
    statuses.sort_unstable();
    statuses
}

#[test]
fn constant_time_comparison_rejects_early_and_length_mismatches() {
    assert!(constant_time_eq(b"secret-token", b"secret-token"));
    assert!(constant_time_eq(b"", b""));
    assert!(!constant_time_eq(b"secret-token", b"xecret-token"));
    assert!(!constant_time_eq(b"secret-token", b"secret-token-extra"));
    assert!(!constant_time_eq(b"secret-token", b""));
    assert!(!constant_time_eq(b"", b"x"));
}

#[test]
fn etag_hash_is_deterministic_and_quoted_hex() {
    let first = etag_for(b"{\"ok\":true}");
    assert_eq!(first, etag_for(b"{\"ok\":true}"));
    assert_ne!(first, etag_for(b"{\"ok\":false}"));
    assert_eq!(first.len(), 18);
    assert!(first.starts_with('"') && first.ends_with('"'));
    assert!(first
        .trim_matches('"')
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn cors_origin_validation_rejects_unsafe_values() {
    assert_eq!(
        cors_origin_from_env_value(" https://app.example "),
        Some("https://app.example".to_string())
    );
    assert_eq!(
        cors_origin_from_env_value("HTTPS://App.Example:8443"),
        Some("https://app.example:8443".to_string())
    );
    assert_eq!(cors_origin_from_env_value("*"), Some("*".to_string()));
    for bad in [
        "null",
        "https://app.example/",
        "https://*.example",
        "https://a b",
        "https://good.example\r\nX-Evil: 1",
        "https://good.example?x=1",
        "ftp://app.example",
    ] {
        assert_eq!(cors_origin_from_env_value(bad), None, "{}", bad);
    }
}

#[test]
fn bearer_auth_rejects_missing_and_wrong_tokens() {
    let server = DemoServer::spawn("auth", &[("OPR_AUTH_TOKEN", "devtoken")]);
    let missing = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(missing.status_line, "HTTP/1.1 401 Unauthorized");
    assert_eq!(missing.status(), 401);
    assert_eq!(missing.body_str(), "{\"error\":\"unauthorized\"}");
    assert_eq!(missing.header("Content-Type"), Some("application/json"));
    assert_eq!(missing.header("ETag"), None);

    let wrong = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Authorization", "Bearer wrong-token")],
        b"",
    ));
    assert_eq!(wrong.status(), 401);
    assert_eq!(wrong.body_str(), "{\"error\":\"unauthorized\"}");

    let valid = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Authorization", "Bearer devtoken")],
        b"",
    ));
    assert_eq!(valid.status(), 200);
    assert_eq!(valid.body_str(), HEALTH_BODY);
    let etag = valid.header("ETag").expect("R5 auth env enables ETag");
    assert_eq!(etag, etag_for(&valid.body).as_str());
    assert_eq!(valid.header_count("ETag"), 1);

    let lowercase_scheme = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Authorization", "bearer devtoken")],
        b"",
    ));
    assert_eq!(lowercase_scheme.status(), 200);

    let conditional = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[
            ("Authorization", "Bearer devtoken"),
            ("If-None-Match", etag),
        ],
        b"",
    ));
    assert_eq!(conditional.status(), 304);
    assert!(conditional.body.is_empty());
}

#[test]
fn unauthorized_request_counts_against_rate_limit_and_is_logged() {
    let server = DemoServer::spawn(
        "auth-compose",
        &[
            ("OPR_AUTH_TOKEN", "devtoken"),
            ("OPR_RATE_LIMIT", "1"),
            ("OPR_LOG_JSON", "1"),
            ("OPR_CORS", CORS_ORIGIN),
        ],
    );
    let first = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Origin", "https://evil.example")],
        b"",
    ));
    assert_eq!(first.status(), 401);
    assert_eq!(first.body_str(), "{\"error\":\"unauthorized\"}");
    assert_eq!(
        first.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert!(vary_has(&first, "Origin"));
    assert_eq!(first.header("ETag"), None);
    assert_eq!(first.header("Content-Encoding"), None);

    let second = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[
            ("Authorization", "Bearer devtoken"),
            ("Origin", "https://evil.example"),
        ],
        b"",
    ));
    assert_eq!(second.status(), 429);
    assert_eq!(second.body_str(), "{\"error\":\"rate_limited\"}");
    assert_eq!(
        second.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert!(second.header("Retry-After").is_some());

    let lines = server.wait_for_json_lines(2);
    assert_eq!(lines.len(), 2, "{:?}", lines);
    assert_eq!(json_statuses(&lines), vec![401, 429]);
    assert!(
        !server.stderr().contains("[opurom-server] ->"),
        "{}",
        server.stderr()
    );
    assert!(server.stdout().is_empty(), "{}", server.stdout());
}

#[test]
fn gzip_round_trips_large_json_and_respects_quality() {
    let server = DemoServer::spawn("gzip", &[]);
    let title = title_for_body_len(GZIP_THRESHOLD_BYTES + 1);
    post_todo(server.port, &title, &[]);
    let expected = expected_todo_list(&title);

    let plain = Answer::parse(&raw_request(server.port, "GET", "/todos", &[], b""));
    assert_eq!(plain.status(), 200);
    assert_eq!(plain.body_str(), expected);
    assert_eq!(plain.header("Content-Encoding"), None);
    assert_eq!(plain.header("ETag"), None);
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
    assert_eq!(compressed.header("ETag"), None);
    assert!(compressed.body.starts_with(&[0x1f, 0x8b]));
    let length = compressed.body.len().to_string();
    assert_eq!(compressed.header("Content-Length"), Some(length.as_str()));
    let decoded = gunzip(&compressed.body);
    assert_eq!(decoded.as_slice(), expected.as_bytes());
    assert_eq!(decoded.as_slice(), plain.body.as_slice());

    let q_zero = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[("Accept-Encoding", "gzip;q=0.0")],
        b"",
    ));
    assert_eq!(q_zero.status(), 200);
    assert_eq!(q_zero.header("Content-Encoding"), None);
    assert_eq!(q_zero.body, plain.body);

    let other_coding = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[("Accept-Encoding", "xgzip")],
        b"",
    ));
    assert_eq!(other_coding.header("Content-Encoding"), None);
}

#[test]
fn gzip_threshold_keeps_small_bodies_uncompressed() {
    let server = DemoServer::spawn("gzip-threshold", &[]);
    let title = title_for_body_len(GZIP_THRESHOLD_BYTES);
    post_todo(server.port, &title, &[]);

    let at_threshold = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[("Accept-Encoding", "gzip")],
        b"",
    ));
    assert_eq!(at_threshold.status(), 200);
    assert_eq!(at_threshold.body.len(), GZIP_THRESHOLD_BYTES);
    assert_eq!(at_threshold.body_str(), expected_todo_list(&title));
    assert_eq!(at_threshold.header("Content-Encoding"), None);
    assert_eq!(at_threshold.header("Vary"), None);

    let health = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Accept-Encoding", "GZIP")],
        b"",
    ));
    assert_eq!(health.status(), 200);
    assert_eq!(health.body_str(), HEALTH_BODY);
    assert_eq!(health.header("Content-Encoding"), None);
}

#[test]
fn etag_over_tcp_returns_304_with_no_body() {
    let server = DemoServer::spawn("etag", &[("OPR_ETAG", "1")]);
    let first = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(first.status(), 200);
    assert_eq!(first.body_str(), HEALTH_BODY);
    let expected_etag = etag_for(&first.body);
    let etag = first.header("ETag").expect("ETag header");
    assert_eq!(etag, expected_etag.as_str());
    assert_eq!(first.header_count("ETag"), 1);
    assert_eq!(first.header("Vary"), None);

    let repeated = Answer::parse(&raw_request(server.port, "GET", "/health", &[], b""));
    assert_eq!(repeated.header("ETag"), Some(etag));

    let conditional = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", etag)],
        b"",
    ));
    assert_eq!(conditional.status_line, "HTTP/1.1 304 Not Modified");
    assert_eq!(conditional.status(), 304);
    assert!(conditional.body.is_empty());
    assert_eq!(conditional.header("Content-Length"), Some("0"));
    assert_eq!(conditional.header("ETag"), Some(etag));
    assert_eq!(conditional.header("Content-Type"), None);
    assert_eq!(conditional.header("Content-Encoding"), None);

    let weak = format!("W/{}", etag);
    let weak_answer = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", weak.as_str())],
        b"",
    ));
    assert_eq!(weak_answer.status(), 304);
    assert!(weak_answer.body.is_empty());

    let list = format!("\"0000000000000000\", {}", etag);
    let list_answer = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", list.as_str())],
        b"",
    ));
    assert_eq!(list_answer.status(), 304);

    let wildcard = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", "*")],
        b"",
    ));
    assert_eq!(wildcard.status(), 304);
    assert!(wildcard.body.is_empty());

    let mismatch = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("If-None-Match", "\"0000000000000000\"")],
        b"",
    ));
    assert_eq!(mismatch.status(), 200);
    assert_eq!(mismatch.body_str(), HEALTH_BODY);
    assert_eq!(mismatch.header("ETag"), Some(etag));

    let post = post_todo(server.port, "x", &[("If-None-Match", "*")]);
    assert_eq!(post.status(), 201);
    assert!(post.body_str().contains("\"title\":\"x\""));
}

#[test]
fn cors_uses_fixed_origin_and_preflight_is_204() {
    let server = DemoServer::spawn("cors", &[("OPR_CORS", CORS_ORIGIN)]);
    let get = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Origin", "https://evil.example")],
        b"",
    ));
    assert_eq!(get.status(), 200);
    assert_eq!(get.body_str(), HEALTH_BODY);
    assert_eq!(get.header("Access-Control-Allow-Origin"), Some(CORS_ORIGIN));
    assert!(vary_has(&get, "Origin"));
    assert_eq!(
        get.header("Access-Control-Allow-Methods"),
        None,
        "preflight-only header"
    );
    let etag = get.header("ETag").expect("R5 CORS env enables ETag");

    let conditional = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/health",
        &[("Origin", "https://evil.example"), ("If-None-Match", etag)],
        b"",
    ));
    assert_eq!(conditional.status(), 304);
    assert!(conditional.body.is_empty());
    assert_eq!(
        conditional.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert!(vary_has(&conditional, "Origin"));

    let preflight = Answer::parse(&raw_request(
        server.port,
        "OPTIONS",
        "/health",
        &[
            ("Origin", "https://evil.example"),
            ("Access-Control-Request-Method", "GET"),
            (
                "Access-Control-Request-Headers",
                "Authorization, Content-Type",
            ),
        ],
        b"",
    ));
    assert_eq!(preflight.status_line, "HTTP/1.1 204 No Content");
    assert_eq!(preflight.status(), 204);
    assert!(preflight.body.is_empty());
    assert_eq!(preflight.header("Content-Length"), Some("0"));
    assert_eq!(
        preflight.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert_eq!(
        preflight.header("Access-Control-Allow-Methods"),
        Some("GET, POST, PUT, DELETE, OPTIONS")
    );
    assert_eq!(
        preflight.header("Access-Control-Allow-Headers"),
        Some("Authorization, Content-Type")
    );
    assert!(vary_has(&preflight, "Origin"));
    assert_eq!(preflight.header("ETag"), None);
}

#[test]
fn cors_wildcard_is_literal_and_invalid_config_is_disabled() {
    let wildcard = DemoServer::spawn("cors-wildcard", &[("OPR_CORS", "*")]);
    let get = Answer::parse(&raw_request(
        wildcard.port,
        "GET",
        "/health",
        &[("Origin", "https://evil.example")],
        b"",
    ));
    assert_eq!(
        get.header("Access-Control-Allow-Origin"),
        Some("*"),
        "request Origin is never reflected"
    );
    let preflight = Answer::parse(&raw_request(
        wildcard.port,
        "OPTIONS",
        "/health",
        &[("Origin", "https://evil.example")],
        b"",
    ));
    assert_eq!(preflight.status(), 204);
    assert_eq!(preflight.header("Access-Control-Allow-Origin"), Some("*"));

    let invalid = DemoServer::spawn(
        "cors-invalid",
        &[("OPR_CORS", "https://good.example\r\nX-Evil: 1")],
    );
    let get = Answer::parse(&raw_request(
        invalid.port,
        "GET",
        "/health",
        &[("Origin", "https://good.example")],
        b"",
    ));
    assert_eq!(get.status(), 200);
    assert_eq!(get.header("Access-Control-Allow-Origin"), None);
    assert_eq!(get.header("X-Evil"), None);
    assert_eq!(get.header("Vary"), None);
    assert_eq!(get.header("ETag"), None);

    let preflight = Answer::parse(&raw_request(
        invalid.port,
        "OPTIONS",
        "/health",
        &[("Origin", "https://good.example")],
        b"",
    ));
    assert_eq!(preflight.status(), 405);
    assert_eq!(preflight.header("Access-Control-Allow-Methods"), None);
    assert_eq!(preflight.body_str(), "{\"error\":\"method_not_allowed\"}");
}

#[test]
fn all_r5_features_compose_on_large_json() {
    let server = DemoServer::spawn(
        "all-features",
        &[
            ("OPR_AUTH_TOKEN", "devtoken"),
            ("OPR_CORS", CORS_ORIGIN),
            ("OPR_ETAG", "1"),
        ],
    );
    let auth = [("Authorization", "Bearer devtoken")];
    let title = title_for_body_len(GZIP_THRESHOLD_BYTES + 100);
    post_todo(server.port, &title, &auth);
    let expected = expected_todo_list(&title);

    let first = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[
            auth[0],
            ("Accept-Encoding", "gzip"),
            ("Origin", CORS_ORIGIN),
        ],
        b"",
    ));
    assert_eq!(first.status(), 200);
    assert_eq!(first.header("Content-Encoding"), Some("gzip"));
    assert_eq!(
        first.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert!(vary_has(&first, "Accept-Encoding"));
    assert!(vary_has(&first, "Origin"));
    let expected_etag = etag_for(expected.as_bytes());
    let etag = first.header("ETag").expect("ETag header").to_string();
    assert_eq!(etag, expected_etag);
    assert_eq!(gunzip(&first.body), expected.as_bytes());

    let not_modified = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[
            auth[0],
            ("Accept-Encoding", "gzip"),
            ("Origin", CORS_ORIGIN),
            ("If-None-Match", etag.as_str()),
        ],
        b"",
    ));
    assert_eq!(not_modified.status(), 304);
    assert!(not_modified.body.is_empty());
    assert_eq!(not_modified.header("Content-Length"), Some("0"));
    assert_eq!(not_modified.header("ETag"), Some(etag.as_str()));
    assert_eq!(
        not_modified.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert!(vary_has(&not_modified, "Origin"));
    assert_eq!(not_modified.header("Content-Encoding"), None);

    let unauthorized = Answer::parse(&raw_request(
        server.port,
        "GET",
        "/todos",
        &[("Accept-Encoding", "gzip"), ("Origin", CORS_ORIGIN)],
        b"",
    ));
    assert_eq!(unauthorized.status(), 401);
    assert_eq!(unauthorized.body_str(), "{\"error\":\"unauthorized\"}");
    assert_eq!(
        unauthorized.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert_eq!(unauthorized.header("ETag"), None);
    assert_eq!(unauthorized.header("Content-Encoding"), None);
}

#[test]
fn preflight_bypasses_auth_but_counts_and_logs() {
    let server = DemoServer::spawn(
        "preflight-compose",
        &[
            ("OPR_AUTH_TOKEN", "devtoken"),
            ("OPR_CORS", CORS_ORIGIN),
            ("OPR_RATE_LIMIT", "1"),
            ("OPR_LOG_JSON", "1"),
        ],
    );
    let preflight = Answer::parse(&raw_request(
        server.port,
        "OPTIONS",
        "/health",
        &[
            ("Origin", CORS_ORIGIN),
            ("Access-Control-Request-Method", "GET"),
        ],
        b"",
    ));
    assert_eq!(preflight.status(), 204);
    assert_eq!(
        preflight.header("Access-Control-Allow-Origin"),
        Some(CORS_ORIGIN)
    );
    assert_eq!(
        preflight.header("Access-Control-Allow-Methods"),
        Some("GET, POST, PUT, DELETE, OPTIONS")
    );
    assert!(preflight.body.is_empty());

    let limited = Answer::parse(&raw_request(
        server.port,
        "OPTIONS",
        "/health",
        &[
            ("Origin", CORS_ORIGIN),
            ("Access-Control-Request-Method", "GET"),
            ("Authorization", "Bearer devtoken"),
        ],
        b"",
    ));
    assert_eq!(limited.status(), 429);
    assert_eq!(limited.body_str(), "{\"error\":\"rate_limited\"}");

    let lines = server.wait_for_json_lines(2);
    assert_eq!(lines.len(), 2, "{:?}", lines);
    let mut statuses: Vec<u64> = lines
        .iter()
        .map(|line| {
            let value: Json = serde_json::from_str(line).expect("valid JSON log line");
            assert_eq!(value["method"], "OPTIONS");
            assert_eq!(value["path"], "/health");
            assert!(value["elapsed_ms"].is_u64(), "{}", line);
            value["status"].as_u64().expect("numeric status")
        })
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, vec![204, 429]);
    assert!(
        !server.stderr().contains("[opurom-server] ->"),
        "{}",
        server.stderr()
    );
    assert!(server.stdout().is_empty(), "{}", server.stdout());
}

#[test]
fn default_behaviour_is_byte_identical_without_r5_env() {
    let server = DemoServer::spawn("default", &[]);
    let expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        HEALTH_BODY.len(),
        HEALTH_BODY
    );
    let raw = raw_request(
        server.port,
        "GET",
        "/health",
        &[
            ("Accept-Encoding", "gzip"),
            ("If-None-Match", "\"0000000000000000\""),
            ("Origin", "https://evil.example"),
            ("Authorization", "Bearer wrong-token"),
        ],
        b"",
    );
    assert_eq!(raw.as_slice(), expected.as_bytes());

    let options = Answer::parse(&raw_request(
        server.port,
        "OPTIONS",
        "/health",
        &[
            ("Origin", "https://evil.example"),
            ("Access-Control-Request-Method", "GET"),
        ],
        b"",
    ));
    assert_eq!(options.status(), 405);
    assert_eq!(options.header("Access-Control-Allow-Origin"), None);
    assert_eq!(options.header("ETag"), None);
    assert_eq!(options.body_str(), "{\"error\":\"method_not_allowed\"}");

    server.wait_for_plain_lines(2);
    let stderr = server.stderr();
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("[opurom-server] ->"))
            .count(),
        2,
        "{}",
        stderr
    );
    assert!(!stderr.lines().any(|line| line.starts_with('{')));
    assert!(server.stdout().is_empty(), "{}", server.stdout());
}
