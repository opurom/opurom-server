//! R4 hardening tests: rate limits, structured logs and unchanged defaults.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use opurom_server::http::Method;
use opurom_server::serde_json::{self, Value as Json};
use opurom_server::server::request_for;
use opurom_server::{request_log_line, RateLimiter, RATE_LIMIT_WINDOW_SECS};

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
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let stderr_path = std::env::temp_dir().join(format!(
            "opurom-server-r4-{}-{}-{}.stderr",
            tag,
            std::process::id(),
            nanos
        ));
        let stdout_path = std::env::temp_dir().join(format!(
            "opurom-server-r4-{}-{}-{}.stdout",
            tag,
            std::process::id(),
            nanos
        ));
        let stderr_file = File::create(&stderr_path).expect("stderr file");
        let stdout_file = File::create(&stdout_path).expect("stdout file");

        let mut command = Command::new(env!("CARGO_BIN_EXE_opurom-server"));
        command
            .arg(port.to_string())
            .env_remove("OPR_PORT")
            .env_remove("OPR_RATE_LIMIT")
            .env_remove("OPR_LOG_JSON")
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

    fn wait_for_json_line(&self) -> Option<String> {
        for _ in 0..100 {
            if let Some(line) = self
                .stderr()
                .lines()
                .find(|line| line.starts_with('{'))
                .map(str::to_string)
            {
                return Some(line);
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
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

fn raw_request(port: u16, method: &str, path: &str, body: &str) -> String {
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
    String::from_utf8_lossy(&raw).into_owned()
}

fn status(raw: &str) -> u16 {
    raw.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0)
}

fn header(raw: &str, name: &str) -> Option<String> {
    let (head, _) = raw.split_once("\r\n\r\n")?;
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn body(raw: &str) -> &str {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

#[test]
fn rate_limiter_allows_n_then_rejects_with_retry_after() {
    let limiter = RateLimiter::new(3);
    let now = Instant::now();
    let health = request_for(Method::Get, "/health", "");
    for _ in 0..3 {
        assert_eq!(limiter.check_at(&health, now), None);
    }
    assert_eq!(limiter.check_at(&health, now), Some(RATE_LIMIT_WINDOW_SECS));

    let other = request_for(Method::Get, "/ssr", "");
    assert_eq!(limiter.check_at(&other, now), None);

    let next_window = now + Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
    assert_eq!(limiter.check_at(&health, next_window), None);
}

#[test]
fn rate_limit_env_rejects_n_plus_one_over_tcp() {
    let server = DemoServer::spawn("rate", &[("OPR_RATE_LIMIT", "3")]);
    for _ in 0..3 {
        let answer = raw_request(server.port, "GET", "/health", "");
        assert_eq!(status(&answer), 200, "{}", answer);
    }

    let limited = raw_request(server.port, "GET", "/health", "");
    assert!(
        limited.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
        "{}",
        limited
    );
    assert_eq!(body(&limited), "{\"error\":\"rate_limited\"}");
    let retry_after = header(&limited, "Retry-After").expect("Retry-After header");
    let seconds: u64 = retry_after.parse().expect("numeric Retry-After");
    assert!(seconds > 0 && seconds <= RATE_LIMIT_WINDOW_SECS);

    let other_route = raw_request(server.port, "GET", "/ssr", "");
    assert_eq!(status(&other_route), 200, "{}", other_route);
    assert!(server.stdout().is_empty(), "{}", server.stdout());
}

#[test]
fn request_log_line_has_measured_numeric_fields() {
    let started = Instant::now();
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap();
    let line = request_log_line("GET", "/health", 200, elapsed_ms);
    assert!(!line.contains('\n'));

    let value: Json = serde_json::from_str(&line).expect("valid JSON line");
    assert_eq!(value.as_object().expect("JSON object").len(), 4);
    assert_eq!(value["method"], "GET");
    assert_eq!(value["path"], "/health");
    assert_eq!(value["status"], 200);
    assert_eq!(value["elapsed_ms"].as_u64(), Some(elapsed_ms));
}

#[test]
fn structured_logging_writes_one_json_line_to_stderr() {
    let server = DemoServer::spawn("log", &[("OPR_LOG_JSON", "1")]);
    let answer = raw_request(server.port, "GET", "/health", "");
    assert_eq!(status(&answer), 200, "{}", answer);

    let line = server.wait_for_json_line().expect("one JSON log line");
    let value: Json = serde_json::from_str(&line).expect("valid JSON log line");
    assert_eq!(value["method"], "GET");
    assert_eq!(value["path"], "/health");
    assert_eq!(value["status"], 200);
    assert!(value["elapsed_ms"].is_u64(), "{}", line);

    let stderr = server.stderr();
    assert_eq!(
        stderr.lines().filter(|line| line.starts_with('{')).count(),
        1,
        "{}",
        stderr
    );
    assert!(!stderr.contains("[opurom-server] ->"), "{}", stderr);
    assert!(server.stdout().is_empty(), "{}", server.stdout());
}

#[test]
fn default_behaviour_is_byte_identical_without_env() {
    let server = DemoServer::spawn("default", &[]);
    let expected_body = "{\"ok\":true,\"app\":\"opurom-server-demo\",\"version\":\"0.2.0\"}";
    let expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        expected_body.len(),
        expected_body
    );

    for _ in 0..5 {
        let answer = raw_request(server.port, "GET", "/health", "");
        assert_eq!(answer, expected);
    }

    let stderr = server.stderr();
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("[opurom-server] ->"))
            .count(),
        5,
        "{}",
        stderr
    );
    assert!(
        !stderr.lines().any(|line| line.starts_with('{')),
        "{}",
        stderr
    );
    assert!(server.stdout().is_empty(), "{}", server.stdout());
}
