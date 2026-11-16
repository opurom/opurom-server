//! Upload persistence over a real loopback server: a multipart POST stores a
//! file under the data directory, a GET serves the exact bytes back, and the
//! path-sanitising rejects traversal and unknown names. The router uses the
//! same helpers the generated service emits.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

use opurom_server::http::Request;
use opurom_server::router::Router;
use opurom_server::serde_json;
use opurom_server::server::Server;
use opurom_server::upload::{download_response, upload_dir_from_env, upload_response};

const BOUNDARY: &str = "----opuromUploadTest7MA4";

#[derive(Debug)]
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn send(port: u16, method: &str, target: &str, extra_headers: &str, body: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let head = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read answer");
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header separator");
    let head_text = String::from_utf8_lossy(&raw[..separator]).into_owned();
    let status = head_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let content_type = head_text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Type: "))
        .map(str::to_string);
    Answer {
        status,
        content_type,
        body: raw[separator + 4..].to_vec(),
    }
}

fn multipart(filename: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(payload);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn router(dir: PathBuf) -> Router {
    let mut router = Router::new();
    let post_dir = dir.clone();
    router.post("/uploads", move |request: &mut Request| {
        upload_response(request, &post_dir)
    });
    router.get("/uploads/:name", move |request: &mut Request| {
        let name = request.param("name").unwrap_or_default();
        download_response(&dir, name)
    });
    router
}

/// Bind on an ephemeral port with the upload dir pointed at a temp directory.
fn start(dir: PathBuf) -> (u16, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let server = Server::bind_with(
        "127.0.0.1:0",
        router(dir),
        Default::default(),
        8 * 1024 * 1024,
    )
    .expect("bind");
    let (addr, shutdown) = server.spawn().expect("spawn");
    (addr.port(), shutdown)
}

#[test]
fn upload_stores_and_serves_the_exact_bytes() {
    let dir = std::env::temp_dir().join(format!("opurom-upload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (port, _shutdown) = start(dir.clone());
    let payload = b"\x89PNG\r\n\x1a\nreal-binary-payload\x00\x01\x02";

    let headers = format!("Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n");
    let created = send(
        port,
        "POST",
        "/uploads",
        &headers,
        &multipart("shot.png", payload),
    );
    assert_eq!(created.status, 201, "{}", created.text());
    let reply: serde_json::Value = serde_json::from_str(&created.text()).expect("json reply");
    let stored = reply["name"].as_str().expect("stored name");
    assert_eq!(reply["size"].as_u64(), Some(payload.len() as u64));
    assert_eq!(stored, "shot.png");

    // The file really exists on disk with the uploaded bytes.
    let on_disk = std::fs::read(dir.join("shot.png")).expect("file on disk");
    assert_eq!(on_disk, payload, "disk bytes match the upload");

    // Serving it back returns the same bytes and a content type.
    let fetched = send(port, "GET", "/uploads/shot.png", "", &[]);
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.body, payload.to_vec());
    assert_eq!(fetched.content_type.as_deref(), Some("image/png"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn upload_never_overwrites_an_existing_file() {
    let dir = std::env::temp_dir().join(format!("opurom-upload-clash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (port, _shutdown) = start(dir.clone());
    let headers = format!("Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n");

    let first = send(
        port,
        "POST",
        "/uploads",
        &headers,
        &multipart("note.txt", b"one"),
    );
    assert_eq!(first.status, 201);
    let second = send(
        port,
        "POST",
        "/uploads",
        &headers,
        &multipart("note.txt", b"two"),
    );
    assert_eq!(second.status, 201);
    let reply: serde_json::Value = serde_json::from_str(&second.text()).expect("json");
    assert_eq!(
        reply["name"].as_str(),
        Some("note-1.txt"),
        "second upload renamed"
    );

    let original = std::fs::read_to_string(dir.join("note.txt")).expect("first file");
    assert_eq!(original, "one", "first file survives the second upload");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn upload_rejects_bad_requests_and_traversal_names() {
    let dir = std::env::temp_dir().join(format!("opurom-upload-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (port, _shutdown) = start(dir.clone());
    let headers = format!("Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n");

    // A body with no file part is a 400, not a stored empty file.
    let no_file = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--{BOUNDARY}--\r\n"
    );
    let rejected = send(port, "POST", "/uploads", &headers, no_file.as_bytes());
    assert_eq!(rejected.status, 400);

    // A multipart body without a Content-Type header is a 400.
    let missing_type = send(port, "POST", "/uploads", "", &multipart("x.bin", b"x"));
    assert_eq!(missing_type.status, 400);

    // Traversal and unknown names never reach the filesystem as a path.
    for name in ["..", "%2Fetc%2Fpasswd", ".hidden", "a%20b"] {
        let answer = send(port, "GET", &format!("/uploads/{name}"), "", &[]);
        assert_eq!(answer.status, 404, "{name} must not resolve");
    }
    // A path-like filename keeps only its final segment; the directory part is
    // dropped, so the file lands inside the upload dir and never escapes it.
    let sneaky = send(
        port,
        "POST",
        "/uploads",
        &headers,
        &multipart("../.ssh/authorized_keys", b"key"),
    );
    assert_eq!(sneaky.status, 201, "{}", sneaky.text());
    let reply: serde_json::Value = serde_json::from_str(&sneaky.text()).expect("json");
    assert_eq!(reply["name"].as_str(), Some("authorized_keys"));
    assert!(
        dir.join("authorized_keys").is_file(),
        "stored inside the dir"
    );
    assert!(
        !dir.join(".ssh").exists(),
        "no directory from the client name is created"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn upload_dir_follows_the_data_env() {
    // Default resolves under ./data; the env var moves it.
    let default_dir = upload_dir_from_env();
    assert!(default_dir.ends_with("uploads"), "{default_dir:?}");
    std::env::set_var("OPR_DATA", "/tmp/opurom-data-env");
    let moved = upload_dir_from_env();
    assert!(moved.starts_with("/tmp/opurom-data-env"), "{moved:?}");
    std::env::remove_var("OPR_DATA");
    assert_ne!(
        upload_dir_from_env(),
        moved,
        "env removal restores the default"
    );
}
