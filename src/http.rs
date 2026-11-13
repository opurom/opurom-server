//! HTTP/1.1 primitives: method, request, response and a bounded std-only parser.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};

use serde_json::Value;

/// Default maximum accepted request body: 1 MiB.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum accepted header block size. Larger header blocks get a 431.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// HTTP methods supported by the server contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Other(String),
}

impl Method {
    pub fn parse(raw: &str) -> Method {
        match raw {
            "GET" => Method::Get,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            other => Method::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Other(other) => other,
        }
    }
}

impl Default for Method {
    fn default() -> Self {
        Method::Get
    }
}

/// A parsed HTTP request. Path parameters are filled in by the router.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub params: BTreeMap<String, String>,
    /// The protocol version of the request line, for example `HTTP/1.1`.
    pub version: String,
}

impl Request {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Value of a `:param` captured by the matched route.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// Decode the body as UTF-8.
    pub fn body_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    /// Decode the body as JSON.
    pub fn json(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// An HTTP response. Errors are values: no handler failure aborts the process.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Response {
        self.set_header(name, value);
        self
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// JSON response with `Content-Type: application/json`.
    pub fn json(status: u16, value: &Value) -> Response {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Response::json_text_bytes(status, body)
    }

    /// JSON response from an already-serialized UTF-8 string.
    pub fn json_text(status: u16, body: &str) -> Response {
        Response::json_text_bytes(status, body.as_bytes().to_vec())
    }

    fn json_text_bytes(status: u16, body: Vec<u8>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body,
        }
    }

    /// Plain-text response.
    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: body.as_bytes().to_vec(),
        }
    }

    /// HTML response.
    pub fn html(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            body: body.as_bytes().to_vec(),
        }
    }

    /// Canonical JSON error body: `{"error":"<message>"}`.
    pub fn error(status: u16, message: &str) -> Response {
        Response::json(status, &serde_json::json!({ "error": message }))
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Reason phrase used in the HTTP status line.
pub fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// A recoverable request-parsing failure.
#[derive(Clone, Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String,
}

impl HttpError {
    fn new(status: u16, message: &str) -> HttpError {
        HttpError {
            status,
            message: message.to_string(),
        }
    }
}

/// Read one HTTP/1.1 request: request line, headers, then a Content-Length
/// body. Bodies larger than `max_body` are rejected with 413 before buffering.
/// The request line and headers share one `MAX_HEADER_BYTES` budget enforced
/// while reading, so an endless line cannot be buffered without a bound.
///
/// `Expect: 100-continue` on an HTTP/1.1 request writes the interim
/// `HTTP/1.1 100 Continue` answer to the transport before the body read, so a
/// client that withholds the body is not blocked. The writer bound is that
/// interim answer; every other request writes nothing here.
pub fn read_request<R: Read + Write>(
    reader: &mut BufReader<R>,
    max_body: usize,
) -> Result<Request, HttpError> {
    let mut head = Read::take(&mut *reader, (MAX_HEADER_BYTES + 1) as u64);
    let mut request_line = String::new();
    let read = head
        .read_line(&mut request_line)
        .map_err(|err| read_error(err, "bad_request: cannot read request line"))?;
    if read == 0 {
        return Err(HttpError::new(400, "bad_request: empty request"));
    }
    if head.limit() == 0 {
        return Err(HttpError::new(431, "header_block_too_large"));
    }

    let mut parts = request_line
        .trim_end_matches(['\r', '\n'])
        .split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpError::new(400, "bad_request: missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| HttpError::new(400, "bad_request: missing target"))?;
    let version = parts
        .next()
        .ok_or_else(|| HttpError::new(400, "bad_request: missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(HttpError::new(400, "bad_request: malformed request line"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::new(505, "http_version_not_supported"));
    }

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let read = head
            .read_line(&mut line)
            .map_err(|err| read_error(err, "bad_request: cannot read header"))?;
        if head.limit() == 0 {
            return Err(HttpError::new(431, "header_block_too_large"));
        }
        if read == 0 || !line.ends_with('\n') {
            return Err(HttpError::new(400, "bad_request: truncated headers"));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpError::new(400, "bad_request: malformed header"))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    drop(head);

    let mut length = 0usize;
    let mut expectation: Option<&str> = None;
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("content-length") {
            length = value
                .parse::<usize>()
                .map_err(|_| HttpError::new(400, "bad_request: invalid Content-Length"))?;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::new(501, "transfer_encoding_not_supported"));
        }
        if name.eq_ignore_ascii_case("expect") && expectation.is_none() {
            expectation = Some(value.as_str());
        }
    }
    // An expectation the server does not understand is refused before the body
    // is read; HTTP/1.0 requests ignore `100-continue` and read as usual.
    let wants_continue = match expectation {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("100-continue") => version == "HTTP/1.1",
        Some(_) => return Err(HttpError::new(417, "expectation_failed")),
    };
    if length > max_body {
        // Drain the oversized body so the client can read the 413 answer
        // instead of hitting a broken pipe. A client that withholds the body
        // behind the interim answer has sent nothing to drain.
        if !wants_continue {
            drain(reader, length);
        }
        return Err(HttpError::new(413, "payload_too_large"));
    }
    if wants_continue && length > 0 {
        // The client holds the body until this interim answer arrives.
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .and_then(|()| reader.get_mut().flush())
            .map_err(|_| HttpError::new(400, "bad_request: cannot send 100 Continue"))?;
    }

    let mut body = vec![0u8; length];
    if length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|err| read_error(err, "bad_request: truncated body"))?;
    }

    let (raw_path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    let (path, path_query) = match raw_path.split_once('?') {
        Some((path, query)) => (path, query),
        None => (raw_path, ""),
    };
    let query = if query.is_empty() { path_query } else { query };
    let path = normalize_path(path);

    Ok(Request {
        method: Method::parse(method),
        path,
        query: query.to_string(),
        headers,
        body,
        params: BTreeMap::new(),
        version: version.to_string(),
    })
}

/// A socket read timeout is a 408; other read failures are malformed requests.
fn read_error(err: std::io::Error, context: &str) -> HttpError {
    if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        HttpError::new(408, "request_timeout")
    } else {
        HttpError::new(400, context)
    }
}

/// Read and discard `count` bytes, ignoring errors.
fn drain<R: BufRead>(reader: &mut R, count: usize) {
    let mut remaining = count;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        match std::io::Read::read(reader, &mut buffer[..chunk]) {
            Ok(0) | Err(_) => break,
            Ok(read) => remaining -= read,
        }
    }
}

/// True for headers that only belong to an HTTP/1.1 connection.
///
/// HTTP/2 and HTTP/3 both forbid these fields, so the transports drop them
/// before they write a response.
pub(crate) fn is_connection_specific(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("te")
}

/// Collapse repeated slashes and drop a trailing slash (except at the root).
pub(crate) fn normalize_path(path: &str) -> String {
    let mut out = String::from("/");
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        out.push_str(&percent_decode(segment));
        out.push('/');
    }
    if out.len() > 1 {
        out.pop();
    }
    out
}

/// Decode `%XX` escapes in a path segment. Invalid escapes are kept verbatim.
pub fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_value(bytes[i + 1]);
            let lo = hex_value(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
