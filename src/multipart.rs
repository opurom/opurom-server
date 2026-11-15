//! `multipart/form-data` request-body parsing for file uploads.
//!
//! The parser is std-only and byte-oriented: it reads the `boundary` from a
//! `Content-Type` header, then walks the body once, splitting on the boundary
//! delimiters and parsing each part's header block into a name, an optional
//! filename, an optional content type and the raw value bytes. It never
//! allocates more than the body already holds and never panics on malformed
//! input: every failure is a readable [`MultipartError`].
//!
//! Limits are explicit so a hostile upload cannot exhaust memory: a header
//! block, a part count and a total body are each bounded, and exceeding a bound
//! is a typed error rather than a partial parse.

use crate::http::{Request, Response};

/// Largest accepted multipart body, in bytes.
pub const MAX_MULTIPART_BODY: usize = 16 * 1024 * 1024;

/// Largest accepted single part header block, in bytes.
pub const MAX_PART_HEADER: usize = 8 * 1024;

/// Largest accepted number of parts.
pub const MAX_PARTS: usize = 64;

/// Why a multipart request was rejected with 400.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartError(pub String);

impl MultipartError {
    fn new(message: impl Into<String>) -> MultipartError {
        MultipartError(message.into())
    }

    /// Canonical 400 response carrying the readable reason.
    pub fn response(&self) -> Response {
        Response::error(400, &self.0)
    }
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One decoded part of a multipart body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartPart {
    /// The form field name from `Content-Disposition: form-data; name="..."`.
    pub name: String,
    /// The client-supplied filename, when the part is a file upload.
    pub filename: Option<String>,
    /// The part's `Content-Type`, when supplied.
    pub content_type: Option<String>,
    /// The raw value bytes, exactly as received (no line-ending trimming).
    pub data: Vec<u8>,
}

impl MultipartPart {
    /// True when the part carries a filename, i.e. it is a file upload.
    pub fn is_file(&self) -> bool {
        self.filename.is_some()
    }
}

/// Extract the `boundary` parameter from a `Content-Type: multipart/form-data`
/// header value. The boundary is returned without its surrounding quotes.
pub fn boundary_from_content_type(value: &str) -> Option<String> {
    let (media, params) = value.split_once(';')?;
    if !media.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    for param in params.split(';') {
        let (key, val) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("boundary") {
            let val = val.trim();
            let unquoted = val
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or(val);
            if unquoted.is_empty() || unquoted.len() > 200 {
                return None;
            }
            return Some(unquoted.to_string());
        }
    }
    None
}

/// Parse a `multipart/form-data` request body.
///
/// `content_type` is the request's `Content-Type` header; `body` is the raw
/// bytes. The delimiter is `--boundary`, the final boundary is followed by
/// `--`, and each part is separated from its value by a blank line.
pub fn parse_multipart(content_type: &str, body: &[u8]) -> Result<Vec<MultipartPart>, MultipartError> {
    if body.len() > MAX_MULTIPART_BODY {
        return Err(MultipartError::new(format!(
            "multipart body of {} bytes exceeds the {MAX_MULTIPART_BODY}-byte limit",
            body.len()
        )));
    }
    let boundary = boundary_from_content_type(content_type).ok_or_else(|| {
        MultipartError::new("missing or invalid multipart/form-data boundary")
    })?;
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut pos = delimiter_search(body, &delimiter, 0)?;
    loop {
        // Skip the delimiter and its trailing CRLF.
        pos += delimiter.len();
        if body[pos..].starts_with(b"--") {
            break; // closing delimiter
        }
        pos = skip_crlf(body, pos);
        // A part body ends at the next delimiter, preceded by CRLF.
        let next = delimiter_search(body, &delimiter, pos)?;
        // Trim the CRLF that introduces the next delimiter.
        let value_end = next.saturating_sub(2);
        if value_end < pos {
            return Err(MultipartError::new("malformed multipart part framing"));
        }
        let part_block = &body[pos..next];
        let header_end = find_header_end(part_block)
            .ok_or_else(|| MultipartError::new("multipart part has no header terminator"))?;
        if header_end > MAX_PART_HEADER {
            return Err(MultipartError::new(format!(
                "multipart part header of {header_end} bytes exceeds the {MAX_PART_HEADER}-byte limit"
            )));
        }
        let headers = std::str::from_utf8(&part_block[..header_end])
            .map_err(|_| MultipartError::new("multipart part header is not valid UTF-8"))?;
        let (name, filename) = parse_disposition(headers)?;
        let content_type = parse_part_content_type(headers);
        let data = body[pos + header_end + 4..value_end].to_vec();
        parts.push(MultipartPart {
            name,
            filename,
            content_type,
            data,
        });
        if parts.len() > MAX_PARTS {
            return Err(MultipartError::new(format!(
                "multipart request has more than {MAX_PARTS} parts"
            )));
        }
        pos = next;
    }
    Ok(parts)
}

/// Parse the first file part of a request body.
pub fn first_file_part(request: &Request) -> Result<Option<MultipartPart>, MultipartError> {
    let content_type = request
        .header("Content-Type")
        .ok_or_else(|| MultipartError::new("missing Content-Type header"))?;
    let parts = parse_multipart(content_type, &request.body)?;
    Ok(parts.into_iter().find(MultipartPart::is_file))
}

fn skip_crlf(body: &[u8], pos: usize) -> usize {
    if body[pos..].starts_with(b"\r\n") {
        pos + 2
    } else {
        pos
    }
}

/// Find `needle` at or after `from`; the delimiter must stand at a line start,
/// so the search requires it to be preceded by nothing or a CRLF.
fn delimiter_search(body: &[u8], needle: &[u8], from: usize) -> Result<usize, MultipartError> {
    let mut i = from;
    while i + needle.len() <= body.len() {
        if &body[i..i + needle.len()] == needle
            && (i == 0 || body[i - 1] == b'\n')
        {
            return Ok(i);
        }
        i += 1;
    }
    Err(MultipartError::new("multipart boundary not found in body"))
}

/// Offset of the blank-line header terminator (`\r\n\r\n`) within `block`.
fn find_header_end(block: &[u8]) -> Option<usize> {
    block.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Parse `Content-Disposition: form-data; name="..."; filename="..."`.
fn parse_disposition(headers: &str) -> Result<(String, Option<String>), MultipartError> {
    let line = headers
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-disposition:"))
        .ok_or_else(|| MultipartError::new("multipart part is missing Content-Disposition"))?;
    let name = header_param(line, "name")
        .ok_or_else(|| MultipartError::new("multipart part is missing a field name"))?;
    Ok((name, header_param(line, "filename")))
}

fn parse_part_content_type(headers: &str) -> Option<String> {
    headers
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
        .map(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()))
        .flatten()
}

/// Read one `key="value"` (or unquoted `key=value`) parameter from a header.
fn header_param(line: &str, key: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let at = lower.find(&format!("{key}="))?;
    let rest = &line[at + key.len() + 1..];
    let value = if let Some(stripped) = rest.strip_prefix('"') {
        // Quoted value: read to the closing quote, honouring backslash escapes.
        let mut out = String::new();
        let mut chars = stripped.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '"' => return Some(out),
                '\\' => {
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                }
                other => out.push(other),
            }
        }
        return None;
    } else {
        rest.split([';', ' ', '\t', '\r', '\n']).next().unwrap_or("")
    };
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
