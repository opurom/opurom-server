//! Multipart upload persistence: store a file part under the application data
//! directory and serve it back by name.
//!
//! Names are sanitised to one safe path segment (no directory part, no dot
//! files, `[A-Za-z0-9._-]` only), so no client-supplied path can escape the
//! upload directory on either write or read. Collisions get a numeric suffix
//! instead of overwriting an existing upload.

use std::path::{Path, PathBuf};

use crate::http::{Request, Response};
use crate::multipart::first_file_part;

/// Application data directory; uploads live in `<OPR_DATA>/uploads`.
pub const DATA_DIR_ENV: &str = "OPR_DATA";

/// Largest accepted file part, in bytes. The server body cap still bounds the
/// whole request before this check runs.
pub const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Resolve the upload directory from the environment (default `./data`).
pub fn upload_dir_from_env() -> PathBuf {
    let base = std::env::var(DATA_DIR_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| "./data".to_string());
    Path::new(&base).join("uploads")
}

/// Reduce a raw filename to one safe path segment: keep only the final
/// component (browsers may send `C:\fakepath\name`), reject empty, dot-only
/// and over-long names, and allow only letters, digits and `._-`. Directory
/// parts are dropped, never followed.
fn safe_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    if base.is_empty() || base == "." || base == ".." || base.len() > 96 {
        return None;
    }
    if base.starts_with('.') {
        return None;
    }
    if !base
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }
    Some(base.to_string())
}

/// Pick an unused name in `dir`: the original when free, otherwise `stem-N.ext`.
fn unique_name(dir: &Path, name: &str) -> Option<String> {
    if !dir.join(name).exists() {
        return Some(name.to_string());
    }
    let stem = name
        .rsplit_once('.')
        .map(|(stem, ext)| (stem.to_string(), Some(ext.to_string())))
        .unwrap_or((name.to_string(), None));
    for attempt in 1..=99 {
        let candidate = match &stem.1 {
            Some(ext) => format!("{}-{}.{}", stem.0, attempt, ext),
            None => format!("{}-{}", stem.0, attempt),
        };
        if !dir.join(&candidate).exists() {
            return Some(candidate);
        }
    }
    None
}

/// Content type for a stored upload by extension; anything else is opaque.
fn content_type(name: &str) -> &'static str {
    match name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
    {
        Some(ext) if ext == "png" => "image/png",
        Some(ext) if ext == "jpg" || ext == "jpeg" => "image/jpeg",
        Some(ext) if ext == "gif" => "image/gif",
        Some(ext) if ext == "webp" => "image/webp",
        Some(ext) if ext == "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// `POST` handler: parse the first file part, store it under `dir` and answer
/// `{"name","size"}` with the stored name the client references afterwards.
pub fn upload_response(request: &Request, dir: &Path) -> Response {
    let part = match first_file_part(request) {
        Ok(Some(part)) => part,
        Ok(None) => return Response::error(400, "no_file"),
        Err(error) => return error.response(),
    };
    if part.data.len() > MAX_UPLOAD_BYTES {
        return Response::error(413, "upload_too_large");
    }
    let raw_name = part.filename.unwrap_or_default();
    let Some(name) = safe_name(&raw_name) else {
        return Response::error(400, "invalid_filename");
    };
    if let Err(error) = std::fs::create_dir_all(dir) {
        return Response::error(500, &format!("storage_error: {}", error));
    }
    let Some(stored) = unique_name(dir, &name) else {
        return Response::error(409, "name_conflict");
    };
    let path = dir.join(&stored);
    if let Err(error) = std::fs::write(&path, &part.data) {
        return Response::error(500, &format!("storage_error: {}", error));
    }
    let mut payload = crate::serde_json::Map::new();
    payload.insert("name".to_string(), crate::serde_json::Value::String(stored));
    payload.insert(
        "size".to_string(),
        crate::serde_json::Value::from(part.data.len()),
    );
    Response::json_text(201, &crate::serde_json::Value::Object(payload).to_string())
}

/// `GET` handler: serve a stored upload. An unknown or unsafe name is a 404,
/// never an error that leaks the filesystem layout.
pub fn download_response(dir: &Path, name: &str) -> Response {
    let Some(safe) = safe_name(name) else {
        return Response::error(404, "not_found");
    };
    match std::fs::read(dir.join(&safe)) {
        Ok(bytes) => {
            let mut response = Response::new(200);
            response.set_header("Content-Type", content_type(&safe));
            response.body = bytes;
            response
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Response::error(404, "not_found")
        }
        Err(error) => Response::error(500, &format!("storage_error: {}", error)),
    }
}
