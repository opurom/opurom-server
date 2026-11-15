//! Multipart upload parsing: a well-formed file part, a text field, quote and
//! escape handling, boundary extraction and every rejection path.

use opurom_server::http::{Method, Request};
use opurom_server::multipart::{
    boundary_from_content_type, first_file_part, parse_multipart, MultipartError, MAX_MULTIPART_BODY,
};

const BOUNDARY: &str = "----opuromBoundary7MA4YWxkTrZu0gW";

fn body(bytes: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes {
        out.extend_from_slice(chunk);
    }
    out
}

fn request(content_type: &str, body: Vec<u8>) -> Request {
    Request {
        method: Method::Post,
        path: "/upload".to_string(),
        headers: vec![("Content-Type".to_string(), content_type.to_string())],
        body,
        ..Request::default()
    }
}

fn multipart_body() -> Vec<u8> {
    body(&[
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Disposition: form-data; name=\"title\"\r\n\r\n",
        b"Sunset\r\n",
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Disposition: form-data; name=\"image\"; filename=\"sunset.png\"\r\n",
        b"Content-Type: image/png\r\n\r\n",
        b"\x89PNG\r\n\x1a\nbinary-payload\r\n",
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ])
}

#[test]
fn extracts_boundary_from_content_type() {
    assert_eq!(
        boundary_from_content_type(&format!("multipart/form-data; boundary={BOUNDARY}")),
        Some(BOUNDARY.to_string())
    );
    assert_eq!(
        boundary_from_content_type(&format!("multipart/form-data; boundary=\"{BOUNDARY}\"")),
        Some(BOUNDARY.to_string())
    );
    assert_eq!(boundary_from_content_type("application/json"), None);
    assert_eq!(boundary_from_content_type("multipart/form-data"), None);
}

#[test]
fn parses_a_text_field_and_a_file_part() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let parts = parse_multipart(&content_type, &multipart_body()).unwrap();
    assert_eq!(parts.len(), 2, "both parts decode");

    let title = &parts[0];
    assert_eq!(title.name, "title");
    assert_eq!(title.filename, None);
    assert_eq!(title.data, b"Sunset");
    assert!(!title.is_file());

    let image = &parts[1];
    assert_eq!(image.name, "image");
    assert_eq!(image.filename.as_deref(), Some("sunset.png"));
    assert_eq!(image.content_type.as_deref(), Some("image/png"));
    assert!(image.is_file());
    assert_eq!(image.data, b"\x89PNG\r\n\x1a\nbinary-payload");
}

#[test]
fn first_file_part_selects_the_upload_and_skips_fields() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let request = request(&content_type, multipart_body());
    let file = first_file_part(&request).unwrap().expect("a file part exists");
    assert_eq!(file.name, "image");
    assert_eq!(file.filename.as_deref(), Some("sunset.png"));
}

#[test]
fn first_file_part_returns_none_when_only_fields() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let only_field = body(&[
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Disposition: form-data; name=\"note\"\r\n\r\n",
        b"hello\r\n",
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ]);
    let request = request(&content_type, only_field);
    assert!(first_file_part(&request).unwrap().is_none());
}

#[test]
fn quoted_field_name_with_escaped_quote_decodes() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let raw = body(&[
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Disposition: form-data; name=\"we\\\"ird\"; filename=\"a.txt\"\r\n\r\n",
        b"x\r\n",
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ]);
    let parts = parse_multipart(&content_type, &raw).unwrap();
    assert_eq!(parts[0].name, "we\"ird");
    assert_eq!(parts[0].filename.as_deref(), Some("a.txt"));
}

#[test]
fn empty_file_value_is_accepted() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let raw = body(&[
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Disposition: form-data; name=\"empty\"; filename=\"e.bin\"\r\n\r\n",
        b"\r\n",
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ]);
    let parts = parse_multipart(&content_type, &raw).unwrap();
    assert_eq!(parts.len(), 1);
    assert!(parts[0].data.is_empty());
    assert!(parts[0].is_file());
}

#[test]
fn missing_boundary_is_rejected() {
    let error = parse_multipart("application/json", b"{}").unwrap_err();
    assert!(error.0.contains("boundary"));
    assert_eq!(error.response().status, 400);
}

#[test]
fn missing_content_disposition_is_rejected() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let raw = body(&[
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Type: text/plain\r\n\r\n",
        b"x\r\n",
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ]);
    let error = parse_multipart(&content_type, &raw).unwrap_err();
    assert!(error.0.contains("Content-Disposition"));
}

#[test]
fn unterminated_body_is_rejected() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    // Opening delimiter but no closing delimiter anywhere.
    let raw = body(&[
        format!("--{BOUNDARY}\r\n").as_bytes(),
        b"Content-Disposition: form-data; name=\"a\"\r\n\r\n",
        b"value-without-close",
    ]);
    let error = parse_multipart(&content_type, &raw).unwrap_err();
    assert!(matches!(error, MultipartError(_)));
}

#[test]
fn oversized_body_is_rejected_before_parsing() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let big = vec![0u8; MAX_MULTIPART_BODY + 1];
    let error = parse_multipart(&content_type, &big).unwrap_err();
    assert!(error.0.contains("exceeds"));
}
