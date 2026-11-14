//! Ordered middleware chain, request logging, rate limiting and HTTP options.
//!
//! A middleware is a boxed closure applied to every request before routing.
//! Returning `Some(response)` short-circuits the request (for example the
//! body-size cap); returning `None` lets the router handle it. Auth, CORS,
//! ETag and gzip are opt-in and are applied by `Server` around routing.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha256};

use crate::http::{Method, Request, Response, MAX_BODY_BYTES};

/// The one route that answers without a bearer token so a health probe works
/// unauthenticated.
pub const HEALTH_PATH: &str = "/health";

/// Environment variable that enables structured JSON request logs.
pub const STRUCTURED_LOG_ENV: &str = "OPR_LOG_JSON";

/// Environment variable holding the per-route request limit per window.
pub const RATE_LIMIT_ENV: &str = "OPR_RATE_LIMIT";

/// Environment variable holding the optional development bearer token.
pub const AUTH_TOKEN_ENV: &str = "OPR_AUTH_TOKEN";

/// Environment variable holding one fixed CORS origin (or the literal `*`).
pub const CORS_ENV: &str = "OPR_CORS";

/// Environment variable that enables ETags by itself.
pub const ETAG_ENV: &str = "OPR_ETAG";

/// Environment variable holding the advertised HTTP/3 UDP port.
pub const ALT_SVC_ENV: &str = "OPR_ALT_SVC_PORT";

/// Environment variable holding the `Cache-Control` value added to successful
/// responses (2xx and 304). Unset leaves responses header-identical to the
/// plain default, so caching stays opt-in.
pub const CACHE_CONTROL_ENV: &str = "OPR_CACHE_CONTROL";

/// Length of one deterministic rate-limit window, in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Response bodies larger than this many bytes may be gzip-compressed.
pub const GZIP_THRESHOLD_BYTES: usize = 1024;

/// One middleware layer.
///
/// The layer is shared through an [`Arc`], so the same chain can serve the
/// HTTP/1.1, HTTP/2 and HTTP/3 listeners.
pub type Middleware = Arc<dyn Fn(&mut Request) -> Option<Response> + Send + Sync>;

/// An ordered list of middleware layers.
#[derive(Default, Clone)]
pub struct MiddlewareChain {
    layers: Vec<Middleware>,
}

impl MiddlewareChain {
    pub fn new() -> MiddlewareChain {
        MiddlewareChain { layers: Vec::new() }
    }

    /// Append a layer. Layers run in insertion order.
    pub fn push(&mut self, layer: Middleware) -> &mut MiddlewareChain {
        self.layers.push(layer);
        self
    }
    /// Number of registered layers.
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Apply every layer in order. The first layer that returns a response
    /// wins and the remaining layers are skipped.
    pub fn apply(&self, request: &mut Request) -> Option<Response> {
        for layer in &self.layers {
            if let Some(response) = layer(request) {
                return Some(response);
            }
        }
        None
    }
}

fn truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// True when an environment flag is set to a truthy value.
fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|raw| truthy(&raw))
}

/// True when a structured access log is written.
pub fn structured_logging_enabled() -> bool {
    env_flag(STRUCTURED_LOG_ENV)
}

/// One JSON object for a completed request. `elapsed_ms` is measured by the
/// caller with `Instant`; no synthetic timing values are produced here.
pub fn request_log_line(method: &str, path: &str, status: u16, elapsed_ms: u64) -> String {
    serde_json::json!({
        "method": method,
        "path": path,
        "status": status,
        "elapsed_ms": elapsed_ms,
    })
    .to_string()
}

/// One JSON access-log object with the extra `duration_ms` and `request_id`
/// fields. The fields are emitted in a fixed order-proving shape:
/// `method, path, status, duration_ms, request_id`. `request_id` is `"-"` when
/// no id was assigned, matching the `-` placeholder of the parse-error path.
pub fn access_log_line(
    method: &str,
    path: &str,
    status: u16,
    duration_ms: u64,
    request_id: Option<&str>,
) -> String {
    serde_json::json!({
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": duration_ms,
        "request_id": request_id.unwrap_or("-"),
    })
    .to_string()
}

/// One JSON access-log object for a TLS/HTTP2/HTTP3 request: the same fixed
/// field order plus the ALPN `alpn` value reported by rustls, not inferred.
pub fn tls_access_log_line(
    method: &str,
    path: &str,
    status: u16,
    duration_ms: u64,
    request_id: Option<&str>,
    alpn: &str,
) -> String {
    serde_json::json!({
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": duration_ms,
        "request_id": request_id.unwrap_or("-"),
        "alpn": alpn,
    })
    .to_string()
}

/// One JSON object for a completed TLS request whose peer negotiated ALPN.
/// The `alpn` value is reported by rustls, not inferred from the HTTP request.
pub fn tls_request_log_line(
    method: &str,
    path: &str,
    status: u16,
    elapsed_ms: u64,
    alpn: &str,
) -> String {
    serde_json::json!({
        "method": method,
        "path": path,
        "status": status,
        "elapsed_ms": elapsed_ms,
        "alpn": alpn,
    })
    .to_string()
}

/// Plain request-logging layer: prints `METHOD PATH` for every request to
/// stderr. When structured logging is enabled the server writes one JSON line
/// instead, so this layer stays silent to avoid a second log line.
pub fn logging() -> Middleware {
    Arc::new(|request: &mut Request| {
        if !structured_logging_enabled() {
            eprintln!(
                "[opurom-server] -> {} {}",
                request.method.as_str(),
                request.path
            );
        }
        None
    })
}

/// Body-size cap layer: rejects a parsed body larger than `limit` with 413.
pub fn body_cap(limit: usize) -> Middleware {
    Arc::new(move |request: &mut Request| {
        if request.body.len() > limit {
            return Some(Response::error(413, "payload_too_large"));
        }
        None
    })
}

/// Body-size cap layer with the default 1 MiB limit.
pub fn default_body_cap() -> Middleware {
    body_cap(MAX_BODY_BYTES)
}

/// Validate an inbound request-id so it can be journaled and echoed without
/// header injection risks: 1 to 64 visible ASCII bytes, no spaces or control
/// characters. Anything else is treated as absent.
pub fn valid_request_id(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    (!raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\')))
    .then_some(raw)
}

/// Assign every request an `X-Request-Id`: reuse a valid inbound value so a
/// caller can correlate its own trace, otherwise mint one from a process-local
/// counter. The assigned value is mirrored onto the request headers, where the
/// access log and the response code read it back. This is layer 0 of the
/// chain; it never short-circuits.
pub fn request_id() -> Middleware {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    Arc::new(|request: &mut Request| {
        // Keep a valid inbound id; replace (never append) a missing or hostile
        // one so the header has exactly one trustworthy value for the log.
        let valid = request
            .header("X-Request-Id")
            .and_then(valid_request_id)
            .map(str::to_string);
        let assigned = valid.unwrap_or_else(|| {
            let next = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("req-{next:016x}")
        });
        request
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("X-Request-Id"));
        request.headers.push(("X-Request-Id".to_string(), assigned));
        None
    })
}

/// Read the request-id assigned by the [`request_id`] layer, if any.
pub fn request_id_of(request: &Request) -> Option<&str> {
    request.header("X-Request-Id").and_then(valid_request_id)
}

/// In-process per-route fixed-window counter.
///
/// The counter is keyed by method plus the normalized request path and resets
/// after [`RATE_LIMIT_WINDOW_SECS`]. It is deterministic for a given `Instant`
/// and is shared through a Mutex across server threads.
// shortcut: keys use the received path, not the router pattern, and counters
// are process-local; a distributed store needs matched-pattern keys.
pub struct RateLimiter {
    limit: u64,
    start: Instant,
    counters: Mutex<BTreeMap<String, (u64, u64)>>,
}

impl RateLimiter {
    pub fn new(limit: u64) -> RateLimiter {
        RateLimiter {
            limit,
            start: Instant::now(),
            counters: Mutex::new(BTreeMap::new()),
        }
    }

    /// Read the positive integer limit from `OPR_RATE_LIMIT`. Invalid or
    /// non-positive values disable rate limiting instead of changing defaults.
    pub fn from_env() -> Option<RateLimiter> {
        std::env::var(RATE_LIMIT_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|limit| *limit > 0)
            .map(RateLimiter::new)
    }

    /// Check one request at the current time. `Some(retry_after)` means 429.
    pub fn check(&self, request: &Request) -> Option<u64> {
        self.check_at(request, Instant::now())
    }

    /// Check one request at an explicit `Instant`, used by deterministic tests.
    pub fn check_at(&self, request: &Request, now: Instant) -> Option<u64> {
        let elapsed = now.saturating_duration_since(self.start).as_secs();
        let window = elapsed / RATE_LIMIT_WINDOW_SECS;
        let retry_after = RATE_LIMIT_WINDOW_SECS - elapsed % RATE_LIMIT_WINDOW_SECS;
        let key = format!("{} {}", request.method.as_str(), request.path);
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = counters.entry(key).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.limit {
            Some(retry_after)
        } else {
            entry.1 += 1;
            None
        }
    }
}

/// Canonical 429 response with seconds remaining in the current window.
pub fn rate_limited_response(retry_after: u64) -> Response {
    Response::error(429, "rate_limited").with_header("Retry-After", &retry_after.to_string())
}

fn rate_limit_with(limiter: Arc<RateLimiter>) -> Middleware {
    Arc::new(move |request: &mut Request| limiter.check(request).map(rate_limited_response))
}

/// Build a middleware layer allowing at most `limit` requests per route per
/// window. The `Server` also installs the environment-derived limiter, so
/// callers normally do not need this function.
pub fn rate_limit(limit: u64) -> Middleware {
    rate_limit_with(Arc::new(RateLimiter::new(limit)))
}

/// Build the middleware layer described by `OPR_RATE_LIMIT`, when set.
pub fn rate_limit_from_env() -> Option<Middleware> {
    RateLimiter::from_env().map(|limiter| rate_limit_with(Arc::new(limiter)))
}

/// HTTP options captured once when a `Server` binds.
#[derive(Clone, Debug, Default)]
pub struct HttpOptions {
    /// The env-independent bearer-token gate.
    pub auth: AuthOptions,
    pub cors_origin: Option<String>,
    pub etag: bool,
    /// The `Cache-Control` value added to successful (2xx/304) responses.
    ///
    /// `None` unless an operator sets [`CACHE_CONTROL_ENV`], so the default
    /// response headers stay unchanged.
    pub cache_control: Option<String>,
    /// The UDP port of the HTTP/3 endpoint, advertised with `Alt-Svc`.
    ///
    /// The value is `None` unless an operator sets [`ALT_SVC_ENV`], so the
    /// default response headers stay unchanged.
    pub alt_svc_port: Option<u16>,
    /// True when the listener terminates TLS.
    ///
    /// An alternative service is advertised only on a TLS listener, because
    /// the client must reach the advertised endpoint over the same origin.
    pub tls: bool,
}

impl HttpOptions {
    /// Read the HTTP options from the environment. Any opt-in variable enables
    /// ETags; `OPR_ETAG` can also enable or explicitly disable them alone.
    pub fn from_env() -> HttpOptions {
        let auth = AuthOptions::from_env();
        let cors_origin = std::env::var(CORS_ENV)
            .ok()
            .and_then(|raw| cors_origin_from_env_value(&raw));
        let etag = match std::env::var(ETAG_ENV) {
            Ok(raw) => truthy(&raw),
            Err(_) => auth.is_enabled() || cors_origin.is_some(),
        };
        HttpOptions {
            auth,
            cors_origin,
            etag,
            cache_control: cache_control_from_env(),
            alt_svc_port: alt_svc_port_from_env(),
            tls: crate::tls::tls_enabled(),
        }
    }
}

/// Read the `Cache-Control` value from [`CACHE_CONTROL_ENV`]. An empty value
/// disables the header instead of adding an empty one.
pub fn cache_control_from_env() -> Option<String> {
    std::env::var(CACHE_CONTROL_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

/// Read the advertised HTTP/3 UDP port from [`ALT_SVC_ENV`].
///
/// An invalid or out-of-range value disables the advertisement instead of
/// changing the default response headers.
pub fn alt_svc_port_from_env() -> Option<u16> {
    std::env::var(ALT_SVC_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .and_then(|raw| raw.parse().ok())
}

/// Compare two byte strings in time that depends only on their lengths.
///
/// Both inputs are compressed to fixed-width SHA-256 digests and the digests
/// are XOR-accumulated without an early exit, so the comparison never leaks how
/// many leading bytes match. The lengths are folded into the verdict before the
/// digest comparison, which keeps unequal-length tokens rejected.
pub fn constant_time_eq(expected: &[u8], provided: &[u8]) -> bool {
    let length_mismatch = usize::from(expected.len() ^ provided.len());
    let left = Sha256::digest(expected);
    let right = Sha256::digest(provided);
    let mut difference = length_mismatch;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

/// Options for the bearer-token gate, supplied by the caller instead of the
/// process environment so one binary can host several differently configured
/// servers.
#[derive(Clone, Debug, Default)]
pub struct AuthOptions {
    /// The required bearer token; `None` leaves authentication disabled.
    pub token: Option<String>,
    /// Allow unauthenticated requests to [`HEALTH_PATH`] so health probes and
    /// load balancers can reach the service without a credential.
    pub allow_health: bool,
}

impl AuthOptions {
    /// Require `token` on every non-health route.
    pub fn new(token: &str) -> AuthOptions {
        AuthOptions {
            token: Some(token.to_string()),
            allow_health: true,
        }
    }

    /// Build the options from `OPR_AUTH_TOKEN`, enabling authentication only
    /// when the variable holds a non-empty value.
    pub fn from_env() -> AuthOptions {
        AuthOptions {
            token: std::env::var(AUTH_TOKEN_ENV)
                .ok()
                .filter(|token| !token.is_empty()),
            allow_health: true,
        }
    }

    /// True when authentication is configured.
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// True when the request may skip the token check: authentication is
    /// disabled, or the request targets the open health route.
    pub fn exempt(&self, request: &Request) -> bool {
        !self.is_enabled()
            || (self.allow_health && request.method == Method::Get && request.path == HEALTH_PATH)
    }

    /// True when the request carries a matching `Authorization: Bearer` value.
    pub fn authorized(&self, request: &Request) -> bool {
        let Some(token) = self.token.as_deref() else {
            return true;
        };
        request
            .header("Authorization")
            .and_then(|raw| raw.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .is_some_and(|(_, candidate)| constant_time_eq(candidate.as_bytes(), token.as_bytes()))
    }
}

/// Check the development bearer token. This is not a production identity
/// system: there are no users, scopes, expiry, hashing or credential storage.
pub fn authorized(request: &Request, token: &str) -> bool {
    AuthOptions::new(token).authorized(request)
}

/// Canonical 401 response for a missing or mismatched bearer token.
pub fn unauthorized_response() -> Response {
    Response::error(401, "unauthorized")
}

/// Validate one operator-configured CORS origin. The value is emitted verbatim;
/// the request's `Origin` header is never used to build a response header.
pub fn cors_origin_from_env_value(raw: &str) -> Option<String> {
    let origin = raw.trim().to_ascii_lowercase();
    if origin == "*" {
        return Some(origin);
    }
    let host = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    if host.is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'[' | b']')
        })
    {
        return None;
    }
    Some(origin)
}

/// A fixed-allow-list CORS preflight response. Preflight bypasses auth but is
/// still rate limited and logged by `Server`.
pub fn cors_preflight(request: &Request, origin: Option<&str>) -> Option<Response> {
    let origin = origin?;
    if request.method.as_str() != "OPTIONS" {
        return None;
    }
    Some(
        Response::new(204)
            .with_header("Access-Control-Allow-Origin", origin)
            .with_header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS",
            )
            .with_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type",
            )
            .with_header("Vary", "Origin"),
    )
}

fn has_header(response: &Response, name: &str) -> bool {
    response
        .headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

fn add_vary(response: &mut Response, value: &str) {
    if let Some((_, current)) = response
        .headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("Vary"))
    {
        if !current
            .split(',')
            .any(|field| field.trim().eq_ignore_ascii_case(value))
        {
            current.push_str(", ");
            current.push_str(value);
        }
    } else {
        response.set_header("Vary", value);
    }
}

/// Deterministic, non-cryptographic FNV-1a validator for an uncompressed body.
pub fn etag_for(body: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in body {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("\"{hash:016x}\"")
}

/// Weak/list comparison for `If-None-Match` on GET requests.
pub fn if_none_match_matches(raw: &str, etag: &str) -> bool {
    raw.split(',').any(|entry| {
        let candidate = entry.trim();
        let strong = candidate
            .strip_prefix("W/")
            .or_else(|| candidate.strip_prefix("w/"))
            .unwrap_or(candidate)
            .trim();
        candidate == "*" || strong == etag
    })
}

/// True when `Accept-Encoding` offers gzip with a nonzero quality.
pub fn accepts_gzip(request: &Request) -> bool {
    request.header("Accept-Encoding").is_some_and(|raw| {
        raw.split(',').any(|entry| {
            let mut fields = entry.trim().split(';');
            let coding = fields.next().unwrap_or_default().trim();
            if !coding.eq_ignore_ascii_case("gzip") {
                return false;
            }
            !fields.any(|parameter| {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    return false;
                };
                name.trim().eq_ignore_ascii_case("q") && value.trim().parse::<f32>() == Ok(0.0)
            })
        })
    })
}

/// Compress one response body into a complete gzip member.
pub fn gzip_body(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body)?;
    encoder.finish()
}

/// The `Alt-Svc` header value that advertises the HTTP/3 endpoint.
pub fn alt_svc_header_value(port: u16) -> String {
    format!("h3=\":{}\"", port)
}

/// The ordered response stages that turn a routed [`Response`] into the wire
/// answer. Each stage is independently testable and runs in this fixed order:
///
/// 1. [`Alt-Svc`](stage_alt_svc) - advertise the HTTP/3 endpoint on TLS.
/// 2. [`CORS`](stage_cors) - fixed `Access-Control-Allow-Origin` plus `Vary`.
/// 3. [`Cache-Control`](stage_cache_control) - configurable caching header.
/// 4. [`ETag`](stage_etag) - body-hash validator and conditional `304`.
/// 5. [`gzip`](stage_compression) - compress an accepted, large body.
///
/// The order is observable because compression runs last: the `ETag` is the
/// hash of the *uncompressed* body, so it is identical with or without
/// `gzip`, and a `304` never carries a `Content-Encoding`.
pub const RESPONSE_STAGES: [&str; 5] = ["alt-svc", "cors", "cache-control", "etag", "gzip"];

/// Apply the opt-in HTTP response features to a completed response.
pub fn apply_response_features(response: &mut Response, request: &Request, options: &HttpOptions) {
    stage_alt_svc(response, options);
    stage_cors(response, options);
    stage_cache_control(response, options);
    stage_etag(response, request, options);
    stage_compression(response, request);
}

/// Stage 1: advertise the HTTP/3 endpoint with `Alt-Svc` on a TLS listener.
pub fn stage_alt_svc(response: &mut Response, options: &HttpOptions) {
    if options.tls {
        if let Some(port) = options.alt_svc_port {
            if !has_header(response, "Alt-Svc") {
                response.set_header("Alt-Svc", &alt_svc_header_value(port));
            }
        }
    }
}

/// Stage 2: fixed-origin CORS headers. The requested `Origin` is never used to
/// build a response header; `Vary: Origin` makes that explicit to caches.
pub fn stage_cors(response: &mut Response, options: &HttpOptions) {
    if let Some(origin) = options.cors_origin.as_deref() {
        if !has_header(response, "Access-Control-Allow-Origin") {
            response.set_header("Access-Control-Allow-Origin", origin);
        }
        add_vary(response, "Origin");
    }
}

/// Stage 3: add the configured `Cache-Control` value to a successful response
/// (2xx or 304) that does not already carry one.
pub fn stage_cache_control(response: &mut Response, options: &HttpOptions) {
    if let Some(value) = options.cache_control.as_deref() {
        let successful = (200..300).contains(&response.status) || response.status == 304;
        if successful && !has_header(response, "Cache-Control") {
            response.set_header("Cache-Control", value);
        }
    }
}

/// Stage 4: add an `ETag` from the body hash and answer a matching
/// `If-None-Match` with a bodyless `304`. Runs before compression so the hash
/// always describes the uncompressed bytes, and a malformed validator simply
/// fails to match (leaving a `200`), never a `500`.
pub fn stage_etag(response: &mut Response, request: &Request, options: &HttpOptions) {
    if !options.etag
        || !(200..300).contains(&response.status)
        || response.body.is_empty()
        || has_header(response, "ETag")
    {
        return;
    }
    let etag = etag_for(&response.body);
    response.set_header("ETag", &etag);
    if request.method == Method::Get
        && request
            .header("If-None-Match")
            .is_some_and(|raw| if_none_match_matches(raw, &etag))
    {
        // The representation the 304 stands in for would have been gzipped for
        // this client, so a shared cache must still vary on Accept-Encoding.
        let compresses = accepts_gzip(request) && response.body.len() > GZIP_THRESHOLD_BYTES;
        response.status = 304;
        response.body.clear();
        // A 304 keeps its validator, the cache-control value and any Vary
        // field, but drops representation headers such as Content-Type.
        response.headers.retain(|(name, _)| {
            name.eq_ignore_ascii_case("ETag")
                || name.eq_ignore_ascii_case("Vary")
                || name.eq_ignore_ascii_case("Cache-Control")
                || name
                    .get(.."Access-Control-".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Access-Control-"))
        });
        if compresses {
            add_vary(response, "Accept-Encoding");
        }
    }
}

/// Stage 5: gzip a body the client accepts when it exceeds the threshold.
/// `Vary: Accept-Encoding` records the negotiation so a shared cache does not
/// serve one encoding to the other kind of client.
pub fn stage_compression(response: &mut Response, request: &Request) {
    if accepts_gzip(request)
        && response.body.len() > GZIP_THRESHOLD_BYTES
        && !has_header(response, "Content-Encoding")
    {
        if let Ok(compressed) = gzip_body(&response.body) {
            response.body = compressed;
            response.set_header("Content-Encoding", "gzip");
            add_vary(response, "Accept-Encoding");
        }
    }
}
