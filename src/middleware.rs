//! Ordered middleware chain, request logging and fixed-window rate limiting.
//!
//! A middleware is a boxed closure applied to every request before routing.
//! Returning `Some(response)` short-circuits the request (for example the
//! body-size cap); returning `None` lets the router handle it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::http::{Request, Response, MAX_BODY_BYTES};

/// Environment variable that enables structured JSON request logs.
pub const STRUCTURED_LOG_ENV: &str = "OPR_LOG_JSON";

/// Environment variable holding the per-route request limit per window.
pub const RATE_LIMIT_ENV: &str = "OPR_RATE_LIMIT";

/// Length of one deterministic rate-limit window, in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// One middleware layer.
pub type Middleware = Box<dyn Fn(&mut Request) -> Option<Response> + Send + Sync>;

/// An ordered list of middleware layers.
#[derive(Default)]
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

/// True when `OPR_LOG_JSON` is set to a truthy value.
pub fn structured_logging_enabled() -> bool {
    std::env::var(STRUCTURED_LOG_ENV)
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
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

/// Plain request-logging layer: prints `METHOD PATH` for every request to
/// stderr. When structured logging is enabled the server writes one JSON line
/// instead, so this layer stays silent to avoid a second log line.
pub fn logging() -> Middleware {
    Box::new(|request: &mut Request| {
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
    Box::new(move |request: &mut Request| {
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

/// In-process per-route fixed-window counter.
///
/// The counter is keyed by method plus the normalized request path and resets
/// after [`RATE_LIMIT_WINDOW_SECS`]. It is deterministic for a given `Instant`
/// and is shared through a Mutex across server threads.
// shortcut: keys use the received path, not the router pattern, and counters
// are process-local; R5+ needs matched-pattern keys and a distributed store.
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
    Box::new(move |request: &mut Request| limiter.check(request).map(rate_limited_response))
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
