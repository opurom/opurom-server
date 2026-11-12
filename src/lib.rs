//! OPUROM R2/R4/R5/R7 backend runtime.
//!
//! The library uses `serde_json` for IR and JSON responses and `flate2` for
//! opt-in gzip. It provides:
//!
//! * [`http`] - HTTP/1.1 request/response types and a bounded parser.
//! * [`router`] - literal and `:param` routing with per-route fault isolation.
//! * [`middleware`] - middleware, rate limiting, logs and opt-in R5 features.
//! * [`server`] - a thread-per-connection `TcpListener` server with optional
//!   TLS and HTTP/1.1 keep-alive.
//! * [`tls`] - the optional TLS listener with a self-signed fallback.
//! * [`websocket`] - the RFC 6455 frame codec, server channel and client.
//! * [`ssr`] - deterministic server-side HTML rendering of the same IR tree.
//! * [`ir`] - the full-stack IR v0.1 data model.
//! * [`codegen`] - the `opurom-serverc` lowering pass.

pub mod codegen;
pub mod http;
pub mod ir;
pub mod middleware;
pub mod router;
pub mod server;
pub mod ssr;
pub mod tls;
pub mod websocket;

pub use codegen::lower_service;
pub use http::{Method, Request, Response, MAX_BODY_BYTES};
pub use middleware::{
    constant_time_eq, cors_origin_from_env_value, etag_for, rate_limit, rate_limit_from_env,
    rate_limited_response, request_log_line, structured_logging_enabled, HttpOptions,
    MiddlewareChain, RateLimiter, AUTH_TOKEN_ENV, CORS_ENV, ETAG_ENV, GZIP_THRESHOLD_BYTES,
    RATE_LIMIT_ENV, RATE_LIMIT_WINDOW_SECS, STRUCTURED_LOG_ENV,
};
pub use router::Router;
pub use server::{
    Server, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS, KEEP_ALIVE_ENV, TLS_ENV, WEBSOCKET_ENV,
};
pub use ssr::ssr_html;
pub use tls::{TlsConfig, TLS_CERT_ENV, TLS_KEY_ENV};
pub use websocket::{WsChannel, WsMessage};

/// Re-export of the JSON crate used by this library, so generated services do
/// not need their own crates.io dependency.
pub use serde_json;
