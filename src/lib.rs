//! OPUROM R2/R4 backend runtime.
//!
//! The library is std-only apart from `serde_json`, which is used to parse IR
//! and to build JSON HTTP responses. It provides:
//!
//! * [`http`] - HTTP/1.1 request/response types and a bounded parser.
//! * [`router`] - literal and `:param` routing with per-route fault isolation.
//! * [`middleware`] - middleware, fixed-window rate limiting and request logs.
//! * [`server`] - a thread-per-connection `TcpListener` server.
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

pub use codegen::lower_service;
pub use http::{Method, Request, Response, MAX_BODY_BYTES};
pub use middleware::{
    rate_limit, rate_limit_from_env, rate_limited_response, request_log_line,
    structured_logging_enabled, MiddlewareChain, RateLimiter, RATE_LIMIT_ENV,
    RATE_LIMIT_WINDOW_SECS, STRUCTURED_LOG_ENV,
};
pub use router::Router;
pub use server::Server;
pub use ssr::ssr_html;

/// Re-export of the JSON crate used by this library, so generated services do
/// not need their own crates.io dependency.
pub use serde_json;
