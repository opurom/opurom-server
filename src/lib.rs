//! OPUROM backend runtime.
//!
//! The library uses `serde_json` for IR and JSON responses and `flate2` for
//! opt-in gzip. It provides:
//!
//! * [`http`] - HTTP/1.1 request/response types and a bounded parser.
//! * [`http2`] - real HTTP/2 frames over an ALPN-selected TLS connection.
//! * [`http3`] - real HTTP/3 over QUIC on a separate UDP listener.
//! * [`router`] - literal and `:param` routing with per-route fault isolation.
//! * [`middleware`] - an ordered request/response pipeline (request-id, access
//!   log, ETag/304, gzip, Cache-Control), rate limiting and opt-in features.
//! * [`query`] - strict list query parsing, stable ordering and the list envelope.
//! * [`server`] - a thread-per-connection `TcpListener` server with optional
//!   TLS, ALPN-selected HTTP/2 and HTTP/1.1 keep-alive.
//! * [`tls`] - the optional TLS listener with a self-signed fallback, opt-in
//!   client-certificate mTLS, a static fingerprint deny list, local DER
//!   CRL/OCSP status sources, an HTTP CRL distribution point and ALPN.
//! * [`cert_status`] - bounded DER CRL/BasicOCSPResponse parsing, std-only
//!   HTTP CRL retrieval with a URL-keyed cache and status checks.
//! * [`websocket`] - the RFC 6455 frame codec, server channel and client.
//! * [`ssr`] - deterministic server-side HTML rendering of the same IR tree.
//! * [`ir`] - the full-stack IR v0.1 data model.
//! * [`codegen`] - the `opurom-serverc` lowering pass.

pub mod cert_status;
pub mod codegen;
pub mod http;
pub mod http2;
pub mod http3;
pub mod ir;
pub mod middleware;
pub mod query;
pub mod router;
pub mod server;
pub mod ssr;
pub mod tls;
pub mod websocket;

pub use codegen::{default_dep_root, lower_service};
pub use http::{Method, Request, Response, MAX_BODY_BYTES};
pub use http2::{
    INITIAL_WINDOW_SIZE, MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE,
    MAX_SEND_BUFFER_SIZE,
};
pub use http3::{
    Http3Endpoint, Http3Server, State as Http3State, DEFAULT_HTTP3_PORT, HTTP3_ALPN, HTTP3_ENV,
    HTTP3_PORT_ENV,
};
pub use middleware::{
    access_log_line, alt_svc_header_value, alt_svc_port_from_env, cache_control_from_env,
    constant_time_eq, cors_origin_from_env_value, etag_for, rate_limit, rate_limit_from_env,
    rate_limited_response, request_id, request_id_of, request_log_line, stage_alt_svc,
    stage_cache_control, stage_compression, stage_cors, stage_etag, structured_logging_enabled,
    tls_access_log_line, tls_request_log_line, unauthorized_response, valid_request_id,
    AuthOptions, HttpOptions, MiddlewareChain, RateLimiter, ALT_SVC_ENV, AUTH_TOKEN_ENV,
    CACHE_CONTROL_ENV, CORS_ENV, ETAG_ENV, GZIP_THRESHOLD_BYTES, HEALTH_PATH, RATE_LIMIT_ENV,
    RATE_LIMIT_WINDOW_SECS, RESPONSE_STAGES, STRUCTURED_LOG_ENV,
};
pub use query::{ListQuery, QueryError, DEFAULT_LIMIT, MAX_LIMIT, MAX_OFFSET};
pub use router::{RegisteredRoute, Router};
pub use server::{
    Server, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS, KEEP_ALIVE_ENV, TLS_ENV, WEBSOCKET_ENV,
};
pub use ssr::ssr_html;
pub use tls::{TlsConfig, TLS_CERT_ENV, TLS_KEY_ENV};
pub use websocket::{WsChannel, WsMessage};

/// Re-export of the JSON crate used by this library, so generated services do
/// not need their own crates.io dependency.
pub use serde_json;
