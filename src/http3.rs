//! Real HTTP/3 over QUIC on a separate UDP listener.
//!
//! The HTTP/1.1 and HTTP/2 paths keep their own transports, but they share
//! the router, the middleware chain, the rate limiter, the response features
//! and the handler fault isolation with HTTP/3: every protocol converts its
//! request into the same [`crate::http::Request`] and calls the same
//! [`crate::server::dispatch_request`]. The same route therefore returns the
//! same JSON body on HTTP/1.1, HTTP/2 and HTTP/3.
//!
//! QUIC carries TLS 1.3 with the ALPN protocol `h3`. The certificate comes
//! from the same [`crate::tls::TlsConfig`] the HTTPS listener uses, so one
//! deployment serves one certificate over TLS 1.3 and QUIC.
//!
//! The listener is opt-in: `OPR_HTTP3=1` starts it and `OPR_HTTP3_PORT`
//! chooses its UDP port. Without those variables no UDP socket is opened.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::server::RequestResolver;

use crate::http::{normalize_path, Method, Request as AppRequest, Response as AppResponse};
use crate::middleware::{
    request_id_of, structured_logging_enabled, tls_access_log_line, HttpOptions, MiddlewareChain,
    RateLimiter,
};
use crate::router::Router;
use crate::server::dispatch_request;
use crate::tls::TlsConfig;

/// Environment variable that enables the HTTP/3 listener.
pub const HTTP3_ENV: &str = "OPR_HTTP3";

/// Environment variable holding the UDP port of the HTTP/3 listener.
pub const HTTP3_PORT_ENV: &str = "OPR_HTTP3_PORT";

/// The ALPN protocol identifier of HTTP/3.
pub const HTTP3_ALPN: &[u8] = b"h3";

/// The default UDP port of the HTTP/3 listener.
pub const DEFAULT_HTTP3_PORT: u16 = 4433;

/// How often the accept loop checks the shutdown handle.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// True when `OPR_HTTP3` is set to a truthy value.
pub fn enabled() -> bool {
    std::env::var(HTTP3_ENV).is_ok_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// The UDP port of the HTTP/3 listener, from `OPR_HTTP3_PORT`.
///
/// An invalid value falls back to [`DEFAULT_HTTP3_PORT`].
pub fn port_from_env() -> u16 {
    std::env::var(HTTP3_PORT_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_HTTP3_PORT)
}

/// The shared state every HTTP/3 request needs.
///
/// The router and the middleware chain are the same shared instances the
/// HTTP/1.1 and HTTP/2 listeners use.
#[derive(Clone)]
pub struct State {
    pub router: Arc<Router>,
    pub middleware: Arc<MiddlewareChain>,
    pub limiter: Option<Arc<RateLimiter>>,
    pub options: Arc<HttpOptions>,
    pub max_body: usize,
}

/// A bound QUIC endpoint with the HTTP/3 TLS configuration.
///
/// The endpoint is bound before the shared state exists, so the real UDP port
/// is known before the responses advertise it.
pub struct Http3Endpoint {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    fingerprint: String,
    /// The runtime that owns the UDP socket. The socket is registered with
    /// this runtime, so the same runtime serves the endpoint later.
    runtime: Arc<tokio::runtime::Runtime>,
}

impl Http3Endpoint {
    /// Bind a QUIC endpoint on `addr` with TLS 1.3 and ALPN `h3`.
    ///
    /// The certificate and the private key come from `tls`; the ALPN protocol
    /// list is replaced with `h3`, because a QUIC connection only carries
    /// HTTP/3.
    pub fn bind(addr: &str, tls: &TlsConfig) -> Result<Http3Endpoint, String> {
        let address: SocketAddr = addr
            .parse()
            .map_err(|err| format!("cannot parse the HTTP/3 address {}: {}", addr, err))?;
        let crypto = tls
            .quic_server_config(HTTP3_ALPN)
            .map_err(|err| err.to_string())?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("cannot start the HTTP/3 runtime: {}", err))?;
        // The QUIC socket is registered with the runtime that serves it.
        let endpoint = {
            let _guard = runtime.enter();
            quinn::Endpoint::server(server_config, address)
                .map_err(|err| format!("cannot bind the HTTP/3 endpoint on {}: {}", address, err))?
        };
        let local_addr = endpoint
            .local_addr()
            .map_err(|err| format!("cannot read the HTTP/3 local address: {}", err))?;
        Ok(Http3Endpoint {
            endpoint,
            local_addr,
            fingerprint: tls.fingerprint().to_string(),
            runtime: Arc::new(runtime),
        })
    }

    /// The bound UDP address, useful when binding to port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The SHA-256 fingerprint of the certificate this endpoint serves.
    pub fn certificate_fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// A running HTTP/3 listener.
pub struct Http3Server {
    endpoint: Http3Endpoint,
    state: State,
    shutdown: Arc<AtomicBool>,
}

impl Http3Server {
    /// Start serving HTTP/3 on a bound endpoint.
    pub fn new(endpoint: Http3Endpoint, state: State) -> Http3Server {
        Http3Server {
            endpoint,
            state,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The bound UDP address, useful when binding to port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    /// The SHA-256 fingerprint of the certificate this listener serves.
    pub fn certificate_fingerprint(&self) -> &str {
        self.endpoint.certificate_fingerprint()
    }

    /// A handle that stops the accept loop after the next accepted connection.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Serve until the shutdown handle is set.
    pub fn serve(&self) {
        // The endpoint runs on the runtime that owns its UDP socket.
        let runtime = Arc::clone(&self.endpoint.runtime);
        runtime.block_on(self.accept_loop());
    }

    /// Serve in a background thread and return the bound address.
    pub fn spawn(self) -> std::io::Result<(SocketAddr, Arc<AtomicBool>)> {
        let addr = self.local_addr();
        let shutdown = self.shutdown_handle();
        std::thread::spawn(move || {
            self.serve();
        });
        Ok((addr, shutdown))
    }

    async fn accept_loop(&self) {
        while !self.shutdown.load(Ordering::Relaxed) {
            let incoming = match self.endpoint.endpoint.accept().await {
                Some(incoming) => incoming,
                None => break,
            };
            let state = self.state.clone();
            let shutdown = Arc::clone(&self.shutdown);
            tokio::spawn(async move {
                serve_connection(incoming, state, shutdown).await;
            });
        }
        self.endpoint.endpoint.close(0u32.into(), b"shutdown");
    }
}

/// Serve one QUIC connection until the peer closes it.
async fn serve_connection(incoming: quinn::Incoming, state: State, shutdown: Arc<AtomicBool>) {
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(err) => {
            eprintln!("[opurom-server] HTTP/3 handshake failed: {}", err);
            return;
        }
    };
    let mut h3_connection =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("[opurom-server] HTTP/3 connection failed: {}", err);
                return;
            }
        };
    loop {
        let resolver = tokio::select! {
            resolver = h3_connection.accept() => resolver,
            _ = wait_for_shutdown(Arc::clone(&shutdown)) => break,
        };
        match resolver {
            Ok(Some(resolver)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    serve_request(resolver, state).await;
                });
            }
            Ok(None) => break,
            Err(err) => {
                eprintln!("[opurom-server] HTTP/3 connection failed: {}", err);
                break;
            }
        }
    }
}

/// Resolve when the shutdown handle is set.
async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(SHUTDOWN_POLL_INTERVAL).await;
    }
}

/// Serve one HTTP/3 request through the shared request pipeline.
async fn serve_request(resolver: RequestResolver<h3_quinn::Connection, Bytes>, state: State) {
    let started = Instant::now();
    let (request, mut stream) = match resolver.resolve_request().await {
        Ok(parts) => parts,
        Err(err) => {
            eprintln!("[opurom-server] HTTP/3 request failed: {}", err);
            return;
        }
    };
    let mut app_request = app_request(&request);
    let method = app_request.method.as_str().to_string();
    let path = app_request.path.clone();
    let head_only = app_request.method == Method::Head;

    let body = match read_body(&mut stream, state.max_body).await {
        Ok(body) => body,
        Err(response) => {
            send_response(&mut stream, &response, false).await;
            return;
        }
    };
    app_request.body = body;

    let response = dispatch_request(
        &mut app_request,
        state.router.as_ref(),
        state.middleware.as_ref(),
        state.limiter.as_deref(),
        state.options.as_ref(),
    );
    // The request-id layer ran inside dispatch and mirrored the id here.
    let request_id = request_id_of(&app_request).map(str::to_string);
    send_response(&mut stream, &response, head_only).await;

    if structured_logging_enabled() {
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        eprintln!(
            "{}",
            tls_access_log_line(
                &method,
                &path,
                response.status,
                duration_ms,
                request_id.as_deref(),
                "h3"
            )
        );
    }
}

/// Convert an HTTP/3 request into the shared request type.
fn app_request(request: &http::Request<()>) -> AppRequest {
    let headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    AppRequest {
        method: Method::parse(request.method().as_str()),
        path: normalize_path(request.uri().path()),
        query: request.uri().query().unwrap_or_default().to_string(),
        headers,
        body: Vec::new(),
        params: BTreeMap::new(),
        version: "HTTP/3.0".to_string(),
    }
}

/// Read the request body, rejecting a body larger than `max_body`.
async fn read_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    max_body: usize,
) -> Result<Vec<u8>, AppResponse> {
    let mut bytes = Vec::new();
    let mut too_large = false;
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|_| AppResponse::error(400, "bad_request"))?
    {
        let size = chunk.remaining();
        if !too_large {
            if bytes.len().saturating_add(size) <= max_body {
                bytes.extend_from_slice(&chunk.copy_to_bytes(size));
            } else {
                bytes.clear();
                too_large = true;
            }
        }
    }
    if too_large {
        Err(AppResponse::error(413, "payload_too_large"))
    } else {
        Ok(bytes)
    }
}

/// Send one response over the HTTP/3 stream.
async fn send_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    response: &AppResponse,
    head_only: bool,
) {
    let status = http::StatusCode::from_u16(response.status)
        .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = http::Response::builder().status(status);
    for (name, value) in &response.headers {
        // HTTP/3 forbids the connection-specific fields of HTTP/1.1.
        if crate::http::is_connection_specific(name) {
            continue;
        }
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        builder = builder.header(name, value);
    }
    let Ok(head) = builder.body(()) else {
        return;
    };
    if stream.send_response(head).await.is_err() {
        return;
    }
    // A HEAD answer ends at the headers, sending no DATA frame.
    if !head_only && !response.body.is_empty() {
        let _ = stream.send_data(Bytes::from(response.body.clone())).await;
    }
    let _ = stream.finish().await;
}
