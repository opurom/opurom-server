//! Thread-per-connection HTTP/1.1 server over `std::net::TcpListener`.
//!
//! The listener serves plain HTTP by default and every default response byte
//! stays identical to the plain-HTTP default. Three opt-in features change that:
//!
//! * `OPR_TLS=1` serves HTTPS on the same bind address.
//! * `OPR_KEEPALIVE=1` reuses a connection for several HTTP/1.1 requests.
//! * `OPR_WEBSOCKET=1` accepts RFC 6455 upgrades.
//!
//! `OPR_MTLS=1` adds opt-in client certificates, the `OPR_REVOKED` static
//! fingerprint deny list and ALPN reporting. HTTP/2 is served when ALPN
//! selects `h2`; every other connection keeps the HTTP/1.1 path. The
//! `OPR_CRL_FILE`, `OPR_CRL_URL` and `OPR_OCSP_FILE` variables add required
//! certificate status sources to the mTLS handshake. No new environment
//! variable enables HTTP/2.
//!
//! With none of the mTLS variables set, no client ALPN offer and no `h2`
//! negotiation, the plain-TLS wire format and response bytes stay identical.
//!
//! Connections are bounded by an idle timeout and a maximum number of
//! in-flight connections.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use rustls::server::ServerConnection;
use rustls::StreamOwned;
use serde_json::{json, Value};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsAcceptor;

use crate::http::{read_request, status_text, Method, Request, Response, MAX_BODY_BYTES};
use crate::http2::{self, State as H2State};
use crate::middleware::{
    access_log_line, apply_response_features, cors_preflight, rate_limited_response, request_id_of,
    structured_logging_enabled, tls_access_log_line, unauthorized_response, valid_request_id,
    AuthOptions, HttpOptions, MiddlewareChain, RateLimiter,
};
use crate::rooms::{self, RoomError, RoomRegistry};
use crate::router::Router;
use crate::tls::{self, TlsConfig};
use crate::websocket::{self, ServerChannel, WsChannel};

/// Environment variable that enables the TLS listener.
pub const TLS_ENV: &str = "OPR_TLS";

/// Environment variable that enables HTTP/1.1 keep-alive.
pub const KEEP_ALIVE_ENV: &str = "OPR_KEEPALIVE";

/// Environment variable that enables WebSocket upgrades.
pub const WEBSOCKET_ENV: &str = "OPR_WEBSOCKET";

/// Default idle timeout of a kept-alive connection.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum number of connections served at the same time.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// A running HTTP server.
pub struct Server {
    listener: TcpListener,
    router: Arc<Router>,
    middleware: Arc<MiddlewareChain>,
    limiter: Option<Arc<RateLimiter>>,
    options: Arc<HttpOptions>,
    max_body: usize,
    shutdown: Arc<AtomicBool>,
    tls: Option<Arc<TlsConfig>>,
    keep_alive: bool,
    websocket: bool,
    idle_timeout: Duration,
    max_connections: usize,
    in_flight: Arc<AtomicUsize>,
    /// Shared room membership and per-connection outbound queues.
    rooms: Arc<RoomHub>,
    /// The optional HTTP/3 listener on its own UDP port.
    http3: Option<Arc<crate::http3::Http3Server>>,
}

impl Server {
    /// Bind to `addr` (for example `127.0.0.1:0`) with the default 1 MiB cap.
    pub fn bind(addr: &str, router: Router) -> std::io::Result<Server> {
        Server::bind_with(addr, router, MiddlewareChain::new(), MAX_BODY_BYTES)
    }

    /// Bind with an explicit middleware chain and body cap.
    pub fn bind_with(
        addr: &str,
        router: Router,
        middleware: MiddlewareChain,
        max_body: usize,
    ) -> std::io::Result<Server> {
        Server::build(addr, router, middleware, max_body, None)
    }

    /// Bind a TLS server. The certificate comes from `config`; when it is
    /// `None` a self-signed certificate is generated at startup.
    pub fn bind_tls(
        addr: &str,
        router: Router,
        middleware: MiddlewareChain,
        max_body: usize,
        config: Option<TlsConfig>,
    ) -> Result<Server, String> {
        let config = match config {
            Some(config) => config,
            None => tls::self_signed_config().map_err(|err| err.to_string())?,
        };
        Server::build(addr, router, middleware, max_body, Some(config))
            .map_err(|err| err.to_string())
    }

    /// Bind with the TLS configuration described by the environment. Without
    /// `OPR_TLS` the server is a plain HTTP server.
    pub fn bind_from_env(
        addr: &str,
        router: Router,
        middleware: MiddlewareChain,
        max_body: usize,
    ) -> Result<Server, String> {
        let config = if tls::tls_enabled() {
            Some(tls::config_from_env().map_err(|err| err.to_string())?)
        } else {
            None
        };
        Server::build(addr, router, middleware, max_body, config).map_err(|err| err.to_string())
    }

    /// The shared implementation of every `bind` variant.
    fn build(
        addr: &str,
        router: Router,
        middleware: MiddlewareChain,
        max_body: usize,
        tls_config: Option<TlsConfig>,
    ) -> std::io::Result<Server> {
        let listener = TcpListener::bind(addr)?;
        let router = Arc::new(router);
        let middleware = Arc::new(middleware);
        let limiter = RateLimiter::from_env().map(Arc::new);
        let rooms = Arc::new(RoomHub::default());
        let mut options = HttpOptions::from_env();
        options.tls = tls_config.is_some();

        // The HTTP/3 listener needs a TLS configuration, so it reuses the
        // certificate of the HTTPS listener. Without one there is no QUIC
        // endpoint and no advertised `Alt-Svc` header.
        let http3 = match (crate::http3::enabled(), tls_config.as_ref()) {
            (true, Some(tls)) => {
                let http3_addr = format!("127.0.0.1:{}", crate::http3::port_from_env());
                let endpoint = crate::http3::Http3Endpoint::bind(&http3_addr, tls)
                    .map_err(std::io::Error::other)?;
                // The real UDP port is advertised, so a port of 0 still works.
                options.alt_svc_port = Some(endpoint.local_addr().port());
                // A client that already speaks HTTP/3 needs no alternative
                // service, so the HTTP/3 responses carry no `Alt-Svc` header.
                let mut http3_options = options.clone();
                http3_options.alt_svc_port = None;
                let state = crate::http3::State {
                    router: Arc::clone(&router),
                    middleware: Arc::clone(&middleware),
                    limiter: limiter.clone(),
                    options: Arc::new(http3_options),
                    max_body,
                };
                Some(Arc::new(crate::http3::Http3Server::new(endpoint, state)))
            }
            (true, None) => {
                eprintln!(
                    "[opurom-server] {} is set but there is no TLS configuration: \
                     the HTTP/3 listener needs a certificate",
                    crate::http3::HTTP3_ENV
                );
                None
            }
            _ => None,
        };

        Ok(Server {
            listener,
            router,
            middleware,
            limiter,
            options: Arc::new(options),
            max_body,
            shutdown: Arc::new(AtomicBool::new(false)),
            tls: tls_config.map(Arc::new),
            keep_alive: truthy_env(KEEP_ALIVE_ENV),
            websocket: truthy_env(WEBSOCKET_ENV),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            in_flight: Arc::new(AtomicUsize::new(0)),
            rooms,
            http3,
        })
    }

    /// Set the idle timeout of a kept-alive connection.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Server {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum number of connections served at the same time.
    pub fn with_max_connections(mut self, limit: usize) -> Server {
        self.max_connections = limit;
        self
    }

    /// Enable WebSocket upgrades on this server.
    pub fn with_websocket(mut self) -> Server {
        self.websocket = true;
        self
    }

    /// Enable HTTP/1.1 keep-alive on this server.
    pub fn with_keep_alive(mut self) -> Server {
        self.keep_alive = true;
        self
    }

    /// Require a bearer token on every non-health request, from an
    /// env-independent [`AuthOptions`] value instead of `OPR_AUTH_TOKEN`.
    pub fn with_auth(mut self, auth: AuthOptions) -> Server {
        Arc::make_mut(&mut self.options).auth = auth;
        self
    }

    /// The bound address, useful when binding to port 0.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// A handle that stops the accept loop after the next accepted connection.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// The TLS configuration of this server, when it has one.
    pub fn tls_config(&self) -> Option<&Arc<TlsConfig>> {
        self.tls.as_ref()
    }

    /// True when HTTP/1.1 keep-alive is enabled for this server.
    pub fn keep_alive_enabled(&self) -> bool {
        self.keep_alive
    }

    /// True when WebSocket upgrades are enabled for this server.
    pub fn websocket_enabled(&self) -> bool {
        self.websocket
    }

    /// The HTTP/3 listener of this server, when one is enabled.
    pub fn http3(&self) -> Option<&Arc<crate::http3::Http3Server>> {
        self.http3.as_ref()
    }

    /// Serve until the shutdown handle is set. One thread per connection.
    pub fn serve(&self) {
        if let Some(http3) = &self.http3 {
            let http3 = Arc::clone(http3);
            let shutdown = Arc::clone(&self.shutdown);
            thread::spawn(move || {
                http3.serve();
                shutdown.store(true, Ordering::Relaxed);
            });
        }
        for stream in self.listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let stream = match stream {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("[opurom-server] accept failed: {}", err);
                    continue;
                }
            };
            let router = Arc::clone(&self.router);
            let middleware = Arc::clone(&self.middleware);
            let limiter = self.limiter.clone();
            let options = Arc::clone(&self.options);
            let max_body = self.max_body;
            let tls_config = self.tls.clone();
            let idle_timeout = self.idle_timeout;
            let keep_alive = self.keep_alive;
            let websocket = self.websocket;
            let rooms = Arc::clone(&self.rooms);
            let shutdown = Arc::clone(&self.shutdown);
            let in_flight = Arc::clone(&self.in_flight);
            let current = in_flight.fetch_add(1, Ordering::Relaxed);
            if current >= self.max_connections {
                in_flight.fetch_sub(1, Ordering::Relaxed);
                // The in-flight limit is reached: answer with 503 and close.
                let _ = reject_connection(stream);
                continue;
            }
            thread::spawn(move || {
                let _ = handle_connection(
                    stream,
                    Connection {
                        router,
                        middleware,
                        limiter,
                        options,
                        max_body,
                        tls_config,
                        idle_timeout,
                        keep_alive,
                        websocket,
                        rooms,
                        shutdown,
                    },
                );
                in_flight.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Serve in a background thread and return the bound address.
    pub fn spawn(self) -> std::io::Result<(SocketAddr, Arc<AtomicBool>)> {
        let addr = self.local_addr()?;
        let shutdown = self.shutdown_handle();
        thread::spawn(move || {
            self.serve();
        });
        Ok((addr, shutdown))
    }
}

/// True when an environment flag is set to a truthy value.
fn truthy_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Answer a connection that arrives while the in-flight limit is reached.
fn reject_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let response = Response::error(503, "server_busy");
    write_response(&mut stream, &response)
}

/// One connection transport: plain TCP or TLS.
enum Transport {
    Plain(TcpStream),
    Tls(Option<Box<StreamOwned<ServerConnection, TcpStream>>>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(stream) => stream.read(buf),
            Transport::Tls(stream) => match stream {
                Some(stream) => stream.read(buf),
                None => Ok(0),
            },
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(stream) => stream.write(buf),
            Transport::Tls(Some(stream)) => {
                // Queue plaintext and drain TLS output without calling
                // complete_io: a socket read timeout must not fail a broadcast.
                let written = {
                    let mut writer = stream.conn.writer();
                    writer.write(buf)?
                };
                drain_tls(stream.as_mut())?;
                Ok(written)
            }
            Transport::Tls(None) => Ok(0),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(stream) => stream.flush(),
            Transport::Tls(Some(stream)) => {
                {
                    let mut writer = stream.conn.writer();
                    writer.flush()?;
                }
                drain_tls(stream.as_mut())
            }
            Transport::Tls(None) => Ok(()),
        }
    }
}

/// Write pending TLS records directly, without reading from the socket.
fn drain_tls(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> std::io::Result<()> {
    while stream.conn.wants_write() {
        match stream.conn.write_tls(&mut stream.sock) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "TLS write returned zero bytes",
                ))
            }
            Ok(_) => {}
            Err(err) if transient(err.kind()) => break,
            Err(err) => return Err(err),
        }
    }
    stream.sock.flush()
}

fn transient(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
    )
}

impl Transport {
    /// Set a short socket read timeout so a shared writer can take the
    /// transport lock while a WebSocket reader waits for the next frame.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Transport::Plain(stream) => stream.set_read_timeout(timeout),
            Transport::Tls(Some(stream)) => stream.get_ref().set_read_timeout(timeout),
            Transport::Tls(None) => Ok(()),
        }
    }

    /// Close the connection. A TLS connection sends `close_notify` first so
    /// the peer sees a clean shutdown instead of a truncated stream.
    fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(stream) => stream.flush(),
            Transport::Tls(stream) => {
                let Some(owned) = stream.take() else {
                    return Ok(());
                };
                let (mut connection, mut socket) = owned.into_parts();
                connection.send_close_notify();
                connection.complete_io(&mut socket).map(|_| ())
            }
        }
    }
}

/// The shared state one connection handler needs.
struct Connection {
    router: Arc<Router>,
    middleware: Arc<MiddlewareChain>,
    limiter: Option<Arc<RateLimiter>>,
    options: Arc<HttpOptions>,
    max_body: usize,
    tls_config: Option<Arc<TlsConfig>>,
    idle_timeout: Duration,
    keep_alive: bool,
    websocket: bool,
    rooms: Arc<RoomHub>,
    shutdown: Arc<AtomicBool>,
}

/// Serve one connection. An ALPN-selected `h2` connection owns a Tokio
/// runtime; every other connection uses the unchanged HTTP/1.1 loop.
fn handle_connection(stream: TcpStream, connection: Connection) -> std::io::Result<()> {
    let Connection {
        router,
        middleware,
        limiter,
        options,
        max_body,
        tls_config,
        idle_timeout,
        keep_alive,
        websocket,
        rooms,
        shutdown,
    } = connection;
    let requires_client_auth = tls_config
        .as_ref()
        .is_some_and(|config| config.requires_client_auth());
    let _ = stream.set_nodelay(true);
    // shortcut: a trickle of bytes resets each read timeout; upgrade to a
    // total request deadline when slowloris resistance is required.
    let _ = stream.set_read_timeout(Some(idle_timeout));
    let report_handshake_error = |err: &std::io::Error| {
        if requires_client_auth {
            eprintln!(
                "[opurom-server] mTLS handshake refused: client certificate missing, untrusted, revoked or status unavailable (check {}, {}, {}, {} and {}): {}",
                tls::CLIENT_CA_ENV,
                tls::REVOKED_ENV,
                tls::CRL_FILE_ENV,
                tls::CRL_URL_ENV,
                tls::OCSP_FILE_ENV,
                err
            );
        } else {
            eprintln!("[opurom-server] TLS handshake failed: {}", err);
        }
    };

    let (transport, alpn) = match tls_config {
        Some(config) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            stream.set_nonblocking(true)?;
            let tokio_stream = {
                let _guard = runtime.enter();
                TokioTcpStream::from_std(stream)?
            };
            let acceptor = TlsAcceptor::from(config.server_config());
            let handshake = async move {
                tokio::time::timeout(idle_timeout, acceptor.accept(tokio_stream)).await
            };
            let tls_stream = match runtime.block_on(handshake) {
                Ok(Ok(tls_stream)) => tls_stream,
                Ok(Err(err)) => {
                    report_handshake_error(&err);
                    return Ok(());
                }
                Err(_) => {
                    let err = std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    );
                    report_handshake_error(&err);
                    return Ok(());
                }
            };
            let alpn = tls_stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
            if alpn.as_deref() == Some("h2") {
                let state = H2State {
                    router: Arc::clone(&router),
                    middleware: Arc::clone(&middleware),
                    limiter: limiter.clone(),
                    options: Arc::clone(&options),
                    max_body,
                };
                return http2::serve(runtime, tls_stream, state, shutdown);
            }

            // Continue with the original blocking HTTP/1.1 transport. The
            // rustls state keeps any plaintext that arrived with the handshake.
            let (tokio_stream, server_connection) = tls_stream.into_inner();
            let stream = {
                let _guard = runtime.enter();
                tokio_stream.into_std()?
            };
            stream.set_nonblocking(false)?;
            let _ = stream.set_read_timeout(Some(idle_timeout));
            (
                Transport::Tls(Some(Box::new(StreamOwned::new(server_connection, stream)))),
                alpn,
            )
        }
        None => (Transport::Plain(stream), None),
    };

    // One connection serves many requests; the reader keeps the bytes the
    // HTTP parser already read so a WebSocket upgrade can use them.
    let mut reader = BufReader::new(transport);
    loop {
        // A closed connection ends the loop without an answer.
        match reader.fill_buf().map(|buffer| buffer.is_empty()) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(err) => return Err(err),
        }

        let started = Instant::now();
        let (response, method, path, reuse, head_only, request_id) =
            match read_request(&mut reader, max_body) {
                Ok(mut request) => {
                    // A WebSocket upgrade takes over the connection.
                    if websocket {
                        if let Some(key) = websocket::upgrade_key(&request) {
                            return serve_websocket(reader, key, rooms);
                        }
                    }
                    let method = request.method.as_str().to_string();
                    let path = request.path.clone();
                    let head_only = request.method == Method::Head;
                    // Capture a client-supplied id before dispatch, because the
                    // request-id layer overwrites the header with the assigned id.
                    let client_id = request
                        .header("X-Request-Id")
                        .and_then(valid_request_id)
                        .map(str::to_string);
                    let mut response = dispatch_request(
                        &mut request,
                        router.as_ref(),
                        middleware.as_ref(),
                        limiter.as_deref(),
                        options.as_ref(),
                    );
                    // The request-id layer runs inside dispatch and mirrors the id
                    // onto the request headers, so read it back only afterwards.
                    let request_id = request_id_of(&request).map(str::to_string);
                    // Echo only a valid client-supplied id so a caller can
                    // correlate its trace. A minted id stays access-log-only,
                    // keeping a plain no-id response byte-identical.
                    if let Some(id) = client_id.as_deref() {
                        if !response
                            .headers
                            .iter()
                            .any(|(name, _)| name.eq_ignore_ascii_case("X-Request-Id"))
                        {
                            response.set_header("X-Request-Id", id);
                        }
                    }
                    let reuse = keep_alive && wants_keep_alive(&request);
                    (response, method, path, reuse, head_only, request_id)
                }
                Err(err) => (
                    Response::error(err.status, &err.message),
                    "-".to_string(),
                    "-".to_string(),
                    false,
                    false,
                    None,
                ),
            };
        let result = write_response_head_aware(reader.get_mut(), &response, reuse, head_only);
        if structured_logging_enabled() {
            let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let line = match alpn.as_deref() {
                Some(protocol) => tls_access_log_line(
                    &method,
                    &path,
                    response.status,
                    duration_ms,
                    request_id.as_deref(),
                    protocol,
                ),
                None => access_log_line(
                    &method,
                    &path,
                    response.status,
                    duration_ms,
                    request_id.as_deref(),
                ),
            };
            eprintln!("{}", line);
        }
        result?;
        if !reuse {
            // A TLS peer must see a clean `close_notify` instead of a
            // truncated stream.
            let _ = reader.get_mut().shutdown();
            return Ok(());
        }
    }
}

/// Apply the existing middleware, rate limiter, router and HTTP features to one
/// request. HTTP/1.1 and HTTP/2 share this conversion point.
pub(crate) fn dispatch_request(
    request: &mut Request,
    router: &Router,
    middleware: &MiddlewareChain,
    limiter: Option<&RateLimiter>,
    options: &HttpOptions,
) -> Response {
    let mut response = match middleware.apply(request) {
        Some(response) => response,
        None => match limiter.and_then(|limiter| limiter.check(request)) {
            Some(retry_after) => rate_limited_response(retry_after),
            None => {
                if let Some(preflight) = cors_preflight(request, options.cors_origin.as_deref()) {
                    preflight
                } else if !options.auth.exempt(request) && !options.auth.authorized(request) {
                    unauthorized_response()
                } else {
                    router.handle(request)
                }
            }
        },
    };
    apply_response_features(&mut response, request, options);
    response
}

/// True when the request may be answered on the same connection.
fn wants_keep_alive(request: &Request) -> bool {
    let connection = request.header("Connection").unwrap_or("");
    if connection
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case("close"))
    {
        return false;
    }
    if request.version == "HTTP/1.0" {
        // HTTP/1.0 clients close unless they ask to keep the connection.
        return connection
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("keep-alive"));
    }
    true
}

/// Write the response and close the connection. This is the plain HTTP/1.1 wire
/// format and stays byte-identical.
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> std::io::Result<()> {
    write_response_with(writer, response, false)
}

/// Write the response. With `keep_alive` the answer carries
/// `Connection: keep-alive`, otherwise `Connection: close`. With `head_only`
/// the `Content-Length` of the full body is kept but the body is not written,
/// which is the HTTP/1.1 HEAD form.
pub fn write_response_with<W: Write>(
    writer: &mut W,
    response: &Response,
    keep_alive: bool,
) -> std::io::Result<()> {
    write_response_head_aware(writer, response, keep_alive, false)
}

/// Write one response, suppressing the body when `head_only` is set while
/// keeping the `Content-Length` that describes the full GET body.
pub(crate) fn write_response_head_aware<W: Write>(
    writer: &mut W,
    response: &Response,
    keep_alive: bool,
    head_only: bool,
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        status_text(response.status)
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    writer.write_all(head.as_bytes())?;
    if !head_only {
        writer.write_all(&response.body)?;
    }
    writer.flush()
}

type ClientId = u64;
type OutboundFrame = Vec<u8>;

const WS_READ_TIMEOUT: Duration = Duration::from_millis(10);

#[derive(Default)]
struct HubState {
    rooms: RoomRegistry<ClientId>,
    senders: BTreeMap<ClientId, mpsc::Sender<OutboundFrame>>,
}

#[derive(Default)]
struct RoomHub {
    state: Mutex<HubState>,
    next_id: AtomicU64,
}

impl RoomHub {
    fn register(&self) -> (ClientId, mpsc::Receiver<OutboundFrame>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (sender, receiver) = mpsc::channel();
        let mut state = lock(&self.state);
        state.senders.insert(id, sender);
        (id, receiver)
    }

    fn deregister(&self, id: ClientId) {
        let mut state = lock(&self.state);
        state.rooms.leave_all(&id);
        state.senders.remove(&id);
    }

    fn join(&self, id: ClientId, room: &str) -> Result<(), RoomError> {
        let mut state = lock(&self.state);
        state.rooms.join(room, id)
    }

    fn leave(&self, id: ClientId, room: &str) -> Result<(), RoomError> {
        let mut state = lock(&self.state);
        state.rooms.leave(room, &id)
    }

    fn broadcast(&self, room: &str, payload: &Value) -> Result<usize, ControlError> {
        rooms::validate_room_name(room).map_err(ControlError::room)?;
        let body = json!({
            "type": "broadcast",
            "room": room,
            "payload": payload,
        })
        .to_string();
        if body.len() > websocket::MAX_FRAME_PAYLOAD {
            return Err(ControlError::new(
                "payload_too_large",
                format!(
                    "broadcast frame exceeds {} bytes",
                    websocket::MAX_FRAME_PAYLOAD
                ),
            ));
        }
        let frame = websocket::encode_frame(websocket::Opcode::Text, body.as_bytes(), true, None);
        let mut state = lock(&self.state);
        let recipients = state.rooms.broadcast(room).map_err(ControlError::room)?;
        let mut delivered = 0;
        let mut broken = Vec::new();
        for id in recipients {
            match state.senders.get(&id) {
                Some(sender) if sender.send(frame.clone()).is_ok() => delivered += 1,
                _ => broken.push(id),
            }
        }
        for id in broken {
            state.senders.remove(&id);
            state.rooms.leave_all(&id);
        }
        Ok(delivered)
    }

    fn send_ack(&self, id: ClientId, kind: &str, room: &str) {
        let body = json!({ "type": kind, "room": room }).to_string();
        self.send_frame(id, &body);
    }

    fn send_error(&self, id: ClientId, error: &ControlError) {
        let body = json!({
            "type": "error",
            "error": error.code,
            "message": error.message.as_str(),
        })
        .to_string();
        self.send_frame(id, &body);
    }

    fn send_frame(&self, id: ClientId, body: &str) {
        let frame = websocket::encode_frame(websocket::Opcode::Text, body.as_bytes(), true, None);
        let mut state = lock(&self.state);
        let broken = match state.senders.get(&id) {
            Some(sender) => sender.send(frame).is_err(),
            None => true,
        };
        if broken {
            state.senders.remove(&id);
            state.rooms.leave_all(&id);
        }
    }
}

struct ControlError {
    code: &'static str,
    message: String,
}

impl ControlError {
    fn new(code: &'static str, message: impl Into<String>) -> ControlError {
        ControlError {
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> ControlError {
        ControlError::new("invalid_control", message)
    }

    fn room(error: RoomError) -> ControlError {
        let code = error.code();
        ControlError::new(code, error.to_string())
    }
}

enum Control {
    Join { room: String },
    Leave { room: String },
    Broadcast { room: String, payload: Value },
}

fn control_room(object: &serde_json::Map<String, Value>) -> Result<String, ControlError> {
    object
        .get("room")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ControlError::invalid("room must be a string"))
}

/// Parse a JSON control object. Other text remains an ordinary echo message.
fn parse_control(text: &str) -> Result<Option<Control>, ControlError> {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Ok(None);
    };
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(kind) = object.get("type") else {
        return Ok(None);
    };
    let Some(kind) = kind.as_str() else {
        return Err(ControlError::invalid("type must be a string"));
    };
    let room = || control_room(object);
    match kind {
        "join" => Ok(Some(Control::Join { room: room()? })),
        "leave" => Ok(Some(Control::Leave { room: room()? })),
        "broadcast" => {
            let payload = object
                .get("payload")
                .cloned()
                .ok_or_else(|| ControlError::invalid("payload is required"))?;
            Ok(Some(Control::Broadcast {
                room: room()?,
                payload,
            }))
        }
        other => Err(ControlError::new(
            "unknown_control_type",
            format!("unknown control type: {}", short(other)),
        )),
    }
}

fn short(value: &str) -> String {
    value.chars().take(64).collect()
}

fn handle_control(rooms: &RoomHub, id: ClientId, control: Control) {
    match control {
        Control::Join { room } => match rooms.join(id, &room) {
            Ok(()) => rooms.send_ack(id, "joined", &room),
            Err(error) => rooms.send_error(id, &ControlError::room(error)),
        },
        Control::Leave { room } => match rooms.leave(id, &room) {
            Ok(()) => rooms.send_ack(id, "left", &room),
            Err(error) => rooms.send_error(id, &ControlError::room(error)),
        },
        Control::Broadcast { room, payload } => {
            if let Err(error) = rooms.broadcast(&room, &payload) {
                rooms.send_error(id, &error);
            }
        }
    }
}

#[derive(Clone)]
struct SharedIo(Arc<Mutex<BufReader<Transport>>>);

impl SharedIo {
    fn new(reader: BufReader<Transport>) -> SharedIo {
        SharedIo(Arc::new(Mutex::new(reader)))
    }
}

impl Read for SharedIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = lock(&self.0);
            match guard.read(buf) {
                Ok(read) => return Ok(read),
                Err(err) if transient(err.kind()) => {
                    drop(guard);
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl Write for SharedIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = lock(&self.0);
        guard.get_mut().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = lock(&self.0);
        guard.get_mut().flush()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Serve the WebSocket side of one connection after a successful handshake.
///
/// The buffered HTTP bytes stay in one shared `BufReader`: the reader decodes
/// inbound frames while an outbound queue writes room broadcasts in order.
fn serve_websocket(
    mut reader: BufReader<Transport>,
    key: &str,
    rooms: Arc<RoomHub>,
) -> std::io::Result<()> {
    reader
        .get_mut()
        .write_all(&websocket::handshake_response(key))?;
    reader.get_mut().flush()?;
    reader.get_mut().set_read_timeout(Some(WS_READ_TIMEOUT))?;
    let shared = SharedIo::new(reader);
    let (id, outbound) = rooms.register();
    let mut writer = shared.clone();
    thread::spawn(move || {
        while let Ok(frame) = outbound.recv() {
            if writer.write_all(&frame).is_err() || writer.flush().is_err() {
                break;
            }
        }
    });

    let mut channel_io = shared.clone();
    let mut channel = ServerChannel::new(&mut channel_io, Vec::new());
    while let Ok(message) = channel.recv() {
        match message {
            websocket::WsMessage::Text(text) => match parse_control(&text) {
                Ok(Some(control)) => handle_control(&rooms, id, control),
                Ok(None) => {
                    if channel.send_text(&text).is_err() {
                        break;
                    }
                }
                Err(error) => rooms.send_error(id, &error),
            },
            websocket::WsMessage::Binary(data) => {
                if channel.send_binary(&data).is_err() {
                    break;
                }
            }
            websocket::WsMessage::Close { code, reason } => {
                let _ = channel.send_close(code, &reason);
                break;
            }
            websocket::WsMessage::Pong(_) | websocket::WsMessage::Ping(_) => {}
        }
    }
    rooms.deregister(id);
    Ok(())
}

/// Convenience helper: build a request that targets `path` with `method`.
pub fn request_for(method: crate::http::Method, path: &str, body: &str) -> Request {
    Request {
        method,
        path: path.to_string(),
        query: String::new(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: body.as_bytes().to_vec(),
        params: BTreeMap::new(),
        version: "HTTP/1.1".to_string(),
    }
}
