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
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::server::ServerConnection;
use rustls::StreamOwned;
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsAcceptor;

use crate::http::{read_request, status_text, Method, Request, Response, MAX_BODY_BYTES};
use crate::http2::{self, State as H2State};
use crate::middleware::{
    apply_response_features, authorized, cors_preflight, rate_limited_response, request_log_line,
    structured_logging_enabled, tls_request_log_line, unauthorized_response, HttpOptions,
    MiddlewareChain, RateLimiter,
};
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
            Transport::Tls(stream) => match stream {
                Some(stream) => stream.write(buf),
                None => Ok(0),
            },
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(stream) => stream.flush(),
            Transport::Tls(stream) => match stream {
                Some(stream) => stream.flush(),
                None => Ok(()),
            },
        }
    }
}

impl Transport {
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
        let (response, method, path, reuse, head_only) = match read_request(&mut reader, max_body) {
            Ok(mut request) => {
                // A WebSocket upgrade takes over the connection.
                if websocket {
                    if let Some(key) = websocket::upgrade_key(&request) {
                        return serve_websocket(&mut reader, key);
                    }
                }
                let method = request.method.as_str().to_string();
                let path = request.path.clone();
                let head_only = request.method == Method::Head;
                let response = dispatch_request(
                    &mut request,
                    router.as_ref(),
                    middleware.as_ref(),
                    limiter.as_deref(),
                    options.as_ref(),
                );
                let reuse = keep_alive && wants_keep_alive(&request);
                (response, method, path, reuse, head_only)
            }
            Err(err) => (
                Response::error(err.status, &err.message),
                "-".to_string(),
                "-".to_string(),
                false,
                false,
            ),
        };
        let result = write_response_head_aware(reader.get_mut(), &response, reuse, head_only);
        if structured_logging_enabled() {
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let line = match alpn.as_deref() {
                Some(protocol) => {
                    tls_request_log_line(&method, &path, response.status, elapsed_ms, protocol)
                }
                None => request_log_line(&method, &path, response.status, elapsed_ms),
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
                } else if options
                    .auth_token
                    .as_deref()
                    .is_some_and(|token| !authorized(request, token))
                {
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

/// Serve the WebSocket side of one connection after a successful handshake.
///
/// The bytes the HTTP parser already buffered belong to the WebSocket
/// stream, so they are handed to the channel instead of the socket.
fn serve_websocket<R: Read + Write>(reader: &mut BufReader<R>, key: &str) -> std::io::Result<()> {
    reader
        .get_mut()
        .write_all(&websocket::handshake_response(key))?;
    reader.get_mut().flush()?;
    let prefix = reader.buffer().to_vec();
    let mut channel = ServerChannel::new(reader.get_mut(), prefix);
    while let Ok(message) = channel.recv() {
        match message {
            websocket::WsMessage::Text(text) => {
                if channel.send_text(&text).is_err() {
                    break;
                }
            }
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
