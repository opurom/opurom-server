//! Real HTTP/2 over an ALPN-selected TLS connection.
//!
//! The existing thread-per-connection server keeps its blocking HTTP/1.1
//! path. When rustls selects `h2`, one current-thread Tokio runtime owns the
//! connection and the `h2` crate handles HPACK, HEADERS/DATA frames, stream
//! multiplexing and flow control. Every request is converted into the same
//! [`crate::http::Request`] and goes through the existing middleware, rate
//! limiter, router and response features.
//!
//! Scope: no HTTP/3/QUIC, server push, priority tree or connection coalescing.

use std::collections::BTreeMap;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::request::Parts;
use http::{HeaderName, HeaderValue, StatusCode, Version};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;

use crate::http::{normalize_path, Method, Request as AppRequest, Response as AppResponse};
use crate::middleware::{
    request_id_of, structured_logging_enabled, tls_access_log_line, HttpOptions, MiddlewareChain,
    RateLimiter,
};
use crate::router::Router;
use crate::server::dispatch_request;

/// Largest HTTP/2 frame payload accepted; h2 splits outbound DATA frames.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024;

/// Largest number of client-initiated streams on one connection.
pub const MAX_CONCURRENT_STREAMS: u32 = 100;

/// Largest uncompressed HPACK header list accepted on one request.
pub const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

/// Initial stream and connection receive window.
pub const INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;

/// Largest buffered send window per stream.
pub const MAX_SEND_BUFFER_SIZE: usize = 1024 * 1024;

const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Shared server state needed by every HTTP/2 stream.
#[derive(Clone)]
pub(crate) struct State {
    pub(crate) router: Arc<Router>,
    pub(crate) middleware: Arc<MiddlewareChain>,
    pub(crate) limiter: Option<Arc<RateLimiter>>,
    pub(crate) options: Arc<HttpOptions>,
    pub(crate) max_body: usize,
}

/// Serve one ALPN-selected `h2` connection until the peer closes or the
/// shutdown handle asks for a graceful GOAWAY.
pub(crate) fn serve(
    runtime: Runtime,
    stream: TlsStream<TokioTcpStream>,
    state: State,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    runtime.block_on(serve_connection(stream, state, shutdown))
}

async fn serve_connection(
    stream: TlsStream<TokioTcpStream>,
    state: State,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut builder = h2::server::Builder::new();
    builder
        .max_frame_size(MAX_FRAME_SIZE)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .initial_window_size(INITIAL_WINDOW_SIZE)
        .initial_connection_window_size(INITIAL_WINDOW_SIZE)
        .max_send_buffer_size(MAX_SEND_BUFFER_SIZE);
    let mut connection = builder
        .handshake::<_, Bytes>(stream)
        .await
        .map_err(io_error)?;

    let (sender, mut shutdown_signal) = oneshot::channel::<()>();
    let watcher = tokio::spawn(async move {
        while !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(SHUTDOWN_POLL_INTERVAL).await;
        }
        let _ = sender.send(());
    });

    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut stopping = false;
    let mut closed = false;
    while !closed {
        tokio::select! {
            incoming = connection.accept() => match incoming {
                Some(Ok((request, respond))) => {
                    let state = state.clone();
                    let _ = tasks.spawn(async move {
                        serve_stream(request, respond, state).await;
                    });
                }
                Some(Err(err)) => {
                    eprintln!("[opurom-server] HTTP/2 connection failed: {}", err);
                    closed = true;
                }
                None => closed = true,
            },
            _ = &mut shutdown_signal, if !stopping => {
                connection.graceful_shutdown();
                stopping = true;
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(err) = result {
                    eprintln!("[opurom-server] HTTP/2 stream task failed: {}", err);
                }
            }
        }
    }

    // Keep driving the connection while the last stream tasks flush DATA.
    let mut drained = false;
    while !tasks.is_empty() {
        tokio::select! {
            Some(result) = tasks.join_next() => {
                if let Err(err) = result {
                    eprintln!("[opurom-server] HTTP/2 stream task failed: {}", err);
                }
            }
            result = poll_fn(|cx| connection.poll_closed(cx)), if !drained => {
                let _ = result;
                drained = true;
            }
        }
    }
    if !drained {
        let _ = poll_fn(|cx| connection.poll_closed(cx)).await;
    }
    watcher.abort();
    Ok(())
}

async fn serve_stream(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    state: State,
) {
    let started = Instant::now();
    let (parts, mut request_body) = request.into_parts();
    let mut app_request = app_request(&parts);
    let method = app_request.method.as_str().to_string();
    let path = app_request.path.clone();
    let head_only = app_request.method == Method::Head;
    let response =
        match read_request(&mut request_body, &mut respond, &state, &mut app_request).await {
            Some(response) => response,
            // The client reset the stream: dropping the body frees h2's buffered
            // frames and returns the connection flow window.
            None => return,
        };
    // The request-id layer ran inside dispatch and mirrored the id here.
    let request_id = request_id_of(&app_request).map(str::to_string);

    if let Err(err) = send_response(&mut respond, &response, head_only).await {
        eprintln!("[opurom-server] HTTP/2 stream failed: {}", err);
        return;
    }
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
                "h2"
            )
        );
    }
}

/// Read the body and dispatch, watching for a client RST_STREAM the whole
/// time: a cancelled stream never runs its handler or sends a response.
async fn read_request(
    body: &mut RecvStream,
    respond: &mut SendResponse<Bytes>,
    state: &State,
    app_request: &mut AppRequest,
) -> Option<AppResponse> {
    let mut read = pin!(read_body(body, state.max_body));
    poll_fn(|cx| {
        // Any completed reset means the stream is dead: stop before dispatch.
        if let Poll::Ready(_) = respond.poll_reset(cx) {
            return Poll::Ready(None);
        }
        match read.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(Some(match result {
                Ok(body) => {
                    app_request.body = body;
                    dispatch_request(
                        app_request,
                        state.router.as_ref(),
                        state.middleware.as_ref(),
                        state.limiter.as_deref(),
                        state.options.as_ref(),
                    )
                }
                Err(response) => response,
            })),
        }
    })
    .await
}

fn app_request(parts: &Parts) -> AppRequest {
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    AppRequest {
        method: Method::parse(parts.method.as_str()),
        path: normalize_path(parts.uri.path()),
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers,
        body: Vec::new(),
        params: BTreeMap::new(),
        version: "HTTP/2.0".to_string(),
    }
}

async fn read_body(body: &mut RecvStream, max_body: usize) -> Result<Vec<u8>, AppResponse> {
    let mut bytes = Vec::new();
    let mut too_large = false;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| AppResponse::error(400, "bad_request"))?;
        let size = chunk.len();
        if !too_large {
            if bytes.len().saturating_add(size) <= max_body {
                bytes.extend_from_slice(&chunk);
            } else {
                bytes.clear();
                too_large = true;
            }
        }
        body.flow_control()
            .release_capacity(size)
            .map_err(|_| AppResponse::error(400, "bad_request"))?;
    }
    if too_large {
        Err(AppResponse::error(413, "payload_too_large"))
    } else {
        Ok(bytes)
    }
}

async fn send_response(
    respond: &mut SendResponse<Bytes>,
    response: &AppResponse,
    head_only: bool,
) -> Result<(), String> {
    let head = h2_response(response)?;
    // A HEAD answer keeps the GET headers and Content-Length but ends the
    // stream at the headers, sending no DATA frame.
    let end_of_stream = head_only || response.body.is_empty();
    let mut send = respond
        .send_response(head, end_of_stream)
        .map_err(|err| err.to_string())?;
    if !end_of_stream {
        write_body(&mut send, &response.body).await?;
    }
    Ok(())
}

fn h2_response(response: &AppResponse) -> Result<http::Response<()>, String> {
    let status = StatusCode::from_u16(response.status).map_err(|err| err.to_string())?;
    let mut builder = http::Response::builder()
        .status(status)
        .version(Version::HTTP_2);
    for (name, value) in &response.headers {
        if is_connection_specific(name) || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            continue;
        };
        builder = builder.header(name, value);
    }
    let length =
        HeaderValue::from_str(&response.body.len().to_string()).map_err(|err| err.to_string())?;
    builder = builder.header(http::header::CONTENT_LENGTH, length);
    builder.body(()).map_err(|err| err.to_string())
}

async fn write_body(send: &mut SendStream<Bytes>, body: &[u8]) -> Result<(), String> {
    // h2 splits this bounded buffer into peer-sized DATA frames and applies
    // stream and connection flow control while the connection is polled.
    send.send_data(Bytes::copy_from_slice(body), true)
        .map_err(|err| err.to_string())
}

fn is_connection_specific(name: &str) -> bool {
    crate::http::is_connection_specific(name)
}

fn io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}
