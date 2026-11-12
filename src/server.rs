//! Thread-per-connection HTTP/1.1 server over `std::net::TcpListener`.

use std::collections::BTreeMap;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crate::http::{read_request, status_text, Request, Response, MAX_BODY_BYTES};
use crate::middleware::{
    apply_response_features, authorized, cors_preflight, rate_limited_response, request_log_line,
    structured_logging_enabled, unauthorized_response, HttpOptions, MiddlewareChain, RateLimiter,
};
use crate::router::Router;

/// A running HTTP server.
pub struct Server {
    listener: TcpListener,
    router: Arc<Router>,
    middleware: Arc<MiddlewareChain>,
    limiter: Option<Arc<RateLimiter>>,
    options: Arc<HttpOptions>,
    max_body: usize,
    shutdown: Arc<AtomicBool>,
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
        let listener = TcpListener::bind(addr)?;
        Ok(Server {
            listener,
            router: Arc::new(router),
            middleware: Arc::new(middleware),
            limiter: RateLimiter::from_env().map(Arc::new),
            options: Arc::new(HttpOptions::from_env()),
            max_body,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The bound address, useful when binding to port 0.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// A handle that stops the accept loop after the next accepted connection.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Serve until the shutdown handle is set. One thread per connection.
    pub fn serve(&self) {
        for stream in self.listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            match stream {
                Ok(stream) => {
                    let router = Arc::clone(&self.router);
                    let middleware = Arc::clone(&self.middleware);
                    let limiter = self.limiter.clone();
                    let options = Arc::clone(&self.options);
                    let max_body = self.max_body;
                    let shutdown = Arc::clone(&self.shutdown);
                    thread::spawn(move || {
                        let _ = handle_connection(
                            stream, router, middleware, limiter, options, max_body, shutdown,
                        );
                    });
                }
                Err(err) => eprintln!("[opurom-server] accept failed: {}", err),
            }
        }
    }

    /// Serve in a background thread and return the bound address.
    pub fn spawn(self) -> std::io::Result<(std::net::SocketAddr, Arc<AtomicBool>)> {
        let addr = self.local_addr()?;
        let shutdown = self.shutdown_handle();
        thread::spawn(move || {
            self.serve();
        });
        Ok((addr, shutdown))
    }
}

/// Read one request, run the middleware chain and the router, write the answer.
fn handle_connection(
    stream: TcpStream,
    router: Arc<Router>,
    middleware: Arc<MiddlewareChain>,
    limiter: Option<Arc<RateLimiter>>,
    options: Arc<HttpOptions>,
    max_body: usize,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let _ = shutdown;
    let started = Instant::now();
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let (response, method, path) = match read_request(&mut reader, max_body) {
        Ok(mut request) => {
            let method = request.method.as_str().to_string();
            let path = request.path.clone();
            let mut response = match middleware.apply(&mut request) {
                Some(response) => response,
                None => match limiter.as_ref().and_then(|limiter| limiter.check(&request)) {
                    Some(retry_after) => rate_limited_response(retry_after),
                    None => {
                        if let Some(preflight) =
                            cors_preflight(&request, options.cors_origin.as_deref())
                        {
                            preflight
                        } else if options
                            .auth_token
                            .as_deref()
                            .is_some_and(|token| !authorized(&request, token))
                        {
                            unauthorized_response()
                        } else {
                            router.handle(&mut request)
                        }
                    }
                },
            };
            apply_response_features(&mut response, &request, options.as_ref());
            (response, method, path)
        }
        Err(err) => (
            Response::error(err.status, &err.message),
            "-".to_string(),
            "-".to_string(),
        ),
    };
    let result = write_response(&mut writer, &response);
    if structured_logging_enabled() {
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        eprintln!(
            "{}",
            request_log_line(&method, &path, response.status, elapsed_ms)
        );
    }
    result
}

/// Write the response and close the connection (no keep-alive in R2).
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> std::io::Result<()> {
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
    head.push_str("Connection: close\r\n\r\n");
    writer.write_all(head.as_bytes())?;
    writer.write_all(&response.body)?;
    writer.flush()
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
    }
}
