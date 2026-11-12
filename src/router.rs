//! Router with literal and `:param` segments, per-route fault isolation and a
//! three-strike circuit breaker.
//!
//! A handler that panics is caught with `catch_unwind`; the request answers
//! `500` JSON and the route's consecutive-failure counter grows. After three
//! consecutive panics the route is disabled and answers `503` JSON while all
//! other routes keep serving. A successful call resets the counter.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::http::{Method, Request, Response};

/// Consecutive panics that disable a route.
pub const PANIC_THRESHOLD: u32 = 3;

/// A request handler.
pub type Handler = Box<dyn Fn(&mut Request) -> Response + Send + Sync>;

/// One segment of a route pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Param(String),
}

impl Segment {
    fn parse(raw: &str) -> Segment {
        if let Some(name) = raw.strip_prefix(':') {
            Segment::Param(name.to_string())
        } else {
            Segment::Literal(raw.to_string())
        }
    }
}

/// One registered route.
struct Route {
    method: Method,
    segments: Vec<Segment>,
    handler: Handler,
    /// Consecutive panics; the route is disabled once it reaches the threshold.
    failures: Arc<AtomicU32>,
    disabled: Arc<AtomicU32>,
}

impl Route {
    fn matches(&self, path: &str) -> Option<BTreeMap<String, String>> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() != self.segments.len() {
            return None;
        }
        let mut params = BTreeMap::new();
        for (segment, part) in self.segments.iter().zip(parts.iter()) {
            match segment {
                Segment::Literal(literal) => {
                    if literal != part {
                        return None;
                    }
                }
                Segment::Param(name) => {
                    params.insert(name.clone(), (*part).to_string());
                }
            }
        }
        Some(params)
    }
}

/// The routing table.
#[derive(Default)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new() -> Router {
        Router { routes: Vec::new() }
    }

    /// Register a handler for `method` and `pattern`.
    ///
    /// Pattern segments starting with `:` capture a path parameter.
    pub fn route<F>(&mut self, method: Method, pattern: &str, handler: F) -> &mut Router
    where
        F: Fn(&mut Request) -> Response + Send + Sync + 'static,
    {
        let segments = pattern
            .split('/')
            .filter(|s| !s.is_empty())
            .map(Segment::parse)
            .collect();
        self.routes.push(Route {
            method,
            segments,
            handler: Box::new(handler),
            failures: Arc::new(AtomicU32::new(0)),
            disabled: Arc::new(AtomicU32::new(0)),
        });
        self
    }

    /// Register a `GET` route.
    pub fn get<F>(&mut self, pattern: &str, handler: F) -> &mut Router
    where
        F: Fn(&mut Request) -> Response + Send + Sync + 'static,
    {
        self.route(Method::Get, pattern, handler)
    }

    /// Register a `POST` route.
    pub fn post<F>(&mut self, pattern: &str, handler: F) -> &mut Router
    where
        F: Fn(&mut Request) -> Response + Send + Sync + 'static,
    {
        self.route(Method::Post, pattern, handler)
    }

    /// Register a `PUT` route.
    pub fn put<F>(&mut self, pattern: &str, handler: F) -> &mut Router
    where
        F: Fn(&mut Request) -> Response + Send + Sync + 'static,
    {
        self.route(Method::Put, pattern, handler)
    }

    /// Register a `DELETE` route.
    pub fn delete<F>(&mut self, pattern: &str, handler: F) -> &mut Router
    where
        F: Fn(&mut Request) -> Response + Send + Sync + 'static,
    {
        self.route(Method::Delete, pattern, handler)
    }

    /// Route a request.
    ///
    /// * unknown path -> `404` JSON
    /// * known path, wrong method -> `405` JSON
    /// * disabled route -> `503` JSON
    /// * panicking handler -> `500` JSON, route disabled after three strikes
    pub fn handle(&self, request: &mut Request) -> Response {
        let mut path_matched = false;
        for route in &self.routes {
            let params = match route.matches(&request.path) {
                Some(params) => params,
                None => continue,
            };
            path_matched = true;
            if route.method != request.method {
                continue;
            }
            request.params = params;
            if route.disabled.load(Ordering::Relaxed) == 1 {
                return Response::error(503, "route_disabled");
            }
            let outcome = catch_unwind(AssertUnwindSafe(|| (route.handler)(request)));
            return match outcome {
                Ok(response) => {
                    route.failures.store(0, Ordering::Relaxed);
                    response
                }
                Err(_) => {
                    let failures = route.failures.fetch_add(1, Ordering::Relaxed) + 1;
                    if failures >= PANIC_THRESHOLD {
                        route.disabled.store(1, Ordering::Relaxed);
                    }
                    Response::error(500, "handler_panic")
                }
            };
        }
        if path_matched {
            Response::error(405, "method_not_allowed")
        } else {
            Response::error(404, "not_found")
        }
    }
}
