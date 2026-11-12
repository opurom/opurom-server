//! Ordered middleware chain.
//!
//! A middleware is a boxed closure applied to every request before routing.
//! Returning `Some(response)` short-circuits the request (for example the
//! body-size cap); returning `None` lets the router handle it.

use crate::http::{Request, Response, MAX_BODY_BYTES};

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

/// Request-logging layer: prints `METHOD PATH` for every request to stderr.
pub fn logging() -> Middleware {
    Box::new(|request: &mut Request| {
        eprintln!(
            "[opurom-server] -> {} {}",
            request.method.as_str(),
            request.path
        );
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
