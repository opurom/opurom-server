use opurom_server::http::{Method, Response};
use opurom_server::router::{RegisteredRoute, Router};
use opurom_server::server::request_for;

fn ok() -> Response {
    Response::text(200, "ok")
}

#[test]
fn empty_router_reports_no_routes() {
    assert!(Router::new().routes().is_empty());
}

#[test]
fn routes_report_methods_and_patterns_in_registration_order() {
    let mut router = Router::new();
    router.get("/health", |_| ok());
    router.post("/todos", |_| ok());
    router.get("/todos/:id", |_| ok());
    router.delete("/todos/:id", |_| ok());
    assert_eq!(
        router.routes(),
        vec![
            RegisteredRoute {
                method: Method::Get,
                path: "/health".to_string(),
            },
            RegisteredRoute {
                method: Method::Post,
                path: "/todos".to_string(),
            },
            RegisteredRoute {
                method: Method::Get,
                path: "/todos/:id".to_string(),
            },
            RegisteredRoute {
                method: Method::Delete,
                path: "/todos/:id".to_string(),
            },
        ]
    );
}

#[test]
fn reported_patterns_are_canonical() {
    let mut router = Router::new();
    router.get("/a//b/", |_| ok());
    router.put("/", |_| ok());
    router.route(Method::Other("PATCH".to_string()), "/x/:name", |_| ok());
    let paths: Vec<String> = router
        .routes()
        .into_iter()
        .map(|route| route.path)
        .collect();
    assert_eq!(
        paths,
        vec!["/a/b".to_string(), "/".to_string(), "/x/:name".to_string(),]
    );
}

#[test]
fn introspection_leaves_dispatch_unchanged() {
    let mut router = Router::new();
    router.get("/health", |_| ok());
    let before = router.routes();
    let mut request = request_for(Method::Get, "/health", "");
    let response = router.handle(&mut request);
    assert_eq!(response.status, 200);
    assert_eq!(response.body_string(), "ok");
    assert_eq!(router.routes(), before);
}
