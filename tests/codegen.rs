//! Tests for the `opurom-serverc` lowering pass.
//!
//! The generated crate is checked for shape here; building and running it
//! against the sibling `opurom-db` is the integration step.

use std::fs;
use std::path::PathBuf;

use opurom_server::codegen::{default_dep_root, lower_service};

const IR: &str = r##"{
  "ir": "0.1",
  "app": "TodoApp",
  "state": [ { "name": "remaining", "type": "int", "init": 0 } ],
  "tree": {
    "id": 0,
    "kind": "Column",
    "props": { "padding": 16 },
    "children": [
      { "id": 1, "kind": "Text", "props": { "value": "Remaining: {remaining}" }, "children": [], "events": {} }
    ],
    "events": {}
  },
  "theme": { "mode": "system", "accent": "#4F46E5", "radius": 12 },
  "models": [
    { "name": "Todo", "fields": [
      { "name": "id", "type": "int", "primary": true, "default": null },
      { "name": "title", "type": "string", "primary": false, "default": null },
      { "name": "done", "type": "bool", "primary": false, "default": false }
    ] }
  ],
  "api": [
    { "path": "/todos", "model": "Todo", "handlers": ["list", "create"] },
    { "path": "/todos/:id", "model": "Todo", "handlers": ["get", "update", "delete"] }
  ]
}"##;

/// A unique temporary directory for one test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "opurom-serverc-test-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn lowering_writes_a_complete_crate() {
    let out = temp_dir("shape");
    let lowered = lower_service(IR, &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");

    let main = fs::read_to_string(out.join("src/main.rs")).expect("main.rs exists");
    let cargo = fs::read_to_string(out.join("Cargo.toml")).expect("Cargo.toml exists");

    // The five CRUD verbs plus /health and /ssr.
    assert!(
        main.contains("router.route(Method::Get, \"/health\""),
        "{}",
        main
    );
    assert!(
        main.contains("router.route(Method::Get, \"/ssr\""),
        "{}",
        main
    );
    assert!(
        main.contains("router.route(Method::Get, \"/todos\""),
        "{}",
        main
    );
    assert!(
        main.contains("router.route(Method::Post, \"/todos\""),
        "{}",
        main
    );
    assert!(
        main.contains("router.route(Method::Get, \"/todos/:id\""),
        "{}",
        main
    );
    assert!(
        main.contains("router.route(Method::Put, \"/todos/:id\""),
        "{}",
        main
    );
    assert!(
        main.contains("router.route(Method::Delete, \"/todos/:id\""),
        "{}",
        main
    );

    // Path dependencies and an isolated workspace.
    assert!(
        cargo.contains("opurom-server = { path = \"/tmp/dep-root/opurom-server\" }"),
        "{}",
        cargo
    );
    assert!(
        cargo.contains("opurom-db = { path = \"/tmp/dep-root/opurom-db\" }"),
        "{}",
        cargo
    );
    assert!(cargo.contains("[workspace]"), "{}", cargo);

    // The IR is embedded, not read at runtime.
    assert!(main.contains("const IR_JSON: &str = r##\""), "{}", main);
    assert!(
        main.contains("include_str!(\"../migrations/001_create_todo.sql\")"),
        "{}",
        main
    );

    assert!(lowered.files.len() >= 4, "{:?}", lowered.files);
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn lowering_writes_the_migration_sql() {
    let out = temp_dir("migration");
    lower_service(IR, &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let sql =
        fs::read_to_string(out.join("migrations/001_create_todo.sql")).expect("migration exists");
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS Todo"), "{}", sql);
    assert!(sql.contains("id INTEGER PRIMARY KEY"), "{}", sql);
    assert!(sql.contains("title TEXT"), "{}", sql);
    assert!(sql.contains("done INTEGER DEFAULT 0"), "{}", sql);
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn lowering_is_deterministic() {
    let first = temp_dir("deterministic-a");
    let second = temp_dir("deterministic-b");
    lower_service(IR, &first, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    lower_service(IR, &second, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let a = fs::read_to_string(first.join("src/main.rs")).expect("main.rs exists");
    let b = fs::read_to_string(second.join("src/main.rs")).expect("main.rs exists");
    assert_eq!(a, b);
    let _ = fs::remove_dir_all(&first);
    let _ = fs::remove_dir_all(&second);
}

#[test]
fn lowering_rejects_a_bad_ir() {
    let out = temp_dir("bad");
    let error = lower_service("{\"ir\":\"9.9\"}", &out, &PathBuf::from("/tmp/dep-root"))
        .expect_err("a wrong IR version is rejected");
    assert!(error.contains("0.1"), "{}", error);
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn lowering_shares_one_pooled_database() {
    let out = temp_dir("pooled");
    lower_service(IR, &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let main = fs::read_to_string(out.join("src/main.rs")).expect("main.rs exists");
    let readme = fs::read_to_string(out.join("README.md")).expect("README.md exists");

    assert!(main.contains("PooledDb::open(&db_path)"), "{}", main);
    assert_eq!(main.matches("PooledDb::open(&db_path)").count(), 1);
    assert_eq!(main.matches(".with(|guard| {").count(), 5, "{}", main);
    assert!(!main.contains("Sqlite::open(&"), "{}", main);
    assert!(!main.contains("Arc<String>"), "{}", main);
    assert!(!main.contains("Arc::clone"), "{}", main);
    assert!(readme.contains("OPR_RATE_LIMIT"), "{}", readme);
    assert!(readme.contains("OPR_LOG_JSON"), "{}", readme);
    assert!(readme.contains("OPR_AUTH_TOKEN"), "{}", readme);
    assert!(readme.contains("OPR_CORS"), "{}", readme);
    assert!(readme.contains("OPR_ETAG"), "{}", readme);
    assert!(readme.contains("Accept-Encoding: gzip"), "{}", readme);
    assert!(
        readme.contains("Mutex-guarded SQLite connection"),
        "{}",
        readme
    );
    assert!(readme.contains("OPR_TLS"), "{}", readme);
    assert!(readme.contains("OPR_KEEPALIVE"), "{}", readme);
    assert!(readme.contains("OPR_WEBSOCKET"), "{}", readme);
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn the_default_dep_root_is_resolved_at_runtime() {
    let root = default_dep_root().expect("the workspace root is discovered");
    assert!(root.is_absolute(), "{}", root.display());
    assert!(root.join("opurom-server").is_dir(), "{}", root.display());
    assert!(root.join("opurom-db").is_dir(), "{}", root.display());
    // The resolved root is the workspace that holds this very crate, so it is
    // an ancestor of the manifest directory.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(
        manifest_dir.starts_with(&root),
        "{} is not under {}",
        manifest_dir.display(),
        root.display()
    );
}

#[test]
fn the_generated_readme_names_no_round_codename() {
    let out = temp_dir("readme-wording");
    lower_service(IR, &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let readme = fs::read_to_string(out.join("README.md")).expect("README.md exists");
    for needle in [
        "the async language layer",
        "the GPU and transport layer",
        "the native network layer",
        "the visual fidelity layer",
        "the production layer",
        "the component library hardening",
        "the integration layer",
        "Honest",
    ] {
        assert!(!readme.contains(needle), "{} in\n{}", needle, readme);
    }
    let _ = fs::remove_dir_all(&out);
}
