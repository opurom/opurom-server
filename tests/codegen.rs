//! Tests for the `opurom-serverc` lowering pass.
//!
//! The generated crate is checked for shape here; building and running it
//! against the sibling `opurom-db` is the integration step.

use std::fs;
use std::path::PathBuf;

use opurom_server::codegen::{default_dep_root, lower_service};

const IR: &str = r##"{
  "ir": "0.1.0",
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
  "theme": { "mode": "system", "accent": "#097FEB", "radius": 12 },
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
    assert!(error.contains("0.1.0"), "{}", error);
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

/// A forum-shaped IR: an account model (username + password) and a model with
/// an `attachment` field, so both conditional features must be lowered in.
const ACCOUNT_IR: &str = r##"{
  "ir": "0.1.0",
  "app": "Forum",
  "state": [],
  "tree": {
    "id": 0,
    "kind": "Column",
    "props": {},
    "children": [
      { "id": 1, "kind": "Text", "props": { "value": "Forum" }, "children": [], "events": {} }
    ],
    "events": {}
  },
  "theme": { "mode": "system", "accent": "#097FEB", "radius": 12 },
  "models": [
    { "name": "User", "fields": [
      { "name": "id", "type": "int", "primary": true, "default": null },
      { "name": "username", "type": "string", "primary": false, "default": null },
      { "name": "password", "type": "string", "primary": false, "default": null },
      { "name": "role", "type": "string", "primary": false, "default": "member" }
    ] },
    { "name": "Post", "fields": [
      { "name": "id", "type": "int", "primary": true, "default": null },
      { "name": "title", "type": "string", "primary": false, "default": null },
      { "name": "attachment", "type": "string", "primary": false, "default": "" }
    ] }
  ],
  "api": [
    { "path": "/users", "model": "User", "handlers": ["list", "create"] },
    { "path": "/users/:id", "model": "User", "handlers": ["get", "update", "delete"] },
    { "path": "/posts", "model": "Post", "handlers": ["list", "create"] },
    { "path": "/posts/:id", "model": "Post", "handlers": ["get", "update", "delete"] }
  ]
}"##;

#[test]
fn sessions_and_uploads_lower_only_when_declared() {
    let dir = temp_dir("account");
    let lowered =
        lower_service(ACCOUNT_IR, &dir, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let main = fs::read_to_string(dir.join("src/main.rs")).expect("main.rs exists");
    let readme = fs::read_to_string(dir.join("README.md")).expect("README exists");

    // Session login/logout, gate and role ladder are all present.
    assert!(
        main.contains("router.route(Method::Post, \"/sessions\""),
        "login route"
    );
    assert!(
        main.contains("router.route(Method::Delete, \"/sessions\""),
        "logout route"
    );
    assert!(
        main.contains("session::login_credentials"),
        "credential parsing"
    );
    assert!(
        main.contains("session::hash_password"),
        "digest verification"
    );
    assert!(main.contains("hash_registration"), "registration hashing");
    assert!(main.contains("constant_time_eq"), "constant-time compare");
    assert!(main.contains("sessions_enabled()"), "env opt-in");
    assert!(
        main.contains("session::session_gate"),
        "session gate in the chain"
    );
    assert!(main.contains("Role::Admin"), "admin gate on put/delete");
    assert!(main.contains("Role::Member"), "member gate on create");
    assert!(
        main.contains(
            "fn build_router(db: PooledDb, rooms: std::sync::Arc<opurom_server::RoomHub>, sessions: opurom_server::session::SessionStore)"
        ),
        "router takes the rooms and the store"
    );
    assert!(
        main.contains("request.path == \"/users\""),
        "registration path stays open"
    );

    // Uploads from the `attachment` field.
    assert!(
        main.contains("router.route(Method::Post, \"/uploads\""),
        "upload route"
    );
    assert!(
        main.contains("router.route(Method::Get, \"/uploads/:name\""),
        "serve route"
    );
    assert!(main.contains("upload::upload_dir_from_env"), "data dir");
    assert!(main.contains("upload::upload_response"), "store helper");
    assert!(main.contains("upload::download_response"), "serve helper");

    assert!(readme.contains("OPR_SESSION=1"), "session env documented");
    assert!(readme.contains("OPR_DATA"), "data env documented");
    assert!(readme.contains("POST /sessions"), "login route documented");
    assert!(readme.contains("POST /uploads"), "upload route documented");

    // The account model serializes through a password-free def: no digest in
    // any row response.
    assert!(main.contains("const MODEL_USER_PUB"), "pub def emitted");
    assert!(
        main.contains("row_to_json(MODEL_USER_PUB"),
        "handlers serialize without the password column"
    );
    let pub_block = main
        .split("const MODEL_USER_PUB")
        .nth(1)
        .expect("pub def block")
        .split("};")
        .next()
        .expect("def body");
    assert!(!pub_block.contains("password"), "digest column omitted");

    assert!(lowered.files.len() >= 4, "{:?}", lowered.files);
}

#[test]
fn plain_ir_keeps_its_default_routes() {
    // The todo IR has no account model and no attachment field: no session,
    // no uploads, no gate - the default service shape is unchanged.
    let dir = temp_dir("plain");
    lower_service(IR, &dir, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let main = fs::read_to_string(dir.join("src/main.rs")).expect("main.rs exists");
    let readme = fs::read_to_string(dir.join("README.md")).expect("README exists");

    assert!(!main.contains("/sessions"), "no login route");
    assert!(!main.contains("/uploads"), "no upload route");
    assert!(!main.contains("session_gate"), "no gate");
    assert!(!main.contains("sessions_enabled"), "no env check");
    assert!(!main.contains("ROLE_GATE"), "no unsubstituted placeholder");
    assert!(!main.contains("BODY_HOOK"), "no unsubstituted placeholder");
    assert!(!readme.contains("OPR_SESSION"), "no session docs");
    assert_eq!(
        main.matches(".with(|guard| {").count(),
        5,
        "the five CRUD handlers are unchanged"
    );
}

#[test]
fn lowering_quotes_reserved_identifiers() {
    // `User` folds to the reserved word `user`, so the migration and every
    // generated statement must quote it; plain names stay bare.
    let out = temp_dir("quoted");
    lower_service(ACCOUNT_IR, &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let migration =
        fs::read_to_string(out.join("migrations/001_create_user.sql")).expect("migration exists");
    assert!(
        migration.contains("CREATE TABLE IF NOT EXISTS \"User\""),
        "{}",
        migration
    );
    assert!(
        migration.contains("    id INTEGER PRIMARY KEY"),
        "{}",
        migration
    );

    let main = fs::read_to_string(out.join("src/main.rs")).expect("main.rs exists");
    // In generated source the SQL lives inside Rust string literals, so the
    // quotes around `User` appear escaped there.
    assert!(
        main.contains(r#"SELECT * FROM \"User\""#),
        "list/login select"
    );
    assert!(main.contains(r#"DELETE FROM \"User\""#), "delete");
    assert!(main.contains(r#"INSERT INTO \"User\""#), "create");
    assert!(main.contains(r#"UPDATE \"User\" SET"#), "update");
    assert!(
        main.contains(r#"next_id(guard, "\"User\"""#),
        "auto id probe"
    );
    // Non-keyword names keep their bare form for cross-repo assertions.
    assert!(
        main.contains("SELECT * FROM Post;"),
        "plain table stays bare"
    );
    assert!(!main.contains(r#"FROM \"Post\""#), "no needless quoting");
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn write_handlers_publish_change_events() {
    let out = temp_dir("change-events");
    lower_service(IR, &out, &PathBuf::from("/tmp/dep-root")).expect("lowering works");
    let main = fs::read_to_string(out.join("src/main.rs")).expect("main.rs exists");

    // One hub per service: the router publishes, the server delivers.
    assert!(
        main.contains("let rooms = std::sync::Arc::new(opurom_server::RoomHub::default());"),
        "hub created"
    );
    assert!(
        main.contains("build_router(pool, rooms.clone())"),
        "hub to router"
    );
    assert!(main.contains("server.with_rooms(rooms)"), "hub to server");
    assert!(
        main.contains("fn change_id(value: &DbValue) -> Json"),
        "id encoding"
    );

    // One event per write, after the database accepts it; reads stay silent.
    for op in ["insert", "update", "delete"] {
        assert!(
            main.contains(&format!(
                "publish_change(\"Todo\", \"{op}\", &change_id(&id_value))"
            )),
            "{op} publishes"
        );
    }
    assert_eq!(main.matches("publish_change(").count(), 3, "writes only");
    let _ = fs::remove_dir_all(&out);
}
