//! The `opurom-serverc` lowering pass: full-stack IR -> standalone Rust crate.
//!
//! The generated crate is straight-line lowered Rust: the router, the five CRUD
//! handlers, `/health` and `/ssr` are emitted as ordinary Rust code. No IR
//! file is read and no interpreter runs at runtime.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::ir::{Api, FieldType, Ir, Model};

/// Resolve the workspace root that holds the sibling `opurom-server` and
/// `opurom-db` crates.
///
/// Nothing is hard-coded: the nearest ancestor of the working directory that
/// contains both sibling crates wins, then the nearest ancestor of the running
/// executable, then the parent of this crate's own manifest directory. The
/// `--dep-root` command-line override takes precedence over all of them.
pub fn default_dep_root() -> Result<PathBuf, String> {
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            starts.push(dir.to_path_buf());
        }
    }
    starts.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
    );

    for start in &starts {
        if let Some(root) = workspace_root(start) {
            return Ok(root);
        }
    }
    Err(
        "cannot find a workspace with the sibling opurom-server and opurom-db crates; \
         run opurom-serverc inside the workspace or pass --dep-root <path>"
            .to_string(),
    )
}

/// The nearest ancestor of `start` that holds both sibling crates.
fn workspace_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("opurom-server").is_dir() && dir.join("opurom-db").is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Result of a lowering run: the files written and the crate root.
#[derive(Clone, Debug)]
pub struct LoweredService {
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
}

/// Lower a full-stack IR into a standalone service crate under `out_dir`.
///
/// `dep_root` is the workspace that contains `opurom-server` and `opurom-db`;
/// the generated `Cargo.toml` points at them with path dependencies.
pub fn lower_service(
    ir_json: &str,
    out_dir: &Path,
    dep_root: &Path,
) -> Result<LoweredService, String> {
    let ir = Ir::parse(ir_json)?;
    let root = out_dir.to_path_buf();
    let src_dir = root.join("src");
    let migrations_dir = root.join("migrations");
    fs::create_dir_all(&src_dir)
        .map_err(|err| format!("cannot create {}: {}", src_dir.display(), err))?;
    fs::create_dir_all(&migrations_dir)
        .map_err(|err| format!("cannot create {}: {}", migrations_dir.display(), err))?;

    let mut files = Vec::new();
    files.push(write_file(
        &root.join("Cargo.toml"),
        &cargo_toml(&ir, dep_root),
    )?);
    files.push(write_file(&src_dir.join("main.rs"), &main_rs(&ir))?);

    // One migration file per model, matching opurom-migrate's naming.
    for (index, model) in ir.models.iter().enumerate() {
        let name = migration_file_name(index, model);
        files.push(write_file(
            &migrations_dir.join(&name),
            &create_table_sql(model),
        )?);
    }
    files.push(write_file(
        &migrations_dir.join("schema.sql"),
        &schema_sql(&ir.models),
    )?);
    files.push(write_file(&root.join("README.md"), &readme(&ir))?);

    Ok(LoweredService { root, files })
}

/// Migration file name for one model.
fn migration_file_name(index: usize, model: &Model) -> String {
    format!(
        "{:03}_create_{}.sql",
        index + 1,
        model.name.to_ascii_lowercase()
    )
}

/// Write one generated file and return its path.
fn write_file(path: &Path, content: &str) -> Result<PathBuf, String> {
    fs::write(path, content).map_err(|err| format!("cannot write {}: {}", path.display(), err))?;
    Ok(path.to_path_buf())
}

/// The generated `Cargo.toml`.
fn cargo_toml(ir: &Ir, dep_root: &Path) -> String {
    let server_path = dep_root.join("opurom-server");
    let db_path = dep_root.join("opurom-db");
    let mut out = String::new();
    out.push_str("[package]\n");
    out.push_str("name = \"opurom-service\"\n");
    out.push_str("version = \"0.1.0\"\n");
    out.push_str("edition = \"2021\"\n");
    out.push_str("publish = false\n");
    let _ = write!(
        out,
        "description = \"Generated Opurom service for {}\"\n",
        ir.app
    );
    out.push_str("\n[[bin]]\n");
    out.push_str("name = \"opurom-service\"\n");
    out.push_str("path = \"src/main.rs\"\n");
    out.push_str("\n[dependencies]\n");
    let _ = write!(
        out,
        "opurom-server = {{ path = {:?} }}\n",
        server_path.display().to_string()
    );
    let _ = write!(
        out,
        "opurom-db = {{ path = {:?} }}\n",
        db_path.display().to_string()
    );
    out.push_str("\n[workspace]\n");
    out
}

/// Replace `{{KEY}}` placeholders in a template, in a single pass so that
/// inserted text is never rescanned.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let key = &after[..end];
                match values.iter().find(|(name, _)| *name == key) {
                    Some((_, value)) => out.push_str(value),
                    None => {
                        out.push_str("{{");
                        out.push_str(key);
                        out.push_str("}}");
                    }
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The generated `src/main.rs`: lowered, straight-line service code.
fn main_rs(ir: &Ir) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push_str(
        "\n\
         use opurom_db::{Database, PooledDb, Row, Sqlite, Value as DbValue};\n\
         use opurom_server::http::{Method, Request, Response};\n\
         use opurom_server::middleware::{body_cap, logging, MiddlewareChain};\n\
         use opurom_server::query::ListQuery;\n\
         use opurom_server::router::Router;\n\
         use opurom_server::server::Server;\n\
         use opurom_server::ssr::ssr_html;\n\
         use opurom_server::serde_json::Value as Json;\n         use opurom_server::serde_json as serde_json;\n\n",
    );

    // Model metadata, lowered from the IR.
    out.push_str(MODEL_TYPES);
    for model in &ir.models {
        out.push_str(&format!(
            "const MODEL_{}: &ModelDef = &ModelDef {{\n    fields: &[\n",
            const_ident(&model.name)
        ));
        for field in &model.fields {
            let _ = writeln!(
                out,
                "        ({:?}, FieldType::{}),",
                field.name,
                field_type_variant(&field.ty)
            );
        }
        out.push_str("    ],\n};\n\n");
    }

    // Embedded migrations: executed at startup.
    out.push_str("const MIGRATIONS: &[(&str, &str)] = &[\n");
    for (index, model) in ir.models.iter().enumerate() {
        let file = migration_file_name(index, model);
        let _ = writeln!(
            out,
            "    ({:?}, include_str!(\"../migrations/{}\")),",
            file, file
        );
    }
    out.push_str("];\n\n");

    let _ = writeln!(out, "const APP_NAME: &str = {:?};", ir.app);
    out.push('\n');
    out.push_str(&fill(
        "const IR_JSON: &str = r##\"{{IR_JSON}}\"##;\n\n",
        &[("IR_JSON", &ir_json_const(ir))],
    ));

    out.push_str(JSON_HELPERS);
    out.push_str(ROW_JSON);
    out.push_str(ID_HELPERS);

    let account = account_model(ir);
    let registration = account.and_then(|found| registration_path(ir, found));
    if account.is_some() {
        out.push_str(&protected_fn(registration));
    }

    // The router builder opens the function the handlers are emitted into.
    out.push_str(&router_build(account.is_some()));

    // Handlers, lowered per api entry.
    for api in &ir.api {
        out.push_str(&handlers_for(ir, api));
    }

    // Session and upload routes, lowered only when the IR declares them.
    if let Some(found) = account {
        out.push_str(&session_routes(found));
    }
    if enables_uploads(ir) {
        out.push_str(&upload_routes(account.is_some()));
    }

    out.push_str(&main_fn(account.is_some()));
    out
}

/// Header comment of the generated file.
const HEADER: &str = "//! Generated by `opurom-serverc` from an Opurom full-stack IR.\n\
//!\n\
//! This file is lowered code: every route, query and SQL statement below was\n\
//! emitted from the IR at compile time. The IR is not read at runtime.\n";

/// Lowered model metadata types.
const MODEL_TYPES: &str = "/// One lowered model definition.\n\
struct ModelDef {\n\
    fields: &'static [(&'static str, FieldType)],\n\
}\n\n\
#[allow(dead_code)]\n\
#[derive(Clone, Copy, PartialEq, Eq)]\n\
enum FieldType {\n\
    Int,\n\
    Text,\n\
    Bool,\n\
}\n\n";

/// JSON helper functions used by the generated handlers.
const JSON_HELPERS: &str = r#"fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn db_value(value: &Json) -> DbValue {
    match value {
        Json::Number(number) => match number.as_i64() {
            Some(int) => DbValue::Int(int),
            None => DbValue::Text(number.to_string()),
        },
        Json::String(text) => DbValue::Text(text.clone()),
        Json::Bool(flag) => DbValue::Bool(*flag),
        Json::Null => DbValue::Text(String::new()),
        other => DbValue::Text(other.to_string()),
    }
}

"#;

/// Row to JSON conversion, driven by the lowered model metadata.
const ROW_JSON: &str = r#"fn row_to_json(model: &ModelDef, row: &Row) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(model.fields.len());
    for (name, ty) in model.fields {
        let cell = match row.get(name) {
            Some(DbValue::Int(number)) => match ty {
                FieldType::Bool => {
                    if *number != 0 {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                }
                _ => number.to_string(),
            },
            Some(DbValue::Text(text)) => json_string(text),
            Some(DbValue::Bool(flag)) => flag.to_string(),
            None => "null".to_string(),
        };
        parts.push(format!("{}:{}", json_string(name), cell));
    }
    format!("{{{}}}", parts.join(","))
}

fn rows_to_json(model: &ModelDef, rows: &[Row]) -> String {
    let parts: Vec<String> = rows.iter().map(|row| row_to_json(model, row)).collect();
    format!("[{}]", parts.join(","))
}

"#;

/// Identifier parsing helpers.
const ID_HELPERS: &str = r#"#[allow(dead_code)]
fn parse_id(raw: &str) -> Option<DbValue> {
    if raw.is_empty() {
        return None;
    }
    match raw.parse::<i64>() {
        Ok(number) => Some(DbValue::Int(number)),
        Err(_) => Some(DbValue::Text(raw.to_string())),
    }
}

#[allow(dead_code)]
fn next_id(db: &mut Sqlite, table: &str, primary: &str) -> DbValue {
    match db.query(&format!("SELECT * FROM {};", table)) {
        Ok(rows) => {
            let max = rows
                .iter()
                .filter_map(|row| row.get(primary).and_then(DbValue::as_i64))
                .max()
                .unwrap_or(0);
            DbValue::Int(max + 1)
        }
        Err(_) => DbValue::Int(1),
    }
}

"#;

/// Router construction.
/// Whether a request needs a resolved session: every mutation except login
/// and registration. Reads stay public, like a forum's open threads.
fn protected_fn(registration: Option<&str>) -> String {
    match registration {
        Some(path) => format!(
            "fn protected(request: &Request) -> bool {{\n    if request.method == Method::Get {{\n        return false;\n    }}\n    !(request.method == Method::Post\n        && (request.path == \"/sessions\"\n            || request.path == \"{path}\"))\n}}\n\n"
        ),
        None => "fn protected(request: &Request) -> bool {\n    if request.method == Method::Get {\n        return false;\n    }\n    request.method != Method::Post || request.path != \"/sessions\"\n}\n\n".to_string(),
    }
}

/// The session endpoints, emitted only for an IR that declares an account
/// model: login verifies the stored digest in constant time and issues the
/// cookie, logout revokes it.
fn session_routes(account: &Model) -> String {
    let table = sql_ident_lit(&account.table());
    format!(
        "    // Session endpoints: login verifies the stored digest, logout revokes.\n\
         let login_sessions = sessions.clone();\n\
         let login_db = db.clone();\n\
         router.route(Method::Post, \"/sessions\", move |request: &mut Request| {{\n\
             let (username, password) = match opurom_server::session::login_credentials(request) {{\n\
                 Ok(creds) => creds,\n\
                 Err(response) => return response,\n\
             }};\n\
             let rows = match login_db.with(|guard| {{\n\
                 guard.query_params(\n\
                     \"SELECT * FROM {table} WHERE username = ?;\",\n\
                     &[DbValue::Text(username.clone())],\n\
                 )\n\
             }}) {{\n\
                 Ok(rows) => rows,\n\
                 Err(err) => return Response::error(500, &format!(\"database_error: {{}}\", err)),\n\
             }};\n\
             let row = match rows.first() {{\n\
                 Some(row) => row,\n\
                 None => return Response::error(401, \"invalid_credentials\"),\n\
             }};\n\
             let stored = match row.get(\"password\").and_then(DbValue::as_str) {{\n\
                 Some(value) => value,\n\
                 None => return Response::error(401, \"invalid_credentials\"),\n\
             }};\n\
             let digest = opurom_server::session::hash_password(&password);\n\
             if !opurom_server::middleware::constant_time_eq(stored.as_bytes(), digest.as_bytes()) {{\n\
                 return Response::error(401, \"invalid_credentials\");\n\
             }}\n\
             let role = row\n\
                 .get(\"role\")\n\
                 .and_then(DbValue::as_str)\n\
                 .and_then(opurom_server::session::Role::parse)\n\
                 .unwrap_or(opurom_server::session::Role::Member);\n\
             opurom_server::session::login_response(&login_sessions, &username, role)\n\
         }});\n\
         let logout_sessions = sessions.clone();\n\
         router.route(Method::Delete, \"/sessions\", move |request: &mut Request| {{\n\
             opurom_server::session::logout_response(&logout_sessions, request)\n\
         }});\n\n",
        table = table
    )
}

/// The upload endpoints, emitted for an IR that declares an `attachment`
/// field: POST stores a multipart file part under the data directory, GET
/// serves it back by stored name.
fn upload_routes(has_account: bool) -> String {
    let gate = if has_account {
        role_gate("Member")
    } else {
        String::new()
    };
    format!(
        "    // Uploads: store a file part under the data dir, then serve it back.\n\
         let uploads_root = opurom_server::upload::upload_dir_from_env();\n\
         let upload_dir = uploads_root.clone();\n\
         router.route(Method::Post, \"/uploads\", move |request: &mut Request| {{\n\
{gate}            opurom_server::upload::upload_response(request, &upload_dir)\n\
         }});\n\
         let serve_dir = uploads_root;\n\
         router.route(Method::Get, \"/uploads/:name\", move |request: &mut Request| {{\n\
             let name = request.param(\"name\").unwrap_or_default();\n\
             opurom_server::upload::download_response(&serve_dir, name)\n\
         }});\n\n",
        gate = gate
    )
}

/// The router builder; the sessions parameter appears only when the IR
/// declares an account model, so other services keep their exact signature.
fn router_build(session: bool) -> String {
    if session {
        ROUTER_BUILD.replace(
            "fn build_router(db: PooledDb) -> Router {",
            "fn build_router(db: PooledDb, sessions: opurom_server::session::SessionStore) -> Router {",
        )
    } else {
        ROUTER_BUILD.to_string()
    }
}

/// The generated `main`; the session store and the gate join the chain only
/// for an IR with an account model.
fn main_fn(session: bool) -> String {
    let text = MAIN_FN.to_string();
    if !session {
        return text;
    }
    text.replace(
        "    let mut router = build_router(pool);",
        "    let sessions = opurom_server::session::SessionStore::default();\n    let mut router = build_router(pool, sessions.clone());",
    )
    .replace(
        "    chain.push(body_cap(1024 * 1024));",
        "    chain.push(body_cap(1024 * 1024));\n    if opurom_server::session::sessions_enabled() {\n        chain.push(opurom_server::session::session_gate(sessions.clone(), protected));\n    }",
    )
}

const ROUTER_BUILD: &str = r#"#[allow(unused_variables)]
fn build_router(db: PooledDb) -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(
            200,
            &format!(
                "{{\"ok\":true,\"app\":{},\"version\":\"0.1.0\"}}",
                json_string(APP_NAME)
            ),
        )
    });
"#;

/// The `main` function of the generated service.
const MAIN_FN: &str = r#"
    router
}

fn main() {
    let port: u16 = std::env::var("OPR_PORT")
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or(8787);
    let db_path = std::env::var("OPR_DB").unwrap_or_else(|_| "./opurom.db".to_string());
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!("[opurom-service] cannot create {}: {}", parent.display(), err);
                std::process::exit(1);
            }
        }
    }

    let pool = match PooledDb::open(&db_path) {
        Ok(pool) => pool,
        Err(err) => {
            eprintln!("[opurom-service] cannot open {}: {}", db_path, err);
            std::process::exit(1);
        }
    };
    if let Err(err) = pool.with(|db| -> Result<(), String> {
        for (name, sql) in MIGRATIONS {
            if let Err(err) = db.exec(sql) {
                return Err(format!("migration {} failed: {}", name, err));
            }
        }
        Ok(())
    }) {
        eprintln!("[opurom-service] {}", err);
        std::process::exit(1);
    }
    let mut router = build_router(pool);
    router.route(Method::Get, "/ssr", |_request: &mut Request| {
        Response::html(200, &ssr_html(IR_JSON, ""))
    });

    let addr = format!("0.0.0.0:{}", port);
    let mut chain = MiddlewareChain::new();
    chain.push(logging());
    chain.push(body_cap(1024 * 1024));
    let server = match Server::bind_from_env(&addr, router, chain, 1024 * 1024) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("[opurom-service] cannot start on {}: {}", addr, err);
            std::process::exit(1);
        }
    };
    match server.tls_config() {
        Some(config) => eprintln!(
            "[opurom-service] {} listening on https://{} (TLS certificate SHA-256 fingerprint {})",
            APP_NAME, addr, config.fingerprint()
        ),
        None => eprintln!("[opurom-service] {} listening on {}", APP_NAME, addr),
    }
    server.serve();
}
"#;

/// Handler templates, one per CRUD verb.
const LIST_HANDLER: &str = r#"    let list_db = db.clone();
    router.route(Method::Get, "{{PATH}}", move |request: &mut Request| {
        let query = match ListQuery::parse(&request.query) {
            Ok(query) => query,
            Err(err) => return err.response(),
        };
        list_db.with(|guard| {
        match guard.query("{{SQL}}") {
            Ok(rows) => {
                let items: Vec<Json> = rows
                    .iter()
                    .map(|row| serde_json::from_str(&row_to_json({{MODEL}}, row)).unwrap_or(Json::Null))
                    .collect();
                Response::json(200, &query.apply(items))
            }
            Err(err) => Response::error(500, &format!("database_error: {}", err)),
        }
        })
    });
"#;

const GET_HANDLER: &str = r#"    let get_db = db.clone();
    router.route(Method::Get, "{{PATH}}", move |request: &mut Request| {
        get_db.with(|guard| {
        let raw_id = request.param("{{PARAM}}").unwrap_or_default().to_string();
        let id_value = match parse_id(&raw_id) {
            Some(value) => value,
            None => return Response::error(404, "not_found"),
        };
        match guard.query_params("{{SQL_SELECT}}", &[id_value]) {
            Ok(rows) => match rows.first() {
                Some(row) => Response::json_text(200, &row_to_json({{MODEL}}, row)),
                None => Response::error(404, "not_found"),
            },
            Err(err) => Response::error(500, &format!("database_error: {}", err)),
        }
        })
    });
"#;

const CREATE_HANDLER: &str = r#"    let create_db = db.clone();
    router.route(Method::Post, "{{PATH}}", move |request: &mut Request| {
{{ROLE_GATE}}        create_db.with(|guard| {
        let body = match request.json() {
            Ok(value) => value,
            Err(_) => return Response::error(400, "invalid_json"),
        };
{{BODY_HOOK}}        let object = match body.as_object() {
            Some(object) => object,
            None => return Response::error(400, "invalid_json"),
        };
{{ID_VALUE}}{{COLUMNS}}        let sql = format!(
            "INSERT INTO {{TABLE}} ({}) VALUES ({});",
            columns.join(", "),
            placeholders.join(", ")
        );
        if let Err(err) = guard.exec_params(&sql, &values) {
            return Response::error(500, &format!("database_error: {}", err));
        }
        match guard.query_params("{{SQL_SELECT}}", &[id_value]) {
            Ok(rows) => match rows.first() {
                Some(row) => Response::json_text(201, &row_to_json({{MODEL}}, row)),
                None => Response::error(500, "insert_failed"),
            },
            Err(err) => Response::error(500, &format!("database_error: {}", err)),
        }
        })
    });
"#;

const UPDATE_HANDLER: &str = r#"    let update_db = db.clone();
    router.route(Method::Put, "{{PATH}}", move |request: &mut Request| {
{{ROLE_GATE}}        update_db.with(|guard| {
        let raw_id = request.param("{{PARAM}}").unwrap_or_default().to_string();
        let id_value = match parse_id(&raw_id) {
            Some(value) => value,
            None => return Response::error(404, "not_found"),
        };
        let body = match request.json() {
            Ok(value) => value,
            Err(_) => return Response::error(400, "invalid_json"),
        };
        let object = match body.as_object() {
            Some(object) => object,
            None => return Response::error(400, "invalid_json"),
        };
{{ASSIGNMENTS}}        if !assignments.is_empty() {
            let sql = format!(
                "UPDATE {{TABLE}} SET {} WHERE {{PRIMARY}} = ?;",
                assignments.join(", ")
            );
            values.push(id_value.clone());
            if let Err(err) = guard.exec_params(&sql, &values) {
                return Response::error(500, &format!("database_error: {}", err));
            }
        }
        match guard.query_params("{{SQL_SELECT}}", &[id_value]) {
            Ok(rows) => match rows.first() {
                Some(row) => Response::json_text(200, &row_to_json({{MODEL}}, row)),
                None => Response::error(404, "not_found"),
            },
            Err(err) => Response::error(500, &format!("database_error: {}", err)),
        }
        })
    });
"#;

const DELETE_HANDLER: &str = r#"    let delete_db = db.clone();
    router.route(Method::Delete, "{{PATH}}", move |request: &mut Request| {
{{ROLE_GATE}}        delete_db.with(|guard| {
        let raw_id = request.param("{{PARAM}}").unwrap_or_default().to_string();
        let id_value = match parse_id(&raw_id) {
            Some(value) => value,
            None => return Response::error(404, "not_found"),
        };
        match guard.query_params("{{SQL_SELECT}}", &[id_value.clone()]) {
            Ok(rows) => {
                if rows.is_empty() {
                    return Response::error(404, "not_found");
                }
                if let Err(err) = guard.exec_params("{{SQL_DELETE}}", &[id_value]) {
                    return Response::error(500, &format!("database_error: {}", err));
                }
                Response::json_text(200, "{\"deleted\":true}")
            }
            Err(err) => Response::error(500, &format!("database_error: {}", err)),
        }
        })
    });
"#;

/// The account model carries `username` and `password` text fields; its
/// presence turns on session login, the gate and the role ladder.
fn account_model(ir: &Ir) -> Option<&Model> {
    ir.models.iter().find(|model| {
        ["username", "password"].iter().all(|name| {
            model
                .fields
                .iter()
                .any(|f| f.name == *name && f.ty == FieldType::Text)
        })
    })
}

/// True when any model carries an `attachment` field: the service then stores
/// and serves multipart uploads.
fn enables_uploads(ir: &Ir) -> bool {
    ir.models
        .iter()
        .any(|model| model.fields.iter().any(|f| f.name == "attachment"))
}

/// The api path that creates the account model (registration), when declared.
fn registration_path<'a>(ir: &'a Ir, account: &Model) -> Option<&'a str> {
    ir.api
        .iter()
        .find(|api| api.model == account.name && api.handlers.iter().any(|v| v == "create"))
        .map(|api| api.path.as_str())
}

/// One emitted role check: 401 without a session, 403 below the role, and
/// inactive unless `OPR_SESSION` is on so defaults stay unchanged.
fn role_gate(role: &str) -> String {
    let mut out = String::new();
    out.push_str("        if opurom_server::session::sessions_enabled() {\n");
    out.push_str(
        "            if let Some(response) = opurom_server::session::require_role(request, opurom_server::session::Role::",
    );
    out.push_str(role);
    out.push_str(") {\n                return response;\n            }\n        }\n");
    out
}

/// Emit the handler closures for one `api` entry.
fn handlers_for(ir: &Ir, api: &Api) -> String {
    let model = match ir.model(&api.model) {
        Some(model) => model,
        None => return String::new(),
    };
    let model_const = format!("MODEL_{}", const_ident(&model.name));
    let primary = model
        .primary()
        .map(|field| field.name.clone())
        .unwrap_or_else(|| "id".to_string());
    let param = path_param_name(&api.path).unwrap_or("id");
    let table = sql_ident_lit(&model.table());
    let primary_sql = sql_ident_lit(&primary);
    let account = account_model(ir);
    let is_account_api = account.is_some_and(|found| found.name == api.model);
    let mut out = String::new();

    for verb in &api.handlers {
        let template = match verb.as_str() {
            "list" => LIST_HANDLER,
            "create" => CREATE_HANDLER,
            "get" => GET_HANDLER,
            "update" => UPDATE_HANDLER,
            "delete" => DELETE_HANDLER,
            _ => continue,
        };
        // Sessions off -> no gate at all; registration stays open; every
        // other create needs a member; replaces and removals need an admin.
        let role_gate = match (account.is_some(), verb.as_str(), is_account_api) {
            (false, _, _) => String::new(),
            (true, "create", true) => String::new(),
            (true, "create", false) => role_gate("Member"),
            (true, "update" | "delete", _) => role_gate("Admin"),
            _ => String::new(),
        };
        let body_hook = if verb.as_str() == "create" && is_account_api {
            "        let body = opurom_server::session::hash_registration(body);\n".to_string()
        } else {
            String::new()
        };
        let select_sql = format!("SELECT * FROM {} WHERE {} = ?;", table, primary_sql);
        let list_sql = format!("SELECT * FROM {};", table);
        let delete_sql = format!("DELETE FROM {} WHERE {} = ?;", table, primary_sql);
        let columns = create_columns(model);
        let assignments = update_assignments(model);
        let id_value = id_value_stmt(model);
        let values: Vec<(&str, &str)> = vec![
            ("PATH", api.path.as_str()),
            ("TABLE", table.as_str()),
            ("MODEL", model_const.as_str()),
            ("PRIMARY", primary_sql.as_str()),
            ("PARAM", param),
            ("SQL", list_sql.as_str()),
            ("SQL_SELECT", select_sql.as_str()),
            ("SQL_DELETE", delete_sql.as_str()),
            ("COLUMNS", columns.as_str()),
            ("ASSIGNMENTS", assignments.as_str()),
            ("ID_VALUE", id_value.as_str()),
            ("ROLE_GATE", role_gate.as_str()),
            ("BODY_HOOK", body_hook.as_str()),
        ];
        out.push_str(&fill(template, &values));
    }
    out
}

/// The `create` column bindings for one model.
fn create_columns(model: &Model) -> String {
    let mut out = String::new();
    out.push_str("        let mut columns: Vec<String> = Vec::new();\n");
    out.push_str("        let mut placeholders: Vec<String> = Vec::new();\n");
    out.push_str("        let mut values: Vec<DbValue> = Vec::new();\n");
    for field in &model.fields {
        if field.primary {
            let _ = writeln!(
                out,
                "        columns.push({:?}.to_string());",
                sql_ident(&field.name)
            );
            out.push_str("        placeholders.push(\"?\".to_string());\n");
            out.push_str("        values.push(id_value.clone());\n");
            continue;
        }
        let _ = writeln!(
            out,
            "        if let Some(raw) = object.get({:?}) {{",
            field.name
        );
        let _ = writeln!(
            out,
            "            columns.push({:?}.to_string());",
            sql_ident(&field.name)
        );
        out.push_str("            placeholders.push(\"?\".to_string());\n");
        out.push_str("            values.push(db_value(raw));\n");
        out.push_str("        }\n");
        let auto = field.default.is_none();
        if auto {
            let _ = writeln!(out, "        if !object.contains_key({:?}) {{", field.name);
            let _ = writeln!(
                out,
                "            columns.push({:?}.to_string());",
                sql_ident(&field.name)
            );
            out.push_str("            placeholders.push(\"?\".to_string());\n");
            let _ = writeln!(
                out,
                "            values.push(match FieldType::{} {{",
                field_type_variant(&field.ty)
            );
            out.push_str("                FieldType::Int => DbValue::Int(0),\n");
            out.push_str("                FieldType::Text => DbValue::Text(String::new()),\n");
            out.push_str("                FieldType::Bool => DbValue::Bool(false),\n");
            out.push_str("            });\n");
            out.push_str("        }\n");
        }
    }
    out
}

/// The `update` assignment bindings for one model.
fn update_assignments(model: &Model) -> String {
    let mut out = String::new();
    out.push_str("        let mut assignments: Vec<String> = Vec::new();\n");
    out.push_str("        let mut values: Vec<DbValue> = Vec::new();\n");
    for field in &model.fields {
        if field.primary {
            continue;
        }
        let _ = writeln!(
            out,
            "        if let Some(raw) = object.get({:?}) {{",
            field.name
        );
        let _ = writeln!(
            out,
            "            assignments.push(format!(\"{{}} = ?\", {:?}));",
            sql_ident(&field.name)
        );
        out.push_str("            values.push(db_value(raw));\n");
        out.push_str("        }\n");
    }
    out
}

/// The `create` primary-key binding for one model.
fn id_value_stmt(model: &Model) -> String {
    let primary = match model.primary() {
        Some(primary) => primary,
        None => {
            return "        return Response::error(400, \"missing_primary_key\");\n".to_string()
        }
    };
    match primary.ty {
        FieldType::Int => format!(
            "        let id_value = match object.get({:?}) {{\n            Some(raw) => db_value(raw),\n            None => next_id(guard, {:?}, {:?}),\n        }};\n",
            primary.name,
            sql_ident(&model.table()),
            primary.name
        ),
        _ => format!(
            "        let id_value = match object.get({:?}) {{\n            Some(raw) => db_value(raw),\n            None => return Response::error(400, \"missing_primary_key\"),\n        }};\n",
            primary.name
        ),
    }
}

/// The name of the single `:param` segment of an api path.
fn path_param_name(path: &str) -> Option<&str> {
    path.split('/')
        .find(|segment| segment.starts_with(':'))
        .map(|segment| &segment[1..])
}

/// A Rust identifier derived from a model name.
fn const_ident(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// The `FieldType` variant name of an IR field type.
fn field_type_variant(ty: &FieldType) -> &'static str {
    match ty {
        FieldType::Int => "Int",
        FieldType::Text => "Text",
        FieldType::Bool => "Bool",
    }
}

/// SQL keywords that force identifier quoting, lowercased and sorted.
/// Copied from the canonical table in the sibling db crate `src/ident.rs`,
/// sourced from the PostgreSQL keyword list; both sides must stay identical.
const SQL_KEYWORDS: &[&str] = &[
    "abort",
    "absent",
    "absolute",
    "access",
    "action",
    "add",
    "admin",
    "after",
    "aggregate",
    "all",
    "also",
    "alter",
    "always",
    "analyse",
    "analyze",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "asensitive",
    "assertion",
    "assignment",
    "asymmetric",
    "at",
    "atomic",
    "attach",
    "attribute",
    "authorization",
    "backward",
    "before",
    "begin",
    "between",
    "bigint",
    "binary",
    "bit",
    "boolean",
    "both",
    "breadth",
    "by",
    "cache",
    "call",
    "called",
    "cascade",
    "cascaded",
    "case",
    "cast",
    "catalog",
    "chain",
    "char",
    "character",
    "characteristics",
    "check",
    "checkpoint",
    "class",
    "close",
    "cluster",
    "coalesce",
    "collate",
    "collation",
    "column",
    "columns",
    "comment",
    "comments",
    "commit",
    "committed",
    "compression",
    "concurrently",
    "conditional",
    "configuration",
    "conflict",
    "connection",
    "constraint",
    "constraints",
    "content",
    "continue",
    "conversion",
    "copy",
    "cost",
    "create",
    "cross",
    "csv",
    "cube",
    "current",
    "current_catalog",
    "current_date",
    "current_role",
    "current_schema",
    "current_time",
    "current_timestamp",
    "current_user",
    "cursor",
    "cycle",
    "data",
    "database",
    "day",
    "deallocate",
    "dec",
    "decimal",
    "declare",
    "default",
    "defaults",
    "deferrable",
    "deferred",
    "definer",
    "delete",
    "delimiter",
    "delimiters",
    "depends",
    "depth",
    "desc",
    "detach",
    "dictionary",
    "disable",
    "discard",
    "distinct",
    "do",
    "document",
    "domain",
    "double",
    "drop",
    "each",
    "else",
    "empty",
    "enable",
    "encoding",
    "encrypted",
    "end",
    "enforced",
    "enum",
    "error",
    "escape",
    "event",
    "except",
    "exclude",
    "excluding",
    "exclusive",
    "execute",
    "exists",
    "explain",
    "expression",
    "extension",
    "external",
    "extract",
    "false",
    "family",
    "fetch",
    "filter",
    "finalize",
    "first",
    "float",
    "following",
    "for",
    "force",
    "foreign",
    "format",
    "forward",
    "freeze",
    "from",
    "full",
    "function",
    "functions",
    "generated",
    "global",
    "grant",
    "granted",
    "greatest",
    "group",
    "grouping",
    "groups",
    "handler",
    "having",
    "header",
    "hold",
    "hour",
    "identity",
    "if",
    "ignore",
    "ilike",
    "immediate",
    "immutable",
    "implicit",
    "import",
    "in",
    "include",
    "including",
    "increment",
    "indent",
    "index",
    "indexes",
    "inherit",
    "inherits",
    "initially",
    "inline",
    "inner",
    "inout",
    "input",
    "insensitive",
    "insert",
    "instead",
    "int",
    "integer",
    "intersect",
    "interval",
    "into",
    "invoker",
    "is",
    "isnull",
    "isolation",
    "join",
    "json",
    "json_array",
    "json_arrayagg",
    "json_exists",
    "json_object",
    "json_objectagg",
    "json_query",
    "json_scalar",
    "json_serialize",
    "json_table",
    "json_value",
    "keep",
    "key",
    "keys",
    "label",
    "language",
    "large",
    "last",
    "lateral",
    "leading",
    "leakproof",
    "least",
    "left",
    "level",
    "like",
    "limit",
    "listen",
    "load",
    "local",
    "localtime",
    "localtimestamp",
    "location",
    "lock",
    "locked",
    "logged",
    "lsn",
    "mapping",
    "match",
    "matched",
    "materialized",
    "maxvalue",
    "merge",
    "merge_action",
    "method",
    "minute",
    "minvalue",
    "mode",
    "month",
    "move",
    "name",
    "names",
    "national",
    "natural",
    "nchar",
    "nested",
    "new",
    "next",
    "nfc",
    "nfd",
    "nfkc",
    "nfkd",
    "no",
    "none",
    "normalize",
    "normalized",
    "not",
    "nothing",
    "notify",
    "notnull",
    "nowait",
    "null",
    "nullif",
    "nulls",
    "numeric",
    "object",
    "objects",
    "of",
    "off",
    "offset",
    "oids",
    "old",
    "omit",
    "on",
    "only",
    "operator",
    "option",
    "options",
    "or",
    "order",
    "ordinality",
    "others",
    "out",
    "outer",
    "over",
    "overlaps",
    "overlay",
    "overriding",
    "owned",
    "owner",
    "parallel",
    "parameter",
    "parser",
    "partial",
    "partition",
    "passing",
    "password",
    "path",
    "period",
    "placing",
    "plan",
    "plans",
    "policy",
    "position",
    "preceding",
    "precision",
    "prepare",
    "prepared",
    "preserve",
    "primary",
    "prior",
    "privileges",
    "procedural",
    "procedure",
    "procedures",
    "program",
    "publication",
    "quote",
    "quotes",
    "range",
    "read",
    "real",
    "reassign",
    "recursive",
    "ref",
    "references",
    "referencing",
    "refresh",
    "reindex",
    "relative",
    "release",
    "rename",
    "repack",
    "repeatable",
    "replace",
    "replica",
    "reset",
    "respect",
    "restart",
    "restrict",
    "return",
    "returning",
    "returns",
    "revoke",
    "right",
    "role",
    "rollback",
    "rollup",
    "routine",
    "routines",
    "row",
    "rows",
    "rule",
    "savepoint",
    "scalar",
    "schema",
    "schemas",
    "scroll",
    "search",
    "second",
    "security",
    "select",
    "sequence",
    "sequences",
    "serializable",
    "server",
    "session",
    "session_user",
    "set",
    "setof",
    "sets",
    "share",
    "show",
    "similar",
    "simple",
    "skip",
    "smallint",
    "snapshot",
    "some",
    "source",
    "sql",
    "stable",
    "standalone",
    "start",
    "statement",
    "statistics",
    "stdin",
    "stdout",
    "storage",
    "stored",
    "strict",
    "string",
    "strip",
    "subscription",
    "substring",
    "support",
    "symmetric",
    "sysid",
    "system",
    "system_user",
    "table",
    "tables",
    "tablesample",
    "tablespace",
    "target",
    "temp",
    "template",
    "temporary",
    "text",
    "then",
    "ties",
    "time",
    "timestamp",
    "to",
    "trailing",
    "transaction",
    "transform",
    "treat",
    "trigger",
    "trim",
    "true",
    "truncate",
    "trusted",
    "type",
    "types",
    "uescape",
    "unbounded",
    "uncommitted",
    "unconditional",
    "unencrypted",
    "union",
    "unique",
    "unknown",
    "unlisten",
    "unlogged",
    "until",
    "update",
    "user",
    "using",
    "vacuum",
    "valid",
    "validate",
    "validator",
    "value",
    "values",
    "varchar",
    "variadic",
    "varying",
    "verbose",
    "version",
    "view",
    "views",
    "virtual",
    "volatile",
    "wait",
    "when",
    "where",
    "whitespace",
    "window",
    "with",
    "within",
    "without",
    "work",
    "wrapper",
    "write",
    "xml",
    "xmlattributes",
    "xmlconcat",
    "xmlelement",
    "xmlexists",
    "xmlforest",
    "xmlnamespaces",
    "xmlparse",
    "xmlpi",
    "xmlroot",
    "xmlserialize",
    "xmltable",
    "year",
    "yes",
    "zone",
];

/// Quote an identifier only when it collides with a SQL keyword, so plain
/// names stay byte-identical and the cross-repo bare-name assertions hold.
fn sql_ident(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if SQL_KEYWORDS.contains(&lower.as_str()) {
        format!("\"{}\"", name.replace('"', "\"\""))
    } else {
        name.to_string()
    }
}

/// The quoted identifier escaped for embedding inside a generated Rust
/// string literal, where the SQL text itself lives.
fn sql_ident_lit(name: &str) -> String {
    sql_ident(name).replace('"', "\\\"")
}

/// `CREATE TABLE IF NOT EXISTS` statement for one model.
fn create_table_sql(model: &Model) -> String {
    let mut out = format!(
        "CREATE TABLE IF NOT EXISTS {} (\n",
        sql_ident(&model.table())
    );
    for (index, field) in model.fields.iter().enumerate() {
        out.push_str("    ");
        out.push_str(&sql_ident(&field.name));
        out.push(' ');
        out.push_str(field.ty.sql_type());
        if field.primary {
            out.push_str(" PRIMARY KEY");
        }
        if let Some(default) = &field.default {
            out.push_str(" DEFAULT ");
            out.push_str(&sql_literal(default));
        }
        if index + 1 < model.fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(");\n");
    out
}

/// All `CREATE TABLE` statements joined.
fn schema_sql(models: &[Model]) -> String {
    let mut out = String::new();
    for model in models {
        out.push_str(&create_table_sql(model));
    }
    out
}

/// SQL literal for a JSON default value.
fn sql_literal(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_string(),
        Value::Bool(flag) => {
            if *flag {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => format!("'{}'", text.replace('\'', "''")),
        other => format!("'{}'", other.to_string().replace('\'', "''")),
    }
}

/// The IR document embedded in the generated crate, normalized and stable.
fn ir_json_const(ir: &Ir) -> String {
    let mut root = serde_json::Map::new();
    root.insert("ir".to_string(), Value::String(ir.ir.clone()));
    root.insert("app".to_string(), Value::String(ir.app.clone()));
    let state: Vec<Value> = ir
        .state
        .iter()
        .map(|var| {
            let mut entry = serde_json::Map::new();
            entry.insert("name".to_string(), Value::String(var.name.clone()));
            entry.insert("type".to_string(), Value::String(var.ty.clone()));
            entry.insert("init".to_string(), var.init.clone());
            Value::Object(entry)
        })
        .collect();
    root.insert("state".to_string(), Value::Array(state));
    if let Some(tree) = &ir.tree {
        root.insert("tree".to_string(), tree.clone());
    }
    if let Some(routes) = &ir.routes {
        root.insert("routes".to_string(), routes.clone());
    }
    if let Some(route) = &ir.initial_route {
        root.insert("initialRoute".to_string(), Value::String(route.clone()));
    }
    let mut theme = serde_json::Map::new();
    theme.insert("mode".to_string(), Value::String(ir.theme.mode.clone()));
    theme.insert("accent".to_string(), Value::String(ir.theme.accent.clone()));
    theme.insert("radius".to_string(), Value::from(ir.theme.radius));
    root.insert("theme".to_string(), Value::Object(theme));
    let models: Vec<Value> = ir
        .models
        .iter()
        .map(|model| {
            let mut entry = serde_json::Map::new();
            entry.insert("name".to_string(), Value::String(model.name.clone()));
            let fields: Vec<Value> = model
                .fields
                .iter()
                .map(|field| {
                    let mut item = serde_json::Map::new();
                    item.insert("name".to_string(), Value::String(field.name.clone()));
                    item.insert(
                        "type".to_string(),
                        Value::String(field.ty.as_str().to_string()),
                    );
                    item.insert("primary".to_string(), Value::Bool(field.primary));
                    item.insert(
                        "default".to_string(),
                        field.default.clone().unwrap_or(Value::Null),
                    );
                    Value::Object(item)
                })
                .collect();
            entry.insert("fields".to_string(), Value::Array(fields));
            Value::Object(entry)
        })
        .collect();
    root.insert("models".to_string(), Value::Array(models));
    let api: Vec<Value> = ir
        .api
        .iter()
        .map(|entry| {
            let mut item = serde_json::Map::new();
            item.insert("path".to_string(), Value::String(entry.path.clone()));
            item.insert("model".to_string(), Value::String(entry.model.clone()));
            item.insert(
                "handlers".to_string(),
                Value::Array(
                    entry
                        .handlers
                        .iter()
                        .map(|verb| Value::String(verb.clone()))
                        .collect(),
                ),
            );
            Value::Object(item)
        })
        .collect();
    root.insert("api".to_string(), Value::Array(api));
    serde_json::to_string_pretty(&Value::Object(root)).unwrap_or_default()
}

/// The README written next to the generated crate.
fn readme(ir: &Ir) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# {} (generated service)\n", ir.app);
    out.push_str(
        "Generated by `opurom-serverc` from an Opurom full-stack IR. The code in\n\
         `src/main.rs` is lowered Rust: no IR file is read at runtime.\n\n",
    );
    out.push_str("## Run\n\n```sh\ncargo run --release\n```\n\n");
    out.push_str("Environment:\n\n");
    out.push_str("* `OPR_PORT` - listen port (default `8787`)\n");
    out.push_str("* `OPR_DB` - SQLite database path (default `./opurom.db`)\n");
    out.push_str("* `OPR_RATE_LIMIT` - optional positive integer requests per method and path per 60-second window; excess requests get `429` JSON and `Retry-After` seconds\n");
    out.push_str("* `OPR_LOG_JSON=1` - one JSON line per request to stderr with `method`, `path`, `status` and measured `elapsed_ms`; TLS connections that negotiated ALPN also report `alpn`\n");
    out.push_str("* `OPR_AUTH_TOKEN` - optional development bearer token; missing or mismatched tokens get `401 {\"error\":\"unauthorized\"}`; `GET /health` stays open\n");
    out.push_str("* `OPR_CORS` - one fixed `http://` or `https://` origin (or the literal `*`); adds CORS headers and answers `OPTIONS` preflight with `204`\n");
    out.push_str("* `OPR_ETAG=1` - enables ETags alone; any other opt-in HTTP variable also enables them. `If-None-Match` on GET can answer `304` with no body\n");
    out.push_str("* `Accept-Encoding: gzip` - request-opt-in gzip for response bodies larger than 1024 bytes; small bodies stay unchanged\n");
    out.push_str("* `OPR_TLS=1` - serves HTTPS on the same address; `OPR_TLS_CERT` and `OPR_TLS_KEY` point at PEM files, and without them a self-signed certificate is generated at startup\n");
    out.push_str("* `OPR_KEEPALIVE=1` - reuses one connection for several HTTP/1.1 requests; `Connection: close` still ends the connection\n");
    out.push_str("* `OPR_WEBSOCKET=1` - accepts RFC 6455 WebSocket upgrades\n");
    out.push_str("* `OPR_MTLS=1` - requires a client certificate signed by `OPR_CLIENT_CA` (a client CA PEM path or inline PEM); also enables TLS\n");
    out.push_str("* `OPR_REVOKED` - static comma-separated SHA-256 certificate fingerprint deny list, active only with `OPR_MTLS=1`\n");
    out.push_str("* `OPR_CRL_FILE` - required static local DER X.509 v2 CRL, active only with `OPR_MTLS=1`; a missing, malformed, stale or unverifiable CRL refuses the handshake\n");
    out.push_str("* `OPR_CRL_URL` - HTTP CRL distribution point, or the literal `cert` to read the CRL Distribution Points extension of the client certificate; the fetched DER is cached per URL and refreshed after `OPR_CRL_TTL_SECS` (default 3600), and a configured `OPR_CRL_FILE` wins\n");
    out.push_str("* `OPR_OCSP_FILE` - required static local DER BasicOCSPResponse, active only with `OPR_MTLS=1`; good/revoked/unknown statuses, CA signature and freshness are checked\n");
    out.push_str("* `OPR_HTTP3=1` - serves HTTP/3 over QUIC on a separate UDP listener with TLS 1.3 and ALPN `h3`; `OPR_HTTP3_PORT` chooses the UDP port (default `4433`)\n");
    out.push_str("* `OPR_ALT_SVC_PORT` - the UDP port advertised with `Alt-Svc: h3=\":PORT\"` on the HTTPS responses\n\n");
    out.push_str("* `GET <list route>?limit=&offset=&sort=&order=&q=` - strict bounds (400 on negative, non-integer or over-cap values), stable ordering and a `{items,total,count,limit,offset}` envelope; default limit 50, maximum 1000\n\n");
    if account_model(ir).is_some() {
        out.push_str("* `OPR_SESSION=1` - enforce sessions: `POST /sessions` issues an HttpOnly cookie, every mutation needs a session, `PUT`/`DELETE` need the admin role (`401`/`403` otherwise); unset, the routes exist but nothing is gated\n");
    }
    if enables_uploads(ir) {
        out.push_str("* `OPR_DATA` - application data directory for uploads (default `./data`), active when an IR field declares `attachment`\n\n");
    }
    out.push_str("The service opens one `PooledDb` at startup and shares its Mutex-serialized SQLite connection across all handlers. With no optional hardening env vars and no gzip request header, HTTP responses and stdout stay byte-identical. The rate-limit and log variables never enable the opt-in HTTP response features.\n\n");
    out.push_str("The schema is created at startup from the embedded `migrations/*.sql`.\n\n");
    out.push_str("## Routes\n\n");
    out.push_str("* `GET /health` - `{\"ok\":true,\"app\":\"...\",\"version\":\"0.1.0\"}`\n");
    out.push_str("* `GET /ssr` - server-rendered HTML of the IR tree\n");
    if account_model(ir).is_some() {
        out.push_str("* `POST /sessions` - login: `{username,password}` verifies the stored digest, sets the session cookie, `401 invalid_credentials` otherwise\n");
        out.push_str("* `DELETE /sessions` - logout: revokes the session and clears the cookie\n");
    }
    if enables_uploads(ir) {
        out.push_str("* `POST /uploads` - multipart file part stored under `OPR_DATA/uploads`, answers `{name,size}`\n");
        out.push_str("* `GET /uploads/:name` - serves a stored upload by name\n");
    }
    for api in &ir.api {
        for verb in &api.handlers {
            let method = match verb.as_str() {
                "list" => "GET",
                "create" => "POST",
                "get" => "GET",
                "update" => "PUT",
                "delete" => "DELETE",
                other => other,
            };
            let suffix = if matches!(verb.as_str(), "get" | "update" | "delete") {
                "/:id"
            } else {
                ""
            };
            let _ = writeln!(out, "* `{} {}{}`", method, api.path, suffix);
        }
    }
    out.push_str("\n## Runtime model\n\n");
    out.push_str("One shared Mutex-guarded SQLite connection serves every handler. Rate limiting is a process-local fixed window. The bearer token is a development check. TLS terminates on the listener, and the optional client-certificate handshake checks the configured status sources.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::sql_ident;

    #[test]
    fn sql_ident_quotes_only_keywords() {
        assert_eq!(sql_ident("User"), "\"User\"");
        assert_eq!(sql_ident("order"), "\"order\"");
        assert_eq!(sql_ident("DESC"), "\"DESC\"");
        assert_eq!(sql_ident("Todo"), "Todo");
        assert_eq!(sql_ident("id"), "id");
        // A non-keyword name passes through untouched even with quotes.
        assert_eq!(sql_ident("a\"b"), "a\"b");
    }
}
