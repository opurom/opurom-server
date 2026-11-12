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

/// Default workspace root that holds the sibling `opurom-server` and
/// `opurom-db` crates.
pub const DEFAULT_DEP_ROOT: &str = "/Users/mac/work/opurom";

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
    out.push_str("version = \"0.2.0\"\n");
    out.push_str("edition = \"2021\"\n");
    out.push_str("publish = false\n");
    let _ = write!(
        out,
        "description = \"Generated OPUROM service for {}\"\n",
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
         use opurom_server::router::Router;\n\
         use opurom_server::server::Server;\n\
         use opurom_server::ssr::ssr_html;\n\
         use opurom_server::serde_json::Value as Json;\n\n",
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

    // The router builder opens the function the handlers are emitted into.
    out.push_str(ROUTER_BUILD);

    // Handlers, lowered per api entry.
    for api in &ir.api {
        out.push_str(&handlers_for(ir, api));
    }

    out.push_str(MAIN_FN);
    out
}

/// Header comment of the generated file.
const HEADER: &str = "//! Generated by `opurom-serverc` from an OPUROM full-stack IR.\n\
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
const ROUTER_BUILD: &str = r#"#[allow(unused_variables)]
fn build_router(db: PooledDb) -> Router {
    let mut router = Router::new();
    router.route(Method::Get, "/health", |_request: &mut Request| {
        Response::json_text(
            200,
            &format!(
                "{{\"ok\":true,\"app\":{},\"version\":\"0.2.0\"}}",
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
    let server = match Server::bind_with(&addr, router, chain, 1024 * 1024) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("[opurom-service] cannot bind {}: {}", addr, err);
            std::process::exit(1);
        }
    };
    eprintln!("[opurom-service] {} listening on {}", APP_NAME, addr);
    server.serve();
}
"#;

/// Handler templates, one per CRUD verb.
const LIST_HANDLER: &str = r#"    let list_db = db.clone();
    router.route(Method::Get, "{{PATH}}", move |_request: &mut Request| {
        list_db.with(|guard| {
        match guard.query("{{SQL}}") {
            Ok(rows) => Response::json_text(200, &rows_to_json({{MODEL}}, &rows)),
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
        create_db.with(|guard| {
        let body = match request.json() {
            Ok(value) => value,
            Err(_) => return Response::error(400, "invalid_json"),
        };
        let object = match body.as_object() {
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
        update_db.with(|guard| {
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
        delete_db.with(|guard| {
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
    let table = model.table();
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
        let select_sql = format!("SELECT * FROM {} WHERE {} = ?;", table, primary);
        let list_sql = format!("SELECT * FROM {};", table);
        let delete_sql = format!("DELETE FROM {} WHERE {} = ?;", table, primary);
        let columns = create_columns(model);
        let assignments = update_assignments(model);
        let id_value = id_value_stmt(model);
        let values: Vec<(&str, &str)> = vec![
            ("PATH", api.path.as_str()),
            ("TABLE", table.as_str()),
            ("MODEL", model_const.as_str()),
            ("PRIMARY", primary.as_str()),
            ("PARAM", param),
            ("SQL", list_sql.as_str()),
            ("SQL_SELECT", select_sql.as_str()),
            ("SQL_DELETE", delete_sql.as_str()),
            ("COLUMNS", columns.as_str()),
            ("ASSIGNMENTS", assignments.as_str()),
            ("ID_VALUE", id_value.as_str()),
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
            let _ = writeln!(out, "        columns.push({:?}.to_string());", field.name);
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
            field.name
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
                field.name
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
            field.name
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
            model.table(),
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

/// `CREATE TABLE IF NOT EXISTS` statement for one model.
fn create_table_sql(model: &Model) -> String {
    let mut out = format!("CREATE TABLE IF NOT EXISTS {} (\n", model.table());
    for (index, field) in model.fields.iter().enumerate() {
        out.push_str("    ");
        out.push_str(&field.name);
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
        "Generated by `opurom-serverc` from an OPUROM full-stack IR. The code in\n\
         `src/main.rs` is lowered Rust: no IR file is read at runtime.\n\n",
    );
    out.push_str("## Run\n\n```sh\ncargo run --release\n```\n\n");
    out.push_str("Environment:\n\n");
    out.push_str("* `OPR_PORT` - listen port (default `8787`)\n");
    out.push_str("* `OPR_DB` - SQLite database path (default `./opurom.db`)\n");
    out.push_str("* `OPR_RATE_LIMIT` - optional positive integer requests per method and path per 60-second window; excess requests get `429` JSON and `Retry-After` seconds\n");
    out.push_str("* `OPR_LOG_JSON=1` - one JSON line per request to stderr with `method`, `path`, `status` and measured `elapsed_ms`; replaces the plain log line\n\n");
    out.push_str("The service opens one `PooledDb` at startup and shares its Mutex-serialized SQLite connection across all handlers. With no optional hardening env vars set, HTTP responses and stdout stay unchanged.\n\n");
    out.push_str("The schema is created at startup from the embedded `migrations/*.sql`.\n\n");
    out.push_str("## Routes\n\n");
    out.push_str("* `GET /health` - `{\"ok\":true,\"app\":\"...\",\"version\":\"0.2.0\"}`\n");
    out.push_str("* `GET /ssr` - server-rendered HTML of the IR tree\n");
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
    out.push_str("\n## Honest status\n\n");
    out.push_str("One shared Mutex-guarded SQLite connection is not a sized connection pool. Rate limiting is a process-local fixed window, not a distributed rate limit. R5+: TLS, authentication, real connection pool sizing, distributed rate limiting, HTTP keep-alive and streaming.\n");
    out
}
