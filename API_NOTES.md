# opurom-db API notes (for opurom-server)

This file records the contract `opurom-server` relies on. It is a note, not a
dependency: the generated service uses the sibling `opurom-db` crate directly.

## Used API

```rust
opurom_db::open(path: &str) -> Result<Sqlite, DbError>   // free function
opurom_db::Sqlite::open(path: &str) -> Result<Sqlite, DbError>

trait Database {
    fn exec(&mut self, sql: &str) -> Result<(), DbError>;
    fn query(&mut self, sql: &str) -> Result<Vec<Row>, DbError>;
    fn exec_params(&mut self, sql: &str, params: &[Value]) -> Result<(), DbError>;
    fn query_params(&mut self, sql: &str, params: &[Value]) -> Result<Vec<Row>, DbError>;
}

Row::get(&self, name: &str) -> Option<&Value>
Value::{Int(i64), Text(String), Bool(bool)}
Value::as_i64() / Value::as_str() / Value::as_bool()
```

## Conventions the generated code relies on

* Identifiers are `[A-Za-z_][A-Za-z0-9_]*`; the model name is the table name.
* `?` placeholders are bound natively by SQLite; the placeholder count must
  match the number of bound values.
* `bool` is stored as `INTEGER` 0/1, so raw queries return `Value::Int(0|1)`.
  The generated `row_to_json` maps the `bool` fields of the lowered model
  metadata back to JSON `true`/`false`.
* `DbError` implements `Display`, so it can be embedded in a JSON error body.

## Open-function tolerance

`opurom-serverc` emits `Sqlite::open(&path)`, the associated form. The free
function `opurom_db::open` exists as well, so either spelling of the sibling
crate keeps the generated service compiling.

## Connection model

`Sqlite` holds a raw pointer and is therefore not `Send`. The generated service
opens one `PooledDb` at startup and shares it across the handlers. `PooledDb`
is `Arc<Mutex<Sqlite>>`, and the sibling crate provides the justified
`unsafe impl Send` and `unsafe impl Sync` under that invariant: every FFI call
holds the Mutex for the whole `&mut Sqlite` borrow. One shared
Mutex-serialized connection serves every request; the fault-isolation
guarantee is unchanged.
