# opurom-server

OPUROM R2 backend runtime: a std-only HTTP/1.1 server, a router with path
parameters, per-route fault isolation, a deterministic SSR host, and
`opurom-serverc`, the compiler that lowers a full-stack IR into a standalone
Rust service crate.

This crate implements the backend half of
[`FULLSTACK_SPEC.md`](../opurom-spec/FULLSTACK_SPEC.md) §4–§5.

## Architecture

```
                     ┌──────────────────────────────────────────┐
  TCP connection ──▶ │ http::read_request                        │
                     │  request line + headers + Content-Length  │
                     │  body cap 1 MiB → 413                    │
                     └───────────────────┬──────────────────────┘
                                         ▼
                     ┌──────────────────────────────────────────┐
                     │ middleware::MiddlewareChain               │
                     │  Vec<Box<dyn Fn(&mut Request) -> Option  │
                     │        <Response> + Send + Sync>>         │
                     │  applied in order; first answer wins     │
                     └───────────────────┬──────────────────────┘
                                         ▼
                     ┌──────────────────────────────────────────┐
                     │ router::Router                           │
                     │  literal + :param segments               │
                     │  404 unknown · 405 wrong method           │
                     │  catch_unwind per handler                │
                     │  3 consecutive panics → route disabled   │
                     └───────────────────┬──────────────────────┘
                                         ▼
                     ┌──────────────────────────────────────────┐
                     │ handler                                  │
                     │  generated CRUD code (opurom-db)         │
                     │  SSR render (ssr::ssr_html)               │
                     └──────────────────────────────────────────┘
```

| Module | Responsibility |
| --- | --- |
| `http` | `Method`, `Request`, `Response`, the bounded request parser, status text |
| `middleware` | `MiddlewareChain`: an ordered `Vec` of boxed closures |
| `router` | route table, `:param` matching, panic isolation, 3-strike breaker |
| `server` | `TcpListener` accept loop, one thread per connection, `Connection: close` |
| `ssr` | deterministic HTML rendering of the IR tree with theme tokens |
| `ir` | IR v0.1 model: state, tree, theme, models, api |
| `codegen` | the `opurom-serverc` lowering pass |

Errors are values everywhere: a failed request is a `Response`, a panicking
handler is caught, and no failure path aborts the process.

## HTTP contract

* Request: HTTP/1.1 request line, headers, `Content-Length` body. `Transfer-Encoding`
  is rejected with 501.
* Body cap: 1 MiB (`http::MAX_BODY_BYTES`). A larger body gets `413` and the body is
  drained so the client can read the answer.
* Response: always `Content-Type: application/json` for JSON bodies, `text/html` for
  SSR, `Content-Length`, and `Connection: close` (no keep-alive in R2).
* Methods: `GET`, `POST`, `PUT`, `DELETE`.

| Situation | Status | Body |
| --- | --- | --- |
| Health check | 200 | `{"ok":true,"app":"<name>","version":"0.2.0"}` |
| List | 200 | bare JSON array of row objects |
| Create | 201 | the created row object |
| Get / Update | 200 | the row object |
| Delete | 200 | `{"deleted":true}` |
| Unknown path | 404 | `{"error":"not_found"}` |
| Wrong method | 405 | `{"error":"method_not_allowed"}` |
| Body over 1 MiB | 413 | `{"error":"payload_too_large"}` |
| Handler panic | 500 | `{"error":"handler_panic"}` |
| Route disabled after 3 panics | 503 | `{"error":"route_disabled"}` |

Row objects use the model field names exactly; a `bool` field is a JSON boolean.

## Generated service (`opurom-serverc`)

```sh
opurom-serverc <fullstack-ir.json> -o <dir> [--dep-root <path>]
```

The generator writes a standalone crate into `<dir>`:

```
<dir>/Cargo.toml                     path deps on opurom-server and opurom-db
<dir>/src/main.rs                    lowered router, CRUD handlers, /health, /ssr
<dir>/migrations/001_create_<model>.sql
<dir>/migrations/schema.sql
<dir>/README.md
```

* `--dep-root` is the workspace holding the sibling `opurom-server/` and
  `opurom-db/` crates. It defaults to `/Users/mac/work/opurom`.
* The generated code is **lowered Rust**, not an IR interpreter: the routes,
  the SQL statements and the JSON field lists are emitted at compile time. The
  IR is embedded as a string only for the `/ssr` route.
* The generated crate reads `OPR_PORT` (default `8787`) and `OPR_DB`
  (default `./opurom.db`). The parent directory of `OPR_DB` is created if
  missing.
* The schema is created at startup: every `migrations/*.sql` statement is
  embedded with `include_str!` and executed (they are `CREATE TABLE IF NOT
  EXISTS`, so startup is idempotent).

Build and run the generated service:

```sh
cargo build --release --manifest-path <dir>/Cargo.toml
OPR_PORT=8787 OPR_DB=./opurom.db <dir>/target/release/opurom-service
```

Because `opurom-db`'s SQLite handle holds a raw pointer, it is not `Send`; the
generated service therefore opens one connection per request. There is no
connection pooling in R2.

## Demo server

```sh
cargo run --bin opurom-server -- 8787      # or: OPR_PORT=8787 cargo run --bin opurom-server
```

The demo serves `/health`, `/ssr` and an in-memory `/todos` collection with the
five CRUD verbs.

## Tests

```sh
cargo fmt
cargo test
```

The suite starts a real server on an ephemeral port and drives it over TCP:

| Test file | Covers |
| --- | --- |
| `tests/http_server.rs` | health, the full CRUD lifecycle, 404, 405, 413, the 1 MiB boundary, panic → 500 → 503 with other routes still serving, `:param` matching |
| `tests/ssr.rs` | byte-identical output for the same IR and theme, theme changes the output, state interpolation, kind → HTML element mapping, IR version validation |
| `tests/codegen.rs` | the generated crate shape, the migration SQL, deterministic lowering, IR validation |

The tests are self-contained: they use an in-process store, not `opurom-db`, so
`cargo test` passes in this repository on its own.

## Status

Implemented and verified in this repository:

| Area | Status |
| --- | --- |
| HTTP/1.1 routing (literal + `:param`) | Implemented, tested |
| Five CRUD verbs via the generated service | Implemented, verified end to end against `opurom-db` |
| SQLite-backed storage (via `opurom-db`) | Implemented through the sibling crate |
| SSR HTML from the same IR | Implemented, deterministic, tested |
| Fault isolation (panic → 500, 3 strikes → 503) | Implemented, tested |
| Middleware chain | Implemented (logging, body cap); no CORS layer by default |
| `opurom-serverc` lowering to a standalone crate | Implemented, tested |

Not implemented (R3+):

| Area | Status |
| --- | --- |
| TLS | Not implemented |
| Authentication / authorization | Not implemented |
| Connection pooling | Not implemented (one connection per request) |
| PostgreSQL / MySQL drivers | Not implemented (SQLite and the `opurom-db` KV/Memory drivers only) |
| Node.js / Serverless deployment | Not implemented |
| Full middleware ecosystem (CORS, compression, rate limiting) | Not implemented |
| Real device benchmarks | Not implemented; no fabricated numbers |
| HTTP keep-alive, chunked bodies, streaming | Not implemented (R2 closes every connection) |
