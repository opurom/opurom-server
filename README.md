# opurom-server

OPUROM R2/R4/R5 backend runtime: a small HTTP/1.1 server, a router with path
parameters, per-route fault isolation, a deterministic SSR host, R4 hardening
(pooled SQLite, fixed-window rate limiting, structured logs), opt-in R5 HTTP
features (bearer auth, gzip, ETag, CORS), and `opurom-serverc`, the compiler
that lowers a full-stack IR into a standalone Rust service crate.

This crate implements the backend half of
[`FULLSTACK_SPEC.md`](../opurom-spec/FULLSTACK_SPEC.md) sections 4-5,
[`R4_ADDENDUM.md`](../opurom-spec/R4_ADDENDUM.md) section 6 and
[`R5_ADDENDUM.md`](../opurom-spec/R5_ADDENDUM.md) section 6.

## Architecture

```
TCP connection -> http::read_request
                  request line + headers + Content-Length
                  body cap 1 MiB -> 413
               -> middleware::MiddlewareChain
                  logging (plain by default) + body cap
               -> server::Server optional OPR_RATE_LIMIT check
                  429 JSON + Retry-After; every parsed request counts
               -> R5 opt-in preflight / bearer auth
                   OPR_CORS OPTIONS -> 204; OPR_AUTH_TOKEN mismatch -> 401
                -> router::Router
                  literal + :param segments
                  404 unknown / 405 wrong method
                  catch_unwind per handler
                  3 consecutive panics -> route disabled
               -> handler
                  generated CRUD code (opurom-db PooledDb)
                  SSR render (ssr::ssr_html)
               -> R5 opt-in response finalization
                   fixed CORS + Vary: Origin, ETag/304, gzip + Vary
                -> server::Server optional OPR_LOG_JSON line to stderr
```

| Module | Responsibility |
| --- | --- |
| `http` | `Method`, `Request`, `Response`, the bounded request parser, status text |
| `middleware` | `MiddlewareChain`, `RateLimiter`, logging helpers, body cap, opt-in R5 HTTP options |
| `router` | route table, `:param` matching, panic isolation, 3-strike breaker |
| `server` | `TcpListener` accept loop, one thread per connection, `Connection: close`, optional limiter, R5 response features and measured JSON log |
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
  SSR, `Content-Length`, and `Connection: close` (no keep-alive in R2). `304`
  and `204` carry no body and `Content-Length: 0`.
* Methods: `GET`, `POST`, `PUT`, `DELETE`. `OPTIONS` is a CORS preflight only
  when `OPR_CORS` is set; otherwise the router answers `405` on known paths.
* R5 features are opt-in. With no R5 environment variable and no
  `Accept-Encoding: gzip`, response bytes stay identical to R4; `Origin`,
  `If-None-Match` and `OPTIONS` request headers alone enable nothing.

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
| Rate limit exceeded | 429 | `{"error":"rate_limited"}` plus `Retry-After` seconds |
| Missing/mismatched bearer token (`OPR_AUTH_TOKEN`) | 401 | `{"error":"unauthorized"}` |
| Matching `If-None-Match` (ETag enabled) | 304 | empty |
| CORS preflight (`OPR_CORS`) | 204 | empty |
| Handler panic | 500 | `{"error":"handler_panic"}` |
| Route disabled after 3 panics | 503 | `{"error":"route_disabled"}` |

Row objects use the model field names exactly; a `bool` field is a JSON boolean.

## R4 hardening

All R4 hardening is opt-in-compatible. With no `OPR_RATE_LIMIT` and no
`OPR_LOG_JSON`, HTTP responses, stdout, and the existing plain stderr log
remain byte-identical. There is no 429 and no JSON log line by default.
`OPR_RATE_LIMIT` and `OPR_LOG_JSON` do not enable any R5 response feature.

### Shared SQLite handle

The generated service opens one `opurom_db::PooledDb` at startup and shares it
across every CRUD handler with `PooledDb::with`. `PooledDb` is
`Arc<Mutex<Sqlite>>`; `Sqlite::open` verifies `sqlite3_threadsafe()`, and every
FFI call holds the Mutex for the whole `&mut Sqlite` borrow. `opurom-db`
provides justified `unsafe impl Send` and `unsafe impl Sync` for `PooledDb`
under that invariant. `Sqlite` itself remains not `Send`.

This is one shared connection, not a sized pool of independent connections.

### Rate limiting

Set `OPR_RATE_LIMIT` to a positive integer N. `Server` installs a deterministic
per-method-and-path fixed-window counter with a 60-second window. The first N
requests in a window are allowed; request N+1 gets `429` JSON and a
`Retry-After` header containing the seconds remaining until the window resets.
Invalid or non-positive values disable rate limiting. The counter is protected
by a Mutex and shared across server threads, but it is process-local: there is
no distributed rate limit.

### Structured request logging

Set `OPR_LOG_JSON=1` (also `true`, `yes`, or `on`). After each response, the
server writes exactly one JSON line to stderr with `method`, `path`, `status`
and `elapsed_ms`. `elapsed_ms` is measured with `std::time::Instant` from the
start of connection handling through the socket write. The plain
`[opurom-server] -> METHOD PATH` middleware line is suppressed in this mode, so
there is still one request log line per request. Stdout is never used for
request logs. A measured sample from the R4 smoke run:

```json
{"elapsed_ms":0,"method":"GET","path":"/health","status":200}
```

## R5 HTTP features (opt-in)

All four features work on the existing demo server and generated services
through `Server::bind_with`; there is no second binary. Options are read once
when the listener binds. A development configuration with every feature on:

```sh
OPR_AUTH_TOKEN=devtoken OPR_CORS=https://app.example OPR_ETAG=1 \
  cargo run --bin opurom-server -- 8787
```

`OPR_ETAG=1` enables ETags alone; `OPR_AUTH_TOKEN` or `OPR_CORS` also enables
them, so a hardened server can be checked with one ETag round trip. Set
`OPR_ETAG=0` to disable them explicitly. The R4 variables `OPR_RATE_LIMIT` and
`OPR_LOG_JSON` never enable R5 features. With no R5 environment variable and no
`Accept-Encoding: gzip` request header, HTTP response bytes, stdout and the
plain stderr log remain byte-identical to R4.

### Bearer auth

`OPR_AUTH_TOKEN=<value>` requires `Authorization: Bearer <value>` on every
non-preflight request. Missing, malformed or mismatched credentials get
`401` with `{"error":"unauthorized"}`. The token bytes are compared without
an early-exit equality loop; length remains visible in timing. **This is a
development token, not a production identity system**: there are no users,
scopes, expiry, password hashing or credential storage.

```sh
curl -i http://127.0.0.1:8787/health
# HTTP/1.1 401 Unauthorized ... {"error":"unauthorized"}
curl -i -H 'Authorization: Bearer devtoken' http://127.0.0.1:8787/health
```

### gzip responses

`Accept-Encoding: gzip` is request-opt-in compression. Only bodies **larger
than 1024 bytes** (`middleware::GZIP_THRESHOLD_BYTES`) are compressed with
`flate2`; the response gains `Content-Encoding: gzip` and
`Vary: Accept-Encoding`. Small bodies, `q=0` and non-gzip codings stay
uncompressed. The hash used for an ETag is computed from the uncompressed
body, and R5 tests decompress the wire bytes back to the original JSON.

```sh
TITLE=$(python3 -c 'print("x" * 1100)')
curl -sS -H 'Authorization: Bearer devtoken' -H 'Content-Type: application/json' \
  -d "{\"title\":\"$TITLE\"}" http://127.0.0.1:8787/todos
curl -i --compressed -H 'Authorization: Bearer devtoken' \
  -H 'Accept-Encoding: gzip' http://127.0.0.1:8787/todos
# Content-Encoding: gzip / Vary: Accept-Encoding[, Origin]
```

### ETags and `304`

`OPR_ETAG=1` (or another R5 opt-in variable) adds a deterministic, quoted
64-bit FNV-1a hex ETag for 2xx responses with a body. The hash is
non-cryptographic and is a representation validator, not a security control.
A matching `If-None-Match` on `GET` (exact, weak, list or `*`) returns
`304 Not Modified` with no body, `Content-Length: 0`, the same ETag and any
CORS/`Vary` headers. Non-GET methods do not turn into `304`.

```sh
curl -i -H 'Authorization: Bearer devtoken' http://127.0.0.1:8787/health
# ETag: "<hash>"
curl -i -H 'Authorization: Bearer devtoken' \
  -H 'If-None-Match: "<hash>"' http://127.0.0.1:8787/health
# HTTP/1.1 304 Not Modified, empty body
```

### CORS

`OPR_CORS=<origin>` accepts one fixed `http://` or `https://` origin, or the
literal `*`. Values with paths, whitespace, control characters or wildcards
inside an origin are rejected. The server emits only its configured value in
`Access-Control-Allow-Origin` plus `Vary: Origin`; **it never reflects an
arbitrary request `Origin`**. `OPTIONS` preflight answers `204` with no body,
`Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS` and the fixed
`Access-Control-Allow-Headers: Authorization, Content-Type`. No cookies or
`Access-Control-Allow-Credentials` are supported; do not use `*` with
credentialed browser clients. Preflight bypasses bearer auth but is still
rate limited and logged.

```sh
curl -i -X OPTIONS -H 'Origin: https://app.example' \
  -H 'Access-Control-Request-Method: GET' \
  http://127.0.0.1:8787/health
# HTTP/1.1 204 No Content, empty body, Allow-Methods/Allow-Headers
```

### Composition and honest scope

Order is: R4 middleware/logging -> R4 rate limit -> CORS preflight -> bearer
auth -> router/pooled handlers -> CORS/ETag/gzip finalization -> one log line.
An unauthorized request still counts against `OPR_RATE_LIMIT` and gets an
`OPR_LOG_JSON` line; a preflight does the same. Gzip, ETag and fixed CORS
headers compose on one response, and `304` keeps CORS headers but has no
compressed body. The generated service's one shared `PooledDb` is unchanged.

Still R6+: TLS, a real authentication/identity provider, token lifecycle,
per-route CORS and credentialed CORS, streaming, HTTP/2, compression
dictionaries, Brotli/zstd, HTTP keep-alive and chunked bodies, a sized
connection pool and a distributed rate limit. There is no streaming
compression: each response is encoded in memory. ETags are body hashes, not a
versioned cache-invalidation system.

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
  missing. It also honours `OPR_RATE_LIMIT`, `OPR_LOG_JSON`,
  `OPR_AUTH_TOKEN`, `OPR_CORS` and `OPR_ETAG`, plus request-opt-in gzip,
  through the runtime described above.
* The schema is created at startup inside one `PooledDb::with` call: every
  `migrations/*.sql` statement is embedded with `include_str!` and executed
  (they are `CREATE TABLE IF NOT EXISTS`, so startup is idempotent).

Build and run the generated service:

```sh
cargo build --release --manifest-path <dir>/Cargo.toml
OPR_PORT=8787 OPR_DB=./opurom.db <dir>/target/release/opurom-service
```

The generated service no longer opens one connection per request. It shares
the one Mutex-serialized connection from `PooledDb`; real connection pool
sizing remains R6+.

## Demo server

```sh
cargo run --bin opurom-server -- 8787      # or: OPR_PORT=8787 cargo run --bin opurom-server
```

The demo serves `/health`, `/ssr` and an in-memory `/todos` collection with the
five CRUD verbs. It uses the same optional rate limiter, structured logging
and opt-in R5 HTTP features as generated services.

## Tests

```sh
cargo fmt --all
cargo test --offline
```

The original 24 tests remain green and `tests/http_features.rs` adds 13 R5
tests, for 37 total. Several suites drive a real server on an ephemeral port
over TCP:

| Test file | Covers |
| --- | --- |
| `tests/http_server.rs` | health, the full CRUD lifecycle, 404, 405, 413, the 1 MiB boundary, panic -> 500 -> 503 with other routes still serving, `:param` matching |
| `tests/ssr.rs` | byte-identical output for the same IR and theme, theme changes the output, state interpolation, kind -> HTML element mapping, IR version validation |
| `tests/codegen.rs` | generated crate shape, migration SQL, deterministic lowering, IR validation, one shared `PooledDb` in generated code |
| `tests/hardening.rs` | deterministic N/N+1 rate-limit boundary and window reset, `OPR_RATE_LIMIT` over TCP, JSON log shape with numeric measured `elapsed_ms`, one JSON stderr line per request, byte-identical default responses |
| `tests/http_features.rs` | 401/304/204 status and body paths, gzip bytes decompressed to the original JSON, exact 1024-byte threshold, fixed CORS headers/preflight, deterministic ETag over TCP, all-feature composition, unauthorized and preflight rate-limit/log composition, default-off wire bytes |

The in-process tests are self-contained: they use an in-memory store, not
`opurom-db`, so `cargo test` passes in this repository on its own. The
generated-service CRUD path is compiled and smoke-tested separately against
the sibling `opurom-db` crate.

## Status

Implemented and verified in this repository:

| Area | Status |
| --- | --- |
| HTTP/1.1 routing (literal + `:param`) | Implemented, tested |
| Five CRUD verbs via the generated service | Implemented, verified end to end against `opurom-db` |
| SQLite-backed storage (via `opurom-db`) | Implemented through the sibling crate |
| One shared Mutex-serialized SQLite handle | Implemented in generated services, tested in `opurom-db` and smoke-tested |
| SSR HTML from the same IR | Implemented, deterministic, tested |
| Fault isolation (panic -> 500, 3 strikes -> 503) | Implemented, tested |
| Middleware chain | Implemented (plain logging by default, body cap) |
| Fixed-window rate limiting | Implemented, opt-in via `OPR_RATE_LIMIT`, process-local |
| Structured request logging | Implemented, opt-in via `OPR_LOG_JSON`, measured `elapsed_ms` |
| Bearer auth (development token) | Implemented, opt-in via `OPR_AUTH_TOKEN`, 401 JSON, no early-exit byte comparison |
| gzip responses | Implemented, request-opt-in above 1024 bytes, `Content-Encoding` and `Vary`, decompression tested |
| ETag / `304` | Implemented, opt-in deterministic body hash, empty-body conditional response over TCP |
| CORS / preflight | Implemented, opt-in fixed origin or literal `*`, 204 with fixed allow lists |
| `opurom-serverc` lowering to a standalone crate | Implemented, tested |

Not implemented (R6+):

| Area | Status |
| --- | --- |
| TLS | Not implemented |
| Real authentication provider / token lifecycle | Not implemented (development bearer token only) |
| Real connection pool sizing | Not implemented (one shared Mutex-guarded connection only) |
| Distributed rate limiting | Not implemented (in-process counters only) |
| PostgreSQL / MySQL drivers | Not implemented in this repository (SQLite and the `opurom-db` KV/Memory drivers only) |
| Node.js / Serverless deployment | Not implemented |
| Per-route CORS, credentialed CORS | Not implemented (one fixed configured origin or `*`; no cookies or credentials) |
| Streaming, HTTP/2, compression dictionaries | Not implemented (whole-body gzip only, HTTP/1.1 with `Connection: close`) |
| Real device benchmarks | Not implemented; no fabricated numbers |
| HTTP keep-alive, chunked bodies | Not implemented (R2 closes every connection) |
