# opurom-server

OPUROM R2/R4/R5/R7/R8 backend runtime: a small HTTP/1.1 server, a router with path
parameters, per-route fault isolation, a deterministic SSR host, R4 hardening
(pooled SQLite, fixed-window rate limiting, structured logs), opt-in R5 HTTP
features (bearer auth, gzip, ETag, CORS), opt-in R7 transport features (TLS,
WebSocket, HTTP/1.1 keep-alive), opt-in R8 TLS features (mutual TLS, a static
certificate revocation deny list and ALPN reporting), and `opurom-serverc`, the
compiler that lowers a full-stack IR into a standalone Rust service crate.

This crate implements the backend half of
[`FULLSTACK_SPEC.md`](../opurom-spec/FULLSTACK_SPEC.md) sections 4-5,
[`R4_ADDENDUM.md`](../opurom-spec/R4_ADDENDUM.md) section 6,
[`R5_ADDENDUM.md`](../opurom-spec/R5_ADDENDUM.md) section 6,
[`R7_ADDENDUM.md`](../opurom-spec/R7_ADDENDUM.md) sections 1 and 5 and
[`R8_ADDENDUM.md`](../opurom-spec/R8_ADDENDUM.md) section 4.

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

The R7/R8 transport layer wraps that core:

```
accept -> optional TLS handshake (rustls, OPR_TLS=1 or OPR_MTLS=1)
           OPR_MTLS=1: require a client certificate, apply the static deny list
           ALPN: advertise h2/http/1.1, report the selected protocol
       -> optional WebSocket upgrade (RFC 6455, OPR_WEBSOCKET=1)
       -> HTTP/1.1 keep-alive loop (OPR_KEEPALIVE=1)
          Content-Length framing, idle timeout, in-flight limit
```

| Module | Responsibility |
| --- | --- |
| `http` | `Method`, `Request`, `Response`, the bounded request parser, status text |
| `middleware` | `MiddlewareChain`, `RateLimiter`, logging helpers, body cap, opt-in R5 HTTP options |
| `router` | route table, `:param` matching, panic isolation, 3-strike breaker |
| `server` | `TcpListener` accept loop, one thread per connection, optional TLS, optional keep-alive, optional WebSocket upgrade, R5 response features and measured JSON log |
| `tls` | the optional TLS listener: environment configuration, PEM loading, self-signed fallback, SHA-256 fingerprint, opt-in client-certificate mTLS, static fingerprint deny list and ALPN |
| `websocket` | the RFC 6455 frame codec with size limits, the server channel and the client helper |
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
  SSR, `Content-Length`, and `Connection: close` by default. `304`
  and `204` carry no body and `Content-Length: 0`. With `OPR_KEEPALIVE=1` the
  answer carries `Connection: keep-alive` and the connection is reused.
* Methods: `GET`, `POST`, `PUT`, `DELETE`. `OPTIONS` is a CORS preflight only
  when `OPR_CORS` is set; otherwise the router answers `405` on known paths.
* R5 features are opt-in. With no R5 environment variable and no
  `Accept-Encoding: gzip`, response bytes stay identical to R4; `Origin`,
  `If-None-Match` and `OPTIONS` request headers alone enable nothing.
* R7 features are opt-in too. With no `OPR_TLS`, `OPR_KEEPALIVE` and
  `OPR_WEBSOCKET`, the wire format is byte-identical to R6.
* R8 features are opt-in too. With no `OPR_MTLS`, `OPR_CLIENT_CA` and
  `OPR_REVOKED`, plain HTTP and the R7 single-sided TLS HTTP response bytes
  stay byte-identical. A TLS client that offers no ALPN negotiates no
  protocol and gets the same four-field request log line.

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
| Too many in-flight connections | 503 | `{"error":"server_busy"}` |

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

Still R6+: a real authentication/identity provider, token lifecycle,
per-route CORS and credentialed CORS, streaming, HTTP/2, compression
dictionaries, Brotli/zstd, chunked bodies, a sized connection pool and a
distributed rate limit. There is no streaming compression: each response is
encoded in memory. ETags are body hashes, not a versioned cache-invalidation
system.

## R7 transport features (opt-in)

All three R7 features are opt-in and independent. With none of them set the
server behaves exactly as in R6: plain HTTP, one request per connection,
`Connection: close` on every response, byte-identical response bytes.

| Variable | Effect |
| --- | --- |
| `OPR_TLS=1` | serve HTTPS on the same bind address |
| `OPR_TLS_CERT` | PEM certificate file for the TLS listener |
| `OPR_TLS_KEY` | PEM private key file for the TLS listener |
| `OPR_KEEPALIVE=1` | reuse one connection for several HTTP/1.1 requests |
| `OPR_WEBSOCKET=1` | accept RFC 6455 WebSocket upgrades |

### TLS listener

`OPR_TLS=1` turns the listener into an HTTPS server on the same bind
address. The TLS implementation is `rustls` with the `ring` provider; there
is no OpenSSL dependency and no system TLS library involved.

`OPR_TLS_CERT` and `OPR_TLS_KEY` point at PEM files and must be set
together. A certificate without a key, or a key without a certificate, is a
startup error that names the missing variable. A certificate that does not
match its key is a startup error that says the pair is not usable:

```
opurom-server: cannot start on 127.0.0.1:8787: the TLS certificate
cert.pem and private key key.pem do not form a usable pair: invalid peer
certificate: ...
```

Without `OPR_TLS_CERT` and `OPR_TLS_KEY` the server generates a self-signed
certificate at startup with `rcgen`, valid for `localhost`, `127.0.0.1` and
`::1`. Only the SHA-256 fingerprint of the generated certificate is logged;
the private key is never written to the log or to disk:

```
opurom-server demo listening on https://127.0.0.1:8787 (TLS certificate
SHA-256 fingerprint 9A:F1:...:2C)
```

A client that does not trust the certificate is refused by the handshake;
there is no "accept any certificate" mode in the server. A TLS connection
that ends normally sends `close_notify`, so the peer sees a clean shutdown
instead of a truncated stream.

```sh
OPR_TLS=1 cargo run --bin opurom-server -- 8787
# https://127.0.0.1:8787/health
```

### WebSocket (RFC 6455)

`OPR_WEBSOCKET=1` accepts RFC 6455 upgrades on any path. The handshake
answers `101 Switching Protocols` with
`Sec-WebSocket-Accept: base64(SHA-1(key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))`,
which is the value RFC 6455 section 1.3 documents for the sample key
`dGhlIHNhbXBsZSBub25jZQ==`: `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.

The server sends text, binary, ping, pong and close frames, and it
reassembles fragmented messages (a data frame followed by continuation
frames). A ping is answered with a pong carrying the same payload. A close
frame carries a status code and a reason.

`websocket::client::WebSocketClient` is the client-side helper in this
repository. It performs the handshake, checks the accept value and speaks
the same frame subset, so a test can talk to the server over a real TCP
socket.

Frame parsing is bounded on purpose. A frame payload is capped at
`websocket::MAX_FRAME_PAYLOAD` (1 MiB) and an assembled message at
`websocket::MAX_MESSAGE_BYTES` (8 MiB). The declared length is checked
against those limits before any buffer is allocated, so a hostile peer
cannot make the server allocate without limit. A control frame payload is
capped at 125 bytes as RFC 6455 requires. Client frames must be masked and
server frames are never masked.

```rust
use opurom_server::websocket::client::WebSocketClient;

let mut client = WebSocketClient::connect("127.0.0.1:8787", "/ws")?;
client.send_text("hello")?;
```

### HTTP/1.1 keep-alive

`OPR_KEEPALIVE=1` lets one connection carry several HTTP/1.1 requests. The
response body is framed with `Content-Length`, so the client knows exactly
where a response ends and can send the next request on the same socket. A
response carries `Connection: keep-alive`; a request that asks for
`Connection: close`, and every HTTP/1.0 request without `keep-alive`, gets
`Connection: close` and the server closes the connection afterwards.

Two bounds keep a long-lived connection from holding resources forever:

* **Idle timeout**: a connection that waits longer than
  `server::DEFAULT_IDLE_TIMEOUT` (30 seconds) for its next request is
  closed. The timeout is also the socket read timeout.
* **Maximum in-flight connections**: at most
  `server::DEFAULT_MAX_CONNECTIONS` (256) connections are served at the
  same time. A connection that arrives above the limit gets
  `503 {"error":"server_busy"}` and is closed.

Both values are settable in code with `Server::with_idle_timeout` and
`Server::with_max_connections`.

### R7 feature limits

* **Client certificates are an R8 opt-in**: the R7 variables alone never ask
  for a client certificate. See the R8 section below.
* **No OCSP or distributed CRL**: R8 adds a static fingerprint deny list, not
  OCSP, stapling, a CRL distribution point or any revocation fetch.
* **No HSM and no cipher-suite tuning**: the cipher suites and the protocol
  versions are the `rustls` library defaults. There is no configuration for
  them.
* **No permessage-deflate**: the WebSocket implementation negotiates no
  extensions and never compresses a frame. `Sec-WebSocket-Extensions` is
  neither sent nor honoured.
* **No HTTP/2 frames and no HTTP/3**: R8 adds ALPN advertisement and
  reporting, but the server still speaks HTTP/1.1 only. There is no QUIC.
* **No load-balancer integration**: no `X-Forwarded-*` handling, no
  `Forwarded` header parsing, no sticky-session or health-probe support for
  a proxy, and no proxy-protocol support.
* **No chunked request bodies**: `Transfer-Encoding` is still rejected with
  `501`, and every response is written with a `Content-Length`.
* **The self-signed certificate is for development**: it is generated in
  memory at startup, is not written to disk, and is not rotated.
* **The keep-alive loop is per connection**: one thread per connection is
  still the model, so the idle timeout bounds each thread rather than a
  shared pool.
* **Still R9+**: HTTP/2 frames, HTTP/3, OCSP/CRL fetch and distributed
  revocation, permessage-deflate, a sized connection pool with a shared event
  loop, and load-balancer integration.

## R8 mutual TLS, revocation and ALPN (opt-in)

R8 extends the same rustls listener. Plain HTTP is unchanged. With no R8
variable set, the R7 single-sided TLS path keeps its HTTP response bytes; a
client that offers no ALPN negotiates no protocol and sees no extra log field.
`OPR_MTLS=1` also enables TLS, so `OPR_TLS=1` is optional (setting both is
harmless). All three R8 variables are read once at startup.

| Variable | Effect |
| --- | --- |
| `OPR_MTLS=1` | require and verify a client certificate signed by `OPR_CLIENT_CA`; also enables TLS |
| `OPR_CLIENT_CA` | PEM file path or inline PEM with one or more trusted client CA certificates |
| `OPR_REVOKED` | comma-separated SHA-256 fingerprints of presented certificates to deny |

```sh
OPR_MTLS=1 OPR_CLIENT_CA=client-ca.pem OPR_REVOKED=<FINGERPRINT> \
  OPR_TLS_CERT=server-chain.pem OPR_TLS_KEY=server.key OPR_LOG_JSON=1 \
  cargo run --bin opurom-server -- 8787
```

Tests generate a CA, a CA-signed server chain, two CA-signed client
certificates and an untrusted self-signed client with `rcgen` in memory. No
private keys are checked in.

### Client-certificate handshake

The server builds a mandatory `rustls` `WebPkiClientVerifier` from
`OPR_CLIENT_CA`. A missing certificate is refused with a
`certificate_required` alert; a self-signed or otherwise untrusted certificate
is refused with an `unknown_ca` alert. The server writes a concrete line to
stderr, for example:

```
[opurom-server] mTLS handshake refused: client certificate missing, untrusted or revoked (check OPR_CLIENT_CA and OPR_REVOKED): peer sent no certificates
```

A trusted client receives an ordinary HTTP/1.1 response. Setting `OPR_MTLS=1`
without `OPR_CLIENT_CA` is a startup error that names the missing variable.
`OPR_CLIENT_CA` accepts a PEM file path (the same convention as
`OPR_TLS_CERT`) or an inline PEM string.

### Static revocation deny list

`OPR_REVOKED` is a **static deny list** of SHA-256 fingerprints of DER
certificates. Entries accept uppercase or lowercase hex, with or without
colons. rustls first verifies the presented chain against `OPR_CLIENT_CA`;
then the server computes the SHA-256 fingerprint of every certificate the
peer presented and aborts the handshake with a `certificate_revoked` alert on
a match. The fingerprint is computed from the presented peer certificate DER,
never from an HTTP header or another client-supplied string. A test proves
that a spoofed `X-Client-Cert-Fingerprint` header does not bypass the list.

**This is NOT OCSP, OCSP stapling, a distributed CRL, a CRL distribution
point or any network fetch.** There is no live status, expiry or distribution:
a certificate is denied only because an operator listed its fingerprint in
one process-local environment variable at startup. An invalid fingerprint is
a startup error rather than a silently ignored entry.

### ALPN negotiation and reporting

Every TLS listener advertises `h2` and `http/1.1`, in that order. rustls
reports the selected protocol; with `OPR_LOG_JSON=1` the structured request
log gains an `alpn` field. A measured R8 sample:

```json
{"alpn":"h2","elapsed_ms":0,"method":"GET","path":"/health","status":200}
```

When the client offers no ALPN, no protocol is selected and the log keeps its
four R4 fields. **The server still parses HTTP/1.1 only**: selecting `h2`
does not enable HTTP/2 frames. R8 implements negotiation and reporting, not a
second HTTP implementation.

### R8 honest scope

* No HTTP/2 frame implementation, no HPACK, no streams, no prioritisation and
  no HTTP/3/QUIC.
* No OCSP, OCSP stapling, CRL fetch, distributed revocation, certificate
  status protocol or revocation cache of any kind.
* No HSM, no private-key isolation, no certificate transparency, no SCT
  validation and no cipher-suite tuning beyond the rustls defaults.
* The client CA and the deny list are static, process-local configuration;
  there is no identity store, no per-client authorization and no rotation.
* Still R9+: HTTP/2 frames, OCSP/CRL fetch, distributed revocation, HSM,
  certificate transparency, permessage-deflate, a sized connection pool and
  load-balancer integration.

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
  through the runtime described above. The R7 transport variables
  `OPR_TLS`, `OPR_TLS_CERT`, `OPR_TLS_KEY`, `OPR_KEEPALIVE` and
  `OPR_WEBSOCKET` work the same way. The R8 TLS variables `OPR_MTLS`,
  `OPR_CLIENT_CA` and `OPR_REVOKED` work the same way too.
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
sizing remains R9+.

## Demo server

```sh
cargo run --bin opurom-server -- 8787      # or: OPR_PORT=8787 cargo run --bin opurom-server
```

The demo serves `/health`, `/ssr` and an in-memory `/todos` collection with the
five CRUD verbs. It uses the same optional rate limiter, structured logging
and opt-in R5 HTTP features as generated services, and it understands the
opt-in R7/R8 transport variables:

```sh
OPR_TLS=1 OPR_KEEPALIVE=1 OPR_WEBSOCKET=1 cargo run --bin opurom-server -- 8787
OPR_MTLS=1 OPR_CLIENT_CA=client-ca.pem OPR_LOG_JSON=1 \
  cargo run --bin opurom-server -- 8787
```

## Dependencies

The R7 transport features add seven pinned dependencies; R8 adds none.
Every version is pinned with `=` so a rebuild cannot pull a different
release.

| Crate | Version | Why |
| --- | --- | --- |
| `rustls` | 0.23.46 | the TLS 1.2/1.3 implementation, with the `ring` provider and no OpenSSL |
| `rustls-pemfile` | 2.2.0 | reading the PEM certificate and private key files |
| `rcgen` | 0.14.10 | generating the self-signed certificate at startup |
| `sha2` | 0.10.9 | the SHA-256 certificate fingerprint that is logged |
| `sha1` | 0.10.6 | the SHA-1 of the WebSocket handshake key, as RFC 6455 requires |
| `base64` | 0.23.1 | the base64 handshake accept value and the client key |
| `getrandom` | 0.2.17 | the random bytes for a WebSocket key and for a frame mask |

`rcgen` is built with `default-features = false` and only the `crypto`,
`pem` and `ring` features, so its optional `x509-parser` and `aws-lc-rs`
paths are not compiled in. `rustls` is built with `default-features = false`
and only `ring`, `std`, `tls12` and `logging`, so no system TLS library is
needed.

## Tests

```sh
cargo fmt --all
cargo test
```

All 67 R7 tests remain green: 37 from R6 and 30 from R7. The R8 suite adds
9 more, for 76 in total. Several suites drive a real server on an ephemeral
port over TCP:

| Test file | Covers |
| --- | --- |
| `tests/http_server.rs` | health, the full CRUD lifecycle, 404, 405, 413, the 1 MiB boundary, panic -> 500 -> 503 with other routes still serving, `:param` matching |
| `tests/ssr.rs` | byte-identical output for the same IR and theme, theme changes the output, state interpolation, kind -> HTML element mapping, IR version validation |
| `tests/codegen.rs` | generated crate shape, migration SQL, deterministic lowering, IR validation, one shared `PooledDb` in generated code |
| `tests/hardening.rs` | deterministic N/N+1 rate-limit boundary and window reset, `OPR_RATE_LIMIT` over TCP, JSON log shape with numeric measured `elapsed_ms`, one JSON stderr line per request, byte-identical default responses |
| `tests/http_features.rs` | 401/304/204 status and body paths, gzip bytes decompressed to the original JSON, exact 1024-byte threshold, fixed CORS headers/preflight, deterministic ETag over TCP, all-feature composition, unauthorized and preflight rate-limit/log composition, default-off wire bytes |
| `tests/tls.rs` | a real TLS handshake over a real socket, an untrusted certificate refused by the client, the SHA-256 fingerprint and the private key never logged, a missing certificate file, a certificate without a key naming the missing variable, a corrupt PEM, a mismatched certificate and key pair, the demo server exiting with a clear error, plain HTTP staying byte-identical |
| `tests/websocket.rs` | the RFC 6455 handshake with the documented accept value, a text frame round trip, a binary frame round trip, ping answered with pong, a close frame with its code and reason, a message reassembled from two fragments, a message reassembled from three fragments, an oversized frame refused before allocation, an unmasked client frame refused, the client refusing a wrong accept value and a non-101 answer |
| `tests/keepalive.rs` | two requests on one socket, a `Connection: close` request ending the connection, the idle timeout closing a silent connection, the in-flight limit answering 503, the documented default limits, the demo server with and without `OPR_KEEPALIVE` |
| `tests/mtls.rs` | real sockets with an rcgen CA -> server chain -> client cert chain, `OPR_MTLS=1` alone enabling TLS, a trusted client accepted, missing and self-signed untrusted clients refused, a revoked-but-trusted cert refused and a non-revoked one accepted, a spoofed fingerprint header ignored, `h2`/`http/1.1` ALPN selection and reporting, the structured log `alpn` field, clear mTLS refusal diagnostics, and the byte-identical R7 single-sided TLS answer |

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
| Structured request logging | Implemented, opt-in via `OPR_LOG_JSON`, measured `elapsed_ms`, plus `alpn` when TLS negotiated a protocol |
| Bearer auth (development token) | Implemented, opt-in via `OPR_AUTH_TOKEN`, 401 JSON, no early-exit byte comparison |
| gzip responses | Implemented, request-opt-in above 1024 bytes, `Content-Encoding` and `Vary`, decompression tested |
| ETag / `304` | Implemented, opt-in deterministic body hash, empty-body conditional response over TCP |
| CORS / preflight | Implemented, opt-in fixed origin or literal `*`, 204 with fixed allow lists |
| `opurom-serverc` lowering to a standalone crate | Implemented, tested |
| TLS listener | Implemented, opt-in via `OPR_TLS=1`, rustls with a self-signed fallback, fingerprint logged, real handshake tested |
| Mutual TLS client certificates | Implemented, opt-in via `OPR_MTLS=1` + `OPR_CLIENT_CA`, mandatory rustls verification over real sockets |
| Certificate revocation | Implemented as a static `OPR_REVOKED` fingerprint deny list over presented peer certificates; NOT OCSP or a distributed CRL |
| ALPN negotiation and reporting | Implemented, `h2` and `http/1.1` advertised, selected protocol in the structured log and test output; no HTTP/2 frames |
| WebSocket (RFC 6455) | Implemented, opt-in via `OPR_WEBSOCKET=1`, handshake, text, binary, ping/pong, close and fragmentation, bounded frames |
| HTTP/1.1 keep-alive | Implemented, opt-in via `OPR_KEEPALIVE=1`, `Content-Length` framing, idle timeout, in-flight limit |

Not implemented (R9+):

| Area | Status |
| --- | --- |
| HTTP/2 frames and HTTP/3 | Not implemented (ALPN advertisement only, HTTP/1.1 parser only, no QUIC) |
| OCSP / CRL fetch / distributed revocation | Not implemented (a static process-local fingerprint deny list only) |
| HSM and certificate transparency | Not implemented (no private-key isolation, no SCT validation) |
| `permessage-deflate` | Not implemented (no extension is negotiated, no frame is compressed) |
| Load-balancer integration | Not implemented (no `X-Forwarded-*`, no `Forwarded`, no proxy protocol) |
| Real authentication provider / token lifecycle | Not implemented (development bearer token only) |
| Real connection pool sizing | Not implemented (one shared Mutex-guarded connection only, one thread per connection) |
| Distributed rate limiting | Not implemented (in-process counters only) |
| PostgreSQL / MySQL drivers | Not implemented in this repository (SQLite and the `opurom-db` KV/Memory drivers only) |
| Node.js / Serverless deployment | Not implemented |
| Per-route CORS, credentialed CORS | Not implemented (one fixed configured origin or `*`; no cookies or credentials) |
| Streaming, HTTP/2 frames, compression dictionaries | Not implemented (whole-body gzip only, HTTP/1.1 only) |
| Real device benchmarks | Not implemented; no fabricated numbers |
| Chunked request bodies | Not implemented (`Transfer-Encoding` is still rejected with 501) |
