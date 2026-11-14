# opurom-server

OPUROM backend runtime: a small HTTP/1.1 server with ALPN-selected HTTP/2 and
opt-in HTTP/3 over QUIC, a router with path parameters, per-route fault
isolation, a deterministic SSR host, hardening (pooled SQLite, fixed-window
rate limiting, structured logs), opt-in HTTP features (bearer auth, gzip,
ETag, CORS), opt-in transport features (TLS, WebSocket, HTTP/1.1 keep-alive),
opt-in mutual TLS with a static certificate revocation deny list and ALPN
reporting, opt-in DER CRL/OCSP certificate status checks from local files or
an HTTP CRL distribution point with a refreshable cache, and
`opurom-serverc`, the compiler that lowers a full-stack IR into a standalone
Rust service crate.

This crate implements the backend half of
[`FULLSTACK_SPEC.md`](https://github.com/opurom/opurom-spec/blob/main/FULLSTACK_SPEC.md) sections 4-5,
[`TOOLCHAIN_AND_PACKAGES.md`](https://github.com/opurom/opurom-spec/blob/main/TOOLCHAIN_AND_PACKAGES.md)
section 6,
[`GPU_WINDOW_TRANSPORT.md`](https://github.com/opurom/opurom-spec/blob/main/GPU_WINDOW_TRANSPORT.md) section 6,
[`NATIVE_NETWORK.md`](https://github.com/opurom/opurom-spec/blob/main/NATIVE_NETWORK.md) sections 1 and 5,
[`BROWSER_AND_NATIVE_SURFACES.md`](https://github.com/opurom/opurom-spec/blob/main/BROWSER_AND_NATIVE_SURFACES.md)
section 4,
[`PRODUCTION_BREADTH.md`](https://github.com/opurom/opurom-spec/blob/main/PRODUCTION_BREADTH.md) section 2,
[`COMPONENT_LIBRARY_HARDENING.md`](https://github.com/opurom/opurom-spec/blob/main/COMPONENT_LIBRARY_HARDENING.md)
section 5 and
[`TRANSPORT_AND_LANGUAGE_ADDITIONS.md`](https://github.com/opurom/opurom-spec/blob/main/TRANSPORT_AND_LANGUAGE_ADDITIONS.md)
section 1.

## Architecture

```
TCP/HTTP request -> HTTP/1.1 parser, HTTP/2 mapping or HTTP/3 mapping
                  request line + headers, HEADERS/DATA + HPACK, or
                  the h3 request/response exchange over QUIC
                  body cap 1 MiB -> 413
               -> middleware::MiddlewareChain
                  logging (plain by default) + body cap
               -> server::Server optional OPR_RATE_LIMIT check
                  429 JSON + Retry-After; every parsed request counts
               -> opt-in preflight / bearer auth
                   OPR_CORS OPTIONS -> 204; OPR_AUTH_TOKEN mismatch -> 401
                   GET /health stays open to an unauthenticated probe
                -> router::Router
                  literal + :param segments
                  list routes: ?limit=&offset=&sort=&order=&q= -> 400 or envelope
                  404 unknown / 405 wrong method
                  catch_unwind per handler
                  3 consecutive panics -> route disabled
               -> handler
                  generated CRUD code (opurom-db PooledDb)
                  SSR render (ssr::ssr_html)
               -> opt-in response finalization
                   fixed CORS + Vary: Origin, ETag/304, gzip + Vary
                -> server::Server optional OPR_LOG_JSON line to stderr
```

The transport layer wraps that core:

```
accept -> optional TLS handshake (rustls, OPR_TLS=1 or OPR_MTLS=1)
           OPR_MTLS=1: require a client certificate, apply the static deny list
            and every required DER CRL/OCSP status source (local or HTTP)
           ALPN: advertise h2/http/1.1, report the selected protocol
        -> h2: http2::serve (HEADERS/DATA, HPACK, streams, flow control, GOAWAY)
           -> same middleware/router/response features
       -> h3: http3::serve (QUIC, TLS 1.3, ALPN "h3", a separate UDP listener)
          -> same middleware/router/response features
       -> http/1.1 or no ALPN: optional WebSocket upgrade (RFC 6455, OPR_WEBSOCKET=1)
       -> HTTP/1.1 keep-alive loop (OPR_KEEPALIVE=1)
          Content-Length framing, idle timeout, in-flight limit
```

| Module | Responsibility |
| --- | --- |
| `http` | `Method`, `Request`, `Response`, the bounded request parser, status text |
| `http2` | ALPN-selected HTTP/2: h2 HEADERS/DATA, HPACK, stream multiplexing, flow control, bounded settings, graceful GOAWAY and mapping into the shared request pipeline |
| `http3` | HTTP/3 over QUIC on a separate UDP listener: the TLS 1.3 and ALPN `h3` endpoint, the real h3 request/response exchange and mapping into the shared request pipeline |
| `middleware` | `MiddlewareChain`, `RateLimiter`, logging helpers, body cap, opt-in HTTP options |
| `router` | route table, `:param` matching, panic isolation, 3-strike breaker, route introspection |
| `query` | strict list query parsing (`limit`, `offset`, `sort`, `order`, `q`), stable ordering and the `{items,total,count,limit,offset}` envelope |
| `server` | `TcpListener` accept loop, one thread per connection, optional TLS, ALPN-selected HTTP/2, optional keep-alive, optional WebSocket upgrade, opt-in response features and measured JSON log |
| `tls` | the optional TLS listener: environment configuration, PEM loading, self-signed fallback, SHA-256 fingerprint, opt-in client-certificate mTLS, static fingerprint deny list, local DER CRL/OCSP status sources, HTTP CRL distribution point configuration and ALPN |
| `cert_status` | bounded DER CRL/BasicOCSPResponse parsing, CA signature checks, serial matching, freshness checks, std-only HTTP CRL retrieval with a URL-keyed cache and fail-closed status decisions |
| `websocket` | the RFC 6455 frame codec with size limits, the server channel and the client helper |
| `ssr` | deterministic HTML rendering of the IR tree with theme tokens |
| `ir` | IR v0.1 model: state, tree, theme, models, api |
| `codegen` | the `opurom-serverc` lowering pass |

Errors are values everywhere: a failed request is a `Response`, a panicking
handler is caught, and no failure path aborts the process.

## Router introspection

`Router::routes()` reports the registered routes in registration order. Each
entry is a `RegisteredRoute` with the `method` and the canonical `path`
pattern; `:name` parameter segments appear as they do at registration.
Repeated slashes and a trailing slash are normalized in the reported pattern
to the segments the router compares. The query is a read-only view of the table:
it neither dispatches a request nor changes router state, so layer-inspection
tooling can enumerate verbs and paths without keeping a second list.

## HTTP contract

* Request: HTTP/1.1 request line, headers, `Content-Length` body. `Transfer-Encoding`
  is rejected with 501. `Expect: 100-continue` on an HTTP/1.1 request gets the interim
  `HTTP/1.1 100 Continue` answer before the body is read, and an unknown `Expect` value
  gets 417.
* Body cap: 1 MiB (`http::MAX_BODY_BYTES`). A larger body gets `413` and the body is
  drained so the client can read the answer.
* Header cap: 64 KiB (`http::MAX_HEADER_BYTES`) covers the request line and all
  header lines, enforced while the bytes arrive. A larger block gets `431`,
  including one line that never terminates. A read that times out gets `408`.
* Response: always `Content-Type: application/json` for JSON bodies, `text/html` for
  SSR, `Content-Length`, and `Connection: close` by default. `304`
  and `204` carry no body and `Content-Length: 0`. With `OPR_KEEPALIVE=1` the
  answer carries `Connection: keep-alive` and the connection is reused.
* Methods: `GET`, `POST`, `PUT`, `DELETE`. `OPTIONS` is a CORS preflight only
  when `OPR_CORS` is set; otherwise the router answers `405` on known paths.
* The HTTP features are opt-in. With no opt-in environment variable
  and no `Accept-Encoding: gzip`, response bytes stay identical to the
  defaults; `Origin`, `If-None-Match` and `OPTIONS` request headers alone
  enable nothing.
* The transport features are opt-in too. With no `OPR_TLS`, `OPR_KEEPALIVE` and
  `OPR_WEBSOCKET`, the wire format is byte-identical to plain HTTP.
* The mutual-TLS features are opt-in too. With no `OPR_MTLS`, `OPR_CLIENT_CA`
  and `OPR_REVOKED`, plain HTTP and the single-sided TLS HTTP response bytes
  stay byte-identical. A TLS client that offers no ALPN negotiates no
  protocol and gets the same four-field request log line.
* HTTP/2 is selected solely by ALPN `h2` on the TLS listener; no new
  environment variable is needed. Requests arrive as HEADERS/DATA frames and
  pass through the same middleware and router. Responses use h2 HEADERS/DATA
  frames, preserve status, body and the opt-in HTTP headers, set an exact
  `Content-Length` and omit HTTP/1.1 `Connection` headers. Plain HTTP, no
  ALPN and `http/1.1` ALPN keep the HTTP/1.1 wire bytes.
* The certificate status sources are opt-in too. With none of `OPR_CRL_FILE`,
  `OPR_OCSP_FILE` and `OPR_CRL_URL` set, the mTLS handshake and HTTP/1.1
  response bytes stay identical. Each configured source is required for every
  mTLS handshake and any unavailable or unusable source refuses the
  connection. `OPR_CRL_FILE` takes precedence over `OPR_CRL_URL`.

| Situation | Status | Body |
| --- | --- | --- |
| Health check | 200 | `{"ok":true,"app":"<name>","version":"0.2.0"}` (open even with auth) |
| List | 200 | `{"items":[...],"total":N,"count":N,"limit":N,"offset":N}` |
| Invalid list query value | 400 | `{"error":"invalid_limit"}` and variants (`negative_*`, `*_too_large`, `invalid_order`) |
| Create | 201 | the created row object |
| Get / Update | 200 | the row object |
| Delete | 200 | `{"deleted":true}` |
| Unknown path | 404 | `{"error":"not_found"}` |
| Wrong method | 405 | `{"error":"method_not_allowed"}` |
| Body over 1 MiB | 413 | `{"error":"payload_too_large"}` |
| Unknown `Expect` value | 417 | `{"error":"expectation_failed"}` |
| Header block over 64 KiB | 431 | `{"error":"header_block_too_large"}` |
| Incomplete request read times out | 408 | `{"error":"request_timeout"}` |
| Rate limit exceeded | 429 | `{"error":"rate_limited"}` plus `Retry-After` seconds |
| Missing/mismatched bearer token (`OPR_AUTH_TOKEN`) | 401 | `{"error":"unauthorized"}` |
| Matching `If-None-Match` (ETag enabled) | 304 | empty |
| CORS preflight (`OPR_CORS`) | 204 | empty |
| Handler panic | 500 | `{"error":"handler_panic"}` |
| Route disabled after 3 panics | 503 | `{"error":"route_disabled"}` |
| Too many in-flight connections | 503 | `{"error":"server_busy"}` |

Row objects use the model field names exactly; a `bool` field is a JSON boolean.

## Hardening

All hardening is opt-in-compatible. With no `OPR_RATE_LIMIT` and no
`OPR_LOG_JSON`, HTTP responses, stdout, and the existing plain stderr log
remain byte-identical. There is no 429 and no JSON log line by default.
`OPR_RATE_LIMIT` and `OPR_LOG_JSON` do not enable any opt-in response
feature.

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
request logs. A measured sample from the smoke run:

```json
{"elapsed_ms":0,"method":"GET","path":"/health","status":200}
```

## Opt-in HTTP features

All four features work on the existing demo server and generated services
through `Server::bind_with`; there is no second binary. Options are read once
when the listener binds. A development configuration with every feature on:

```sh
OPR_AUTH_TOKEN=devtoken OPR_CORS=https://app.example OPR_ETAG=1 \
  cargo run --bin opurom-server -- 8787
```

`OPR_ETAG=1` enables ETags alone; `OPR_AUTH_TOKEN` or `OPR_CORS` also enables
them, so a hardened server can be checked with one ETag round trip. Set
`OPR_ETAG=0` to disable them explicitly. The hardening variables
`OPR_RATE_LIMIT` and `OPR_LOG_JSON` never enable the opt-in HTTP features.
With no opt-in environment variable and no `Accept-Encoding: gzip` request
header, HTTP response bytes, stdout and the plain stderr log remain
byte-identical to the defaults.

### Bearer auth

`OPR_AUTH_TOKEN=<value>` requires `Authorization: Bearer <value>` on every
non-preflight request. Missing, malformed or mismatched credentials get
`401` with `{"error":"unauthorized"}`. `GET /health` stays open so a health
probe or load balancer reaches the service with no credential. The token bytes
are compared in time that depends only on their lengths: both sides are folded
to SHA-256 digests and XOR-accumulated without an early exit, so a wrong token
never reveals how many leading bytes matched. **This is a development token,
not a production identity system**: there are no users, scopes, expiry,
password hashing or credential storage.

The gate is configured by an env-independent `AuthOptions` value
(`AuthOptions::new(token)`, `allow_health` on by default) through
`Server::with_auth(options)`; `OPR_AUTH_TOKEN` is only one way to fill it. A
server built with `AuthOptions::default()` leaves every route open.

```sh
curl -i http://127.0.0.1:8787/health        # open: 200, no credential
curl -i http://127.0.0.1:8787/todos         # 401
# HTTP/1.1 401 Unauthorized ... {"error":"unauthorized"}
curl -i -H 'Authorization: Bearer devtoken' http://127.0.0.1:8787/todos
```

### List query and pagination

The list routes (`GET /todos` in the demo, `list` in generated services) accept
a structured query and answer a paginated envelope:

```
GET /todos?limit=20&offset=40&sort=title&order=desc&q=write
{
  "items":  [ {"id": 7, "title": "write tests"}, ... ],
  "total":  5,   // rows after the filter, before paging
  "count":  2,   // rows in this page (items length)
  "limit":  20,
  "offset": 40
}
```

* `limit` - page size, default 50 (`query::DEFAULT_LIMIT`), `1..=1000`
  (`query::MAX_LIMIT`). `limit=0` is accepted and returns an empty page.
* `offset` - rows to skip, default 0, `0..=1_000_000` (`query::MAX_OFFSET`).
* `sort` - the field name to order by; absent means the handler's own order.
* `order` - `asc` (default) or `desc`.
* `q` - case-insensitive substring filter across a row's scalar fields.

Validation is strict and returns `400` with a specific reason instead of
silently clamping: a negative (`negative_limit`), non-integer
(`invalid_limit`), or over-cap (`limit_too_large`) value, an unknown `order`
(`invalid_order`) and the same for `offset`. Unknown parameters are ignored so a
link with `?utm=...` still lists. Ordering is deterministic and stable: equal
keys keep their incoming order, integers compare exactly, strings by bytes, and
a missing key sorts last, so repeated calls return identical bytes.

### gzip responses

`Accept-Encoding: gzip` is request-opt-in compression. Only bodies **larger
than 1024 bytes** (`middleware::GZIP_THRESHOLD_BYTES`) are compressed with
`flate2`; the response gains `Content-Encoding: gzip` and
`Vary: Accept-Encoding`. Small bodies, `q=0` and non-gzip codings stay
uncompressed. The hash used for an ETag is computed from the uncompressed
body, and the tests decompress the wire bytes back to the original JSON.

```sh
TITLE=$(python3 -c 'print("x" * 1100)')
curl -sS -H 'Authorization: Bearer devtoken' -H 'Content-Type: application/json' \
  -d "{\"title\":\"$TITLE\"}" http://127.0.0.1:8787/todos
curl -i --compressed -H 'Authorization: Bearer devtoken' \
  -H 'Accept-Encoding: gzip' http://127.0.0.1:8787/todos
# Content-Encoding: gzip / Vary: Accept-Encoding[, Origin]
```

### ETags and `304`

`OPR_ETAG=1` (or another opt-in variable) adds a deterministic, quoted
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

### Composition

Order is: middleware/logging -> rate limit -> CORS preflight -> bearer
auth -> router/pooled handlers (list routes parse the structured query here)
-> CORS/ETag/gzip finalization -> one log line. An unauthorized request still
counts against `OPR_RATE_LIMIT` and gets an `OPR_LOG_JSON` line; a preflight
does the same, and an open `/health` request does too. Gzip, ETag and fixed CORS
headers compose on one response, and `304` keeps CORS headers but has no
compressed body. The generated service's one shared `PooledDb` is unchanged.

The bearer token is a development check. h2 applies the same whole-response
features; there is no streaming compression because each response is encoded
in memory before h2 frames it. ETags are body hashes, not a versioned
cache-invalidation system.

## Transport features (opt-in)

All three transport features are opt-in and independent. With none of them
set the server serves plain HTTP: one request per connection, `Connection:
close` on every response, byte-identical response bytes.

| Variable | Effect |
| --- | --- |
| `OPR_TLS=1` | serve HTTPS on the same bind address |
| `OPR_TLS_CERT` | PEM certificate file for the TLS listener |
| `OPR_TLS_KEY` | PEM private key file for the TLS listener |
| `OPR_KEEPALIVE=1` | reuse one connection for several HTTP/1.1 requests |
| `OPR_WEBSOCKET=1` | accept RFC 6455 WebSocket upgrades |
| `OPR_HTTP3=1` | serve HTTP/3 over QUIC on a separate UDP listener |
| `OPR_HTTP3_PORT` | the UDP port of the QUIC listener; the default is `4433` |

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
  closed. The timeout is also the socket read timeout, so an incomplete
  request gets `408` before the connection closes.
* **Maximum in-flight connections**: at most
  `server::DEFAULT_MAX_CONNECTIONS` (256) connections are served at the
  same time. A connection that arrives above the limit gets
  `503 {"error":"server_busy"}` and is closed.

Both values are settable in code with `Server::with_idle_timeout` and
`Server::with_max_connections`.

### Transport feature limits

* **Client certificates are a separate opt-in**: the transport variables alone
  never ask for a client certificate. See the mutual-TLS section below.
* **The CRL distribution point uses HTTP**: `OPR_CRL_URL` fetches a DER CRL
  with bounded connect and read timeouts, a bounded response size and strict
  status and `Content-Length` handling; the DER is cached per URL and
  refreshed after `OPR_CRL_TTL_SECS`. See the certificate-status section
  below.
* **No HSM and no cipher-suite tuning**: the cipher suites and the protocol
  versions are the `rustls` library defaults. There is no configuration for
  them.
* **No permessage-deflate**: the WebSocket implementation negotiates no
  extensions and never compresses a frame. `Sec-WebSocket-Extensions` is
  neither sent nor honoured.
* **The HTTP/3 listener is opt-in**: `OPR_HTTP3=1` starts a QUIC endpoint with
  TLS 1.3 and ALPN `h3` on its own UDP port. Without the variable no UDP
  socket is opened. See the HTTP/3 section below.
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
## Mutual TLS, revocation and ALPN (opt-in)

The mutual-TLS features extend the same rustls listener. Plain HTTP is
unchanged. With no mutual-TLS variable set, the single-sided TLS path keeps
its HTTP response bytes; a client that offers no ALPN negotiates no protocol
and sees no extra log field. Real h2 frames are served on a TLS connection
whose ALPN selection is `h2`. `OPR_MTLS=1` also enables TLS, so `OPR_TLS=1` is
optional (setting both is harmless). All three variables are read once at
startup.

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
[opurom-server] mTLS handshake refused: client certificate missing, untrusted, revoked or status unavailable (check OPR_CLIENT_CA, OPR_REVOKED, OPR_CRL_FILE, OPR_CRL_URL and OPR_OCSP_FILE): peer sent no certificates
```

A trusted client receives the negotiated response: unchanged HTTP/1.1 for
`http/1.1` or no ALPN, and real h2 frames for `h2`. Setting `OPR_MTLS=1`
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

`OPR_REVOKED` is a process-local list of presented certificate fingerprints.
The DER CRL/OCSP sources and the HTTP CRL distribution point are separate
checks applied after rustls verifies the chain. An invalid fingerprint is a
startup error rather than a silently ignored entry.

### ALPN negotiation and reporting

Every TLS listener advertises `h2` and `http/1.1`, in that order. rustls
reports the selected protocol; with `OPR_LOG_JSON=1` the structured request
log gains an `alpn` field. A measured sample:

```json
{"alpn":"h2","elapsed_ms":0,"method":"GET","path":"/health","status":200}
```

When the client offers no ALPN, no protocol is selected and the log keeps its
four default fields. HTTP/2 is served when `h2` is selected, and the
unchanged HTTP/1.1 parser stays in place when `http/1.1` is selected. Each
completed h2 stream writes the same structured log fields with `"alpn":"h2"`.

### Mutual-TLS behaviour

* The HTTP/2 implementation covers HPACK, HEADERS/DATA frames, streams and
  flow control. The HTTP/3 implementation covers QUIC transport, the HTTP/3
  frame layer and QPACK header compression on a separate UDP listener.
* The required status sources are local DER CRL/OCSP files and an HTTP CRL
  distribution point whose DER is cached per URL and refreshed on an interval.
  Every handshake verifies the CRL signature, issuer and freshness before a
  serial is accepted.
* The cipher suites and protocol versions are the rustls defaults.
* The client CA and the deny list are process-local configuration.

## Real HTTP/2 (ALPN-selected)

`OPR_TLS=1` or `OPR_MTLS=1` enables the existing rustls listener. **No new
environment variable enables HTTP/2**: rustls ALPN decides. A client that
selects `h2` gets real HTTP/2 on that TLS connection; `http/1.1` or no ALPN
keeps the unchanged HTTP/1.1 path. Plain HTTP stays byte-identical.

The `h2` crate handles the HTTP/2 connection preface, HPACK, HEADERS/DATA
frames, stream multiplexing and stream/connection flow control. One
current-thread Tokio runtime is created per negotiated h2 connection; the
outer server remains thread-per-connection. Each h2 request is converted into
the existing `http::Request` (method, path, query, headers and bounded DATA
body) and goes through `server::dispatch_request`: the same middleware chain,
rate limiter, CORS preflight, bearer auth, router, fault isolation,
ETag/gzip/CORS finalization and structured log. Response headers are copied
to h2 HEADERS except HTTP/1.1 connection-specific fields; an exact
`Content-Length` is set and the body is sent as DATA frames. Empty `204`/`304`
responses close the stream with HEADERS only.

| Limit | Value | Purpose |
| --- | --- | --- |
| Frame payload | 16,384 bytes | `SETTINGS_MAX_FRAME_SIZE`; h2 splits outbound DATA to the peer's frame size |
| Concurrent client streams | 100 | `SETTINGS_MAX_CONCURRENT_STREAMS`; further streams are reset |
| HPACK header list | 64 KiB | maximum uncompressed received header list |
| Initial receive window | 1 MiB | per stream and per connection |
| Per-stream send buffer | 1 MiB | bounded queued DATA |
| Request body | 1 MiB | the existing `http::MAX_BODY_BYTES`; overflow gets 413 |

The server watches the existing `Server::shutdown_handle()`. On shutdown it
calls h2 graceful shutdown, sends an initial `GOAWAY` with
`last_stream_id=2^31-1` and `NO_ERROR`, waits for the PING/PONG round trip,
drains active streams and sends the final `GOAWAY` with the actual last stream
ID. A raw-frame test verifies both GOAWAY frames and the `NO_ERROR` code.

A real h2 client opens one TLS connection and several concurrent streams. One
five-stream test yields `GET /health -> 200`, `GET /items/42?q=one -> 200`,
`POST /echo -> 200`, `OPTIONS /health -> 204` and
`GET /blocked -> 418`, with exact bodies and ETag/CORS headers. A second test
sends a 256 KiB response and a 128 KiB request across flow-control windows on
the same connection while `GET /panic -> 500` leaves `GET /health -> 200`
intact.

The HTTP/2 implementation has no server push, no client-controlled priority
tree, no connection coalescing across origins, no h2 extended CONNECT or
WebSocket-over-h2 upgrade, and no trailers. There is no application-level
streaming: each response body is built in memory before h2 frames it.

## Real HTTP/3 over QUIC (opt-in)

`OPR_HTTP3=1` starts a QUIC endpoint on its own UDP port and serves real
HTTP/3 on it. `OPR_HTTP3_PORT` chooses that port; the default is `4433`. The
listener needs a certificate, so it reuses the configuration of the HTTPS
listener: with `OPR_TLS=1` or `OPR_MTLS=1` the QUIC endpoint serves the same
certificate and the same key pair. Without a TLS configuration there is no QUIC
endpoint, and the server says so on stderr.

The endpoint uses TLS 1.3 with the ALPN protocol `h3`. The `quinn` crate
carries the QUIC transport and the `h3` crate the HTTP/3 frame layer with
QPACK header compression. A QUIC connection only carries HTTP/3, so the ALPN
list of the QUIC configuration contains `h3` alone.

```sh
OPR_TLS=1 OPR_HTTP3=1 OPR_HTTP3_PORT=4433 opurom-server
```

| Variable | Effect |
| --- | --- |
| `OPR_HTTP3` | starts the QUIC listener; without it no UDP socket is opened |
| `OPR_HTTP3_PORT` | the UDP port of the QUIC listener; the default is `4433` |
| `OPR_ALT_SVC_PORT` | the UDP port advertised with `Alt-Svc` on the HTTPS responses |

### One shared request pipeline

The HTTP/1.1, HTTP/2 and HTTP/3 paths have separate transports but one shared
request pipeline. Each protocol converts its request into the same
`http::Request` and calls the same `server::dispatch_request`, so the same
middleware chain, rate limiter, CORS preflight, bearer auth, router, handler
fault isolation, ETag/gzip/CORS finalization and structured log apply to all
three. The same route therefore returns the same JSON body on every protocol;
an integration test compares the HTTP/1.1 and HTTP/3 answers byte for byte.

A panicking handler is caught by the same `catch_unwind` in the router on
every protocol: HTTP/3 answers `500 {"error":"handler_panic"}` and the endpoint
keeps serving the other routes.

### Alt-Svc advertisement

An HTTPS response advertises the HTTP/3 endpoint with an `Alt-Svc` header, so
a client learns the QUIC alternative of the same origin:

```
Alt-Svc: h3=":4433"
```

The header is opt-in and appears only on a TLS listener, because the client has
to reach the advertised endpoint over the same origin. Set
`OPR_ALT_SVC_PORT` to choose the advertised port; without the variable the
response headers stay unchanged. When the HTTP/3 listener is enabled its real
UDP port is advertised, so a listener bound to an ephemeral port is
advertised correctly. The HTTP/3 responses themselves carry no `Alt-Svc`
header, because a client that already speaks HTTP/3 needs no alternative
service.

### Measured HTTP/3 exchange

The integration test binds a QUIC endpoint on an ephemeral UDP port, completes
a real TLS 1.3 handshake with ALPN `h3` and exchanges real h3 requests. The
timings below are measured with `std::time::Instant` on the host that produced
them; they are the handshake time of one QUIC connection and the round trip of
one request.

```
[h3] GET /health -> 200 body={"ok":true} handshake=2.705875ms request=1.202666ms
[h3] GET /items/42?q=one -> 200 body={"id":"42","query":"q=one"} handshake=1.830667ms request=736µs
[h3] POST /echo -> 200 body=hello h3 handshake=1.763459ms request=452.583µs
[h3] GET /panic -> 500 body={"error":"handler_panic"}
[h3] GET /health after the panic -> 200 body={"ok":true}
```

### Measured HTTP/3 concurrency and body boundaries

Three more integration tests measure the shared router under concurrent HTTP/3
load. One batch opens eight in-flight `GET` streams on a single QUIC
connection and asserts the exact body of every response; a second batch sends
ten concurrent requests where two hit the panicking handler and asserts the
exact `500` diagnostic next to the exact `200` bodies; a third echoes POST
bodies at the boundary sizes of the 1 MiB cap through HTTP/3 and the HTTP/1.1
path of the same router and asserts both answers are identical. Every number
below is measured with `std::time::Instant` during the run that produced it:

```
[h3] 8 concurrent GET requests on one QUIC connection -> 8x 200 with exact bodies; handshake=1.925958ms batch=964.583µs per-request=830.833µs..857.5µs
[h3] GET /health after the batch -> 200 body={"ok":true}
[h3] 10 concurrent requests, 2 to the panicking route -> 8x 200 with exact bodies, 2x 500 {"error":"handler_panic"}; batch=1.623375ms
[h3] GET /health after the load -> 200 body={"ok":true}
[h3] POST /echo 0 bytes -> HTTP/1.1 200 and HTTP/3 200 return the identical echo; h3 request=925.042µs
[h3] POST /echo 1 bytes -> HTTP/1.1 200 and HTTP/3 200 return the identical echo; h3 request=769.042µs
[h3] POST /echo 4096 bytes -> HTTP/1.1 200 and HTTP/3 200 return the identical echo; h3 request=364.083µs
[h3] POST /echo 1048576 bytes -> HTTP/1.1 200 and HTTP/3 200 return the identical echo; h3 request=19.04025ms
```

## Certificate status (opt-in)

Real certificate status checks run on the same rustls mTLS listener. They do
not replace the fingerprint deny list. Local DER files named at startup are
read again at each handshake. `OPR_CRL_URL` retrieves a DER CRL from an HTTP
distribution point and keeps it in a URL-keyed cache. With none of these
variables set, the mTLS path is unchanged, including byte-identical HTTP/1.1
answers.

| Variable | Effect |
| --- | --- |
| `OPR_CRL_FILE` | required local DER X.509 v2 CRL; takes precedence over `OPR_CRL_URL` |
| `OPR_CRL_URL` | `http://` CRL distribution point, or the literal `cert` to read the first URI of the client certificate's CRL Distribution Points extension |
| `OPR_CRL_TTL_SECS` | cache refresh interval in seconds (fractional values allowed); default `3600` |
| `OPR_OCSP_FILE` | required local DER `BasicOCSPResponse` |

All four variables are read only when `OPR_MTLS=1`. A configured source is
required: a missing, unreadable, empty or oversized file, a failed or
malformed distribution-point response, malformed DER, an unverifiable
signature, a mismatched issuer, a stale `nextUpdate`, a future
`thisUpdate`/`producedAt`, an OCSP `unknown` status or a serial with no OCSP
entry refuses the handshake. A CRL that names the presented client serial or
an OCSP `revoked` status refuses it; a non-revoked CRL entry and/or an OCSP
`good` status lets the already-verified chain complete.

The CRL is parsed with `x509-parser` 0.18.1, including the CRL Distribution
Points extension of the presented certificate. The OCSP response uses a strict,
definite-length DER reader for `BasicOCSPResponse`, `ResponseData`,
`SingleResponse`, `CertID` and `CertStatus` (`good` / `revoked` / `unknown`).
SHA-256 `CertID` hashes of the CA subject Name and subject public key are
compared with the configured `OPR_CLIENT_CA`, and both CRL and OCSP signatures
are verified against that CA's public key through `x509-parser`'s
`ring`-backed verifier. Serials are compared as canonical positive DER
INTEGERs. Every DER input is capped at `cert_status::MAX_STATUS_DER_BYTES`
(256 KiB); local files are read through a bounded `take`, HTTP responses are
bounded by `Content-Length`, serials at 20 octets, OCSP responses at 64
`SingleResponse` entries, and indefinite or non-minimal DER lengths are
rejected before slicing.

The HTTP client is a `std::net::TcpStream` GET with a 3-second connect
timeout, 3-second read/write timeouts and a total response deadline, a
required `200` status, exactly one `Content-Length` header and no chunked
transfer. Fetched DER is cached in a `Mutex`-guarded, URL-keyed map with at
most 16 entries, each capped at 256 KiB. A fresh entry is used without a
request; an expired one is refetched; a failed fetch with no fresh cached copy
refuses the handshake with a clear error. Cached DER still goes through the CA
signature, issuer and freshness checks on every handshake. URLs use the
`http://` scheme.

Tests generate a CA, a CA-signed server chain, two CA-signed clients, DER CRLs
and CA-signed OCSP responses with `rcgen` in memory; local DER files are
written only under the ignored `target/` tree at test runtime. A revoked,
stale, malformed, tampered or oversized source is refused over a real socket
and a good client gets `200`. The live-CRL tests run a loopback HTTP server on
`127.0.0.1:0` and measure its request counts: the first handshake fetches, a
second handshake inside the refresh interval makes no request, an expired
entry refetches, a fresh cached CRL works with the server stopped, and an
absent or expired copy with the server stopped fails closed. No private keys
are checked in.

Additional distribution and transparency transports are listed under Future
directions.

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
  `opurom-db/` crates. It is optional: without it the workspace is resolved at
  runtime from the nearest ancestor of the working directory that holds both
  sibling crates, then from the nearest ancestor of the running executable,
  then from the parent of this crate's own manifest directory. An explicit
  `--dep-root` always wins.
* The generated code is **lowered Rust**, not an IR interpreter: the routes,
  the SQL statements and the JSON field lists are emitted at compile time. The
  IR is embedded as a string only for the `/ssr` route.
* The generated crate reads `OPR_PORT` (default `8787`) and `OPR_DB`
  (default `./opurom.db`). The parent directory of `OPR_DB` is created if
  missing. It also honours `OPR_RATE_LIMIT`, `OPR_LOG_JSON`,
  `OPR_AUTH_TOKEN`, `OPR_CORS` and `OPR_ETAG`, plus request-opt-in gzip,
  through the runtime described above. The transport variables `OPR_TLS`,
  `OPR_TLS_CERT`, `OPR_TLS_KEY`, `OPR_KEEPALIVE` and `OPR_WEBSOCKET` work the
  same way. The mutual-TLS variables `OPR_MTLS`, `OPR_CLIENT_CA` and
  `OPR_REVOKED` work the same way too. The status variables `OPR_CRL_FILE`,
  `OPR_OCSP_FILE`, `OPR_CRL_URL` and `OPR_CRL_TTL_SECS` configure the DER
  status sources on those mTLS listeners. h2 is selected by ALPN on those TLS
  listeners; it needs no new variable.
* The schema is created at startup inside one `PooledDb::with` call: every
  `migrations/*.sql` statement is embedded with `include_str!` and executed
  (they are `CREATE TABLE IF NOT EXISTS`, so startup is idempotent).

Build and run the generated service:

```sh
cargo build --release --manifest-path <dir>/Cargo.toml
OPR_PORT=8787 OPR_DB=./opurom.db <dir>/target/release/opurom-service
```

The generated service no longer opens one connection per request. It shares
the one Mutex-serialized connection from `PooledDb`.

## Demo server

```sh
cargo run --bin opurom-server -- 8787      # or: OPR_PORT=8787 cargo run --bin opurom-server
```

The demo serves `/health`, `/ssr` and an in-memory `/todos` collection with the
five CRUD verbs. It uses the same optional rate limiter, structured logging
and opt-in HTTP features as generated services, and it understands the
opt-in transport and mutual-TLS variables. When TLS is on, ALPN `h2` selects
the HTTP/2 path without another variable:

```sh
OPR_TLS=1 OPR_KEEPALIVE=1 OPR_WEBSOCKET=1 cargo run --bin opurom-server -- 8787
OPR_MTLS=1 OPR_CLIENT_CA=client-ca.pem OPR_LOG_JSON=1 \
  cargo run --bin opurom-server -- 8787
```

## Dependencies

The transport features add seven pinned dependencies; the mutual-TLS features
add none; HTTP/2 adds five pinned dependencies; the certificate-status
features add one. Every direct version is pinned with `=` so a rebuild cannot
pull a different release.

| Crate | Version | Why |
| --- | --- | --- |
| `rustls` | 0.23.46 | the TLS 1.2/1.3 implementation, with the `ring` provider and no OpenSSL |
| `rustls-pemfile` | 2.2.0 | reading the PEM certificate and private key files |
| `rcgen` | 0.14.10 | generating the self-signed certificate at startup |
| `sha2` | 0.10.9 | the SHA-256 certificate fingerprint that is logged |
| `sha1` | 0.10.6 | the SHA-1 of the WebSocket handshake key, as RFC 6455 requires |
| `base64` | 0.23.1 | the base64 handshake accept value and the client key |
| `getrandom` | 0.2.17 | the random bytes for a WebSocket key and for a frame mask |
| `h2` | 0.4.20 | HTTP/2 HEADERS/DATA frames, HPACK, multiplexed streams, flow control and GOAWAY |
| `http` | 1.5.0 | request and response header/status types used by the h2 API |
| `bytes` | 1.12.1 | bounded DATA frame buffers |
| `tokio` | 1.54.1 | current-thread runtime, sockets, timers and task sets for h2 connections |
| `tokio-rustls` | 0.26.6 | async TLS handshake exposing the selected ALPN protocol |
| `x509-parser` | 0.18.1 | DER X.509/CRL parsing and `ring`-backed status signature verification |

`rcgen` is built with `default-features = false` and only the `crypto`,
`pem` and `ring` features, so its optional `x509-parser` and `aws-lc-rs`
paths are not compiled in. The certificate-status features enable
`x509-parser`'s `verify` feature directly; it reuses the same `ring` version
that rustls already brings in.
`rustls` is built with `default-features = false`
and only `ring`, `std`, `tls12` and `logging`, so no system TLS library is
needed. `tokio` uses `default-features = false` with only `io-util`, `macros`,
`net`, `rt`, `sync` and `time`; `tokio-rustls` uses `default-features = false`
with `ring`, `tls12` and `logging`, so HTTP/2 does not pull in `aws-lc-rs`.

## Tests

```sh
cargo fmt --all
cargo test
```

`cargo test` runs 141 tests: the base HTTP, request-contract, SSR, hardening, codegen,
router-introspection and list-query/auth suites plus the opt-in HTTP, TLS,
WebSocket, keep-alive, mutual-TLS, HTTP/2, HTTP/3 and certificate-status suites.
Several suites drive a real server on an ephemeral port over TCP:

| Test file | Covers |
| --- | --- |
| `tests/http_server.rs` | health, the full CRUD lifecycle, 404, 405, 413, the 1 MiB boundary, panic -> 500 -> 503 with other routes still serving, `:param` matching |
| `tests/list_query_auth.rs` | real loopback TCP for bearer auth (authenticated vs unauthenticated, wrong token, missing token) and the list query: malformed/negative/over-cap 400s, boundary values, the `total/count/limit/offset` envelope, stable ordering across repeated calls, and other routes still serving after a rejected request |
| `tests/router_introspection.rs` | the route-table query: an empty table, methods and patterns in registration order, canonical pattern normalization and a read-only query that leaves dispatch unchanged |
| `tests/request_bounds.rs` | loopback TCP checks for the 1 MiB body cap (413), the 64 KiB header block cap (431), an unterminated oversized header line stopped by the same cap, a stalled request timing out with 408 while another connection still gets 200, pipelined requests answered in order, the `Expect: 100-continue` interim answer with the body after it, 417 for an unknown expectation, a 413 behind `Expect` without a drain wait and the documented limit constants |
| `tests/ssr.rs` | byte-identical output for the same IR and theme, theme changes the output, state interpolation, kind -> HTML element mapping, IR version validation |
| `tests/codegen.rs` | generated crate shape, migration SQL, deterministic lowering, IR validation, one shared `PooledDb` in generated code |
| `tests/hardening.rs` | deterministic N/N+1 rate-limit boundary and window reset, `OPR_RATE_LIMIT` over TCP, JSON log shape with numeric measured `elapsed_ms`, one JSON stderr line per request, byte-identical default responses |
| `tests/http_features.rs` | 401/304/204 status and body paths, gzip bytes decompressed to the original JSON, exact 1024-byte threshold, fixed CORS headers/preflight, deterministic ETag over TCP, all-feature composition, unauthorized and preflight rate-limit/log composition, default-off wire bytes |
| `tests/tls.rs` | a real TLS handshake over a real socket, an untrusted certificate refused by the client, the SHA-256 fingerprint and the private key never logged, a missing certificate file, a certificate without a key naming the missing variable, a corrupt PEM, a mismatched certificate and key pair, the demo server exiting with a clear error, plain HTTP staying byte-identical |
| `tests/websocket.rs` | the RFC 6455 handshake with the documented accept value, a text frame round trip, a binary frame round trip, ping answered with pong, a close frame with its code and reason, a message reassembled from two fragments, a message reassembled from three fragments, an oversized frame refused before allocation, an unmasked client frame refused, the client refusing a wrong accept value and a non-101 answer |
| `tests/keepalive.rs` | two requests on one socket, a `Connection: close` request ending the connection, the idle timeout closing a silent connection, the in-flight limit answering 503, the documented default limits, the demo server with and without `OPR_KEEPALIVE` |
| `tests/mtls.rs` | real sockets with an rcgen CA -> server chain -> client cert chain, `OPR_MTLS=1` alone enabling TLS, a trusted client accepted, missing and self-signed untrusted clients refused, a revoked-but-trusted cert refused and a non-revoked one accepted, a spoofed fingerprint header ignored, `h2`/`http/1.1` ALPN selection with a real h2 client for `h2`, the structured log `alpn` field, clear mTLS refusal diagnostics, and the byte-identical single-sided TLS answer |
| `tests/http2.rs` | `h2_concurrent_streams_share_one_tls_connection`, `h2_large_body_flow_control_isolates_failed_stream` and `h2_shutdown_sends_graceful_goaway`: one real h2 client connection with several concurrent streams, exact statuses/bodies and the opt-in response features, 256 KiB response and 128 KiB request across flow-control windows, panic isolation, and raw-frame initial/final GOAWAY with PING/PONG |
| `src/cert_status.rs` | DER GeneralizedTime, canonical serial, strict DER-length, HTTP URL validation, HTTP status/framing bounds and CRL Distribution Points extension unit tests |
| `tests/cert_status.rs` | real mTLS sockets with rcgen CRL/OCSP fixtures: `crl_revoked_serial_is_refused_and_good_client_is_accepted`, `crl_stale_or_tampered_der_fails_closed`, `crl_malformed_or_oversized_der_fails_closed`, `ocsp_good_status_is_accepted_and_revoked_status_is_refused`, `ocsp_unknown_and_wrong_serial_fail_closed`, `ocsp_stale_or_tampered_response_fails_closed`, `ocsp_empty_env_value_fails_closed`, `ocsp_unavailable_or_malformed_file_fails_closed`, both-sources-required and byte-identical default checks |
| `tests/status_env.rs` | `crl_and_ocsp_env_files_configure_mtls`: `OPR_CRL_FILE`/`OPR_OCSP_FILE` local DER files over a real mTLS socket, with missing sources failing closed |
| `tests/crl_live.rs` | a loopback HTTP/1.1 distribution point with measured request counts: `live_crl_url_fetches_caches_refreshes_and_fails_closed`, `live_crl_without_cache_and_without_server_fails_closed`, `live_crl_url_keeps_signature_freshness_and_serial_checks`, `crl_file_takes_precedence_over_crl_url`, `crl_url_from_certificate_extension_fetches_and_caches` and `invalid_crl_url_or_ttl_is_a_startup_error` |

The in-process tests are self-contained: they use an in-memory store, not
`opurom-db`, so `cargo test` passes in this repository on its own. The
generated-service CRUD path is compiled and smoke-tested separately against
the sibling `opurom-db` crate.

## Status

Implemented and verified in this repository:

| Area | Status |
| --- | --- |
| HTTP/1.1 routing (literal + `:param`) | Implemented, tested |
| Route table introspection | Implemented, tested |
| Five CRUD verbs via the generated service | Implemented, verified end to end against `opurom-db` |
| SQLite-backed storage (via `opurom-db`) | Implemented through the sibling crate |
| One shared Mutex-serialized SQLite handle | Implemented in generated services, tested in `opurom-db` and smoke-tested |
| SSR HTML from the same IR | Implemented, deterministic, tested |
| Fault isolation (panic -> 500, 3 strikes -> 503) | Implemented, tested |
| Middleware chain | Implemented (plain logging by default, body cap) |
| Fixed-window rate limiting | Implemented, opt-in via `OPR_RATE_LIMIT`, process-local |
| Structured request logging | Implemented, opt-in via `OPR_LOG_JSON`, measured `elapsed_ms`, plus `alpn` when TLS negotiated a protocol |
| Bearer auth (development token) | Implemented, opt-in via `OPR_AUTH_TOKEN` or an env-independent `AuthOptions` + `Server::with_auth`, 401 JSON, SHA-256 constant-time comparison, open `/health` |
| List query and pagination | Implemented, `?limit=&offset=&sort=&order=&q=` with strict 400s, stable ordering and a `{items,total,count,limit,offset}` envelope on demo and generated list routes |
| gzip responses | Implemented, request-opt-in above 1024 bytes, `Content-Encoding` and `Vary`, decompression tested |
| ETag / `304` | Implemented, opt-in deterministic body hash, empty-body conditional response over TCP |
| CORS / preflight | Implemented, opt-in fixed origin or literal `*`, 204 with fixed allow lists |
| `opurom-serverc` lowering to a standalone crate | Implemented, tested |
| TLS listener | Implemented, opt-in via `OPR_TLS=1`, rustls with a self-signed fallback, fingerprint logged, real handshake tested |
| Real HTTP/2 | Implemented, ALPN-selected `h2` only, h2 0.4.20 frames/HPACK/multiplexing/flow control, shared router/middleware, bounded limits and graceful GOAWAY; no new environment variable |
| Real HTTP/3 over QUIC | Implemented, opt-in via `OPR_HTTP3=1`, a separate UDP listener with TLS 1.3 and ALPN `h3`, real h3 request/response exchange, shared router/middleware/fault isolation, `Alt-Svc` advertisement on the HTTPS responses |
| Mutual TLS client certificates | Implemented, opt-in via `OPR_MTLS=1` + `OPR_CLIENT_CA`, mandatory rustls verification over real sockets |
| Certificate revocation | Implemented as a static `OPR_REVOKED` fingerprint deny list plus required DER CRL/OCSP serial status checks |
| Local certificate status | Implemented, opt-in via `OPR_CRL_FILE` / `OPR_OCSP_FILE`, CA-signature-verified, bounded DER parsing, fail-closed on unavailable/malformed/stale sources |
| Live CRL retrieval with cache | Implemented, opt-in via `OPR_CRL_URL` (an `http://` URL or the certificate CRL Distribution Points extension), std-only HTTP client with bounded timeouts and response size, URL-keyed cache refreshed by `OPR_CRL_TTL_SECS`, fail-closed with a clear error when no valid copy exists |
| ALPN negotiation and reporting | Implemented, `h2` and `http/1.1` advertised, selected protocol in the structured log; h2 frames are served when `h2` is selected |
| WebSocket (RFC 6455) | Implemented, opt-in via `OPR_WEBSOCKET=1`, handshake, text, binary, ping/pong, close and fragmentation, bounded frames |
| HTTP/1.1 keep-alive | Implemented, opt-in via `OPR_KEEPALIVE=1`, `Content-Length` framing, idle timeout, in-flight limit |

Out of scope for this repository:

| Area | Note |
| --- | --- |
| HTTP/3 server push and WebTransport | the HTTP/3 implementation covers the request/response exchange; no push promises and no WebTransport sessions |
| HTTP/2 server push, priority tree and coalescing | no push promises, no client-controlled priority tree and no cross-origin connection reuse |
| HTTP/2 extended CONNECT, WebSocket-over-h2, trailers | the RFC 6455 upgrade remains HTTP/1.1 only |
| HSM and private-key isolation | the private key is loaded from PEM or generated in memory |
| `permessage-deflate` | no extension is negotiated, no frame is compressed |
| Load-balancer integration | no `X-Forwarded-*`, no `Forwarded`, no proxy protocol |
| Authentication provider / token lifecycle | one development bearer token only; no users, scopes, expiry, hashing or rotation |
| Connection pool sizing | one shared Mutex-guarded connection, one thread per TCP connection |
| Distributed rate limiting | in-process counters only |
| PostgreSQL / MySQL drivers | SQLite and the `opurom-db` KV/Memory drivers only |
| Node.js / Serverless deployment | out of scope here |
| Per-route CORS, credentialed CORS | one fixed configured origin or `*`; no cookies or credentials |
| Application streaming and compression dictionaries | whole-body gzip only; each response is built in memory before h2 DATA frames |
| Chunked HTTP/1.1 request bodies | `Transfer-Encoding` is rejected with 501; h2 uses DATA frames |

## Future directions

* HTTPS CRL distribution points
* OCSP stapling
* Distributed revocation
* Certificate Transparency
