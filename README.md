# wisp-worker

A [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) server (**v1 and v2**) implemented as a Cloudflare Worker. It is wire-compatible with [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python), so any Wisp client (including [libcurl.js](https://github.com/ading2210/libcurl.js)) works unchanged — just point it at the worker's URL.

Wisp v2 is used when the client's websocket upgrade carries a `Sec-WebSocket-Protocol` header (the client requests the `wisp-v2` subprotocol, which the worker echoes in the 101 response). Connections without that header are served with the plain v1 flow. On v2, the worker supports extension negotiation, password authentication, a MOTD, and stream-open confirmation.

Unlike the Python server, this worker:

- Runs on Cloudflare's edge (no server of your own to maintain).
- Relays raw TCP over Cloudflare's `connect()` API (`cloudflare:sockets`). The default connector performs real outbound TCP on **all plans, including the free tier** — the WARP protocol (which would only add UDP) is not used.
- Does **not** support UDP streams. A UDP `CONNECT` packet is rejected with a `CLOSE (0x48)` packet, and the UDP extension is absent from the v2 handshake so well-behaved v2 clients never request it.

## Usage

Install dependencies and run a local dev server (real `workerd` runtime, so the full relay path is testable):

```sh
npm install
npm run dev
```

Deploy to Cloudflare (requires a [wrangler OAuth login](https://developers.cloudflare.com/workers/wrangler/commands/#login) or API token):

```sh
npm run deploy
```

Or deploy with one click:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/alpgul/worker-wisp-server)

Point a Wisp client at the root path of the worker — **with** the trailing slash:

```
wss://<your-worker>.<your-subdomain>.workers.dev/
```

For libcurl.js, set the proxy URL (e.g. `libcurl.conf.ws` / your wisp proxy setting) to that URL.

On a Wisp v2 client you can also pass credentials to authenticate, mirroring the server's `WISP_AUTH_USERNAME` / `WISP_AUTH_PASSWORD`:

```js
let conn = new WispConnection("wss://<your-worker>....workers.dev/", {
  username: "alice",
  password: "hunter2"
});
```

## Configuration

Configuration is done via Worker environment variables, read from the `env` binding passed to the fetch handler (set them in `wrangler.toml` under `[vars]`, the Cloudflare dashboard, or `wrangler secret`):

| Variable                | Default | Description                           |
| ----------------------- | ------- | ------------------------------------- |
| `RATELIMIT_ENABLED`     | `false` | Enable the fixed-window rate limiter. |
| `RATELIMIT_CONNECTIONS` | `30`    | Max new streams per IP per window.    |
| `RATELIMIT_AUTH_FAILURES`| `5`    | Max failed password handshakes per IP per window, then close with 0x49. |
| `RATELIMIT_WINDOW`      | `60`    | Window length in seconds.             |
| `BANDWIDTH_LIMIT`       | `26214400` | Per-IP relayed-byte budget per window (both directions). Once spent, existing streams close with `CLOSE 0x49` and new `CONNECT`s are refused until the window rolls over. `0` disables the byte cap (stream/auth limits still apply). |
| `STREAM_LIMIT_TOTAL`    | `50`    | Max concurrent streams per WebSocket connection. |
| `ALLOW_LOOPBACK`        | `false` | `true` allows connections to loopback IPs. |
| `ALLOW_PRIVATE`         | `false` | `true` allows connections to private IPs.  |
| `HOSTNAME_BLACKLIST`    | *(empty)* | Comma-separated hostnames to refuse with `CLOSE 0x48` (matches the host and its subdomains). |
| `ALLOW_HOSTNAME`        | *(empty)* | Optional allowlist. When set, only these hostnames (and their subdomains) are accepted; everything else is refused with `CLOSE 0x48`. IP literals must match an entry verbatim. |
| `PORT_BLACKLIST`        | *(empty)* | Comma-separated ports to refuse with `CLOSE 0x48`. |
| `WISP_MOTD`             | *(none)* | Wisp v2 MOTD sent during the handshake. |
| `WISP_AUTH_USERNAME`    | *(none)* | Enables Wisp v2 password auth; matching credentials are required. |
| `WISP_AUTH_PASSWORD`    | *(none)* | The expected password (store via `wrangler secret`). |
| `ENFORCE_HTTPS`         | `true` | Refuse plain-text entry points: `ws://` upgrades get `426` (browsers do not follow redirects on upgrades) and `http://` page loads get a `308` redirect to `https://`. `localhost`/loopback is always exempt so the local dev server keeps working. |
| `DOWNSTREAM_BUFFER`     | `512` | Max tcp→ws DATA packets buffered per stream before the downstream (client) is considered stalled. `0` disables the bound (direct unbounded sends). |
| `DOWNSTREAM_STALL_TIMEOUT` | `10000` | How long (ms) a full downstream buffer may persist before the stream is proactively closed with `0x03`. |
| `STREAM_IDLE_TIMEOUT`  | `120000` | Lazy per-stream liveness (ms). Streams with no wisp activity (client DATA, server DATA, CLOSE) past this are closed with `CLOSE 0x47` the next time the connection receives any inbound packet. `0` disables the sweep. |
| `SOCKET_IDLE_TIMEOUT`  | `60000` | Idle timeout (ms) passed to `socket.connect()`. A fully quiet upstream socket self-closes here instead of holding a connection at Cloudflare's ~7-minute default; the tcp reader sees that as EOF and closes the stream with `CLOSE 0x02`. `0` keeps the platform default. |

Both authentication variables must be set for auth to be enabled. Failed auth (`0xc0`/`0xc2`) and blocked destinations (`0x48`) end the stream/connection with the corresponding Wisp close reason.

### Transport security

Credentials and traffic must never cross the network in clear text, so production is assumed to be served behind TLS: point clients at `wss://<your-worker>....workers.dev/`. By default the worker enforces this — set `ENFORCE_HTTPS=false` only for private, HTTP-only deployments (e.g. a LAN test server).

> Password-auth wire format: the v2 protocol spec omits the password length, but the reference implementation ([wisp-js](https://github.com/wasm-libcurl/wisp-js)) sends a `u16` password length in the client credentials. This worker follows the wisp-js layout (`[username_len u8][password_len u16 LE][username][password]`) for interoperability.

### Slow downstream clients

Wisp only has client→server flow control (CONTINUE credits); there is no way for the server to tell a client to slow down. A client that stops consuming would otherwise fill Cloudflare's websocket buffers until the connection dies with a late, unexplained error. The worker instead keeps a bounded per-stream outbound queue (`DOWNSTREAM_BUFFER`): the TCP reader pauses while it is full (TCP backpressure reaches the remote producer), and if the queue stays full past `DOWNSTREAM_STALL_TIMEOUT` the stream is proactively closed with `0x03`.

Liveness completes the picture: `connect()` gets an explicit `SOCKET_IDLE_TIMEOUT`, while the connection-level sweep (`STREAM_IDLE_TIMEOUT`, run lazily on inbound packets) reclaims streams that stay silent, closing them with `0x47` so a peer that went quiet doesn't pin a stream forever. Clients that want the server to notice a dead connection should send a periodic keepalive (`keepalive_interval` in wisp.js) so the sweep is triggered by the stream's own liveness clock.

The rate limiter keeps its per-IP counters in a Durable Object (`GlobalRateLimiter`, the `GLOBAL_RATELIMITER` binding): every isolate routes `get`/`inc`/`spend` operations to the single fleet-wide instance named `"global"`, whose transactional storage backs the counters. The fixed window is therefore genuinely global — one consistent window per IP across the whole fleet, surviving isolate restarts — instead of per-isolate memory. The window rolls over lazily on access (an entry whose `start` has aged past `RATELIMIT_WINDOW` is re-initialized), so no sweeper is needed. With no durable-object binding configured (e.g. plain node tests), the module falls back to an in-memory store with identical semantics. With `RATELIMIT_ENABLED`, the `BANDWIDTH_LIMIT` byte budget (the inverse of the downstream queue: instead of capping a buffered backlog it caps the sustained relay rate) augments the stream-count and failed-auth counters — a client that burns through its window's bytes has its streams closed with `0x49` and cannot open new ones until the window rolls over.

## Testing

The protocol core is unit-tested on plain node (no Cloudflare runtime needed). The tests import the real `src/wisp.js`; a small Node loader (`test/imports-loader.mjs`) redirects the worker-only imports (`net.js`, `config.js`, `ratelimit.js`) to in-memory stubs in `test/stubs/`:

```sh
npm test
```

The suite covers the v1 flow, the v2 handshake (INFO exchange, version mismatch, extension negotiation, stream-open confirmation), password auth, blocklists, per-connection stream caps, backpressure, early data sent while a socket is still connecting, the HTTP(S) hygiene policy (`308`/`426` on plain-text entry points, loopback exemption, `ENFORCE_HTTPS` toggle), and the state counters behind `/__metrics`.

## Metrics

`GET /__metrics` returns a small prometheus-style text summary of the current isolate's runtime state:

```text
# libcurl.js worker metrics
libcurl_connections_total 0
libcurl_streams_opened_total 0
libcurl_streams_closed_total 0
libcurl_bytes_ws_to_tcp_total 0
libcurl_packets_ws_to_tcp_total 0
libcurl_bytes_tcp_to_ws_total 0
libcurl_packets_tcp_to_ws_total 0
libcurl_downstream_stalls_total 0
libcurl_out_queue_max 0
libcurl_closes_total{reason="0x0f"} 0
```

Counters are per-isolate and in-memory (isolates are ephemeral), so sample them over short windows; `?reset=1` zeroes the counters to start a clean observation window. Other HTTP methods get a `405`. The endpoint sits behind the HTTPS policy, so production reaches it over `https://<worker>/__metrics`.

## Routes

- **`/` (with trailing slash)** — Wisp multiplexed WebSocket connection.
- **`/host:port`** — legacy wsproxy mode, one WebSocket per TCP connection (raw relay).
- **plain HTTP** — serves static files from the `assets/` binding (`/index.html`, the landing page); everything else is a 404.

## File layout

```
src/
  index.js      # WebSocket routing (subprotocol selection) + fetch handler
  wisp.js       # WispConnection / WSProxyConnection (protocol core)
  net.js        # TCPConnection over connect() (default TCP connector)
  util.js       # Wisp packet codec + INFO/extension/auth helpers
  config.js     # runtime configuration, applied from the env binding
  ratelimit.js  # fixed-window rate limiter
  metrics.js    # per-isolate runtime counters (state, snapshot, render)
test/
  wisp.test.js        # unit tests for the protocol core (npm test)
  imports-loader.mjs  # node loader: worker imports -> test stubs
  stubs/              # in-memory fake net/config/ratelimit
assets/
  index.html          # landing page served at / 
```

## Behavior and limits

Cloudflare applies limits per **request**, and a Wisp WebSocket connection is a single request (the initial `Upgrade`):

- **Long transfers: no wall-clock timeout.** Workers keep streaming as long as the client stays connected (the rare Cloudflare runtime update gives in-flight requests a 30-second grace period).
- **CPU: 10 ms per request on Free, up to 30 s (5 min) on Paid.** This relay only copies bytes between a socket and a WebSocket (~2 small copies per 64 KiB chunk) and is I/O-bound, so ordinary browsing stays comfortably within the Free budget. Sustained bulk transfer can accumulate past 10 ms and be terminated with Error 1102 — if that happens, raise `limits.cpu_ms` on a Paid plan.
- **Simultaneous outbound sockets: 6 per request on all plans.** A single Wisp client can have at most 6 concurrent TCP streams at once; a 7th fails until another closes. Browsers opening many parallel HTTPS sessions through one Wisp connection will queue against this.
- **Memory: the per-stream queue is capped** (`queue_size`, 128 packets) with real backpressure; if a client ignores flow control, the connection stalls instead of accumulating memory.
- **Free tier ToS** disallows running a video/streaming/large-file CDN on it. Using it as a browsing proxy for ordinary web traffic is fine.

## Billing

WebSocket pricing on Workers counts **connections**, not messages: each WebSocket connection is billed as one request (the `Upgrade`), and messages, duration, egress and bandwidth are free. Free plan: 100,000 connections/day, 10 ms CPU per connection. Standard: 10M requests/month included (+$0.30/M), plus 30M ms CPU (+$0.02/M ms), $5/month minimum. Cost therefore scales with connection count and CPU time, not data volume; long-lived connections with modest traffic are effectively free.

## Limitations

- Plain TCP only. UDP streams are not supported (`connect()`'s default connector is TCP; WARP would be needed for UDP and is not used), and outgoing TCP on port 25 is prohibited by Cloudflare.
- The worker pins `binaryType = "arraybuffer"` before `accept()` so binary messages stay `ArrayBuffer` regardless of the `websocket_standard_binary_type` flag (Blob is the default from compat date 2026-03-17 and would break packet parsing). Single WebSocket frames are capped at 32 MiB by the platform — irrelevant here since Wisp fragments all data into small packets.
- Hostnames are resolved on Cloudflare's edge by `connect()`, so loopback/private IP blocking only applies to IP literals in the CONNECT packet (the `HOSTNAME_BLACKLIST` applies to hostnames regardless). The edge also refuses localhost, private and Cloudflare IPs regardless of this worker's config.
- Per-connection stream count is capped (`STREAM_LIMIT_TOTAL`, default 50; excess `CONNECT`s are refused with `CLOSE 0x49`).
- WSProxy mode relays a single TCP stream per WebSocket by design (as in the Python server).

## Copyright

Port of [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python). Licensed under the GNU AGPL v3 (see the upstream project's LICENSE).