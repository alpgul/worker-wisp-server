# wisp-worker

A [Wisp v1](https://github.com/MercuryWorkshop/wisp-protocol) server implemented as a Cloudflare Worker. It is wire-compatible with [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python) and is the backend used by this project — just point the libcurl.js/wisp client at the worker's URL.

Unlike the Python server, this worker:

- Runs on Cloudflare's edge (no server of your own to maintain).
- Relays raw TCP over Cloudflare's `connect()` API (`cloudflare:sockets`). The default connector performs real outbound TCP on **all plans, including the free tier** — the WARP protocol (which would only add UDP) is not used.
- Does **not** support UDP streams. A UDP `CONNECT` packet is rejected with a `CLOSE (0x42)` packet.

The Wisp packet format is identical to the Python server (`<BI` header, little-endian), so the existing clients keep working unchanged.

## Usage

Install dependencies and run a local dev server:

```sh
npm install
npm run dev
```

Deploy to Cloudflare:

```sh
npm run deploy
```

Or deploy the whole worker with one click (works when `server/worker-wisp-server` contents are served from the repository root):

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/alpgul/worker-wisp-server)

Point a Wisp client at the root path of the worker — **with** the trailing slash:

```
wss://<your-worker>.<your-subdomain>.workers.dev/
```

For libcurl.js, set the proxy URL (e.g. `libcurl.conf.ws` / your wisp proxy setting) to that URL.

## Configuration

Configuration is done via Worker environment variables (set them in `wrangler.toml` under `[vars]`, the Cloudflare dashboard, or `wrangler secret`):

| Variable               | Default | Description                                            |
| ---------------------- | ------- | ------------------------------------------------------ |
| `RATELIMIT_ENABLED`    | `false` | Enable the fixed-window rate limiter.                  |
| `RATELIMIT_CONNECTIONS`| `30`    | Max new streams per IP per window.                     |
| `RATELIMIT_BANDWIDTH`  | `100`   | Bandwidth limit per IP in KB/s.                        |
| `RATELIMIT_WINDOW`     | `60`    | Window length in seconds.                              |
| `ALLOW_LOOPBACK`       | `false` | `true` allows connections to loopback IPs.             |
| `ALLOW_PRIVATE`        | `false` | `true` allows connections to private IPs.              |

The rate limiter is per-isolate and in-memory: Workers isolates are ephemeral, so the counters only apply while an isolate stays warm. This deters simple abuse but is not a hard global guarantee.

## Testing

The protocol core is unit-tested on plain node (no Cloudflare runtime needed). The tests import the real `src/wisp.js`; a small Node loader (`test/imports-loader.mjs`) redirects the worker-only imports (`net.js`, `config.js`, `ratelimit.js`) to in-memory stubs in `test/stubs/`:

```sh
npm test
```

Run with the real `workerd` runtime locally for live relay verification:

```sh
npm run dev
```

## Routes

- **`/` (with trailing slash)** — Wisp multiplexed WebSocket connection.
- **`/host:port`** — legacy wsproxy mode, one WebSocket per TCP connection (raw relay).
- **plain HTTP** — serves static assets (`/`, `/browserleaks.html`, `/libcurl.js`, `/libcurl.wasm`, `/transport_ws.html`) from the `assets/` directory, `404` otherwise.

## File layout

```
src/
  index.js      # WebSocket routing + fetch handler
  wisp.js       # WispConnection / WSProxyConnection (protocol core)
  net.js        # TCPConnection over connect() (default TCP connector)
  util.js       # Wisp packet codec (<BI, <BH, <I, <B)
  config.js     # runtime configuration
  ratelimit.js  # fixed-window rate limiter
test/
  wisp.test.js        # unit tests for the protocol core (npm test)
  imports-loader.mjs  # node loader: worker imports -> test stubs
  stubs/              # in-memory fake net/config/ratelimit
```

## How long requests and large files behave

Cloudflare applies limits per **request**, and a Wisp WebSocket connection is a single request (the initial `Upgrade`). With that in mind:

- **Long transfers (wall clock): no hard timeout.** Workers keep processing and streaming as long as the client stays connected. There is no wall-clock ceiling on TCP relays, so a multi-hour stream is fine. The only exception is a rare Cloudflare runtime update, which gives in-flight requests a 30-second grace period.
- **CPU (the real constraint): 10 ms per request on Free, 30 s (up to 5 min) on Paid.** This relay only copies bytes between a socket and a WebSocket (~2 small copies per 64 KiB chunk); it is I/O-bound, not CPU-bound, so typical web files and even hundreds of megabytes stay within the Free-tier budget. Sustained, heavy bulk transfer on Free can accumulate past 10 ms and be terminated with Error 1102 — if that shows up, raise `limits.cpu_ms` on a Paid plan. Idle connections use ~0 CPU.
- **Simultaneous outbound sockets: 6 per request on all plans.** Since every Wisp connection is one request, a single client can have at most **6 concurrent TCP streams open at once**. Opening a 7th stream will fail until another closes. (Browsers opening many parallel HTTPS sessions through one Wisp connection will queue against this.)
- **Memory: 128 MB per isolate.** The per-stream send queue is capped (`queue_size`, 128 packets) with real backpressure; if a client ignores flow control the connection stalls instead of accumulating memory.
- **WebSocket message size: 32 MiB received (max).** The relay sends small chunks (64 KiB), so frames never approach this.
- **Free tier ToS** disallows running a video/streaming/large-file CDN on it. Using it as a browsing proxy for ordinary web traffic is fine; using it to bulk-serve huge files continuously may get the account flagged.

## Billing

WebSocket pricing on Workers only counts **connections**, not messages:

- Each WebSocket connection made to this worker is billed as **one request** (the initial HTTP `Upgrade`). Once established, **WebSocket messages do not count as requests** — neither inbound nor outbound, and protocol pings are free.
- There are **no duration, egress or bandwidth charges** on the Standard usage model, so keeping a connection open and relaying gigabytes costs nothing extra.
- Free plan: 100,000 requests (connections) per **day**; CPU is limited to **10 ms per connection/invocation**. Standard: 10M requests/month included then +$0.30/M, plus 30M ms of CPU included (+$0.02/M ms); flat $5/month minimum.

For this relay, cost therefore scales with the number of Wisp connections and their total CPU time, not with data volume. Long-lived connections with modest traffic are effectively free; many short-lived reconnects (connection churn) burn request quota.

## Limitations

- Plain TCP only. UDP streams are not supported (`connect()`'s default connector is TCP; the WARP protocol that would allow UDP is not used), and outgoing TCP on port 25 is prohibited by Cloudflare.
- The worker pins `binaryType = "arraybuffer"` before `accept()` so binary messages stay `ArrayBuffer` regardless of the `websocket_standard_binary_type` flag (Blob is the default from compat date 2026-03-17 and would break packet parsing). Single WebSocket frames are capped at 32 MiB by the platform — irrelevant here since Wisp fragments all data into small packets.
- `wrangler dev` runs the same code on the real `workerd` runtime, so the full relay path (WebSocket ↔ TCP) is testable locally — unlike the earlier WARP-only design.
- At most 6 concurrent outbound sockets per Wisp connection (Cloudflare limit, all plans).
- Hostnames are resolved on Cloudflare's edge by `connect()`, so loopback/private IP blocking only applies to IP literals in the CONNECT packet. Edge also refuses localhost, private and Cloudflare IPs regardless of this worker's config.
- WSProxy mode is single-stream by design (as in the Python server).

## Copyright

Port of [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python). Licensed under the GNU AGPL v3 (see the upstream project's LICENSE).