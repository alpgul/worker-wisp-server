//cloudflare worker entry point. routes websocket upgrades to a wisp server
//connection and serves a small landing page for plain http requests, mirroring
//wisp-server-python's http.py.
//
//the wisp protocol is exactly the same as the python server, so this worker is
//a drop-in replacement for the backend of libcurl.js - just point the client
//at wss://<your-worker>.workers.dev/ (keep the trailing slash).
//
//per the protocol spec, wisp v2 is used when the websocket upgrade request
//carries a Sec-WebSocket-Protocol header; otherwise the connection acts as a
//wisp v1 server. the client requests the "wisp-v2" subprotocol, which we echo
//in the 101 response so the browser negotiates it successfully.

import { WispConnection, WSProxyConnection } from "./wisp.js"
import { apply_env as apply_config, config } from "./config.js"
import { ratelimit, get_client_attr, inc_client_attr, apply_env, start_cleanup } from "./ratelimit.js"
import { metrics, reset as reset_metrics, render as render_metrics } from "./metrics.js"

//re-exported so the wrangler durable_object binding can find the class in the
//entry module
export { GlobalRateLimiter } from "./ratelimit.js"

//tls hygiene policy. returns null when the request may proceed, otherwise a
//Response that short-circuits it.
//
//credentials and traffic must never cross the network in clear text, so any
//non-localhost endpoint reached over a plain scheme is refused: websocket
//upgrades get 426 (browsers do not follow 3xx on upgrades) and plain page
//loads get a permanent 308 redirect to the https url.
//
//localhost/loopback is always exempt: the local dev server has no tls
//terminator, and tests run over plain http too.
export function https_policy(request, url, enforce_https) {
  if (!enforce_https) return null
  const host = url.hostname
  if (host === "localhost" || host === "127.0.0.1" || host === "0:0:0:0:0:0:0:1" || host === "::1") return null

  //cloudflare (and reverse proxies) declare the client-facing scheme here;
  //absent that, fall back to the url scheme, which is also the real one under
  //wrangler dev.
  const proto = (request.headers.get("x-forwarded-proto") || url.protocol).replace(":", "")
  if (proto === "https" || proto === "wss") return null

  const upgrade = request.headers.get("Upgrade")
  if (upgrade && upgrade.toLowerCase() === "websocket") {
    return new Response("websocket connection refused: wss:// is required", { status: 426 })
  }
  url.protocol = "https:"
  return Response.redirect(url.toString(), 308)
}

function get_client_ip(request) {
  let ip = request.cf?.connectingIpAddress
  //honor the reverse proxy headers when we are behind one
  if (!ip || ip === "127.0.0.1") {
    ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Real-IP") || ip || "unknown"
  }
  return ip
}

async function handle_websocket(server, path, client_ip, wisp_version) {
  //pin binary frames to ArrayBuffer. with the websocket_standard_binary_type
  //flag (default on/after 2026-03-17) incoming binary messages arrive as Blob,
  //which our packet parsing (new Uint8Array(message.data)) cannot handle.
  //setting this before accept() guarantees the delivery type for every frame.
  server.binaryType = "arraybuffer"
  server.accept()

  if (path.endsWith("/")) {
    //wisp multiplexed connection
    let wisp_conn = new WispConnection(server, path, client_ip, wisp_version)
    wisp_conn.setup()

    server.addEventListener("message", event => {
      wisp_conn.handle_ws_message(event)
    })
    server.addEventListener("close", () => {
      wisp_conn.close_all()
      //complete the close handshake on legacy manual-reply dates; on the
      //auto-reply default this call is silently ignored
      server.close(1000)
    })
    server.addEventListener("error", () => {
      wisp_conn.close_all()
    })
  } else {
    //legacy wsproxy connection: /host:port relays a single tcp stream
    let stream_count = await get_client_attr(client_ip, "streams")
    if (ratelimit.enabled && stream_count > ratelimit.connections_limit) {
      server.close()
      return
    }

    let wsproxy_conn = new WSProxyConnection(server, path)
    await inc_client_attr(client_ip, "streams")
    wsproxy_conn.setup_connection().then(() => {
      wsproxy_conn.handle_tcp()
    }).catch(() => {
      server.close()
    })
    server.addEventListener("message", event => {
      wsproxy_conn.handle_ws(event).catch(() => {})
    })
    server.addEventListener("close", () => {
      wsproxy_conn.conn?.close().catch(() => {})
      server.close(1000)
    })
  }
}

//select the websocket subprotocol from the upgrade request. returns null for
//plain v1 connections (no header at all) and rejects upgrades which offer
//subprotocols we don't implement.
function select_subprotocol(request) {
  let header = request.headers.get("Sec-WebSocket-Protocol")
  if (!header) return null
  let offered = header.split(",").map(s => s.trim()).filter(s => s !== "")
  if (offered.includes("wisp-v2")) return "wisp-v2"
  return "unsupported"
}

export default {
  async fetch(request, env, ctx) {
    //read the per-deploy settings from the env binding and ensure the
    //rate limiter's periodic cleanup is running
    apply_config(env)
    apply_env(env)
    start_cleanup()

    let url = new URL(request.url)
    let upgrade = request.headers.get("Upgrade")

    const blocked = https_policy(request, url, config.enforce_https)
    if (blocked) return blocked

    if (upgrade && upgrade.toLowerCase() === "websocket") {
      let subprotocol = select_subprotocol(request)
      if (subprotocol === "unsupported") {
        return new Response("unsupported websocket subprotocol", { status: 426 })
      }

      let client_ip = get_client_ip(request)
      metrics.inc("connections_total")
      let pair = new WebSocketPair()
      let [client, server] = Object.values(pair)
      //the presence of Sec-WebSocket-Protocol selects wisp v2; echo the chosen
      //subprotocol in the 101 response
      let headers = subprotocol ? { "Sec-WebSocket-Protocol": subprotocol } : {}
      await handle_websocket(server, url.pathname, client_ip, subprotocol ? 2 : 1)
      return new Response(null, { status: 101, headers, webSocket: client })
    }

    //lightweight metrics endpoint (prometheus-ish text). counters are
    //per-isolate, so use `?reset=1` to start a clean observation window.
    //https_policy() runs before this so production reaches it over https.
    if (url.pathname === "/__metrics") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response("method not allowed", { status: 405 })
      }
      if (url.searchParams.get("reset") === "1") reset_metrics()
      return new Response(render_metrics(), {
        headers: { "content-type": "text/plain; charset=utf-8" }
      })
    }

    //plain http request - content is served from the assets binding only.
    // / and /index.html always resolve to the landing page: the assets
    // binding maps the root path to index.html, so normalize literal
    // requests to the root instead of relying on the directory index.
    if (env.ASSETS) {
      const url = new URL(request.url)
      if (url.pathname === "/" || url.pathname === "/index.html") url.pathname = "/"
      const asset = await env.ASSETS.fetch(new Request(url.toString(), request))
      //an asset conditional request that still matches (If-None-Match /
      //If-Modified-Since) comes back as 304, which is not asset.ok - pass it
      //through so the browser can keep using its cached copy instead of 404
      if (asset.ok || asset.status === 304) return asset
    }
    return new Response("404 not found", { status: 404 })
  }
}