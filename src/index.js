//cloudflare worker entry point. routes websocket upgrades to a wisp server
//connection and serves a small landing page for plain http requests, mirroring
//wisp-server-python's http.py.
//
//the wisp protocol is exactly the same as the python server, so this worker is
//a drop-in replacement for the backend of libcurl.js - just point the client
//at wss://<your-worker>.workers.dev/ (keep the trailing slash).

import { WispConnection, WSProxyConnection } from "./wisp.js"
import { apply_env as apply_config } from "./config.js"
import * as ratelimit from "./ratelimit.js"

function get_client_ip(request) {
  let ip = request.cf?.connectingIpAddress
  //honor the reverse proxy headers when we are behind one
  if (!ip || ip === "127.0.0.1") {
    ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Real-IP") || ip || "unknown"
  }
  return ip
}

function handle_websocket(server, path, client_ip) {
  //pin binary frames to ArrayBuffer. with the websocket_standard_binary_type
  //flag (default on/after 2026-03-17) incoming binary messages arrive as Blob,
  //which our packet parsing (new Uint8Array(message.data)) cannot handle.
  //setting this before accept() guarantees the delivery type for every frame.
  server.binaryType = "arraybuffer"
  server.accept()

  if (path.endsWith("/")) {
    //wisp multiplexed connection
    let wisp_conn = new WispConnection(server, path, client_ip)
    wisp_conn.setup()
    ratelimit.inc_client_attr(client_ip, "streams")

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
    let stream_count = ratelimit.get_client_attr(client_ip, "streams")
    if (ratelimit.enabled && stream_count > ratelimit.connections_limit) {
      server.close()
      return
    }

    let wsproxy_conn = new WSProxyConnection(server, path)
    ratelimit.inc_client_attr(client_ip, "streams")
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

export default {
  async fetch(request, env, ctx) {
    //read the per-deploy settings from the env binding and ensure the
    //rate limiter's periodic cleanup is running
    apply_config(env)
    ratelimit.apply_env(env)
    ratelimit.start_cleanup()

    let url = new URL(request.url)
    let upgrade = request.headers.get("Upgrade")

    if (upgrade && upgrade.toLowerCase() === "websocket") {
      let client_ip = get_client_ip(request)
      let pair = new WebSocketPair()
      let [client, server] = Object.values(pair)
      handle_websocket(server, url.pathname, client_ip)
      return new Response(null, { status: 101, webSocket: client })
    }

    //plain http request - content is served from the assets binding only
    if (env.ASSETS) {
      const asset = await env.ASSETS.fetch(request)
      if (asset.ok) return asset
    }
    return new Response("404 not found", { status: 404 })
  }
}