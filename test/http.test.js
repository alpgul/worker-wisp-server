import { test } from "node:test"
import assert from "node:assert/strict"
import worker from "../src/index.js"
import { https_policy } from "../src/index.js"
import { ratelimit, apply_env as apply_ratelimit } from "../src/ratelimit.js"

//the fetch handler's first call registers a setInterval cleanup ticker
//(ratelimit.start_cleanup) which would keep the test process alive; shadow it
const originalSetInterval = globalThis.setInterval
globalThis.setInterval = () => 0
test.after(() => { globalThis.setInterval = originalSetInterval })

//exercise the tls hygiene policy both as a pure function and through the
//fetch handler (non-websocket branches never touch WebSocketPair, so they run
//fine under node).

function upgradeRequest(url, extra = {}) {
  const headers = { Upgrade: "websocket", Connection: "Upgrade", ...(extra.headers || {}) }
  return new Request(url, { method: "GET", headers })
}

test("https_policy: localhost is always exempt", () => {
  assert.equal(https_policy(new Request("http://localhost:8787/x"), new URL("http://localhost:8787/x"), true), null)
  assert.equal(https_policy(new Request("http://127.0.0.1/wisp/"), new URL("http://127.0.0.1/wisp/"), true), null)
})

test("https_policy: enforce_https=false disables the policy", () => {
  const url = new URL("http://example.com/wisp/")
  assert.equal(https_policy(new Request("http://example.com/wisp/"), url, false), null)
})

test("https_policy: plain http page load redirects to https", () => {
  const url = new URL("http://example.com/page")
  const res = https_policy(new Request("http://example.com/page"), url, true)
  assert.equal(res.status, 308)
  assert.equal(res.headers.get("location"), "https://example.com/page")
})

test("https_policy: websocket upgrade over plain http gets 426, not a redirect", () => {
  const url = new URL("ws://example.com/wisp/")
  const res = https_policy(upgradeRequest("ws://example.com/wisp/"), url, true)
  assert.equal(res.status, 426)
})

test("https_policy: x-forwarded-proto https allows the request", () => {
  const url = new URL("http://example.com/wisp/")
  const req = new Request("http://example.com/wisp/", { headers: { "x-forwarded-proto": "https" } })
  assert.equal(https_policy(req, url, true), null)
})

test("fetch: redirects plain http non-localhost requests", async () => {
  const res = await worker.fetch(new Request("http://example.com/page"), {})
  assert.equal(res.status, 308)
  assert.equal(res.headers.get("location"), "https://example.com/page")
})

test("fetch: 426 on insecure websocket upgrade", async () => {
  const res = await worker.fetch(upgradeRequest("http://example.com/wisp/"), {})
  assert.equal(res.status, 426)
})

test("fetch: https and localhost requests pass straight through", async () => {
  const httpsRes = await worker.fetch(new Request("https://example.com/page"), {})
  assert.equal(httpsRes.status, 404, "no assets binding -> 404, but not a redirect")
  const localRes = await worker.fetch(new Request("http://localhost:8787/page"), {})
  assert.equal(localRes.status, 404, "localhost exempt -> 404, but not a redirect")
})

test("fetch: ENFORCE_HTTPS=false disables the policy", async () => {
  const res = await worker.fetch(new Request("http://example.com/page"), { ENFORCE_HTTPS: "false" })
  assert.equal(res.status, 404, "policy off -> passthrough, no redirect")
})

test("fetch: subprotocol negotiation still runs on secure upgrades", async () => {
  //an unsupported subprotocol over https reaches select_subprotocol and is
  //rejected there (426) without ever touching WebSocketPair
  const res = await worker.fetch(upgradeRequest("https://example.com/wisp/", { headers: { "Sec-WebSocket-Protocol": "bogus" } }), {})
  assert.equal(res.status, 426)
})

test("fetch: unsupported subprotocol over plain http reports the http problem first", async () => {
  const res = await worker.fetch(upgradeRequest("http://example.com/wisp/", { headers: { "Sec-WebSocket-Protocol": "bogus" } }), {})
  assert.equal(res.status, 426)
})

test("fetch: /__metrics serves counter text and resets on demand", async () => {
  const res = await worker.fetch(new Request("https://example.com/__metrics"), {})
  assert.equal(res.status, 200)
  assert.match(res.headers.get("content-type"), /text\/plain/)
  const body = await res.text()
  assert.match(body, /libcurl_connections_total 0/)
  assert.match(body, /libcurl_streams_opened_total 0/)
  assert.match(body, /# libcurl.js worker metrics/)

  const res2 = await worker.fetch(new Request("https://example.com/__metrics?reset=1"), {})
  assert.equal(res2.status, 200)
  const body2 = await res2.text()
  assert.match(body2, /libcurl_streams_opened_total 0/)
})

test("fetch: /__metrics rejects non-GET methods", async () => {
  const res = await worker.fetch(new Request("https://example.com/__metrics", { method: "POST" }), {})
  assert.equal(res.status, 405)
})

test("ratelimit env: BANDWIDTH_LIMIT overrides the per-ip byte budget", () => {
  const origEnabled = ratelimit.enabled
  const origLimit = ratelimit.bandwidth_limit
  try {
    apply_ratelimit({ RATELIMIT_ENABLED: "true", BANDWIDTH_LIMIT: "1048576" })
    assert.equal(ratelimit.enabled, true)
    assert.equal(ratelimit.bandwidth_limit, 1048576)
    apply_ratelimit({})
    assert.equal(ratelimit.bandwidth_limit, 25 * 1024 * 1024, "falls back to the 25 MiB default")
    assert.equal(ratelimit.enabled, false)
  } finally {
    apply_ratelimit({})
    ratelimit.enabled = origEnabled
    ratelimit.bandwidth_limit = origLimit
  }
})