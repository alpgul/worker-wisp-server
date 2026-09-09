import { test } from "node:test"
import assert from "node:assert/strict"
import {
  GlobalRateLimiter,
  ratelimit,
  get_client_attr,
  inc_client_attr,
  spend_client_bandwidth,
  apply_env
} from "../src/ratelimit.js"

const now = () => Date.now() / 1000

//minimal workerd storage double: a Map whose read/write/transaction follow
//the ctx.storage contract (values survive across calls, transactions see the
//committed state of prior ones)
function makeStorage() {
  const map = new Map()
  const clone = v => (v === undefined ? v : JSON.parse(JSON.stringify(v)))
  return {
    map,
    async get(key) { return map.has(key) ? clone(map.get(key)) : undefined },
    async put(key, value) { map.set(key, clone(value)) },
    async transaction(fn) {
      const txn = {
        async get(key) { return map.has(key) ? clone(map.get(key)) : undefined },
        async put(key, value) { map.set(key, clone(value)) }
      }
      return fn(txn)
    }
  }
}

function makeDO() {
  return new GlobalRateLimiter({ storage: makeStorage() }, {})
}

function age(doStorage, ip, seconds) {
  const entry = doStorage.map.get("ip:" + ip)
  entry.start = now() - seconds
  doStorage.map.set("ip:" + ip, entry)
}

const WINDOW = 60
const LIMIT = 1024

//the Durable Object owns one fixed window per ip, shared across isolates

test("GlobalRateLimiter: get_window initializes a fresh window per ip", async () => {
  const do_ = makeDO()
  const w = await do_.get_window("192.0.2.10", WINDOW, LIMIT)
  assert.deepEqual({ streams: w.streams, auth_failures: w.auth_failures, bandwidth: w.bandwidth },
    { streams: 0, auth_failures: 0, bandwidth: LIMIT })
  const w2 = await do_.get_window("192.0.2.11", WINDOW, LIMIT)
  assert.equal(w2.streams, 0)
  assert.equal(w.streams, 0, "ips are isolated")
})

test("GlobalRateLimiter: inc accumulates and get_window sees the same window", async () => {
  const do_ = makeDO()
  await do_.inc("198.51.100.5", "streams", 3, WINDOW, LIMIT)
  await do_.inc("198.51.100.5", "streams", 2, WINDOW, LIMIT)
  const w = await do_.get_window("198.51.100.5", WINDOW, LIMIT)
  assert.equal(w.streams, 5)
  const w2 = await do_.get_window("192.0.2.1", WINDOW, LIMIT)
  assert.equal(w2.streams, 0)
})

test("GlobalRateLimiter: spend short-circuits once the budget is exhausted", async () => {
  const do_ = makeDO()
  assert.equal(await do_.spend("203.0.113.9", 600, WINDOW, LIMIT), 424)
  assert.equal(await do_.spend("203.0.113.9", 424, WINDOW, LIMIT), 0)
  //charges against a spent budget stay <= 0 instead of going negative
  assert.equal(await do_.spend("203.0.113.9", 9999, WINDOW, LIMIT), 0)
})

test("GlobalRateLimiter: a lapsed window resets counters and the budget", async () => {
  const do_ = makeDO()
  const storage = do_.storage
  await do_.inc("192.0.2.20", "auth_failures", 3, WINDOW, LIMIT)
  await do_.spend("192.0.2.20", 900, WINDOW, LIMIT)
  age(storage, "192.0.2.20", WINDOW + 1)
  const w = await do_.get_window("192.0.2.20", WINDOW, LIMIT)
  assert.equal(w.auth_failures, 0, "counters roll back when the window lapses")
  assert.equal(w.bandwidth, LIMIT, "budget is replenished for the new window")
})

test("GlobalRateLimiter: a live window keeps its counters", async () => {
  const do_ = makeDO()
  const storage = do_.storage
  await do_.inc("192.0.2.21", "streams", 4, WINDOW, LIMIT)
  age(storage, "192.0.2.21", WINDOW - 1)
  const w = await do_.get_window("192.0.2.21", WINDOW, LIMIT)
  assert.equal(w.streams, 4, "window still open -> counters survive")
})

//the module routes to the DO when a binding is configured; without one it
//falls back to the in-memory store with identical semantics

test("fallback: in-memory store matches DO semantics when no binding is present", async () => {
  const origEnabled = ratelimit.enabled
  const origLimit = ratelimit.bandwidth_limit
  apply_env({ RATELIMIT_ENABLED: "true", BANDWIDTH_LIMIT: "1024" })
  try {
    const ip = "192.0.2.30"
    assert.equal(await get_client_attr(ip, "streams"), 0)
    assert.equal(await inc_client_attr(ip, "streams"), 1)
    assert.equal(await inc_client_attr(ip, "streams", 4), 5)
    assert.equal(await spend_client_bandwidth(ip, 1000), 24)
    //a charge that overshoots a still-positive budget goes negative (both the
    //DO and the fallback behave this way); the short-circuit only kicks in
    //once the budget is already <= 0
    assert.equal(await spend_client_bandwidth(ip, 1000), 24 - 1000)
  } finally {
    apply_env({})
    ratelimit.enabled = origEnabled
    ratelimit.bandwidth_limit = origLimit
  }
})