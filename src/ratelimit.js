//rate limiting for the wisp worker, ported from wisp-server-python's
//ratelimit.py. uses a fixed window strategy.
//
//the per-ip counters live in a Durable Object (GlobalRateLimiter) so limits
//are enforced once per window across the whole fleet instead of only while a
//single isolate stays warm. every worker isolate routes its counter
//operations to one DO instance (the "global" id); the DO persists them to
//transactional storage and rolls the window over lazily. when no DO binding
//is present (node tests, deployments without durable objects) the module
//falls back to an in-memory store with identical semantics.

const active_clients = new Map()

const ratelimit = {
  enabled: false,
  //max new streams per ip per window
  connections_limit: 30,
  //max failed password-handshakes per ip per window, before closing with 0x49
  auth_fail_limit: 5,
  //fixed window size, in seconds
  window_size: 60,
  //per-ip byte budget: total data relayed (ws->tcp + tcp->ws) per window. the
  //inverse of downstream buffering - instead of bounding a queued backlog it
  //caps the sustained byte rate, so a single client cannot saturate the
  //free-tier quota. 0 disables the byte cap (stream/auth limits still apply).
  bandwidth_limit: 25 * 1024 * 1024
}

function env_bool(env, name, default_value) {
  let val = env ? env[name] : undefined
  if (val !== undefined) return String(val).toLowerCase() === "true"
  return default_value
}

function env_num(env, name, default_value) {
  let val = env ? env[name] : undefined
  if (val !== undefined) {
    let n = Number(val)
    if (!isNaN(n)) return n
  }
  return default_value
}

//cached handle to the shared DO instance, populated from the env binding on
//every fetch. null when the binding is missing, in which case ops stay local.
let do_stub = null

//apply the per-deploy settings from the env binding (see config.js). when the
//GLOBAL_RATELIMITER durable-object binding is configured, every counter
//operation is routed to that object - a single fleet-wide instance, keyed by
//the process-global name so all isolates share the exact same window.
export function apply_env(env) {
  ratelimit.enabled = env_bool(env, "RATELIMIT_ENABLED", false)
  ratelimit.connections_limit = env_num(env, "RATELIMIT_CONNECTIONS", 30)
  ratelimit.auth_fail_limit = env_num(env, "RATELIMIT_AUTH_FAILURES", 5)
  ratelimit.window_size = env_num(env, "RATELIMIT_WINDOW", 60)
  ratelimit.bandwidth_limit = env_num(env, "BANDWIDTH_LIMIT", 25 * 1024 * 1024)
  do_stub = env && env.GLOBAL_RATELIMITER
    ? env.GLOBAL_RATELIMITER.get(env.GLOBAL_RATELIMITER.idFromName("global"))
    : null
}

//the shared limiter state for the whole fleet. one fixed window per ip, kept
//in transactional storage. windows are not swept on a timer: an entry whose
//start has aged past window_size is re-initialized on its next access, which
//is exactly the same fixed-window behavior as the in-memory fallback.
export class GlobalRateLimiter {
  constructor(state, env) {
    this.state = state
    this.storage = state.storage
  }

  //return the ip's current window, (re)initializing it once it has lapsed
  async get_window(ip, window_size, bandwidth_limit) {
    return this._access(ip, window_size, bandwidth_limit, entry => entry)
  }

  //increment `attr` on the ip's current window, returning the new value
  async inc(ip, attr, amount, window_size, bandwidth_limit) {
    if (amount === undefined || amount === null) amount = 1
    return this._access(ip, window_size, bandwidth_limit, entry => {
      entry[attr] = (entry[attr] || 0) + amount
      return entry[attr]
    })
  }

  //charge `amount` bytes against the ip's window budget, returning the
  //remaining budget. once spent, further charges short-circuit so the
  //remainder stays <= 0 rather than ballooning negative (the caller throttles
  //the client when it reaches 0).
  async spend(ip, amount, window_size, bandwidth_limit) {
    return this._access(ip, window_size, bandwidth_limit, entry => {
      if (entry.bandwidth > 0) entry.bandwidth -= amount
      return entry.bandwidth
    })
  }

  //transactional read-modify-write so concurrent operations from different
  //isolates never lose an update
  async _access(ip, window_size, bandwidth_limit, mutate) {
    return this.storage.transaction(async txn => {
      const key = "ip:" + ip
      const now = Date.now() / 1000
      let entry = (await txn.get(key)) || null
      if (!entry || now - entry.start >= window_size) {
        entry = { streams: 0, auth_failures: 0, bandwidth: bandwidth_limit, start: now }
      }
      const result = mutate(entry)
      await txn.put(key, entry)
      return result
    })
  }
}

function init_client(client_ip) {
  if (!client_ip || active_clients.has(client_ip)) return
  active_clients.set(client_ip, {
    streams: 0, //number of newly created streams
    auth_failures: 0, //number of failed password handshakes
    bandwidth: ratelimit.bandwidth_limit, //remaining per-window byte budget
    start: Date.now() / 1000
  })
}

function local_get(client_ip, attr) {
  init_client(client_ip)
  let client = active_clients.get(client_ip)
  return client ? client[attr] : undefined
}

function local_inc(client_ip, attr, amount) {
  init_client(client_ip)
  let client = active_clients.get(client_ip)
  if (client) client[attr] += amount
  return client ? client[attr] : undefined
}

//charge `amount` bytes against the client's per-window budget, returning the
//remaining budget (the caller throttles the client when it hits 0). once the
//budget is spent, further charges are short-circuited so the remainder
//stays <= 0 rather than ballooning negative.
function local_spend(client_ip, amount) {
  init_client(client_ip)
  let client = active_clients.get(client_ip)
  if (!client || client.bandwidth <= 0) return client ? client.bandwidth : undefined
  client.bandwidth -= amount
  return client.bandwidth
}

export async function get_client_attr(client_ip, attr) {
  if (do_stub) {
    let window = await do_stub.get_window(client_ip, ratelimit.window_size, ratelimit.bandwidth_limit)
    return window[attr]
  }
  return local_get(client_ip, attr)
}

export async function inc_client_attr(client_ip, attr, amount = 1) {
  if (do_stub) {
    return do_stub.inc(client_ip, attr, amount, ratelimit.window_size, ratelimit.bandwidth_limit)
  }
  return local_inc(client_ip, attr, amount)
}

export async function spend_client_bandwidth(client_ip, amount) {
  if (do_stub) {
    return do_stub.spend(client_ip, amount, ratelimit.window_size, ratelimit.bandwidth_limit)
  }
  return local_spend(client_ip, amount)
}

//periodically clear the in-memory counters so a single window never grows
//forever. only needed for the fallback path (the DO renews its own windows);
//in workers, setInterval is not allowed at global scope, so this is called
//lazily from the fetch handler on first request.
let cleanup_interval = null
export function start_cleanup() {
  if (cleanup_interval || do_stub) return
  cleanup_interval = setInterval(() => {
    let now = Date.now() / 1000
    for (let [ip, client] of active_clients) {
      if (now - client.start > ratelimit.window_size) {
        active_clients.delete(ip)
      }
    }
  }, 1000)
}

export { ratelimit }