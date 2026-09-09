//rate limiting for the wisp worker, ported from wisp-server-python's
//ratelimit.py. uses a fixed window strategy.
//
//note: worker isolates are ephemeral, so the counters below only apply while
//an isolate stays warm and are per-isolate, not global across the fleet. this
//deters simple abuse but is not a hard guarantee.

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

//apply the per-deploy settings from the env binding (see config.js)
export function apply_env(env) {
  ratelimit.enabled = env_bool(env, "RATELIMIT_ENABLED", false)
  ratelimit.connections_limit = env_num(env, "RATELIMIT_CONNECTIONS", 30)
  ratelimit.auth_fail_limit = env_num(env, "RATELIMIT_AUTH_FAILURES", 5)
  ratelimit.window_size = env_num(env, "RATELIMIT_WINDOW", 60)
  ratelimit.bandwidth_limit = env_num(env, "BANDWIDTH_LIMIT", 25 * 1024 * 1024)
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

export function get_client_attr(client_ip, attr) {
  init_client(client_ip)
  let client = active_clients.get(client_ip)
  return client ? client[attr] : undefined
}

export function inc_client_attr(client_ip, attr, amount = 1) {
  init_client(client_ip)
  let client = active_clients.get(client_ip)
  if (client) client[attr] += amount
  return client ? client[attr] : undefined
}

//charge `amount` bytes against the client's per-window budget, returning the
//remaining budget (the caller throttles the client when it hits 0). once the
//budget is spent, further charges are short-circuited so the remainder
//stays <= 0 rather than ballooning negative.
export function spend_client_bandwidth(client_ip, amount) {
  init_client(client_ip)
  let client = active_clients.get(client_ip)
  if (!client || client.bandwidth <= 0) return client ? client.bandwidth : undefined
  client.bandwidth -= amount
  return client.bandwidth
}

//periodically clear the counters so a single window never grows forever.
//in workers, setInterval is not allowed at global scope, so this is called
//lazily from the fetch handler on first request.
let cleanup_interval = null
export function start_cleanup() {
  if (cleanup_interval) return
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