//rate limiting for the wisp worker, ported from wisp-server-python's
//ratelimit.py. uses a fixed window strategy.
//
//note: worker isolates are ephemeral, so the counters below only apply while
//an isolate stays warm and are per-isolate, not global across the fleet. this
//deters simple abuse but is not a hard guarantee.

const active_clients = new Map()

function env_int(name, default_value) {
  if (typeof globalThis !== "undefined" && globalThis[name] !== undefined) {
    let val = Number(globalThis[name])
    if (!isNaN(val)) return val
  }
  return default_value
}

function env_float(name, default_value) {
  if (typeof globalThis !== "undefined" && globalThis[name] !== undefined) {
    let val = Number(globalThis[name])
    if (!isNaN(val)) return val
  }
  return default_value
}

function env_bool(name, default_value) {
  if (typeof globalThis !== "undefined" && globalThis[name] !== undefined) {
    return String(globalThis[name]).toLowerCase() === "true"
  }
  return default_value
}

export const enabled = env_bool("RATELIMIT_ENABLED", false)
//max new streams per ip per window
export const connections_limit = env_int("RATELIMIT_CONNECTIONS", 30)
//bandwidth limit in kilobytes per second
export const bandwidth_limit = env_float("RATELIMIT_BANDWIDTH", 100)
//fixed window size, in seconds
export const window_size = env_float("RATELIMIT_WINDOW", 60)

function init_client(client_ip) {
  if (!active_clients.has(client_ip)) {
    active_clients.set(client_ip, {
      streams: 0, //number of newly created streams
      tcp: 0, //total ws -> tcp traffic
      ws: 0, //total tcp -> ws traffic
      start: Date.now() / 1000
    })
  }
}

export function get_client_attr(client_ip, attr) {
  init_client(client_ip)
  return active_clients.get(client_ip)[attr]
}

export function set_client_attr(client_ip, attr, value) {
  init_client(client_ip)
  active_clients.get(client_ip)[attr] = value
}

export function inc_client_attr(client_ip, attr, amount = 1) {
  set_client_attr(client_ip, attr, get_client_attr(client_ip, attr) + amount)
}

function calculate_client_bandwidth(client_ip, attr) {
  let client = active_clients.get(client_ip)
  let elapsed = Date.now() / 1000 - client.start
  if (elapsed <= 0) elapsed = 0.001
  return client[attr] / elapsed / 1000
}

//increment the byte counter for a client and resolve once the client is back
//under the bandwidth limit, mirroring the blocking sleep in ratelimit.py.
export async function limit_client_bandwidth(client_ip, length, attr) {
  if (!enabled) return
  inc_client_attr(client_ip, attr, length)
  while (calculate_client_bandwidth(client_ip, attr) > bandwidth_limit) {
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}

//periodically clear the counters so a single window never grows forever.
//in workers, setInterval is not allowed at global scope, so this is called
//lazily from the fetch handler on first request.
let cleanup_started = false
export function start_cleanup() {
  if (cleanup_started) return
  cleanup_started = true
  setInterval(() => {
    let now = Date.now() / 1000
    for (let [ip, client] of active_clients) {
      if (now - client.start > window_size) {
        active_clients.delete(ip)
      }
    }
  }, 1000)
}