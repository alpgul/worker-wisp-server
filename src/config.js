//runtime configuration for the wisp worker.
//
//values are read from the env binding that workerd passes to the fetch handler
//(modules format exposes bindings via the env parameter, not globalThis), so
//index.js calls apply_env() on every request. the values are constant at
//runtime, so re-applying them per request is cheap.

const config = {
  //block connections to loopback ip addresses
  block_loopback: true,
  //block connections to private/private-range ip addresses
  block_private: true,
  //udp streams are not supported: the default connect() connector is tcp-only,
  //and the warp protocol (which would allow udp) is not used here
  block_udp: true,
  //hostnames (and their subdomains) which are refused with close reason 0x48
  hostname_blocklist: [],
  //optional allowlist. when non-empty, only these hostnames (and their
  //subdomains) are accepted; everything else is refused with close reason 0x48
  hostname_allowlist: [],
  //ports which are refused with close reason 0x48
  port_blocklist: [],
  //maximum number of simultaneously open streams per websocket connection
  stream_limit_total: 50,
  //wisp v2 MOTD shown to wisp v2 clients during the handshake
  wisp_motd: null,
  //wisp v2 password auth. auth is only enabled when both values are set.
  auth_username: null,
  auth_password: null
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

function env_str(env, name, default_value) {
  let val = env ? env[name] : undefined
  if (val !== undefined) return String(val)
  return default_value
}

function env_list(env, name) {
  let val = env ? env[name] : undefined
  if (val === undefined || val === "") return []
  return String(val).split(",").map(s => s.trim()).filter(s => s !== "")
}

//apply the per-deploy settings from the env binding
export function apply_env(env) {
  config.block_loopback = !env_bool(env, "ALLOW_LOOPBACK", false)
  config.block_private = !env_bool(env, "ALLOW_PRIVATE", false)
  config.hostname_blocklist = env_list(env, "HOSTNAME_BLACKLIST")
  config.hostname_allowlist = env_list(env, "ALLOW_HOSTNAME")
  config.port_blocklist = env_list(env, "PORT_BLACKLIST").map(Number).filter(n => !isNaN(n))
  config.stream_limit_total = env_num(env, "STREAM_LIMIT_TOTAL", 50)
  config.wisp_motd = env_str(env, "WISP_MOTD", null)
  config.auth_username = env_str(env, "WISP_AUTH_USERNAME", null)
  config.auth_password = env_str(env, "WISP_AUTH_PASSWORD", null)
}

export { config }