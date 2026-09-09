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
  auth_password: null,
  //when true, plain-text entry points are refused: websocket upgrades over
  //insecure schemes get 426 and plain http page loads redirect to https.
  //localhost/loopback is always exempt so the local dev server keeps working.
  enforce_https: true,
  //max tcp->ws DATA packets buffered per stream before we declare the
  //downstream (client) stalled. 0 disables the bound (unbuffered direct send).
  downstream_buffer: 512,
  //how long a full downstream queue may persist before the client is
  //considered stuck and the stream is proactively closed with 0x03. wisp has
  //no server->client flow control, so without this a stalled client fills
  //cloudflare's ws buffers and the connection dies with a late, unexplained
  //NETWORK_ERROR instead.
  downstream_stall_timeout: 10000,
  //tcp->ws wire coalescing: the tcp reader accumulates small chunks into one
  //DATA packet to amortize the per-message ws framing overhead of bulk
  //transfers. bytes are delivered when the batch reaches coalesce_max, when
  //the downstream queue is already full (backpressure takes over), or after
  //coalesce_timeout ms of quiet - so interactive traffic is only ever delayed
  //by one coalesce window per burst, not inflated per chunk.
  coalesce_max: 65536,
  //0 disables coalescing entirely (every chunk is sent as its own packet)
  coalesce_timeout: 10,
  //close a stream whose wisp-level activity is older than this (ms) - swept
  //lazily on inbound packets. 0 disables the stream-level sweep; the per-socket
  //idleTimeout below still reclaims each socket.
  stream_idle_timeout: 120000,
  //idleTimeout passed to socket.connect() (ms). cloudflare's mode default is
  //7 minutes; a shorter value makes silent sockets self-close and error early
  //instead of holding connections open. 0 disables (platform default).
  socket_idle_timeout: 60000
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
  config.enforce_https = env_bool(env, "ENFORCE_HTTPS", true)
  config.downstream_buffer = env_num(env, "DOWNSTREAM_BUFFER", 512)
  config.downstream_stall_timeout = env_num(env, "DOWNSTREAM_STALL_TIMEOUT", 10000)
  config.coalesce_max = env_num(env, "WISP_COALESCE_MAX", 65536)
  config.coalesce_timeout = env_num(env, "WISP_COALESCE_TIMEOUT", 10)
  config.stream_idle_timeout = env_num(env, "STREAM_IDLE_TIMEOUT", 120000)
  config.socket_idle_timeout = env_num(env, "SOCKET_IDLE_TIMEOUT", 60000)
}

export { config }