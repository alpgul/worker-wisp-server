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
  block_udp: true
}

function env_bool(env, name, default_value) {
  let val = env ? env[name] : undefined
  if (val !== undefined) return String(val).toLowerCase() === "true"
  return default_value
}

//apply the per-deploy settings from the env binding
export function apply_env(env) {
  config.block_loopback = !env_bool(env, "ALLOW_LOOPBACK", false)
  config.block_private = !env_bool(env, "ALLOW_PRIVATE", false)
}

export { config }