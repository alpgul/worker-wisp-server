//runtime configuration for the wisp worker.
//values are read from environment bindings so they can be tuned per-deploy.

function env_bool(name, default_value) {
  if (typeof globalThis !== "undefined" && globalThis[name] !== undefined) {
    return String(globalThis[name]) !== "false" && String(globalThis[name]) !== ""
  }
  return default_value
}

//allow connections to loopback ip addresses
export const block_loopback = !env_bool("ALLOW_LOOPBACK", false)
//allow connections to private/private-range ip addresses
export const block_private = !env_bool("ALLOW_PRIVATE", false)

//udp streams are not supported: the default connect() connector is tcp-only,
//and the warp protocol (which would allow udp) is not used here.
export const block_udp = true

//size of the per-stream send buffer, in packets
export const queue_size = 128

//number of bytes to read from a socket at a time
export const tcp_size = 64 * 1024
