//portable stand-in for src/config.js (permissive by default, matching a permissive test env)
export const config = {
  block_loopback: false,
  block_private: false,
  block_udp: true,
  hostname_blocklist: [],
  hostname_allowlist: [],
  port_blocklist: [],
  stream_limit_total: 50,
  wisp_motd: null,
  auth_username: null,
  auth_password: null,
  enforce_https: false,
  downstream_buffer: 512,
  downstream_stall_timeout: 10000,
  stream_idle_timeout: 0,
  socket_idle_timeout: 0
}