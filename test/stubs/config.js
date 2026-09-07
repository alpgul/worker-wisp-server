//portable stand-in for src/config.js (permissive by default, matching a permissive test env)
export const config = {
  block_loopback: false,
  block_private: false,
  block_udp: true,
  hostname_blocklist: [],
  port_blocklist: [],
  stream_limit_total: 50,
  wisp_motd: null,
  auth_username: null,
  auth_password: null
}