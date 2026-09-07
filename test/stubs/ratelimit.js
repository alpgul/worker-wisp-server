//portable stand-in for src/ratelimit.js (rate limiting disabled in tests)
export const enabled = false
export const connections_limit = 30
export const bandwidth_limit = 100
export const window_size = 60
const clients = new Map()

export function get_client_attr(ip, attr) {
  if (!clients.has(ip)) clients.set(ip, { streams: 0 })
  return clients.get(ip)[attr]
}
export function set_client_attr(ip, attr, v) {
  if (!clients.has(ip)) clients.set(ip, { streams: 0 })
  clients.get(ip)[attr] = v
}
export function inc_client_attr(ip, attr, amount = 1) {
  set_client_attr(ip, attr, get_client_attr(ip, attr) + amount)
}
export async function limit_client_bandwidth() {}