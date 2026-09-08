//portable stand-in for src/ratelimit.js (rate limiting disabled in tests)
const clients = new Map()

export const ratelimit = {
  enabled: false,
  connections_limit: 30,
  auth_fail_limit: 5,
  window_size: 60
}

export function get_client_attr(ip, attr) {
  if (!clients.has(ip)) clients.set(ip, { streams: 0 })
  return clients.get(ip)[attr]
}
export function inc_client_attr(ip, attr, amount = 1) {
  if (!clients.has(ip)) clients.set(ip, { streams: 0 })
  clients.get(ip)[attr] = (clients.get(ip)[attr] || 0) + amount
  return clients.get(ip)[attr]
}