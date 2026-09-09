//portable stand-in for src/ratelimit.js (rate limiting disabled in tests).
//mirrors the async api so wisp.js can await the same way in both worlds.
const clients = new Map()

export const ratelimit = {
  enabled: false,
  connections_limit: 30,
  auth_fail_limit: 5,
  window_size: 60,
  bandwidth_limit: 0
}

function clientOf(ip) {
  if (!clients.has(ip)) clients.set(ip, { streams: 0, auth_failures: 0, bandwidth: ratelimit.bandwidth_limit })
  return clients.get(ip)
}
export async function get_client_attr(ip, attr) {
  return clientOf(ip)[attr]
}
export async function inc_client_attr(ip, attr, amount = 1) {
  clientOf(ip)[attr] = (clientOf(ip)[attr] || 0) + amount
  return clientOf(ip)[attr]
}
export async function spend_client_bandwidth(ip, amount) {
  const client = clientOf(ip)
  if (client.bandwidth <= 0) return client.bandwidth
  client.bandwidth -= amount
  return client.bandwidth
}