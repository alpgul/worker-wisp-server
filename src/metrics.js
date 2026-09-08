//lightweight in-memory metrics for the wisp worker, exposed via the
///__metrics endpoint (see index.js). like the rate limiter, counters are
//per-isolate: they reset when the isolate is evicted, so treat them as recent
//activity, not fleet-wide truth. that is still enough to validate the
//performance items with data instead of guesses.

const state = {
  connections_total: 0, //websocket connections accepted
  streams_opened_total: 0, //streams whose destination socket connected
  streams_closed_total: 0, //stream entries torn down
  bytes_ws_to_tcp_total: 0, //client -> server payload bytes
  packets_ws_to_tcp_total: 0,
  bytes_tcp_to_ws_total: 0, //server -> client payload bytes
  packets_tcp_to_ws_total: 0,
  downstream_stalls_total: 0, //times a slow client filled the outbound buffer
  out_queue_max: 0, //peak per-stream tcp->ws buffer fill (packets)
  closes_by_reason: {} //protocol CLOSE packets, keyed by "0xHH" reason byte
}

export function reset() {
  for (let key of Object.keys(state)) {
    if (key === "closes_by_reason") state[key] = {}
    else state[key] = 0
  }
}

export function inc(name, by = 1) {
  state[name] += by
}

export function add(name, by) {
  state[name] += by
}

export function record_close(reason) {
  let key = "0x" + reason.toString(16).padStart(2, "0")
  state.closes_by_reason[key] = (state.closes_by_reason[key] || 0) + 1
}

export function observe_out_queue(length) {
  if (length > state.out_queue_max) state.out_queue_max = length
}

export function snapshot() {
  return state
}

//prometheus-ish text render (no #TYPE boilerplate)
export function render() {
  let lines = ["# libcurl.js worker metrics"]
  for (let key of Object.keys(state)) {
    if (key === "closes_by_reason") continue
    lines.push(`libcurl_${key} ${state[key]}`)
  }
  for (let reason of Object.keys(state.closes_by_reason).sort()) {
    lines.push(`libcurl_closes_total{reason="${reason}"} ${state.closes_by_reason[reason]}`)
  }
  return lines.join("\n") + "\n"
}

//the object the rest of the worker calls into
export const metrics = { inc, add, record_close, observe_out_queue, snapshot, render }