import { test } from "node:test"
import assert from "node:assert/strict"
import { WispConnection } from "../src/wisp.js"
import { create_packet } from "../src/util.js"
import { metrics, reset, render, snapshot } from "../src/metrics.js"
import { config } from "./stubs/config.js"

//fake websocket recording everything sent to the client
function makeWs() {
  const handler = { msgs: [] }
  return {
    async send(bytes) {
      handler.msgs.push(new Uint8Array(bytes))
    },
    close() {},
    accept: async () => {},
    handler
  }
}

function msg(bytes) {
  return { type: "message", data: bytes }
}

function connectPacket(streamId, host, port) {
  const hostBuf = new TextEncoder().encode(host)
  const p = new Uint8Array(8 + hostBuf.length)
  p.set([0x01, streamId & 0xff, (streamId >> 8) & 0xff, (streamId >> 16) & 0xff, (streamId >> 24) & 0xff, 0x01], 0)
  p[6] = port & 0xff
  p[7] = (port >> 8) & 0xff
  p.set(hostBuf, 8)
  return p
}

const encode = new TextEncoder().encode.bind(new TextEncoder())
const tick = (ms = 10) => new Promise(r => setTimeout(r, ms))

test("metrics accumulate across a relay, reject and close", async () => {
  reset()
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  //opened stream with bidirectional data
  await wisp.handle_ws_message(msg(connectPacket(1, "example.com", 80)))
  await tick()
  const stream = wisp.active_streams[1]
  stream.conn._push(encode("aaaa")) //tcp -> ws
  await tick()
  await wisp.handle_ws_message(msg(create_packet(0x02, 1, encode("bbb")))) //ws -> tcp
  await tick()

  //blocked host -> reject 0x48
  config.hostname_blocklist = ["evil.com"]
  try {
    await wisp.handle_ws_message(msg(connectPacket(2, "evil.com", 80)))
  } finally {
    config.hostname_blocklist = []
  }
  await tick()

  //voluntary close of stream 1
  await wisp.handle_ws_message(msg(create_packet(0x04, 1, new Uint8Array([0x02]))))
  await tick()

  const s = snapshot()
  assert.equal(s.streams_opened_total, 1, "one socket connected")
  assert.ok(s.bytes_ws_to_tcp_total >= 3, "client -> server bytes counted")
  assert.ok(s.bytes_tcp_to_ws_total >= 4, "server -> client bytes counted")
  assert.ok(s.packets_ws_to_tcp_total >= 1 && s.packets_tcp_to_ws_total >= 1, "packet counters ticked")
  assert.equal(s.closes_by_reason["0x48"], 1, "blocked host recorded as 0x48 close")
  assert.ok(s.streams_closed_total >= 2, "entries torn down")
  assert.equal(s.out_queue_max, 1, "observed the outbound queue fill (peak 1)")
})

test("stall increments downstream_stalls_total and closes with 0x03", async () => {
  reset()
  const origBuffer = config.downstream_buffer
  const origTimeout = config.downstream_stall_timeout
  config.downstream_buffer = 2
  config.downstream_stall_timeout = 80
  try {
    const ws = makeWs()
    ws._slow = true
    ws.send = async bytes => {
      if (ws._slow) await new Promise(r => setTimeout(r, 40))
      ws.handler.msgs.push(new Uint8Array(bytes))
    }
    const wisp = new WispConnection(ws, "/", "127.0.0.1")
    wisp.setup()

    await wisp.handle_ws_message(msg(connectPacket(1, "example.com", 80)))
    await tick()
    const stream = wisp.active_streams[1]
    const blob = encode("x".repeat(10))
    for (let i = 0; i < 20; i++) stream.conn._push(blob)

    let sawClose = false
    const deadline = Date.now() + 3000
    while (!sawClose && Date.now() < deadline) {
      sawClose = !!ws.handler.msgs.find(m => m[0] === 0x04 && m[1] === 1 && m[5] === 0x03)
      await tick(20)
    }
    assert.ok(sawClose, "stalled stream closed with 0x03")
    const s = snapshot()
    assert.ok(s.downstream_stalls_total >= 1, "stall counter incremented")
    assert.equal(s.closes_by_reason["0x03"], 1, "0x03 recorded under closes")
    assert.ok(s.out_queue_max >= config.downstream_buffer, "peak buffer fill observed")
    assert.equal(Object.keys(s.closes_by_reason).length, 1, "no stray close reasons")
  } finally {
    config.downstream_buffer = origBuffer
    config.downstream_stall_timeout = origTimeout
  }
})

test("render produces prometheus-ish text labels", () => {
  reset()
  metrics.inc("connections_total")
  metrics.record_close(0x48)
  metrics.record_close(0x09)
  const text = render()
  assert.match(text, /libcurl_connections_total 1/)
  assert.match(text, /libcurl_closes_total\{reason="0x09"\} 1/)
  assert.match(text, /libcurl_closes_total\{reason="0x48"\} 1/)
  assert.match(text, /\n$/, "ends with a newline")
})

test("reset zeroes every counter", () => {
  metrics.inc("connections_total", 3)
  metrics.record_close(0x42)
  reset()
  const text = render()
  assert.match(text, /libcurl_connections_total 0/)
  assert.match(text, /libcurl_streams_opened_total 0/)
  assert.match(text, /libcurl_bytes_tcp_to_ws_total 0/)
  assert.match(text, /libcurl_downstream_stalls_total 0/)
  assert.match(text, /libcurl_out_queue_max 0/)
  assert.doesNotMatch(text, /libcurl_closes_total/, "no close reasons left")
  assert.match(text, /\n$/, "ends with a newline")
})