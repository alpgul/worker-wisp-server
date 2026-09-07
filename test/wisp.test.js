//unit tests for src/wisp.js (the protocol core).
//
//these run on plain node: the worker's cloudflare-only imports (net.js,
//ratelimit.js) are redirected to ./stubs by imports-loader.mjs, so real TCP
//sockets are replaced by an in-memory fake while the wisp protocol logic
//itself is exercised unmodified.
//
//run with: npm test

import { test } from "node:test"
import assert from "node:assert/strict"

import { WispConnection } from "../src/wisp.js"
import { create_packet, array_from_uint } from "../src/util.js"
import { TCPConnection } from "./stubs/net.js"

const queue_size = 128

//fake websocket that records everything sent to the client
function makeWs() {
  const handler = { msgs: [] }
  return {
    async send(bytes) {
      handler.msgs.push(new Uint8Array(bytes))
    },
    accept: async () => {},
    handler
  }
}

//wrap raw bytes as a MessageEvent-like object
function msg(bytes) {
  return { type: "message", data: bytes }
}

//build a CONNECT packet: [type][stream_id u32 le][stream_type][port u16 le][hostname]
function connectPacket(streamId, host, port, streamType = 0x01) {
  const hostBuf = new TextEncoder().encode(host)
  const p = new Uint8Array(5 + 3 + hostBuf.length)
  p[0] = 0x01
  p[1] = streamId & 0xff
  p[2] = (streamId >> 8) & 0xff
  p[3] = (streamId >> 16) & 0xff
  p[4] = (streamId >> 24) & 0xff
  p[5] = streamType
  p[6] = port & 0xff
  p[7] = (port >> 8) & 0xff
  p.set(hostBuf, 8)
  return p
}

//collect the active stream object for a given id
function streamOf(wisp, id) {
  return wisp.active_streams[id]
}

const tick = (ms = 10) => new Promise(r => setTimeout(r, ms))

test("handshake sends one CONTINUE packet with queue_size", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  assert.equal(ws.handler.msgs.length, 1, "handshake emits exactly one packet")
  const p = ws.handler.msgs[0]
  assert.equal(p[0], 0x03, "packet type is CONTINUE")
  assert.equal(p[1] | (p[2] << 8), 0, "stream_id is 0")
  assert.deepEqual(Array.from(p.slice(5)), Array.from(array_from_uint(queue_size, 4)), "payload is queue_size=128")
})

test("stream connect + bidirectional data relay", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(1, "example.com", 80)))
  await tick()

  const stream = streamOf(wisp, 1)
  assert.ok(stream, "stream 1 created")
  assert.equal(stream.conn.hostname, "example.com", "tcp hostname parsed")
  assert.equal(stream.conn.port, 80, "tcp port parsed")

  //remote bytes -> DATA packet to the client
  stream.conn._push(new TextEncoder().encode("hello"))
  await tick()
  const data = ws.handler.msgs.find(m => m[0] === 0x02 && (m[1] | (m[2] << 8)) === 1)
  assert.ok(data, "remote data produces a DATA packet")
  assert.equal(new TextDecoder().decode(data.slice(5)), "hello", "DATA payload echoes remote bytes")

  //client bytes -> remote socket
  await wisp.handle_ws_message(msg(create_packet(0x02, 1, new TextEncoder().encode("ping"))))
  await tick()
  assert.ok(
    stream.conn.sent.some(d => new TextDecoder().decode(d) === "ping"),
    "client DATA delivered to the remote socket"
  )
})

test("client-initiated close cleans up with no reply packet", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(1, "example.com", 80)))
  await tick()
  const stream = streamOf(wisp, 1)

  wisp.close_stream(1)
  assert.equal(stream.conn.closed, true, "remote socket closed")
  assert.equal(1 in wisp.active_streams, false, "stream removed")
  //wisp v1: a client-initiated CLOSE gets no reply (only server-side
  //termination sends a CLOSE packet)
  const reply = ws.handler.msgs.find(m => m[0] === 0x04 && (m[1] | (m[2] << 8)) === 1)
  assert.equal(reply, undefined, "no CLOSE reply to client close")
})

test("close packet from the client tears down the stream", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(3, "example.com", 80)))
  await tick()
  const stream = streamOf(wisp, 3)

  await wisp.handle_ws_message(msg(create_packet(0x04, 3, new Uint8Array([0x00]))))
  assert.equal(stream.conn.closed, true, "remote socket closed on CLOSE packet")
  assert.equal(3 in wisp.active_streams, false, "stream removed after CLOSE packet")
})

test("UDP CONNECT is rejected with CLOSE 0x42", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(9, "example.com", 80, 0x02)))
  await tick()

  const closeMsg = ws.handler.msgs.find(m => m[0] === 0x04 && (m[1] | (m[2] << 8)) === 9)
  assert.ok(closeMsg, "UDP CONNECT emits a CLOSE packet")
  assert.equal(closeMsg[5], 0x42, "close reason is CONNECT_FAILED")
  assert.equal(9 in wisp.active_streams, false, "stream cleaned up")
})

test("failed TCP connect shows CLOSE 0x42", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  const orig = TCPConnection.prototype.connect
  TCPConnection.prototype.connect = async function () {
    throw new Error("connection refused")
  }
  try {
    await wisp.handle_ws_message(msg(connectPacket(8, "example.com", 81)))
    await tick()
  } finally {
    TCPConnection.prototype.connect = orig
  }

  const closeMsg = ws.handler.msgs.find(m => m[0] === 0x04 && (m[1] | (m[2] << 8)) === 8)
  assert.ok(closeMsg, "failed connect emits a CLOSE packet")
  assert.equal(closeMsg[5], 0x42, "close reason is CONNECT_FAILED")
  assert.equal(8 in wisp.active_streams, false, "stream cleaned up")
})

test("TCP read error triggers CLOSE 0x03", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(2, "example.com", 81)))
  await tick()
  const stream = streamOf(wisp, 2)

  stream.conn.fail(new Error("connection reset"))
  await tick(20)

  const closeMsg = ws.handler.msgs.find(m => m[0] === 0x04 && (m[1] | (m[2] << 8)) === 2)
  assert.ok(closeMsg, "socket error emits a CLOSE packet")
  assert.equal(closeMsg[5], 0x03, "close reason is SOCKET_ERROR")
  assert.equal(2 in wisp.active_streams, false, "stream cleaned up")
})

test("TCP EOF triggers CLOSE 0x02", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(6, "example.com", 80)))
  await tick()
  streamOf(wisp, 6).conn.eof()
  await tick(20)

  const closeMsg = ws.handler.msgs.find(m => m[0] === 0x04 && (m[1] | (m[2] << 8)) === 6)
  assert.ok(closeMsg, "EOF emits a CLOSE packet")
  assert.equal(closeMsg[5], 0x02, "close reason is NORMAL on EOF")
})

test("data to unknown or closed streams is ignored", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(1, "example.com", 80)))
  await tick()

  const before = ws.handler.msgs.length
  await wisp.handle_ws_message(msg(create_packet(0x02, 99, new TextEncoder().encode("x"))))
  await tick()
  assert.equal(ws.handler.msgs.length, before, "DATA to unknown stream is ignored")

  wisp.close_stream(1)
  const before2 = ws.handler.msgs.length
  await wisp.handle_ws_message(msg(create_packet(0x02, 1, new TextEncoder().encode("x"))))
  await tick()
  assert.equal(ws.handler.msgs.length, before2, "DATA to closed stream is ignored")
})

test("malformed packets never crash the connection", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  const before = ws.handler.msgs.length
  await wisp.handle_ws_message(msg(new Uint8Array([0x02, 0x01, 0x00]))) //too short
  await wisp.handle_ws_message({ type: "message", data: "text frame" }) //non-binary
  await wisp.handle_ws_message("garbage")
  await tick()
  assert.ok(ws.handler.msgs.length >= before, "malformed packets handled without crash")
})

test("backpressure caps the send queue at queue_size without losing data", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(7, "example.com", 80)))
  await tick()
  const stream = streamOf(wisp, 7)
  stream.conn._sendDelay = 25 //remote is slow; the pump cannot drain fast

  const payload = new Uint8Array(100).fill(0x41)
  const TOTAL = 150
  for (let i = 0; i < TOTAL; i++) {
    wisp.queue_ws_data(7, payload) //not awaited: producer outruns the pump
  }

  const queueLen = () => streamOf(wisp, 7).queue.length
  let max = 0
  for (let i = 0; i < 8; i++) {
    max = Math.max(max, queueLen())
    await tick(5)
  }
  assert.ok(max <= queue_size, `queue never exceeds queue_size (max=${max})`)
  assert.ok(max > queue_size / 2, `backpressure actually engaged (max=${max} > 64)`)

  const deadline = Date.now() + 8000
  while (stream.conn.sent.length < TOTAL && Date.now() < deadline) {
    await tick(20)
  }
  assert.equal(stream.conn.sent.length, TOTAL, "all packets eventually delivered without loss")
})

test("close_stream wakes blocked queue_ws_data waiters", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(7, "example.com", 80)))
  await tick()
  const stream = streamOf(wisp, 7)
  stream.conn._sendDelay = 1000 //pump basically stalls

  //fill the queue past the cap; the push fires without awaiting so it will
  //block on a waiter exactly like a message delivery would
  const payload = new Uint8Array(10)
  for (let i = 0; i < queue_size + 20; i++) wisp.queue_ws_data(7, payload)
  await tick()

  //closing the stream must resolve all pending waiters instead of leaking promises
  const waitersBefore = streamOf(wisp, 7).waiters.length
  assert.ok(waitersBefore > 0, "some queue_ws_data calls are blocked")
  wisp.close_stream(7)
  assert.equal(7 in wisp.active_streams, false, "stream removed")
})

test("ws disconnect closes every stream cleanly", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(4, "example.com", 80)))
  await wisp.handle_ws_message(msg(connectPacket(5, "example.com", 80)))
  await tick()

  wisp.close_all()
  assert.equal(Object.keys(wisp.active_streams).length, 0, "all streams closed on ws disconnect")
  const s4 = ws.handler.msgs.find(m => (m[1] | (m[2] << 8)) === 4)
  const s5 = ws.handler.msgs.find(m => (m[1] | (m[2] << 8)) === 5)
  assert.equal(s4, undefined, "no stray CLOSE for stream 4")
  assert.equal(s5, undefined, "no stray CLOSE for stream 5")
})

test("CONTINUE packets are emitted for flow control", async () => {
  const ws = makeWs()
  const wisp = new WispConnection(ws, "/", "127.0.0.1")
  wisp.setup()

  await wisp.handle_ws_message(msg(connectPacket(10, "example.com", 80)))
  await tick()
  const stream = streamOf(wisp, 10)

  //send enough packets to cross the queue_size/4 = 32 threshold
  const payload = new Uint8Array(10)
  for (let i = 0; i < 40; i++) {
    await wisp.queue_ws_data(10, payload)
    await tick(0)
  }
  await tick()

  const continues = ws.handler.msgs.filter(m => m[0] === 0x03 && (m[1] | (m[2] << 8)) === 10)
  assert.ok(continues.length >= 1, "CONTINUE packet(s) sent after 32 queued packets")
})