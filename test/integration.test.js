//cross-implementation integration tests: the real wisp.js client
//(client/wisp_client/wisp.js, executed inside a vm context) is connected over
//an in-memory websocket pair to the real worker src/wisp.js server connection.
//this proves wire compatibility between the two halves of the stack end to end
//(v2 handshake, extension negotiation, password auth, data relay, close).
//
//run with: npm test

import { test } from "node:test"
import assert from "node:assert/strict"
import vm from "node:vm"
import fs from "node:fs"

import { WispConnection as ServerWispConnection } from "../src/wisp.js"
import { config } from "./stubs/config.js"

const wisp_source = fs.readFileSync(new URL("../../../client/wisp_client/wisp.js", import.meta.url), "utf8")

const encode = new TextEncoder().encode.bind(new TextEncoder())
const decode = new TextDecoder().decode.bind(new TextDecoder())
const settled = () => new Promise((resolve) => setTimeout(resolve, 0))

function parsePacket(bytes) {
  const view = new Uint8Array(bytes)
  const dv = new DataView(view.buffer, view.byteOffset, view.byteLength)
  return {
    type: dv.getUint8(0),
    stream_id: dv.getUint32(1, true),
    payload: view.subarray(5)
  }
}

//---- in-memory websocket endpoints ------------------------------------------

//a single endpoint in an in-memory websocket pair. message delivery is
//synchronous (in-order, like workerd). a "message" event which arrives before
//any listener is attached is buffered and replayed when one shows up, which
//covers the server sending its INFO packet before the client even constructs.
class VirtualSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  constructor(autoReplay = true) {
    this.binaryType = "blob"
    this.readyState = VirtualSocket.OPEN
    this._listeners = new Map()
    this._buffered = []
    this.autoReplay = autoReplay
    this.received = [] // ArrayBuffers of packets delivered to this endpoint
  }

  addEventListener(type, fn) {
    let set = this._listeners.get(type)
    if (!set) {
      set = new Set()
      this._listeners.set(type, set)
    }
    set.add(fn)
    if (type === "message" && this.autoReplay) this.replay()
  }

  removeEventListener(type, fn) {
    const set = this._listeners.get(type)
    if (set) set.delete(fn)
  }

  _emit(type, init) {
    if (type === "message") {
      const ab = init.data
      this.received.push(ab)
      const set = this._listeners.get("message")
      if (!set || set.size === 0) {
        this._buffered.push(init)
        return
      }
    }
    const event = { type, target: this }
    if (init) Object.assign(event, init)
    const set = this._listeners.get(type)
    if (!set) return
    for (const fn of [...set]) fn.call(this, event)
  }

  //deliver any messages which arrived before a listener was attached
  replay() {
    const set = this._listeners.get("message")
    if (!set || set.size === 0) return
    const pending = this._buffered
    this._buffered = []
    for (const init of pending) {
      const event = { type: "message", target: this }
      Object.assign(event, init)
      for (const fn of [...set]) fn.call(this, event)
    }
  }

  //send a binary message to the peer
  send(data) {
    const bytes = new Uint8Array(data)
    const copy = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
    this.peer._emit("message", { data: copy })
  }

  close() {
    if (this._closed) return
    this._closed = true
    this.readyState = VirtualSocket.CLOSED
    this.peer._emit("close", {})
  }
}

//fake DOM / logging globals for the client vm (mirrors test/client.test.mjs)
class FakeEvent {
  constructor(type, init) {
    this.type = type
    this.target = null
    Object.assign(this, init)
  }
}

class FakeEventTarget {
  constructor() {
    this._listeners = new Map()
  }
  addEventListener(type, fn) {
    let set = this._listeners.get(type)
    if (!set) {
      set = new Set()
      this._listeners.set(type, set)
    }
    set.add(fn)
  }
  removeEventListener(type, fn) {
    const set = this._listeners.get(type)
    if (set) set.delete(fn)
  }
  dispatchEvent(event) {
    event.target = this
    const set = this._listeners.get(event.type)
    if (!set) return true
    for (const fn of [...set]) fn.call(this, event)
    return true
  }
}

//---- client harness ----------------------------------------------------------

//the client's vm WebSocket constructor returns a pre-wired shared instance so
//the in-memory pair can be built by the test before the client exists
function sharedWebSocketBinding(sharedWs) {
  class SharedWebSocket {
    constructor(url, protocols) {
      sharedWs.url = url
      sharedWs.protocols = protocols
      return sharedWs
    }
  }
  Object.assign(SharedWebSocket, VirtualSocket)
  return SharedWebSocket
}

//create a WispConnection in a vm context whose WebSocket is `clientWs`
function makeClient(clientWs, options) {
  const sandbox = {
    WebSocket: sharedWebSocketBinding(clientWs),
    Event: FakeEvent,
    EventTarget: FakeEventTarget,
    CloseEvent: FakeEvent,
    MessageEvent: FakeEvent,
    TextEncoder,
    TextDecoder,
    warn_msg: () => {},
    error_msg: () => {}
  }
  const context = vm.createContext(sandbox)
  vm.runInContext(wisp_source + "\n;globalThis.__wisp_pairs = {WispConnection, WispStream};", context)
  return new context.__wisp_pairs.WispConnection("wss://example.com/wisp/", options)
}

//---- shared setup ------------------------------------------------------------

//wire the real client and real server to each other. `clientAutoReplay: false`
//lets the test drive the handshake manually so it can attach listeners before
//the (possibly rejecting) server INFO exchange runs.
function openPair({ wispVersion = 2, clientAutoReplay = true, motd = null, auth = null, clientOptions = {} } = {}) {
  config.wisp_motd = motd
  config.auth_username = auth ? auth.username : null
  config.auth_password = auth ? auth.password : null

  const clientWs = new VirtualSocket(clientAutoReplay)
  const serverWs = new VirtualSocket()
  clientWs.peer = serverWs
  serverWs.peer = clientWs

  const server = new ServerWispConnection(serverWs, "/", "127.0.0.1", wispVersion)
  const h = { server, clientWs, serverWs, errors: [] }
  serverWs.addEventListener("message", (e) => {
    server.handle_ws_message(e).catch((err) => { h.errors.push(err) })
  })
  serverWs.addEventListener("close", () => server.close_all())
  server.setup()
  h.client = makeClient(clientWs, clientOptions)
  return h
}

test("v2 handshake between the real client and real server negotiates extensions", () => {
  const h = openPair({ wispVersion: 2, motd: "welcome" })

  assert.equal(h.client.connected, true, "client opens after CONTINUE(0)")
  assert.equal(h.client.wisp_version, 2, "v2 stays negotiated")
  assert.equal(h.client.max_buffer_size, 128, "opening CONTINUE carries the server's queue size")
  assert.equal(h.client.server_motd, "welcome", "client reads the server's MOTD extension")
  assert.equal(h.client.udp_enabled, false, "udp is not negotiated (the server does not advertise it)")

  //server-side negotiation: only extensions both sides advertise may be used
  assert.ok(h.server.client_exts[0x04], "client's MOTD extension is negotiated")
  assert.equal(h.server.client_exts[0x01], undefined, "udp (client-only) is not negotiated")
  assert.equal(h.server.client_exts[0x05], undefined, "stream open confirmation (server-only) is not negotiated")
  assert.equal(h.server.handshake_done, true)
  assert.deepEqual(h.errors, [])
})

test("stream data relays in both directions between the real pair", async () => {
  const h = openPair({ wispVersion: 2 })

  const stream = h.client.create_stream("example.com", 80)
  assert.equal(h.client.active_streams[1], stream)
  await settled()
  const tcp = Object.values(h.server.active_streams)[0].conn
  assert.ok(tcp, "server opened a tcp connection")
  assert.equal(tcp.hostname, "example.com")
  assert.equal(tcp.port, 80)

  //client -> server -> tcp socket
  stream.send(encode("ping"))
  await settled()
  assert.ok(tcp.sent.length > 0, "server forwarded client data to the socket")
  assert.equal(decode(tcp.sent[tcp.sent.length - 1]), "ping")

  //tcp socket -> server -> client
  let received = []
  stream.addEventListener("message", (e) => received.push(decode(e.data)))
  tcp._push(encode("pong"))
  await settled()
  assert.deepEqual(received, ["pong"], "socket data reaches the client stream")
  assert.deepEqual(h.errors, [])
})

test("data flows in both directions simultaneously (full duplex)", async () => {
  const h = openPair({ wispVersion: 2 })
  const stream = h.client.create_stream("example.com", 80)
  await settled()
  const tcp = Object.values(h.server.active_streams)[0].conn

  let received = []
  stream.addEventListener("message", (e) => received.push(decode(e.data)))

  //interleave outbound and inbound without settling between each hop
  for (let i = 1; i <= 5; i++) {
    stream.send(encode("c" + i))
    tcp._push(encode("s" + i))
  }
  await settled()

  assert.deepEqual(tcp.sent.map(decode), ["c1", "c2", "c3", "c4", "c5"], "outbound reaches the socket in order")
  assert.deepEqual(received, ["s1", "s2", "s3", "s4", "s5"], "inbound reaches the client in order")
  assert.deepEqual(h.errors, [])
})

test("client-initiated close tears down the stream server-side", async () => {
  const h = openPair({ wispVersion: 2 })
  const stream = h.client.create_stream("example.com", 80)
  await settled()
  assert.ok(h.server.active_streams[1])

  stream.close(0x02)
  await settled()
  assert.equal(h.server.active_streams[1], undefined, "server removed the closed stream")
  assert.equal(stream.open, false)
  assert.deepEqual(h.errors, [])
})

test("correct password authenticates the v2 handshake", () => {
  const h = openPair({
    wispVersion: 2,
    auth: { username: "bob", password: "hunter2" },
    clientOptions: { username: "bob", password: "hunter2" }
  })
  assert.equal(h.client.connected, true, "connection opens after authenticating")
  assert.equal(h.server.handshake_done, true)
  assert.deepEqual(h.errors, [])
})

test("wrong password closes the connection with 0xc0", () => {
  const h = openPair({
    wispVersion: 2,
    clientAutoReplay: false,
    auth: { username: "bob", password: "hunter2" },
    clientOptions: { username: "bob", password: "nope" }
  })
  let closeCode = null
  h.client.addEventListener("close", (e) => { closeCode = e.code })

  h.clientWs.replay() // deliver the server INFO; the client replies and is rejected
  assert.equal(closeCode, 0xc0, "bad credentials yield CLOSE 0xc0")
  assert.equal(h.client.connected, false)
  assert.equal(h.server.handshake_done, false)
  assert.deepEqual(h.errors, [])
})

test("missing credentials close the connection with 0xc2", () => {
  const h = openPair({
    wispVersion: 2,
    clientAutoReplay: false,
    auth: { username: "bob", password: "hunter2" }
  })
  let closeCode = null
  h.client.addEventListener("close", (e) => { closeCode = e.code })

  h.clientWs.replay()
  assert.equal(closeCode, 0xc2, "no credentials yield CLOSE 0xc2")
  assert.equal(h.client.connected, false)
  assert.deepEqual(h.errors, [])
})

test("client falls back to v1 against a v1 server", () => {
  const h = openPair({ wispVersion: 1 })
  assert.equal(h.client.wisp_version, 1, "client downgrades to v1")
  assert.equal(h.client.connected, true, "opening CONTINUE alone is enough for v1")
  assert.equal(h.client.udp_enabled, true, "udp is assumed enabled on v1 connections")
  assert.ok(!h.server.client_exts[0x05])
  assert.deepEqual(h.errors, [])
})

test("stream open confirmation is sent when the client also offers 0x05", async () => {
  const h = openPair({
    wispVersion: 2,
    clientOptions: {
      wisp_extensions: [
        { id: 0x01, payload: new Uint8Array(0) },
        { id: 0x05, payload: new Uint8Array(0) }
      ]
    }
  })
  assert.ok(h.server.client_exts[0x05], "0x05 is negotiated when both sides advertise it")

  h.client.create_stream("example.com", 80)
  await settled()
  const confirmation = h.clientWs.received.map(parsePacket).find((p) => p.type === 0x03 && p.stream_id === 1)
  assert.ok(confirmation, "server sends a per-stream CONTINUE after the socket connects")
  assert.deepEqual(h.errors, [])
})