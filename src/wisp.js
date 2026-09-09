//a wisp server connection, implemented as a websocket message handler. this
//is a direct port of wisp-server-python's connection.py to the cloudflare
//workers event model, extended with wisp v2 support (INFO handshake, extension
//negotiation, password auth, MOTD, stream open confirmation) and per-connection
//stream caps. instead of two asyncio infinite loops per stream we use a queue
//pump (ws -> tcp) and a single long-running promise (tcp -> ws), both of which
//are torn down in close_stream().
//
//a socket is wisp v2 when the client's websocket upgrade carried a
//Sec-WebSocket-Protocol header (index.js selects the subprotocol and passes the
//detected version in here); otherwise the legacy v1 flow is used.

import { TCPConnection } from "./net.js"
import {
  packet_types,
  extension_ids,
  close_reasons,
  queue_size,
  array_from_uint,
  uint_from_array,
  create_packet,
  create_info_packet,
  parse_extensions,
  serialize_extensions,
  parse_password_auth,
  bytes_to_str,
  HostBlockedError
} from "./util.js"
import { config } from "./config.js"
import { ratelimit, get_client_attr, inc_client_attr, spend_client_bandwidth } from "./ratelimit.js"
import { metrics } from "./metrics.js"

export class WSProxyConnection {
  constructor(ws, path) {
    this.ws = ws
    this.path = path
    this.conn = null
  }

  //the wsproxy url is /host:port and each websocket relays a single tcp connection
  async setup_connection() {
    let addr_str = this.path.split("/").pop()
    let [host, port] = addr_str.split(":")
    port = Number(port)
    try {
      this.conn = new TCPConnection(host, port)
      await this.conn.connect()
    } catch (e) {
      await this.ws.close()
      throw e
    }
  }

  //tcp -> ws
  async handle_tcp() {
    while (true) {
      let data
      try {
        data = await this.conn.recv()
      } catch (e) {
        break
      }
      if (data.length === 0) break //socket closed
      try {
        await this.ws.send(data)
      } catch (e) {
        break
      }
    }
    try {
      await this.ws.close()
    } catch (e) { /* ignore */ }
  }

  //ws -> tcp
  async handle_ws(ws_message) {
    if (typeof ws_message.data !== "object") return
    let data = new Uint8Array(ws_message.data)
    await this.conn.send(data)
  }
}

export class WispConnection {
  constructor(ws, path, client_ip, wisp_version = 1) {
    this.ws = ws
    this.path = path
    this.client_ip = client_ip
    this.wisp_version = wisp_version
    this.active_streams = {}
    this.server_exts = {}
    this.client_exts = {}
    //v2 requires an INFO exchange before the opening CONTINUE(0); v1 skips it
    this.handshake_done = wisp_version !== 2
  }

  //start the connection: for v1 this just emits the opening CONTINUE. for v2,
  //an INFO packet describing this server is sent and the opening CONTINUE is
  //deferred until the client's INFO packet is received.
  setup() {
    if (this.wisp_version === 2) {
      this.setup_wisp_v2()
    } else {
      this.send_continue_packet(0, queue_size)
    }
  }

  //the extensions this server supports. udp is intentionally absent because
  //workers cannot open udp sockets: a compliant v2 client then knows not to
  //request udp streams.
  build_server_extensions() {
    let extensions = []
    extensions.push({ id: extension_ids.STREAM_OPEN_CONFIRMATION, payload: new Uint8Array(0) })
    if (config.wisp_motd) {
      extensions.push({ id: extension_ids.MOTD, payload: new TextEncoder().encode(String(config.wisp_motd)) })
    }
    if (config.auth_username !== null && config.auth_username !== undefined &&
        config.auth_password !== null && config.auth_password !== undefined) {
      //payload [1] means password auth is required
      extensions.push({ id: extension_ids.PASSWORD_AUTH, payload: array_from_uint(1, 1) })
    }
    return extensions
  }

  setup_wisp_v2() {
    let server_extensions = this.build_server_extensions()
    this.server_exts = {}
    for (let ext of server_extensions) {
      this.server_exts[ext.id] = ext
    }
    let info_packet = create_info_packet(this.wisp_version, 0, serialize_extensions(server_extensions))
    this.ws.send(info_packet)
  }

  async new_stream(stream_id, payload) {
    //stream info validation: [stream_type u8][port u16 le][hostname]
    if (payload.length < 3) {
      await this.send_close_packet(stream_id, close_reasons.INVALID_INFO)
      this.close_stream(stream_id)
      return
    }
    let stream_type = payload[0]
    let destination_port = uint_from_array(payload.subarray(1, 3))
    let hostname = bytes_to_str(payload.subarray(3))

    if (stream_type !== 0x01 && stream_type !== 0x02) {
      await this.send_close_packet(stream_id, close_reasons.INVALID_INFO)
      this.close_stream(stream_id)
      return
    }
    if (!hostname || destination_port < 1 || destination_port > 65535) {
      await this.send_close_packet(stream_id, close_reasons.INVALID_INFO)
      this.close_stream(stream_id)
      return
    }

    //per-connection stream cap (the current stream's entry is already registered)
    if (Object.keys(this.active_streams).length > config.stream_limit_total) {
      await this.send_close_packet(stream_id, close_reasons.CONN_THROTTLED)
      this.close_stream(stream_id)
      return
    }

    //rate limited
    if (ratelimit.enabled) {
      let stream_count = await get_client_attr(this.client_ip, "streams")
      if (stream_count > ratelimit.connections_limit) {
        await this.send_close_packet(stream_id, close_reasons.CONN_THROTTLED)
        this.close_stream(stream_id)
        return
      }
      //per-ip bandwidth budget: once the window's bytes are spent, no further
      //streams may be opened (existing streams are closed on their next data)
      if (ratelimit.bandwidth_limit > 0) {
        let remaining = await get_client_attr(this.client_ip, "bandwidth")
        if (remaining <= 0) {
          await this.send_close_packet(stream_id, close_reasons.CONN_THROTTLED)
          this.close_stream(stream_id)
          return
        }
      }
    }

    //info looks valid - try to open the connection now
    let connection = null
    try {
      if (stream_type === 0x01) {
        connection = new TCPConnection(hostname, destination_port)
      } else {
        //udp is never negotiated (the extension is absent from our INFO
        //packet), but guard against v1 clients or broken v2 clients anyway
        if (config.block_udp) throw new HostBlockedError("UDP streams are not supported by this worker.")
      }
      await connection.connect()
    } catch (e) {
      //policy rejections map to HOST_BLOCKED (0x48); anything else came from
      //the network layer and maps to UNREACHABLE_HOST (0x42)
      let reason = e instanceof HostBlockedError ? close_reasons.HOST_BLOCKED : close_reasons.UNREACHABLE_HOST
      await this.send_close_packet(stream_id, reason)
      this.close_stream(stream_id)
      return
    }

    //the client may have closed the stream while we were connecting
    if (this.active_streams[stream_id].closed) {
      connection.close().catch(() => {})
      return
    }

    //the socket is up: start the tcp -> ws pump and flush any ws data which
    //arrived while connect() was pending (the client may send early data
    //before the connect resolves)
    this.active_streams[stream_id].conn = connection
    this.active_streams[stream_id].tcp_to_ws_task = this.stream_tcp_to_ws(stream_id)
    this.pump_stream(stream_id)
    metrics.inc("streams_opened_total")

    //stream open confirmation: when both sides support the 0x05 extension, a
    //CONTINUE for this stream signals that the underlying socket is connected
    if (this.client_exts[extension_ids.STREAM_OPEN_CONFIRMATION]) {
      let buffer_remaining = queue_size - this.active_streams[stream_id].queue.length
      this.send_continue_packet(stream_id, buffer_remaining)
    }

    await inc_client_attr(this.client_ip, "streams")
  }

  //charge `amount` relayed bytes against the per-ip budget. when the budget is
  //exhausted every active stream for this client is closed with CONN_THROTTLED,
  //and new_stream refuses further CONNECTs until the window rolls over.
  async enforce_bandwidth(amount) {
    if (!ratelimit.enabled || ratelimit.bandwidth_limit <= 0) return
    let remaining = await spend_client_bandwidth(this.client_ip, amount)
    if (remaining !== undefined && remaining <= 0 && Object.keys(this.active_streams).length > 0) {
      await this.close_all_with_reason(close_reasons.CONN_THROTTLED)
    }
  }

  //close every active stream with the given close reason (used to end the
  //connection's streams when a per-ip limit is hit)
  async close_all_with_reason(reason) {
    for (let stream_id of Object.keys(this.active_streams)) {
      await this.send_close_packet(Number(stream_id), reason)
      this.close_stream(Number(stream_id))
    }
  }

  //ws -> tcp. data is queued and drained asynchronously. the queue is capped
  //at queue_size; when it is full, the caller awaits a slot, mirroring the
  //blocking asyncio.Queue.put() in connection.py. workerd delivers ws messages
  //to a handler one at a time and awaits the handler's promise, so this
  //applies backpressure to the whole connection exactly like the python server.
  async queue_ws_data(stream_id, data) {
    let stream = this.active_streams[stream_id]
    if (!stream || stream.closed) return
    metrics.add("bytes_ws_to_tcp_total", data.length)
    metrics.inc("packets_ws_to_tcp_total")
    await this.enforce_bandwidth(data.length)
    if (stream.closed) return //throttled away while spending
    while (stream.queue.length >= queue_size && !stream.closed) {
      await new Promise(resolve => stream.waiters.push(resolve))
    }
    if (stream.closed) return
    stream.last_activity = Date.now()
    stream.queue.push(data)
    this.pump_stream(stream_id)
  }

  pump_stream(stream_id) {
    let stream = this.active_streams[stream_id]
    if (!stream || stream.draining) return
    stream.draining = true
    ;(async () => {
      try {
        while (stream.queue.length > 0 && !stream.closed && stream.conn) {
          let data = stream.queue.shift()
          try {
            await stream.conn.send(data)
          } catch (e) {
            break
          }
          //send a CONTINUE packet periodically
          stream.packets_sent += 1
          if (stream.packets_sent % (queue_size / 4) === 0) {
            let buffer_remaining = queue_size - stream.queue.length
            this.send_continue_packet(stream_id, buffer_remaining)
          }
        }
      } finally {
        stream.draining = false
        //wake up any blocked queue_ws_data calls now that the queue drained
        while (stream.waiters.length > 0) stream.waiters.shift()()
      }
    })()
  }

  //tcp -> ws. data is queued into a bounded per-stream buffer and drained by
  //drain_downstream(). wisp has no server->client flow control, so when the
  //client stops consuming we cannot slow it down with credits; instead the
  //buffer fills and, if it stays full past downstream_stall_timeout, the
  //stream is proactively closed with 0x03. this replaces cloudflare's
  //unexplained platform backstop (a dead connection at ~the ws send buffer).
  async stream_tcp_to_ws(stream_id) {
    let stream = this.active_streams[stream_id]
    if (!stream) return
    while (true) {
      let data
      try {
        data = await stream.conn.recv()
      } catch (e) {
        //socket error
        await this.send_close_packet(stream_id, close_reasons.NETWORK_ERROR)
        this.close_stream(stream_id)
        return
      }

      if (data.length === 0) break //connection closed

      metrics.add("bytes_tcp_to_ws_total", data.length)
      metrics.inc("packets_tcp_to_ws_total")

      await this.enforce_bandwidth(data.length)
      if (stream.closed) return //throttled away while spending

      //stop reading the socket while the downstream queue is full: this both
      //bounds our memory and lets tcp backpressure reach the remote producer
      while (config.downstream_buffer > 0 && stream.out_queue.length >= config.downstream_buffer && !stream.closed) {
        if (!stream.stalled_at) {
          stream.stalled_at = Date.now()
          metrics.inc("downstream_stalls_total")
        }
        let timed_out = await new Promise(resolve => {
          let hold = setTimeout(() => resolve(true), config.downstream_stall_timeout)
          stream.out_waiters.push(() => { clearTimeout(hold); resolve(false) })
        })
        if (timed_out) {
          //the client is not draining; drop the stream instead of buffering forever
          await this.send_close_packet(stream_id, close_reasons.NETWORK_ERROR)
          this.close_stream(stream_id)
          return
        }
        if (stream.closed) return
      }
      if (stream.closed) return

      let data_packet = create_packet(packet_types.DATA, stream_id, data)
      stream.out_queue.push(data_packet)
      stream.last_activity = Date.now()
      metrics.observe_out_queue(stream.out_queue.length)
      this.drain_downstream(stream_id)
    }

    await this.send_close_packet(stream_id, close_reasons.VOLUNTARY)
    this.close_stream(stream_id)
  }

  //drain the bounded tcp->ws buffer. a full buffer marks the stream as
  //stalled; once the queue drops below the cap the stall resets and any
  //blocked tcp reader is woken.
  drain_downstream(stream_id) {
    let stream = this.active_streams[stream_id]
    if (!stream || stream.out_draining) return
    stream.out_draining = true
    ;(async () => {
      try {
        while (stream.out_queue.length > 0 && !stream.closed) {
          let packet = stream.out_queue.shift()
          if (stream.out_queue.length < config.downstream_buffer) stream.stalled_at = null
          try {
            await this.ws.send(packet)
          } catch (e) {
            break //the websocket is dying; stream teardown happens upstream
          }
        }
      } finally {
        stream.out_draining = false
        //wake up any tcp readers blocked on a full buffer now that it drained
        while (stream.out_waiters.length > 0) stream.out_waiters.shift()()
      }
    })()
  }

  send_continue_packet(stream_id, buffer_remaining) {
    let continue_payload = array_from_uint(buffer_remaining, 4)
    let continue_packet = create_packet(packet_types.CONTINUE, stream_id, continue_payload)
    this.ws.send(continue_packet)
  }

  async send_close_packet(stream_id, reason) {
    if (stream_id !== 0 && !(stream_id in this.active_streams)) return
    let close_payload = array_from_uint(reason, 1)
    let close_packet = create_packet(packet_types.CLOSE, stream_id, close_payload)
    metrics.record_close(reason)
    await this.ws.send(close_packet)
  }

  //close the underlying websocket (used after a rejected v2 handshake)
  terminate() {
    try { this.ws.close() } catch (e) { /* ignore */ }
  }

  //reject a v2 handshake that failed password auth. when rate limiting is
  //enabled, consecutive failures from the same ip are counted against the
  //per-window limit and eventually close with 0x49 (throttled).
  async reject_auth(reason) {
    if (ratelimit.enabled) {
      let failures = await inc_client_attr(this.client_ip, "auth_failures")
      if (failures > ratelimit.auth_fail_limit) {
        await this.send_close_packet(0, close_reasons.CONN_THROTTLED)
        this.terminate()
        return
      }
    }
    await this.send_close_packet(0, reason)
    this.terminate()
  }

  //handle the client's INFO packet (v2 handshake). accepted connections get an
  //opening CONTINUE(0); rejected ones get a CLOSE(0) followed by a websocket
  //close. the reason codes are defined in the protocol spec.
  async handle_info(payload) {
    if (payload.length < 2 || payload[0] !== this.wisp_version) {
      await this.send_close_packet(0, close_reasons.INCOMPATIBLE_EXTENSIONS)
      this.terminate()
      return
    }
    let client_extensions = parse_extensions(payload.subarray(2))

    //negotiate: only extensions both sides support may be used
    this.client_exts = {}
    for (let client_ext of client_extensions) {
      if (this.server_exts[client_ext.id]) {
        this.client_exts[client_ext.id] = client_ext
      }
    }

    //password auth is verified here; the credentials arrive embedded in the
    //client's extension list
    if (this.server_exts[extension_ids.PASSWORD_AUTH]) {
      let auth = null
      let client_auth = client_extensions.find(ext => ext.id === extension_ids.PASSWORD_AUTH)
      if (client_auth) {
        auth = parse_password_auth(client_auth.payload)
      }
      if (!auth) {
        await this.reject_auth(close_reasons.AUTH_MISSING_CREDENTIALS)
        return
      }
      if (auth.username !== config.auth_username || auth.password !== config.auth_password) {
        await this.reject_auth(close_reasons.AUTH_BAD_PASSWORD)
        return
      }
    }

    this.handshake_done = true
    this.send_continue_packet(0, queue_size)
  }

  close_stream(stream_id) {
    if (!(stream_id in this.active_streams)) return //stream already closed
    let stream = this.active_streams[stream_id]
    stream.closed = true
    metrics.inc("streams_closed_total")
    //wake up any queue_ws_data calls blocked on a full queue
    while (stream.waiters.length > 0) stream.waiters.shift()()
    //wake up tcp readers blocked on a full downstream buffer
    while (stream.out_waiters.length > 0) stream.out_waiters.shift()()
    stream.stalled_at = null
    if (stream.conn) {
      stream.conn.close().catch(() => {})
    }
    delete this.active_streams[stream_id]
  }

  //handle a single websocket message
  async handle_ws_message(ws_message) {
    if (ws_message.type !== "message") return
    if (typeof ws_message.data !== "object") return //ignore non-binary frames

    let data = new Uint8Array(ws_message.data)
    if (data.length < 5) return //packet too short

    //get basic packet info
    let payload = data.subarray(5)
    let packet_type = data[0]
    let stream_id = uint_from_array(data.subarray(1, 5))

    //packets on stream 0 are part of the v2 handshake
    if (stream_id === 0) {
      if (this.wisp_version === 2 && !this.handshake_done) {
        if (packet_type === packet_types.INFO) {
          await this.handle_info(payload)
        }
        //everything else is dropped until the handshake completes
      }
      return
    }

    if (packet_type == packet_types.CONNECT) {
      //create the stream entry before the async connect so DATA packets
      //arriving immediately don't get dropped
      this.active_streams[stream_id] = {
        conn: null,
        queue: [],
        waiters: [],
        packets_sent: 0,
        draining: false,
        closed: false,
        tcp_to_ws_task: null,
        //bounded tcp->ws downstream buffer (see drain_downstream)
        out_queue: [],
        out_waiters: [],
        out_draining: false,
        stalled_at: null,
        //last wisp-level activity (inbound/outbound DATA or a close), used by
        //_sweep_idle_streams to reclaim silent streams with TRANSFER_TIMEOUT
        last_activity: Date.now()
      }
      await this.new_stream(stream_id, payload)
    } else if (packet_type == packet_types.DATA) {
      await this.queue_ws_data(stream_id, payload)
    } else if (packet_type == packet_types.CLOSE) {
      let stream = this.active_streams[stream_id]
      if (stream) stream.last_activity = Date.now()
      this.close_stream(stream_id)
    }

    //lazy idle sweep: reclaim streams whose wisp-level activity stopped long
    //ago. runs on inbound packets, so it costs nothing when a connection is
    //active; fully silent sockets are reclaimed by the per-socket idleTimeout.
    if (config.stream_idle_timeout > 0) this._sweep_idle_streams()
  }

  //close streams with no wisp-level activity past config.stream_idle_timeout.
  //TRANSFER_TIMEOUT tells the client the peer went quiet rather than letting
  //the stream sit open forever on an unrelated-but-busy connection.
  _sweep_idle_streams() {
    let now = Date.now()
    for (let stream_id of Object.keys(this.active_streams)) {
      let stream = this.active_streams[stream_id]
      if (stream.closed || now - stream.last_activity <= config.stream_idle_timeout) continue
      this.send_close_packet(Number(stream_id), close_reasons.TRANSFER_TIMEOUT).catch(() => {})
      this.close_stream(Number(stream_id))
    }
  }

  //close all active streams when the websocket disconnects
  close_all() {
    for (let stream_id of Object.keys(this.active_streams)) {
      this.close_stream(Number(stream_id))
    }
  }
}