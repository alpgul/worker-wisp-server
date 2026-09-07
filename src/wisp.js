//a wisp v1 server connection, implemented as a websocket message handler.
//this is a direct port of wisp-server-python's connection.py to the
//cloudflare workers event model. instead of two asyncio infinite loops per
//stream we use a queue pump (ws -> tcp) and a single long-running promise
//(tcp -> ws), both of which are torn down in close_stream().

import { TCPConnection } from "./net.js"
import {
  packet_types,
  queue_size,
  array_from_uint,
  uint_from_array,
  create_packet,
  bytes_to_str
} from "./util.js"
import { config } from "./config.js"
import * as ratelimit from "./ratelimit.js"

//wisp close reason codes
const REASON_NORMAL = 0x02
const REASON_SOCKET_ERROR = 0x03
const REASON_CONNECT_FAILED = 0x42
const REASON_LIMITED = 0x49

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
  constructor(ws, path, client_ip) {
    this.ws = ws
    this.path = path
    this.client_ip = client_ip
    this.active_streams = {}
  }

  //send the initial CONTINUE packet
  setup() {
    let continue_payload = array_from_uint(queue_size, 4)
    let continue_packet = create_packet(packet_types.CONTINUE, 0, continue_payload)
    this.ws.send(continue_packet)
  }

  async new_stream(stream_id, payload) {
    let stream_type = payload[0]
    let destination_port = uint_from_array(payload.slice(1, 3))
    let hostname = bytes_to_str(payload.slice(3))

    //rate limited
    if (ratelimit.enabled) {
      let stream_count = ratelimit.get_client_attr(this.client_ip, "streams")
      if (stream_count > ratelimit.connections_limit) {
        await this.send_close_packet(stream_id, REASON_LIMITED)
        this.close_stream(stream_id)
        return
      }
    }

    //info looks valid - try to open the connection now
    let connection = null
    try {
      if (stream_type == 0x01) {
        connection = new TCPConnection(hostname, destination_port)
      } else if (stream_type == 0x02) {
        if (config.block_udp) throw new TypeError("UDP streams are not supported by this worker.")
      } else {
        throw new TypeError("Invalid stream type.")
      }
      this.active_streams[stream_id].conn = connection
      await connection.connect()
    } catch (e) {
      await this.send_close_packet(stream_id, REASON_CONNECT_FAILED)
      this.close_stream(stream_id)
      return
    }

    //the client may have closed the stream while we were connecting
    if (!this.active_streams[stream_id].closed) {
      this.active_streams[stream_id].tcp_to_ws_task = this.stream_tcp_to_ws(stream_id)
    } else {
      connection.close().catch(() => {})
      return
    }

    ratelimit.inc_client_attr(this.client_ip, "streams")
  }

  //ws -> tcp. data is queued and drained asynchronously. the queue is capped
  //at queue_size; when it is full, the caller awaits a slot, mirroring the
  //blocking asyncio.Queue.put() in connection.py. workerd delivers ws messages
  //to a handler one at a time and awaits the handler's promise, so this
  //applies backpressure to the whole connection exactly like the python server.
  async queue_ws_data(stream_id, data) {
    let stream = this.active_streams[stream_id]
    if (!stream || stream.closed) return
    while (stream.queue.length >= queue_size && !stream.closed) {
      await new Promise(resolve => stream.waiters.push(resolve))
    }
    if (stream.closed) return
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
            let continue_payload = array_from_uint(buffer_remaining, 4)
            let continue_packet = create_packet(packet_types.CONTINUE, stream_id, continue_payload)
            await this.ws.send(continue_packet)
          }
        }
      } finally {
        stream.draining = false
        //wake up any blocked queue_ws_data calls now that the queue drained
        while (stream.waiters.length > 0) stream.waiters.shift()()
      }
    })()
  }

  //tcp -> ws
  async stream_tcp_to_ws(stream_id) {
    let stream = this.active_streams[stream_id]
    if (!stream) return
    while (true) {
      let data
      try {
        data = await stream.conn.recv()
      } catch (e) {
        //socket error
        await this.send_close_packet(stream_id, REASON_SOCKET_ERROR)
        this.close_stream(stream_id)
        return
      }

      if (data.length === 0) break //connection closed

      let data_packet = create_packet(packet_types.DATA, stream_id, data)
      try {
        await this.ws.send(data_packet)
      } catch (e) {
        break
      }
    }

    await this.send_close_packet(stream_id, REASON_NORMAL)
    this.close_stream(stream_id)
  }

  async send_close_packet(stream_id, reason) {
    if (!(stream_id in this.active_streams)) return
    let close_payload = array_from_uint(reason, 1)
    let close_packet = create_packet(packet_types.CLOSE, stream_id, close_payload)
    await this.ws.send(close_packet)
  }

  close_stream(stream_id) {
    if (!(stream_id in this.active_streams)) return //stream already closed
    let stream = this.active_streams[stream_id]
    stream.closed = true
    //wake up any queue_ws_data calls blocked on a full queue
    while (stream.waiters.length > 0) stream.waiters.shift()()
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
    let payload = data.slice(5)
    let packet_type = data[0]
    let stream_id = uint_from_array(data.slice(1, 5))

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
        tcp_to_ws_task: null
      }
      this.new_stream(stream_id, payload)
    } else if (packet_type == packet_types.DATA) {
      await this.queue_ws_data(stream_id, payload)
    } else if (packet_type == packet_types.CLOSE) {
      this.close_stream(stream_id)
    }
  }

  //close all active streams when the websocket disconnects
  close_all() {
    for (let stream_id of Object.keys(this.active_streams)) {
      this.close_stream(Number(stream_id))
    }
  }
}