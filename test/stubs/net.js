//portable stand-in for src/net.js (cloudflare:sockets is not available in node)
//the HostBlockedError/blocklist logic mirrors src/net.js so that tests of the
//protocol core can exercise the real close-reason mapping.

import { HostBlockedError } from "../../src/util.js"
import { config } from "./config.js"

function ip_is_loopback(addr) {
  if (addr === "127.0.0.1" || addr === "::1") return true
  if (addr.startsWith("127.")) return true
  return false
}

function ip_is_private(addr) {
  if (ip_is_loopback(addr)) return true
  let parts = addr.split(".")
  if (parts.length == 4) {
    let a = Number(parts[0]), b = Number(parts[1])
    if (a == 10) return true
    if (a == 172 && b >= 16 && b <= 31) return true
    if (a == 192 && b == 168) return true
    if (a == 169 && b == 254) return true
  }
  if (addr.startsWith("fe80:") || addr.startsWith("fc") || addr.startsWith("fd")) return true
  return false
}

export function is_ip(addr_str) {
  if (addr_str.includes(":")) return true
  let parts = addr_str.split(".")
  if (parts.length != 4) return false
  for (let part of parts) {
    if (!/^\d+$/.test(part)) return false
    let n = Number(part)
    if (n < 0 || n > 255) return false
  }
  return true
}

export function validate_hostname(host, port) {
  let host_lower = host.toLowerCase()
  for (let blocked of config.hostname_blocklist) {
    let b = blocked.toLowerCase()
    if (host_lower === b || host_lower.endsWith("." + b)) {
      throw new HostBlockedError(`Connection to ${host} blocked by server policy.`)
    }
  }
  if (config.hostname_allowlist.length > 0) {
    let allowed = false
    for (let allowed_host of config.hostname_allowlist) {
      let a = allowed_host.toLowerCase()
      if (host_lower === a || host_lower.endsWith("." + a)) {
        allowed = true
        break
      }
    }
    if (!allowed) {
      throw new HostBlockedError(`Connection to ${host} refused: destination not in allowlist.`)
    }
  }
  if (config.port_blocklist.includes(port)) {
    throw new HostBlockedError(`Connection to port ${port} blocked by server policy.`)
  }
  if (is_ip(host)) {
    if (config.block_loopback && ip_is_loopback(host)) {
      throw new HostBlockedError("Connection to loopback ip address blocked.")
    }
    if (config.block_private && ip_is_private(host)) {
      throw new HostBlockedError("Connection to private ip address blocked.")
    }
  }
  return host
}

export class TCPConnection {
  constructor(hostname, port) {
    this.hostname = hostname
    this.port = port
    this.sent = []
    this.recv_queue = []
    this.closed = false
    this.err = null
    this._waiters = []
    this._sendDelay = 0
    validate_hostname(hostname, port)
  }

  async connect() {}

  //simulate bytes arriving from the remote end
  _push(data) {
    if (this._waiters.length > 0) this._waiters.shift().resolve(data)
    else this.recv_queue.push(data)
  }

  //simulate a clean EOF from the remote end
  eof() {
    this._push(new Uint8Array(0))
  }

  //simulate a socket error; interrupts any pending recv
  fail(err) {
    this.err = err
    while (this._waiters.length > 0) this._waiters.shift().reject(err)
  }

  async recv() {
    if (this.err) throw this.err
    if (this.recv_queue.length > 0) return this.recv_queue.shift()
    return await new Promise((resolve, reject) => this._waiters.push({ resolve, reject }))
  }

  async send(data) {
    if (this.err) throw this.err
    //optional artificial slowness to exercise backpressure in tests
    if (this._sendDelay) await new Promise(r => setTimeout(r, this._sendDelay))
    this.sent.push(data)
  }

  async close() {
    this.closed = true
    while (this._waiters.length > 0) this._waiters.shift().resolve(new Uint8Array(0))
  }
}