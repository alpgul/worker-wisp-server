//network layer for the wisp worker.
//
//this replaces wisp-server-python's net.py. cloudflare workers cannot open
//plain tcp/udp sockets, so raw tcp is relayed through the connect() api from
//the "cloudflare:sockets" module. the default connect() (no protocol string)
//performs real outbound TCP from the edge and is available on all plans,
//including the free tier. the "warp" protocol connector is not used here;
//it is only needed for UDP (not supported by this worker).

import { connect } from "cloudflare:sockets"
import { config } from "./config.js"
import { HostBlockedError } from "./util.js"

export function is_ip(addr_str) {
  //cloudflare sockets will do dns for us; only ip strings need validating
  if (addr_str.includes(":")) return true // ipv6
  let parts = addr_str.split(".")
  if (parts.length != 4) return false
  for (let part of parts) {
    if (!/^\d+$/.test(part)) return false
    let n = Number(part)
    if (n < 0 || n > 255) return false
  }
  return true
}

function ip_is_loopback(addr) {
  if (addr === "127.0.0.1" || addr === "::1") return true
  if (addr.startsWith("127.")) return true
  return false
}

function ip_is_private(addr) {
  if (ip_is_loopback(addr)) return true
  //ipv4 private ranges
  let parts = addr.split(".")
  if (parts.length == 4) {
    let a = Number(parts[0]), b = Number(parts[1])
    if (a == 10) return true
    if (a == 172 && b >= 16 && b <= 31) return true
    if (a == 192 && b == 168) return true
    if (a == 169 && b == 254) return true
  }
  //ipv6 link-local / unique-local
  if (addr.startsWith("fe80:") || addr.startsWith("fc") || addr.startsWith("fd")) return true
  return false
}

//validates a destination host against server policy. throws HostBlockedError
//when the destination is blocked; this maps to wisp close reason 0x48.
export function validate_hostname(host, port) {
  //hostname blocklist: exact matches and subdomains ("corp.example.com")
  let host_lower = host.toLowerCase()
  for (let blocked of config.hostname_blocklist) {
    let b = blocked.toLowerCase()
    if (host_lower === b || host_lower.endsWith("." + b)) {
      throw new HostBlockedError(`Connection to ${host} blocked by server policy.`)
    }
  }

  //port blocklist
  if (config.port_blocklist.includes(port)) {
    throw new HostBlockedError(`Connection to port ${port} blocked by server policy.`)
  }

  let addr = host
  if (addr.startsWith("::ffff:")) addr = addr.slice(7)

  //hostnames are resolved by the cloudflare edge when connect() runs, so we
  //can only validate ip literals here. production additionally refuses
  //connections to loopback, private and cloudflare ips regardless of this.
  if (is_ip(host)) {
    if (config.block_loopback && ip_is_loopback(addr)) {
      throw new HostBlockedError("Connection to loopback ip address blocked.")
    }
    if (config.block_private && ip_is_private(addr)) {
      throw new HostBlockedError("Connection to private ip address blocked.")
    }
  }
  return host
}

export class TCPConnection {
  constructor(hostname, port) {
    this.hostname = hostname
    this.port = port
    this.socket = null
    this.reader = null
    this.writer = null
    //note: warp connect() resolves dns on cloudflare's network, so hostnames
    //cannot be pre-resolved here. block_loopback/block_private only apply to
    //ip literals.
    validate_hostname(hostname, port)
  }

  async connect() {
    //default connector = real outbound TCP from the cloudflare edge, no plan
    //restrictions. a socket is returned immediately; connection errors surface
    //on the first read/write instead of being thrown here.
    this.socket = connect({
      hostname: this.hostname,
      port: this.port,
      allowHalfOpen: false
    })
    this.reader = this.socket.readable.getReader()
    this.writer = this.socket.writable.getWriter()
  }

  async recv() {
    let result = await this.reader.read()
    if (result.done) return new Uint8Array(0)
    return result.value
  }

  async send(data) {
    await this.writer.write(data)
  }

  async close() {
    if (this.writer) {
      try { await this.writer.abort("closed") } catch (e) { /* ignore */ }
    }
    if (this.reader) {
      try { await this.reader.cancel() } catch (e) { /* ignore */ }
    }
  }
}