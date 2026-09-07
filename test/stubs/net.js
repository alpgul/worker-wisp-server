//portable stand-in for src/net.js (cloudflare:sockets is not available in node)
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

export function validate_hostname(host) {
  return host
}