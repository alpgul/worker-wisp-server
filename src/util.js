//wisp packet format definitions
//the wire format is identical to wisp-server-python, so a single byte stream
//can be interpreted the same way by both implementations. all integers are
//little-endian.
//
//packet header: <BI
//  1 byte packet type + 4 byte little-endian stream id
//
//packet 0x01 (CONNECT): payload <BH
//  1 byte stream type (0x01 tcp, 0x02 udp) + 2 byte little-endian port + hostname
//packet 0x02 (DATA):    payload <raw bytes>
//packet 0x03 (CONTINUE): payload <I
//  4 byte little-endian buffer size
//packet 0x04 (CLOSE):   payload <B
//  1 byte reason code
//packet 0x05 (INFO):    payload <BB (wisp v2 handshake)
//  major version + minor version + extension data

export const packet_types = {
  CONNECT: 0x01,
  DATA: 0x02,
  CONTINUE: 0x03,
  CLOSE: 0x04,
  INFO: 0x05
}

//wisp v2 protocol extension ids
export const extension_ids = {
  UDP: 0x01,
  PASSWORD_AUTH: 0x02,
  KEY_AUTH: 0x03,
  MOTD: 0x04,
  STREAM_OPEN_CONFIRMATION: 0x05
}

//wisp close reason codes (the full table from the protocol spec)
export const close_reasons = {
  UNKNOWN: 0x01,
  VOLUNTARY: 0x02,
  NETWORK_ERROR: 0x03,
  INCOMPATIBLE_EXTENSIONS: 0x04,
  INVALID_INFO: 0x41,
  UNREACHABLE_HOST: 0x42,
  NO_RESPONSE: 0x43,
  CONN_REFUSED: 0x44,
  TRANSFER_TIMEOUT: 0x47,
  HOST_BLOCKED: 0x48,
  CONN_THROTTLED: 0x49,
  CLIENT_ERROR: 0x81,
  AUTH_BAD_PASSWORD: 0xc0,
  AUTH_BAD_SIGNATURE: 0xc1,
  AUTH_MISSING_CREDENTIALS: 0xc2
}

export const queue_size = 128

//thrown when a connection is refused by server policy (blocklist / protected
//address / unsupported stream type). maps to close reason 0x48 HOST_BLOCKED.
export class HostBlockedError extends Error {
  constructor(message) {
    super(message)
    this.name = "HostBlockedError"
  }
}

//build a uint8 array of `size` bytes holding `int`, little-endian
export function array_from_uint(int, size) {
  let buffer = new ArrayBuffer(size)
  let view = new DataView(buffer)
  if (size == 1) view.setUint8(0, int, true)
  else if (size == 2) view.setUint16(0, int, true)
  else if (size == 4) view.setUint32(0, int, true)
  else throw "invalid array length"
  return new Uint8Array(buffer)
}

//read a little-endian unsigned integer from a uint8 array view, honoring any
//byteOffset so subarray() slices avoid copying
export function uint_from_array(array) {
  if (array.length == 4) return new DataView(array.buffer, array.byteOffset, 4).getUint32(0, true)
  else if (array.length == 2) return new DataView(array.buffer, array.byteOffset, 2).getUint16(0, true)
  else if (array.length == 1) return new DataView(array.buffer, array.byteOffset, 1).getUint8(0)
  else throw "invalid array length"
}

//concatenate an arbitrary number of uint8 arrays
export function concat_uint8array(...arrays) {
  let total_length = 0
  for (let array of arrays) total_length += array.length
  let new_array = new Uint8Array(total_length)
  let index = 0
  for (let array of arrays) {
    new_array.set(array, index)
    index += array.length
  }
  return new_array
}

//build a full wisp packet from a packet type, stream id and payload
export function create_packet(packet_type, stream_id, payload) {
  let stream_id_array = array_from_uint(stream_id, 4)
  let packet_type_array = array_from_uint(packet_type, 1)
  return concat_uint8array(packet_type_array, stream_id_array, payload)
}

//utf-8 string from bytes
export function bytes_to_str(bytes) {
  return new TextDecoder().decode(bytes)
}

//build a single extension metadata entry: [id u8][payload_len u32 le][payload]
export function make_extension(ext_id, payload) {
  return concat_uint8array(array_from_uint(ext_id, 1), array_from_uint(payload.length, 4), payload)
}

//parse the extension list of an INFO packet payload into [{id, payload}].
//malformed or truncated entries are skipped.
export function parse_extensions(payload_bytes) {
  let extensions = []
  let index = 0
  while (index < payload_bytes.length) {
    if (payload_bytes.length - index < 5) break
    let ext_id = payload_bytes[index]
    let ext_len = uint_from_array(payload_bytes.subarray(index + 1, index + 5))
    let end = index + 5 + ext_len
    if (end > payload_bytes.length) break
    extensions.push({
      id: ext_id,
      payload: payload_bytes.subarray(index + 5, end)
    })
    index = end
  }
  return extensions
}

//serialize a list of {id, payload} extension objects into raw bytes
export function serialize_extensions(extensions) {
  let parts = []
  let total_length = 0
  for (let extension of extensions) {
    let part = make_extension(extension.id, extension.payload)
    parts.push(part)
    total_length += part.length
  }
  return concat_uint8array(...parts)
}

//build a wisp v2 INFO packet for the initial handshake
export function create_info_packet(major_version, minor_version, extensions_bytes) {
  let payload = concat_uint8array(array_from_uint(major_version, 1), array_from_uint(minor_version, 1), extensions_bytes)
  return create_packet(packet_types.INFO, 0, payload)
}

//parse a password auth client payload:
//[username_len u8][username utf-8][password utf-8 (rest of payload)]
export function parse_password_auth(payload) {
  if (payload.length < 2) return null
  let username_len = payload[0]
  if (payload.length < 1 + username_len) return null
  let username = bytes_to_str(payload.subarray(1, 1 + username_len))
  let password = bytes_to_str(payload.subarray(1 + username_len))
  return { username, password }
}