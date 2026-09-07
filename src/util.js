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

export const packet_types = {
  CONNECT: 0x01,
  DATA: 0x02,
  CONTINUE: 0x03,
  CLOSE: 0x04
}

export const queue_size = 128

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

//read a little-endian unsigned integer from a uint8 array
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

//bytes from a utf-8 string
export function str_to_bytes(str) {
  return new TextEncoder().encode(str)
}

//utf-8 string from bytes
export function bytes_to_str(bytes) {
  return new TextDecoder().decode(bytes)
}
