"""Legacy ARC4 and WAKE-OFB stream ciphers in pure Mojo."""
from std.memory import bitcast


from ..internal.bytes import load_be32


comptime _WAKE_TT: InlineArray[UInt32, 8] = [
    0x726A8F3B,
    0xE69A3B5C,
    0xD3C71FE5,
    0xAB3C73D2,
    0x4D3A8EB3,
    0x0396D6E8,
    0x3D4C2F7A,
    0x9EE27CF3,
]


def arc4[
    key_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
    discard_bytes: Int = 0,
) raises -> List[UInt8]:
    if len(key) < 1 or len(key) > 256 or discard_bytes < 0:
        raise Error("invalid ARC4 parameters")
    var state = InlineArray[UInt8, 256](uninitialized=True)
    var state_pointer = Span(state).unsafe_ptr()
    for i in range(256):
        state_pointer.unsafe_store(i, UInt8(i))
    var index = 0
    if len(key) == 16:
        for i in range(256):
            index = (
                index + Int(state_pointer.unsafe_load(i)) + Int(key[i & 15])
            ) & 255
            var swap = state_pointer.unsafe_load(i)
            state_pointer.unsafe_store(i, state_pointer.unsafe_load(index))
            state_pointer.unsafe_store(index, swap)
    else:
        for i in range(256):
            index = (
                index
                + Int(state_pointer.unsafe_load(i))
                + Int(key[i % len(key)])
            ) & 255
            var swap = state_pointer.unsafe_load(i)
            state_pointer.unsafe_store(i, state_pointer.unsafe_load(index))
            state_pointer.unsafe_store(index, swap)
    var x = 1
    var y = 0
    for _ in range(discard_bytes):
        var a = state_pointer.unsafe_load(x)
        y = (y + Int(a)) & 255
        var b = state_pointer.unsafe_load(y)
        state_pointer.unsafe_store(x, b)
        state_pointer.unsafe_store(y, a)
        x = (x + 1) & 255
    var output = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    for position in range(len(input)):
        var a = state_pointer.unsafe_load(x)
        y = (y + Int(a)) & 255
        var b = state_pointer.unsafe_load(y)
        state_pointer.unsafe_store(x, b)
        state_pointer.unsafe_store(y, a)
        x = (x + 1) & 255
        output_pointer.unsafe_store(
            position,
            input_pointer.unsafe_load(position)
            ^ state_pointer.unsafe_load((Int(a) + Int(b)) & 255),
        )
    return output^


@always_inline("nodebug")
def _wake_m(x: UInt32, y: UInt32, table: InlineArray[UInt32, 257]) -> UInt32:
    var value = x + y
    return (value >> 8) ^ table[Int(value & 255)]


@always_inline("nodebug")
def _wake_stream_bytes(
    words: SIMD[DType.uint32, 4], little_endian: Bool
) -> SIMD[DType.uint8, 16]:
    var stream_words = words
    if not little_endian:
        stream_words = (
            ((stream_words & 0x000000FF) << 24)
            | ((stream_words & 0x0000FF00) << 8)
            | ((stream_words & 0x00FF0000) >> 8)
            | ((stream_words & 0xFF000000) >> 24)
        )
    return bitcast[DType.uint8, 16](stream_words)


def wake[
    key_origin: Origin, input_origin: Origin
](
    little_endian: Bool,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 32:
        raise Error("WAKE-OFB key must be 32 bytes")
    var r3 = load_be32(key, 0)
    var r4 = load_be32(key, 4)
    var r5 = load_be32(key, 8)
    var r6 = load_be32(key, 12)
    var table = InlineArray[UInt32, 257](uninitialized=True)
    var constants = materialize[_WAKE_TT]()
    table[0] = load_be32(key, 16)
    table[1] = load_be32(key, 20)
    table[2] = load_be32(key, 24)
    table[3] = load_be32(key, 28)
    for p in range(4, 256):
        var unsigned_value = table[p - 4] + table[p - 1]
        var signed_value = bitcast[DType.int32, 1](
            SIMD[DType.uint32, 1](unsigned_value)
        )[0]
        table[p] = (
            UInt32(signed_value >> 3) ^ constants[Int(unsigned_value & 7)]
        )
    for p in range(23):
        table[p] += table[p + 89]
    var x = table[33]
    var z = (table[59] | 0x01000001) & 0xFF7FFFFF
    for p in range(256):
        x = (x & 0xFF7FFFFF) + z
        table[p] = (table[p] & 0x00FFFFFF) ^ x
    table[256] = table[0]
    var y = UInt8(x)
    for p in range(256):
        y = UInt8(table[p ^ Int(y)] ^ UInt32(y))
        table[p] = table[Int(y)]
        table[Int(y)] = table[p + 1]
    var output = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    var offset = 0
    while offset + 16 <= len(input):
        var words = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            words[lane] = r6
            r3 = _wake_m(r3, r6, table)
            r4 = _wake_m(r4, r3, table)
            r5 = _wake_m(r5, r4, table)
            r6 = _wake_m(r6, r5, table)
        output_pointer.unsafe_store[width=16](
            offset,
            input_pointer.unsafe_load[width=16](offset)
            ^ _wake_stream_bytes(words, little_endian),
        )
        offset += 16
    while offset < len(input):
        var count = min(4, len(input) - offset)
        for i in range(count):
            var shift = 8 * i if little_endian else 24 - 8 * i
            output_pointer.unsafe_store(
                offset + i,
                input_pointer.unsafe_load(offset + i)
                ^ UInt8(r6 >> UInt32(shift)),
            )
        r3 = _wake_m(r3, r6, table)
        r4 = _wake_m(r4, r3, table)
        r5 = _wake_m(r5, r4, table)
        r6 = _wake_m(r6, r5, table)
        offset += 4
    return output^
