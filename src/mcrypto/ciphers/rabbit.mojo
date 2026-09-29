"""Rabbit stream cipher with optional 64-bit IV."""
from std.memory import bitcast


from ..internal.bytes import load_le32


@always_inline("nodebug")
def _rol(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


@always_inline("nodebug")
def _g(x: UInt32) -> UInt32:
    var z = UInt64(x) * UInt64(x)
    return UInt32(z) ^ UInt32(z >> 32)


@always_inline("nodebug")
def _next(
    mut c: InlineArray[UInt32, 8],
    mut x: InlineArray[UInt32, 8],
    carry: UInt32,
) -> UInt32:
    var old = c[0]
    c[0] += 0x4D34D34D + carry
    var next_carry = UInt32(c[0] < old)
    old = c[1]
    c[1] += 0xD34D34D3 + next_carry
    next_carry = UInt32(c[1] < old)
    old = c[2]
    c[2] += 0x34D34D34 + next_carry
    next_carry = UInt32(c[2] < old)
    old = c[3]
    c[3] += 0x4D34D34D + next_carry
    next_carry = UInt32(c[3] < old)
    old = c[4]
    c[4] += 0xD34D34D3 + next_carry
    next_carry = UInt32(c[4] < old)
    old = c[5]
    c[5] += 0x34D34D34 + next_carry
    next_carry = UInt32(c[5] < old)
    old = c[6]
    c[6] += 0x4D34D34D + next_carry
    next_carry = UInt32(c[6] < old)
    old = c[7]
    c[7] += 0xD34D34D3 + next_carry
    next_carry = UInt32(c[7] < old)
    var g = InlineArray[UInt32, 8](fill=0)
    comptime for i in range(8):
        g[i] = _g(x[i] + c[i])
    x[0] = g[0] + _rol(g[7], 16) + _rol(g[6], 16)
    x[1] = g[1] + _rol(g[0], 8) + g[7]
    x[2] = g[2] + _rol(g[1], 16) + _rol(g[0], 16)
    x[3] = g[3] + _rol(g[2], 8) + g[1]
    x[4] = g[4] + _rol(g[3], 16) + _rol(g[2], 16)
    x[5] = g[5] + _rol(g[4], 8) + g[3]
    x[6] = g[6] + _rol(g[5], 16) + _rol(g[4], 16)
    x[7] = g[7] + _rol(g[6], 8) + g[5]
    return next_carry


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 16 or (len(nonce) != 0 and len(nonce) != 8):
        raise Error("Rabbit requires 16-byte key and zero- or 8-byte IV")
    var t: InlineArray[UInt32, 4] = [
        load_le32(key, 0),
        load_le32(key, 4),
        load_le32(key, 8),
        load_le32(key, 12),
    ]
    var x: InlineArray[UInt32, 8] = [
        t[0],
        (t[3] << 16) | (t[2] >> 16),
        t[1],
        (t[0] << 16) | (t[3] >> 16),
        t[2],
        (t[1] << 16) | (t[0] >> 16),
        t[3],
        (t[2] << 16) | (t[1] >> 16),
    ]
    var c: InlineArray[UInt32, 8] = [
        _rol(t[2], 16),
        (t[0] & 0xFFFF0000) | (t[1] & 0xFFFF),
        _rol(t[3], 16),
        (t[1] & 0xFFFF0000) | (t[2] & 0xFFFF),
        _rol(t[0], 16),
        (t[2] & 0xFFFF0000) | (t[3] & 0xFFFF),
        _rol(t[1], 16),
        (t[3] & 0xFFFF0000) | (t[0] & 0xFFFF),
    ]
    var carry = UInt32(0)
    for _ in range(4):
        carry = _next(c, x, carry)
    comptime for i in range(8):
        c[i] ^= x[(i + 4) & 7]
    if len(nonce) == 8:
        var v0 = load_le32(nonce, 0)
        var v2 = load_le32(nonce, 4)
        var v1 = (v0 >> 16) | (v2 & 0xFFFF0000)
        var v3 = (v2 << 16) | (v0 & 0xFFFF)
        c[0] ^= v0
        c[1] ^= v1
        c[2] ^= v2
        c[3] ^= v3
        c[4] ^= v0
        c[5] ^= v1
        c[6] ^= v2
        c[7] ^= v3
        for _ in range(4):
            carry = _next(c, x, carry)
    var output = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    for offset in range(0, len(input), 16):
        carry = _next(c, x, carry)
        var words = SIMD[DType.uint32, 4](
            x[0] ^ (x[5] >> 16) ^ (x[3] << 16),
            x[2] ^ (x[7] >> 16) ^ (x[5] << 16),
            x[4] ^ (x[1] >> 16) ^ (x[7] << 16),
            x[6] ^ (x[3] >> 16) ^ (x[1] << 16),
        )
        if offset + 16 <= len(input):
            output_pointer.unsafe_store[width=16](
                offset,
                input_pointer.unsafe_load[width=16](offset)
                ^ bitcast[DType.uint8, 16](words),
            )
        else:
            for i in range(len(input) - offset):
                output_pointer.unsafe_store(
                    offset + i,
                    input_pointer.unsafe_load(offset + i)
                    ^ UInt8(words[i // 4] >> UInt32(8 * (i & 3))),
                )
    return output^
