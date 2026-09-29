"""SM3 hash in pure Mojo."""

from std.collections import InlineArray
from std.memory import bitcast
from std.sys.intrinsics import llvm_intrinsic


@always_inline("nodebug")
def _rotl(value: UInt32, amount: Int) -> UInt32:
    var shift = amount % 32
    if shift == 0:
        return value
    return (value << UInt32(shift)) | (value >> UInt32(32 - shift))


@always_inline("nodebug")
def _p0(value: UInt32) -> UInt32:
    return value ^ _rotl(value, 9) ^ _rotl(value, 17)


@always_inline("nodebug")
def _p1(value: UInt32) -> UInt32:
    return value ^ _rotl(value, 15) ^ _rotl(value, 23)


@always_inline("nodebug")
def _compress[
    origin: Origin
](mut state: InlineArray[UInt32, 8], block: Span[UInt8, origin], offset: Int,):
    var words = InlineArray[UInt32, 68](uninitialized=True)
    var block_pointer = block.unsafe_ptr()
    comptime for i in range(16):
        words[i] = llvm_intrinsic[
            "llvm.bswap.i32", UInt32, has_side_effect=False
        ](
            bitcast[DType.uint32, 1](
                block_pointer.unsafe_load[width=4](offset + i * 4)
            )[0]
        )
    comptime for i in range(16, 68):
        words[i] = (
            _p1(words[i - 16] ^ words[i - 9] ^ _rotl(words[i - 3], 15))
            ^ _rotl(words[i - 13], 7)
            ^ words[i - 6]
        )
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    comptime for round in range(64):
        comptime tj = UInt32(0x79CC4519 if round < 16 else 0x7A879D8A)
        var ss1 = _rotl(_rotl(a, 12) + e + _rotl(tj, round), 7)
        var ss2 = ss1 ^ _rotl(a, 12)
        var ff: UInt32
        var gg: UInt32
        comptime if round < 16:
            ff = a ^ b ^ c
            gg = e ^ f ^ g
        else:
            ff = (a & b) | (c & (a | b))
            gg = g ^ (e & (f ^ g))
        var tt1 = ff + d + ss2 + (words[round] ^ words[round + 4])
        var tt2 = gg + h + ss1 + words[round]
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _p0(tt2)
    state[0] ^= a
    state[1] ^= b
    state[2] ^= c
    state[3] ^= d
    state[4] ^= e
    state[5] ^= f
    state[6] ^= g
    state[7] ^= h


def sm3[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var state: InlineArray[UInt32, 8] = [
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E,
    ]
    var data_length = len(data)
    var offset = 0
    while offset + 64 <= data_length:
        _compress(state, data, offset)
        offset += 64

    var tail = InlineArray[UInt8, 128](fill=0)
    var remainder = data_length - offset
    for i in range(remainder):
        tail[i] = data[offset + i]
    tail[remainder] = 0x80
    var tail_length = 64
    if remainder >= 56:
        tail_length = 128
    var bit_length = UInt64(data_length) * 8
    for i in range(8):
        tail[tail_length - 8 + i] = UInt8(bit_length >> UInt64(56 - i * 8))
    _compress(state, Span(tail), 0)
    if tail_length == 128:
        _compress(state, Span(tail), 64)

    var output = List[UInt8](capacity=32)
    for word in state:
        output.append(UInt8(word >> 24))
        output.append(UInt8(word >> 16))
        output.append(UInt8(word >> 8))
        output.append(UInt8(word))
    return output^
