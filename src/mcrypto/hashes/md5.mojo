"""MD5 in pure Mojo for legacy compatibility only."""

from std.collections import InlineArray
from std.memory import bitcast


@always_inline("nodebug")
def _rotl(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


def _constants() -> InlineArray[UInt32, 64]:
    return [
        0xD76AA478,
        0xE8C7B756,
        0x242070DB,
        0xC1BDCEEE,
        0xF57C0FAF,
        0x4787C62A,
        0xA8304613,
        0xFD469501,
        0x698098D8,
        0x8B44F7AF,
        0xFFFF5BB1,
        0x895CD7BE,
        0x6B901122,
        0xFD987193,
        0xA679438E,
        0x49B40821,
        0xF61E2562,
        0xC040B340,
        0x265E5A51,
        0xE9B6C7AA,
        0xD62F105D,
        0x02441453,
        0xD8A1E681,
        0xE7D3FBC8,
        0x21E1CDE6,
        0xC33707D6,
        0xF4D50D87,
        0x455A14ED,
        0xA9E3E905,
        0xFCEFA3F8,
        0x676F02D9,
        0x8D2A4C8A,
        0xFFFA3942,
        0x8771F681,
        0x6D9D6122,
        0xFDE5380C,
        0xA4BEEA44,
        0x4BDECFA9,
        0xF6BB4B60,
        0xBEBFBC70,
        0x289B7EC6,
        0xEAA127FA,
        0xD4EF3085,
        0x04881D05,
        0xD9D4D039,
        0xE6DB99E5,
        0x1FA27CF8,
        0xC4AC5665,
        0xF4292244,
        0x432AFF97,
        0xAB9423A7,
        0xFC93A039,
        0x655B59C3,
        0x8F0CCC92,
        0xFFEFF47D,
        0x85845DD1,
        0x6FA87E4F,
        0xFE2CE6E0,
        0xA3014314,
        0x4E0811A1,
        0xF7537E82,
        0xBD3AF235,
        0x2AD7D2BB,
        0xEB86D391,
    ]


def _shifts() -> InlineArray[Int, 64]:
    return [
        7,
        12,
        17,
        22,
        7,
        12,
        17,
        22,
        7,
        12,
        17,
        22,
        7,
        12,
        17,
        22,
        5,
        9,
        14,
        20,
        5,
        9,
        14,
        20,
        5,
        9,
        14,
        20,
        5,
        9,
        14,
        20,
        4,
        11,
        16,
        23,
        4,
        11,
        16,
        23,
        4,
        11,
        16,
        23,
        4,
        11,
        16,
        23,
        6,
        10,
        15,
        21,
        6,
        10,
        15,
        21,
        6,
        10,
        15,
        21,
        6,
        10,
        15,
        21,
    ]


@always_inline("nodebug")
def _compress_md5[
    origin: Origin
](mut h: InlineArray[UInt32, 4], block: Span[UInt8, origin], offset: Int,):
    comptime constants = _constants()
    comptime shifts = _shifts()
    var words = InlineArray[UInt32, 16](uninitialized=True)
    var block_pointer = block.unsafe_ptr()
    comptime for i in range(16):
        words[i] = bitcast[DType.uint32, 1](
            block_pointer.unsafe_load[width=4](offset + i * 4)
        )[0]
    var a = h[0]
    var b = h[1]
    var c = h[2]
    var d = h[3]
    comptime for i in range(64):
        var f: UInt32
        comptime g = (
            i if i
            < 16 else (5 * i + 1) % 16 if i
            < 32 else (3 * i + 5) % 16 if i
            < 48 else (7 * i) % 16
        )
        comptime if i < 16:
            f = (b & c) | ((~b) & d)
        elif i < 32:
            f = (d & b) | ((~d) & c)
        elif i < 48:
            f = b ^ c ^ d
        else:
            f = c ^ (b | (~d))
        var next = d
        d = c
        c = b
        b += _rotl(
            a + f + materialize[constants[i]]() + words[g],
            materialize[shifts[i]](),
        )
        a = next
    h[0] += a
    h[1] += b
    h[2] += c
    h[3] += d


def md5[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var h: InlineArray[UInt32, 4] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
    ]
    var data_length = len(data)
    var offset = 0
    while offset + 64 <= data_length:
        _compress_md5(h, data, offset)
        offset += 64
    var remaining = data_length - offset
    var tail = InlineArray[UInt8, 128](fill=0)
    for i in range(remaining):
        tail[i] = data[offset + i]
    tail[remaining] = 0x80
    var final_size = 64 if remaining < 56 else 128
    var bit_length = UInt64(data_length) * 8
    for i in range(8):
        tail[final_size - 8 + i] = UInt8(bit_length >> UInt64(i * 8))
    var tail_span = Span(tail)
    _compress_md5(h, tail_span, 0)
    if final_size == 128:
        _compress_md5(h, tail_span, 64)
    var output = List[UInt8](length=16, fill=0)
    Span(output).unsafe_ptr().unsafe_store[width=16](
        0,
        bitcast[DType.uint8, 16](Span(h).unsafe_ptr().unsafe_load[width=4]()),
    )
    return output^
