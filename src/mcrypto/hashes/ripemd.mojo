"""RIPEMD-128, RIPEMD-160, RIPEMD-256, and RIPEMD-320 in pure Mojo."""

from std.collections import InlineArray
from std.memory import bitcast


@always_inline("nodebug")
def _rotl(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _f[group: Int](x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    comptime if group == 0:
        return x ^ y ^ z
    elif group == 1:
        return (x & y) | ((~x) & z)
    elif group == 2:
        return (x | (~y)) ^ z
    elif group == 3:
        return (x & z) | (y & (~z))
    else:
        return x ^ (y | (~z))


def _message_order() -> InlineArray[Int, 80]:
    return [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        7,
        4,
        13,
        1,
        10,
        6,
        15,
        3,
        12,
        0,
        9,
        5,
        2,
        14,
        11,
        8,
        3,
        10,
        14,
        4,
        9,
        15,
        8,
        1,
        2,
        7,
        0,
        6,
        13,
        11,
        5,
        12,
        1,
        9,
        11,
        10,
        0,
        8,
        12,
        4,
        13,
        3,
        7,
        15,
        14,
        5,
        6,
        2,
        4,
        0,
        5,
        9,
        7,
        12,
        2,
        10,
        14,
        1,
        3,
        8,
        11,
        6,
        15,
        13,
    ]


def _parallel_order() -> InlineArray[Int, 80]:
    return [
        5,
        14,
        7,
        0,
        9,
        2,
        11,
        4,
        13,
        6,
        15,
        8,
        1,
        10,
        3,
        12,
        6,
        11,
        3,
        7,
        0,
        13,
        5,
        10,
        14,
        15,
        8,
        12,
        4,
        9,
        1,
        2,
        15,
        5,
        1,
        3,
        7,
        14,
        6,
        9,
        11,
        8,
        12,
        2,
        10,
        0,
        4,
        13,
        8,
        6,
        4,
        1,
        3,
        11,
        15,
        0,
        5,
        12,
        2,
        13,
        9,
        7,
        10,
        14,
        12,
        15,
        10,
        4,
        1,
        5,
        8,
        7,
        6,
        2,
        13,
        14,
        0,
        3,
        9,
        11,
    ]


def _rotations() -> InlineArray[Int, 80]:
    return [
        11,
        14,
        15,
        12,
        5,
        8,
        7,
        9,
        11,
        13,
        14,
        15,
        6,
        7,
        9,
        8,
        7,
        6,
        8,
        13,
        11,
        9,
        7,
        15,
        7,
        12,
        15,
        9,
        11,
        7,
        13,
        12,
        11,
        13,
        6,
        7,
        14,
        9,
        13,
        15,
        14,
        8,
        13,
        6,
        5,
        12,
        7,
        5,
        11,
        12,
        14,
        15,
        14,
        15,
        9,
        8,
        9,
        14,
        5,
        6,
        8,
        6,
        5,
        12,
        9,
        15,
        5,
        11,
        6,
        8,
        13,
        12,
        5,
        12,
        13,
        14,
        11,
        8,
        5,
        6,
    ]


def _parallel_rotations() -> InlineArray[Int, 80]:
    return [
        8,
        9,
        9,
        11,
        13,
        15,
        15,
        5,
        7,
        7,
        8,
        11,
        14,
        14,
        12,
        6,
        9,
        13,
        15,
        7,
        12,
        8,
        9,
        11,
        7,
        7,
        12,
        7,
        6,
        15,
        13,
        11,
        9,
        7,
        15,
        11,
        8,
        6,
        6,
        14,
        12,
        13,
        5,
        14,
        13,
        13,
        7,
        5,
        15,
        5,
        8,
        11,
        14,
        14,
        6,
        14,
        6,
        9,
        12,
        9,
        12,
        5,
        15,
        8,
        8,
        5,
        12,
        9,
        12,
        5,
        14,
        6,
        8,
        13,
        6,
        5,
        15,
        13,
        11,
        11,
    ]


def _pad[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var padded = List[UInt8](capacity=len(data) + 72)
    for byte in data:
        padded.append(byte)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    var bit_length = UInt64(len(data)) * 8
    for i in range(8):
        padded.append(UInt8(bit_length >> UInt64(i * 8)))
    return padded^


@always_inline("nodebug")
def _word(data: List[UInt8], offset: Int) -> UInt32:
    return bitcast[DType.uint32, 1](
        Span(data).unsafe_ptr().unsafe_load[width=4](offset)
    )[0]


def _append_words[width: Int](state: InlineArray[UInt32, width]) -> List[UInt8]:
    var output = List[UInt8](length=width * 4, fill=0)
    var state_pointer = Span(state).unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    comptime if width >= 8:
        output_pointer.unsafe_store[width=32](
            0,
            bitcast[DType.uint8, 32](state_pointer.unsafe_load[width=8]()),
        )
    else:
        output_pointer.unsafe_store[width=16](
            0,
            bitcast[DType.uint8, 16](state_pointer.unsafe_load[width=4]()),
        )
    comptime if width == 5:
        output_pointer.unsafe_store[width=4](
            16,
            bitcast[DType.uint8, 4](state_pointer.unsafe_load[width=1](4)),
        )
    elif width == 10:
        output_pointer.unsafe_store[width=8](
            32,
            bitcast[DType.uint8, 8](state_pointer.unsafe_load[width=2](8)),
        )
    return output^


@always_inline("nodebug")
def _round160[
    group: Int
](
    mut registers: InlineArray[UInt32, 5],
    word: UInt32,
    rotation: Int,
    constant: UInt32,
):
    var temporary = (
        _rotl(
            registers[0]
            + _f[group](registers[1], registers[2], registers[3])
            + word
            + constant,
            rotation,
        )
        + registers[4]
    )
    registers[0] = registers[4]
    registers[4] = registers[3]
    registers[3] = _rotl(registers[2], 10)
    registers[2] = registers[1]
    registers[1] = temporary


def ripemd160[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var padded = _pad(data)
    var state: InlineArray[UInt32, 5] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ]
    comptime order = _message_order()
    comptime parallel_order = _parallel_order()
    comptime rotations = _rotations()
    comptime parallel_rotations = _parallel_rotations()
    comptime constants: InlineArray[UInt32, 5] = [
        0,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xA953FD4E,
    ]
    comptime parallel_constants: InlineArray[UInt32, 5] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0x7A6D76E9,
        0,
    ]
    var padded_pointer = Span(padded).unsafe_ptr()
    for offset in range(0, len(padded), 64):
        var words = InlineArray[UInt32, 16](uninitialized=True)
        comptime for i in range(16):
            words[i] = bitcast[DType.uint32, 1](
                padded_pointer.unsafe_load[width=4](offset + i * 4)
            )[0]
        var left = state.copy()
        var right = state.copy()
        comptime for i in range(80):
            comptime group = i // 16
            _round160[group](
                left,
                words[materialize[order[i]]()],
                materialize[rotations[i]](),
                materialize[constants[group]](),
            )
            _round160[4 - group](
                right,
                words[materialize[parallel_order[i]]()],
                materialize[parallel_rotations[i]](),
                materialize[parallel_constants[group]](),
            )
        var temporary = state[1] + left[2] + right[3]
        state[1] = state[2] + left[3] + right[4]
        state[2] = state[3] + left[4] + right[0]
        state[3] = state[4] + left[0] + right[1]
        state[4] = state[0] + left[1] + right[2]
        state[0] = temporary
    return _append_words(state)


@always_inline("nodebug")
def _round128[
    group: Int
](
    mut registers: InlineArray[UInt32, 4],
    word: UInt32,
    rotation: Int,
    constant: UInt32,
):
    var temporary = _rotl(
        registers[0]
        + _f[group](registers[1], registers[2], registers[3])
        + word
        + constant,
        rotation,
    )
    registers[0] = registers[3]
    registers[3] = registers[2]
    registers[2] = registers[1]
    registers[1] = temporary


@always_inline("nodebug")
def _compress128[
    origin: Origin
](mut state: InlineArray[UInt32, 4], block: Span[UInt8, origin], offset: Int,):
    comptime order = _message_order()
    comptime parallel_order = _parallel_order()
    comptime rotations = _rotations()
    comptime parallel_rotations = _parallel_rotations()
    comptime constants: InlineArray[UInt32, 4] = [
        0,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
    ]
    comptime parallel_constants: InlineArray[UInt32, 4] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0,
    ]
    var block_pointer = block.unsafe_ptr()
    var words = InlineArray[UInt32, 16](uninitialized=True)
    comptime for i in range(16):
        words[i] = bitcast[DType.uint32, 1](
            block_pointer.unsafe_load[width=4](offset + i * 4)
        )[0]
    var left = state.copy()
    var right = state.copy()
    comptime for group in range(4):
        comptime for within in range(16):
            comptime i = group * 16 + within
            _round128[group](
                left,
                words[materialize[order[i]]()],
                materialize[rotations[i]](),
                materialize[constants[group]](),
            )
            _round128[3 - group](
                right,
                words[materialize[parallel_order[i]]()],
                materialize[parallel_rotations[i]](),
                materialize[parallel_constants[group]](),
            )
    var temporary = state[1] + left[2] + right[3]
    state[1] = state[2] + left[3] + right[0]
    state[2] = state[3] + left[0] + right[1]
    state[3] = state[0] + left[1] + right[2]
    state[0] = temporary


def ripemd128[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var state: InlineArray[UInt32, 4] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
    ]
    var data_length = len(data)
    var offset = 0
    while offset + 64 <= data_length:
        _compress128(state, data, offset)
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
    _compress128(state, tail_span, 0)
    if final_size == 128:
        _compress128(state, tail_span, 64)
    return _append_words(state)


@always_inline("nodebug")
def _compress256[
    origin: Origin
](mut state: InlineArray[UInt32, 8], block: Span[UInt8, origin], offset: Int,):
    comptime order = _message_order()
    comptime parallel_order = _parallel_order()
    comptime rotations = _rotations()
    comptime parallel_rotations = _parallel_rotations()
    comptime constants: InlineArray[UInt32, 4] = [
        0,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
    ]
    comptime parallel_constants: InlineArray[UInt32, 4] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0,
    ]
    var block_pointer = block.unsafe_ptr()
    var words = InlineArray[UInt32, 16](uninitialized=True)
    comptime for i in range(16):
        words[i] = bitcast[DType.uint32, 1](
            block_pointer.unsafe_load[width=4](offset + i * 4)
        )[0]
    var left: InlineArray[UInt32, 4] = [
        state[0],
        state[1],
        state[2],
        state[3],
    ]
    var right: InlineArray[UInt32, 4] = [
        state[4],
        state[5],
        state[6],
        state[7],
    ]
    comptime for group in range(4):
        comptime for within in range(16):
            comptime i = group * 16 + within
            _round128[group](
                left,
                words[materialize[order[i]]()],
                materialize[rotations[i]](),
                materialize[constants[group]](),
            )
            _round128[3 - group](
                right,
                words[materialize[parallel_order[i]]()],
                materialize[parallel_rotations[i]](),
                materialize[parallel_constants[group]](),
            )
        var temporary = left[group]
        left[group] = right[group]
        right[group] = temporary
    comptime for i in range(4):
        state[i] += left[i]
        state[i + 4] += right[i]


def ripemd256[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var state: InlineArray[UInt32, 8] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0x76543210,
        0xFEDCBA98,
        0x89ABCDEF,
        0x01234567,
    ]
    var data_length = len(data)
    var offset = 0
    while offset + 64 <= data_length:
        _compress256(state, data, offset)
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
    _compress256(state, tail_span, 0)
    if final_size == 128:
        _compress256(state, tail_span, 64)
    return _append_words(state)


def ripemd320[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var padded = _pad(data)
    var state: InlineArray[UInt32, 10] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
        0x76543210,
        0xFEDCBA98,
        0x89ABCDEF,
        0x01234567,
        0x3C2D1E0F,
    ]
    comptime order = _message_order()
    comptime parallel_order = _parallel_order()
    comptime rotations = _rotations()
    comptime parallel_rotations = _parallel_rotations()
    comptime constants: InlineArray[UInt32, 5] = [
        0,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xA953FD4E,
    ]
    comptime parallel_constants: InlineArray[UInt32, 5] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0x7A6D76E9,
        0,
    ]
    comptime swap_indices: InlineArray[Int, 5] = [1, 3, 0, 2, 4]
    var padded_pointer = Span(padded).unsafe_ptr()
    for offset in range(0, len(padded), 64):
        var words = InlineArray[UInt32, 16](uninitialized=True)
        comptime for i in range(16):
            words[i] = bitcast[DType.uint32, 1](
                padded_pointer.unsafe_load[width=4](offset + i * 4)
            )[0]
        var left: InlineArray[UInt32, 5] = [
            state[0],
            state[1],
            state[2],
            state[3],
            state[4],
        ]
        var right: InlineArray[UInt32, 5] = [
            state[5],
            state[6],
            state[7],
            state[8],
            state[9],
        ]
        comptime for group in range(5):
            comptime for within in range(16):
                comptime i = group * 16 + within
                _round160[group](
                    left,
                    words[materialize[order[i]]()],
                    materialize[rotations[i]](),
                    materialize[constants[group]](),
                )
                _round160[4 - group](
                    right,
                    words[materialize[parallel_order[i]]()],
                    materialize[parallel_rotations[i]](),
                    materialize[parallel_constants[group]](),
                )
            var swap_index = materialize[swap_indices[group]]()
            var temporary = left[swap_index]
            left[swap_index] = right[swap_index]
            right[swap_index] = temporary
        comptime for i in range(5):
            state[i] += left[i]
            state[i + 5] += right[i]
    return _append_words(state)
