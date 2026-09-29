"""BLAKE2b and BLAKE2s, including keyed mode, in pure Mojo."""

from std.bit import rotate_bits_left
from std.memory import bitcast

from std.collections import InlineArray
from ..internal.bytes import load_le32, load_le64


comptime _SIGMA: InlineArray[UInt8, 160] = [
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
    14,
    10,
    4,
    8,
    9,
    15,
    13,
    6,
    1,
    12,
    0,
    2,
    11,
    7,
    5,
    3,
    11,
    8,
    12,
    0,
    5,
    2,
    15,
    13,
    10,
    14,
    3,
    6,
    7,
    1,
    9,
    4,
    7,
    9,
    3,
    1,
    13,
    12,
    11,
    14,
    2,
    6,
    5,
    10,
    4,
    0,
    15,
    8,
    9,
    0,
    5,
    7,
    2,
    4,
    10,
    15,
    14,
    1,
    11,
    12,
    6,
    8,
    3,
    13,
    2,
    12,
    6,
    10,
    0,
    11,
    8,
    3,
    4,
    13,
    7,
    5,
    15,
    14,
    1,
    9,
    12,
    5,
    1,
    15,
    14,
    13,
    4,
    10,
    0,
    7,
    6,
    3,
    9,
    2,
    8,
    11,
    13,
    11,
    7,
    14,
    12,
    1,
    3,
    9,
    5,
    0,
    15,
    4,
    8,
    6,
    2,
    10,
    6,
    15,
    14,
    9,
    11,
    3,
    0,
    8,
    12,
    2,
    13,
    7,
    1,
    4,
    10,
    5,
    10,
    2,
    8,
    4,
    7,
    6,
    1,
    5,
    15,
    11,
    9,
    14,
    3,
    12,
    13,
    0,
]


@always_inline("nodebug")
def _g64x4(
    mut a: SIMD[DType.uint64, 4],
    mut b: SIMD[DType.uint64, 4],
    mut c: SIMD[DType.uint64, 4],
    mut d: SIMD[DType.uint64, 4],
    x: SIMD[DType.uint64, 4],
    y: SIMD[DType.uint64, 4],
):
    a += b + x
    d = rotate_bits_left[32](d ^ a)
    c += d
    b = rotate_bits_left[40](b ^ c)
    a += b + y
    d = rotate_bits_left[48](d ^ a)
    c += d
    b = rotate_bits_left[1](b ^ c)


@always_inline("nodebug")
def _rotl16x4(value: SIMD[DType.uint32, 4]) -> SIMD[DType.uint32, 4]:
    return bitcast[DType.uint32, 4](
        bitcast[DType.uint8, 16](value).shuffle[
            2,
            3,
            0,
            1,
            6,
            7,
            4,
            5,
            10,
            11,
            8,
            9,
            14,
            15,
            12,
            13,
        ]()
    )


@always_inline("nodebug")
def _rotl24x4(value: SIMD[DType.uint32, 4]) -> SIMD[DType.uint32, 4]:
    return bitcast[DType.uint32, 4](
        bitcast[DType.uint8, 16](value).shuffle[
            1,
            2,
            3,
            0,
            5,
            6,
            7,
            4,
            9,
            10,
            11,
            8,
            13,
            14,
            15,
            12,
        ]()
    )


@always_inline("nodebug")
def _g32x4(
    mut a: SIMD[DType.uint32, 4],
    mut b: SIMD[DType.uint32, 4],
    mut c: SIMD[DType.uint32, 4],
    mut d: SIMD[DType.uint32, 4],
    x: SIMD[DType.uint32, 4],
    y: SIMD[DType.uint32, 4],
):
    a += b + x
    d = _rotl16x4(d ^ a)
    c += d
    b = rotate_bits_left[20](b ^ c)
    a += b + y
    d = _rotl24x4(d ^ a)
    c += d
    b = rotate_bits_left[25](b ^ c)


@always_inline("nodebug")
def _compress_b[
    origin: Origin
](
    mut h0: SIMD[DType.uint64, 4],
    mut h1: SIMD[DType.uint64, 4],
    block: Span[UInt8, origin],
    block_offset: Int,
    counter: UInt128,
    final: Bool,
):
    var c = SIMD[DType.uint64, 4](
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
    )
    var d = SIMD[DType.uint64, 4](
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    )
    var message = InlineArray[UInt64, 16](uninitialized=True)
    var block_pointer = block.unsafe_ptr()
    comptime for lane in range(16):
        message[lane] = bitcast[DType.uint64, 1](
            block_pointer.unsafe_load[width=8](block_offset + lane * 8)
        )[0]
    var a = h0
    var b = h1
    d[0] ^= UInt64(counter)
    d[1] ^= UInt64(counter >> 64)
    if final:
        d[2] = ~d[2]
    comptime for round in range(12):
        comptime row = (round % 10) * 16
        var x = SIMD[DType.uint64, 4](0)
        var y = SIMD[DType.uint64, 4](0)
        comptime for lane in range(4):
            comptime x_index = Int(_SIGMA[row + lane * 2])
            comptime y_index = Int(_SIGMA[row + lane * 2 + 1])
            x[lane] = message[x_index]
            y[lane] = message[y_index]
        _g64x4(a, b, c, d, x, y)

        var diagonal_b = b.shuffle[1, 2, 3, 0]()
        var diagonal_c = c.shuffle[2, 3, 0, 1]()
        var diagonal_d = d.shuffle[3, 0, 1, 2]()
        comptime for lane in range(4):
            comptime x_index = Int(_SIGMA[row + 8 + lane * 2])
            comptime y_index = Int(_SIGMA[row + 9 + lane * 2])
            x[lane] = message[x_index]
            y[lane] = message[y_index]
        _g64x4(a, diagonal_b, diagonal_c, diagonal_d, x, y)
        b = diagonal_b.shuffle[3, 0, 1, 2]()
        c = diagonal_c.shuffle[2, 3, 0, 1]()
        d = diagonal_d.shuffle[1, 2, 3, 0]()
    h0 ^= a ^ c
    h1 ^= b ^ d


@always_inline("nodebug")
def _compress_s[
    origin: Origin
](
    mut h0: SIMD[DType.uint32, 4],
    mut h1: SIMD[DType.uint32, 4],
    block: Span[UInt8, origin],
    block_offset: Int,
    counter: UInt64,
    final: Bool,
):
    var c = SIMD[DType.uint32, 4](
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    )
    var d = SIMD[DType.uint32, 4](
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )
    var message = InlineArray[UInt32, 16](uninitialized=True)
    var block_pointer = block.unsafe_ptr()
    comptime for lane in range(16):
        message[lane] = bitcast[DType.uint32, 1](
            block_pointer.unsafe_load[width=4](block_offset + lane * 4)
        )[0]
    var a = h0
    var b = h1
    d[0] ^= UInt32(counter)
    d[1] ^= UInt32(counter >> 32)
    if final:
        d[2] = ~d[2]
    comptime for round in range(10):
        var x: SIMD[DType.uint32, 4]
        var y: SIMD[DType.uint32, 4]
        var diagonal_x: SIMD[DType.uint32, 4]
        var diagonal_y: SIMD[DType.uint32, 4]
        comptime if round == 0:
            x = SIMD[DType.uint32, 4](
                message[0], message[2], message[4], message[6]
            )
            y = SIMD[DType.uint32, 4](
                message[1], message[3], message[5], message[7]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[8], message[10], message[12], message[14]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[9], message[11], message[13], message[15]
            )
        elif round == 1:
            x = SIMD[DType.uint32, 4](
                message[14], message[4], message[9], message[13]
            )
            y = SIMD[DType.uint32, 4](
                message[10], message[8], message[15], message[6]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[1], message[0], message[11], message[5]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[12], message[2], message[7], message[3]
            )
        elif round == 2:
            x = SIMD[DType.uint32, 4](
                message[11], message[12], message[5], message[15]
            )
            y = SIMD[DType.uint32, 4](
                message[8], message[0], message[2], message[13]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[10], message[3], message[7], message[9]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[14], message[6], message[1], message[4]
            )
        elif round == 3:
            x = SIMD[DType.uint32, 4](
                message[7], message[3], message[13], message[11]
            )
            y = SIMD[DType.uint32, 4](
                message[9], message[1], message[12], message[14]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[2], message[5], message[4], message[15]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[6], message[10], message[0], message[8]
            )
        elif round == 4:
            x = SIMD[DType.uint32, 4](
                message[9], message[5], message[2], message[10]
            )
            y = SIMD[DType.uint32, 4](
                message[0], message[7], message[4], message[15]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[14], message[11], message[6], message[3]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[1], message[12], message[8], message[13]
            )
        elif round == 5:
            x = SIMD[DType.uint32, 4](
                message[2], message[6], message[0], message[8]
            )
            y = SIMD[DType.uint32, 4](
                message[12], message[10], message[11], message[3]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[4], message[7], message[15], message[1]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[13], message[5], message[14], message[9]
            )
        elif round == 6:
            x = SIMD[DType.uint32, 4](
                message[12], message[1], message[14], message[4]
            )
            y = SIMD[DType.uint32, 4](
                message[5], message[15], message[13], message[10]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[0], message[6], message[9], message[8]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[7], message[3], message[2], message[11]
            )
        elif round == 7:
            x = SIMD[DType.uint32, 4](
                message[13], message[7], message[12], message[3]
            )
            y = SIMD[DType.uint32, 4](
                message[11], message[14], message[1], message[9]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[5], message[15], message[8], message[2]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[0], message[4], message[6], message[10]
            )
        elif round == 8:
            x = SIMD[DType.uint32, 4](
                message[6], message[14], message[11], message[0]
            )
            y = SIMD[DType.uint32, 4](
                message[15], message[9], message[3], message[8]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[12], message[13], message[1], message[10]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[2], message[7], message[4], message[5]
            )
        else:
            x = SIMD[DType.uint32, 4](
                message[10], message[8], message[7], message[1]
            )
            y = SIMD[DType.uint32, 4](
                message[2], message[4], message[6], message[5]
            )
            diagonal_x = SIMD[DType.uint32, 4](
                message[15], message[9], message[3], message[13]
            )
            diagonal_y = SIMD[DType.uint32, 4](
                message[11], message[14], message[12], message[0]
            )
        _g32x4(a, b, c, d, x, y)
        var diagonal_b = b.shuffle[1, 2, 3, 0]()
        var diagonal_c = c.shuffle[2, 3, 0, 1]()
        var diagonal_d = d.shuffle[3, 0, 1, 2]()
        _g32x4(
            a,
            diagonal_b,
            diagonal_c,
            diagonal_d,
            diagonal_x,
            diagonal_y,
        )
        b = diagonal_b.shuffle[3, 0, 1, 2]()
        c = diagonal_c.shuffle[2, 3, 0, 1]()
        d = diagonal_d.shuffle[1, 2, 3, 0]()
    h0 ^= a ^ c
    h1 ^= b ^ d


def blake2b_keyed[
    data_origin: Origin, key_origin: Origin
](
    data: Span[UInt8, data_origin],
    key: Span[UInt8, key_origin],
    output_bytes: Int = 64,
) raises -> List[UInt8]:
    if output_bytes < 1 or output_bytes > 64 or len(key) > 64:
        raise Error(
            "BLAKE2b requires 1..64 output bytes and at most 64 key bytes"
        )
    var h0 = SIMD[DType.uint64, 4](
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
    )
    var h1 = SIMD[DType.uint64, 4](
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    )
    h0[0] ^= UInt64(0x01010000 | (len(key) << 8) | output_bytes)
    var counter = UInt128(0)
    if len(key) != 0:
        var key_block = InlineArray[UInt8, 128](fill=0)
        for i in range(len(key)):
            key_block[i] = key[i]
        counter = 128
        _compress_b(h0, h1, Span(key_block), 0, counter, len(data) == 0)
        if len(data) == 0:
            return _blake2b_output(h0, h1, output_bytes)
    var offset = 0
    while offset + 128 < len(data):
        counter += 128
        _compress_b(h0, h1, data, offset, counter, False)
        offset += 128
    var final_block = InlineArray[UInt8, 128](fill=0)
    var final_bytes = len(data) - offset
    for i in range(final_bytes):
        final_block[i] = data[offset + i]
    counter += UInt128(final_bytes)
    _compress_b(h0, h1, Span(final_block), 0, counter, True)
    return _blake2b_output(h0, h1, output_bytes)


def blake2b_keyed_salt_personal_into[
    data_origin: Origin,
    key_origin: Origin,
    salt_origin: Origin,
    personal_origin: Origin,
    output_origin: MutOrigin,
](
    data: Span[UInt8, data_origin],
    key: Span[UInt8, key_origin],
    salt: Span[UInt8, salt_origin],
    personal: Span[UInt8, personal_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if (
        len(output) < 1
        or len(output) > 64
        or len(key) > 64
        or len(salt) != 16
        or len(personal) != 16
    ):
        raise Error("BLAKE2b parameters require 16-byte salt/personal")
    var h0 = SIMD[DType.uint64, 4](
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
    )
    var h1 = SIMD[DType.uint64, 4](
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    )
    h0[0] ^= UInt64(len(output) | (len(key) << 8) | 0x01010000)
    h1[0] ^= load_le64(salt, 0)
    h1[1] ^= load_le64(salt, 8)
    h1[2] ^= load_le64(personal, 0)
    h1[3] ^= load_le64(personal, 8)
    var key_block = InlineArray[UInt8, 128](fill=0)
    for i in range(len(key)):
        key_block[i] = key[i]
    _compress_b(h0, h1, Span(key_block), 0, UInt128(128), len(data) == 0)
    if len(data) == 0:
        _blake2b_output_into(h0, h1, output)
        return
    var counter = UInt128(128)
    var offset = 0
    while offset + 128 < len(data):
        counter += 128
        _compress_b(h0, h1, data, offset, counter, False)
        offset += 128
    var final_block = InlineArray[UInt8, 128](fill=0)
    var final_bytes = len(data) - offset
    for i in range(final_bytes):
        final_block[i] = data[offset + i]
    counter += UInt128(final_bytes)
    _compress_b(h0, h1, Span(final_block), 0, counter, True)
    _blake2b_output_into(h0, h1, output)


def blake2b_keyed_salt_personal[
    data_origin: Origin,
    key_origin: Origin,
    salt_origin: Origin,
    personal_origin: Origin,
](
    data: Span[UInt8, data_origin],
    key: Span[UInt8, key_origin],
    salt: Span[UInt8, salt_origin],
    personal: Span[UInt8, personal_origin],
    output_bytes: Int = 64,
) raises -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    blake2b_keyed_salt_personal_into(data, key, salt, personal, Span(output))
    return output^


def _blake2b_output_into[
    output_origin: MutOrigin
](
    h0: SIMD[DType.uint64, 4],
    h1: SIMD[DType.uint64, 4],
    output: Span[mut=True, UInt8, output_origin],
):
    if len(output) == 64:
        var output_pointer = output.unsafe_ptr()
        output_pointer.unsafe_store[width=32](0, bitcast[DType.uint8, 32](h0))
        output_pointer.unsafe_store[width=32](32, bitcast[DType.uint8, 32](h1))
        return
    for i in range(len(output)):
        var word = h0[i // 8] if i < 32 else h1[i // 8 - 4]
        output[i] = UInt8(word >> UInt64((i % 8) * 8))


def _blake2b_output(
    h0: SIMD[DType.uint64, 4],
    h1: SIMD[DType.uint64, 4],
    output_bytes: Int,
) -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    _blake2b_output_into(h0, h1, Span(output))
    return output^


def blake2b_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) < 1 or len(output) > 64:
        raise Error("BLAKE2b requires 1..64 output bytes")
    var h0 = SIMD[DType.uint64, 4](
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
    )
    var h1 = SIMD[DType.uint64, 4](
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    )
    h0[0] ^= UInt64(0x01010000 | len(output))
    var counter = UInt128(0)
    var offset = 0
    var data_length = len(data)
    while offset + 128 < data_length:
        counter += 128
        _compress_b(h0, h1, data, offset, counter, False)
        offset += 128
    var final_block = InlineArray[UInt8, 128](fill=0)
    var final_bytes = data_length - offset
    for i in range(final_bytes):
        final_block[i] = data[offset + i]
    counter += UInt128(final_bytes)
    _compress_b(h0, h1, Span(final_block), 0, counter, True)
    _blake2b_output_into(h0, h1, output)


def blake2b[
    origin: Origin
](data: Span[UInt8, origin], output_bytes: Int = 64,) raises -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    blake2b_into(data, Span(output))
    return output^


def blake2s_keyed[
    data_origin: Origin, key_origin: Origin
](
    data: Span[UInt8, data_origin],
    key: Span[UInt8, key_origin],
    output_bytes: Int = 32,
) raises -> List[UInt8]:
    if output_bytes < 1 or output_bytes > 32 or len(key) > 32:
        raise Error(
            "BLAKE2s requires 1..32 output bytes and at most 32 key bytes"
        )
    var h0 = SIMD[DType.uint32, 4](
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    )
    var h1 = SIMD[DType.uint32, 4](
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )
    h0[0] ^= UInt32(0x01010000 | (len(key) << 8) | output_bytes)
    var counter = UInt64(0)
    var data_length = len(data)
    if len(key) != 0:
        var key_block = InlineArray[UInt8, 64](fill=0)
        for i in range(len(key)):
            key_block[i] = key[i]
        counter = 64
        _compress_s(h0, h1, Span(key_block), 0, counter, data_length == 0)
        if data_length == 0:
            return _blake2s_output(h0, h1, output_bytes)
    var offset = 0
    while offset + 64 < data_length:
        counter += 64
        _compress_s(h0, h1, data, offset, counter, False)
        offset += 64
    var final_block = InlineArray[UInt8, 64](fill=0)
    var final_bytes = data_length - offset
    for i in range(final_bytes):
        final_block[i] = data[offset + i]
    counter += UInt64(final_bytes)
    _compress_s(h0, h1, Span(final_block), 0, counter, True)
    return _blake2s_output(h0, h1, output_bytes)


def _blake2s_output_into[
    output_origin: MutOrigin
](
    h0: SIMD[DType.uint32, 4],
    h1: SIMD[DType.uint32, 4],
    output: Span[mut=True, UInt8, output_origin],
):
    if len(output) == 32:
        var output_pointer = output.unsafe_ptr()
        output_pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](h0))
        output_pointer.unsafe_store[width=16](16, bitcast[DType.uint8, 16](h1))
        return
    for i in range(len(output)):
        var word = h0[i // 4] if i < 16 else h1[i // 4 - 4]
        output[i] = UInt8(word >> UInt32((i % 4) * 8))


def _blake2s_output(
    h0: SIMD[DType.uint32, 4],
    h1: SIMD[DType.uint32, 4],
    output_bytes: Int,
) -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    _blake2s_output_into(h0, h1, Span(output))
    return output^


def blake2s_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) < 1 or len(output) > 32:
        raise Error("BLAKE2s requires 1..32 output bytes")
    var h0 = SIMD[DType.uint32, 4](
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
    )
    var h1 = SIMD[DType.uint32, 4](
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )
    h0[0] ^= UInt32(0x01010000 | len(output))
    var counter = UInt64(0)
    var offset = 0
    var data_length = len(data)
    while offset + 64 < data_length:
        counter += 64
        _compress_s(h0, h1, data, offset, counter, False)
        offset += 64
    var final_block = InlineArray[UInt8, 64](fill=0)
    var final_bytes = data_length - offset
    for i in range(final_bytes):
        final_block[i] = data[offset + i]
    counter += UInt64(final_bytes)
    _compress_s(h0, h1, Span(final_block), 0, counter, True)
    _blake2s_output_into(h0, h1, output)


def blake2s[
    origin: Origin
](data: Span[UInt8, origin], output_bytes: Int = 32,) raises -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    blake2s_into(data, Span(output))
    return output^
