"""MD2 and MD4 in pure Mojo for legacy compatibility only."""

from std.collections import InlineArray
from std.memory import bitcast


def _md2_sbox() -> InlineArray[UInt8, 256]:
    return [
        41,
        46,
        67,
        201,
        162,
        216,
        124,
        1,
        61,
        54,
        84,
        161,
        236,
        240,
        6,
        19,
        98,
        167,
        5,
        243,
        192,
        199,
        115,
        140,
        152,
        147,
        43,
        217,
        188,
        76,
        130,
        202,
        30,
        155,
        87,
        60,
        253,
        212,
        224,
        22,
        103,
        66,
        111,
        24,
        138,
        23,
        229,
        18,
        190,
        78,
        196,
        214,
        218,
        158,
        222,
        73,
        160,
        251,
        245,
        142,
        187,
        47,
        238,
        122,
        169,
        104,
        121,
        145,
        21,
        178,
        7,
        63,
        148,
        194,
        16,
        137,
        11,
        34,
        95,
        33,
        128,
        127,
        93,
        154,
        90,
        144,
        50,
        39,
        53,
        62,
        204,
        231,
        191,
        247,
        151,
        3,
        255,
        25,
        48,
        179,
        72,
        165,
        181,
        209,
        215,
        94,
        146,
        42,
        172,
        86,
        170,
        198,
        79,
        184,
        56,
        210,
        150,
        164,
        125,
        182,
        118,
        252,
        107,
        226,
        156,
        116,
        4,
        241,
        69,
        157,
        112,
        89,
        100,
        113,
        135,
        32,
        134,
        91,
        207,
        101,
        230,
        45,
        168,
        2,
        27,
        96,
        37,
        173,
        174,
        176,
        185,
        246,
        28,
        70,
        97,
        105,
        52,
        64,
        126,
        15,
        85,
        71,
        163,
        35,
        221,
        81,
        175,
        58,
        195,
        92,
        249,
        206,
        186,
        197,
        234,
        38,
        44,
        83,
        13,
        110,
        133,
        40,
        132,
        9,
        211,
        223,
        205,
        244,
        65,
        129,
        77,
        82,
        106,
        220,
        55,
        200,
        108,
        193,
        171,
        250,
        36,
        225,
        123,
        8,
        12,
        189,
        177,
        74,
        120,
        136,
        149,
        139,
        227,
        99,
        232,
        109,
        233,
        203,
        213,
        254,
        59,
        0,
        29,
        57,
        242,
        239,
        183,
        14,
        102,
        88,
        208,
        228,
        166,
        119,
        114,
        248,
        235,
        117,
        75,
        10,
        49,
        68,
        80,
        180,
        143,
        237,
        31,
        26,
        219,
        153,
        141,
        51,
        159,
        17,
        131,
        20,
    ]


@always_inline("nodebug")
def _md2_block[
    substitution_origin: Origin, block_origin: Origin
](
    mut state: InlineArray[UInt8, 48],
    mut checksum: InlineArray[UInt8, 16],
    substitution: Span[UInt8, substitution_origin],
    block: Span[UInt8, block_origin],
    block_offset: Int,
):
    var block_pointer = block.unsafe_ptr()
    var substitution_pointer = substitution.unsafe_ptr()
    var t = checksum[15]
    for i in range(16):
        var value = block_pointer.unsafe_load(block_offset + i)
        state[16 + i] = value
        state[32 + i] = value ^ state[i]
        checksum[i] ^= substitution_pointer.unsafe_load(Int(value ^ t))
        t = checksum[i]
    t = 0
    for round in range(18):
        for i in range(48):
            state[i] ^= substitution_pointer.unsafe_load(Int(t))
            t = state[i]
        t = UInt8((Int(t) + round) & 0xFF)


@always_inline("nodebug")
def _md2_block_two[
    substitution_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
](
    mut first_state: InlineArray[UInt8, 48],
    mut first_checksum: InlineArray[UInt8, 16],
    mut second_state: InlineArray[UInt8, 48],
    mut second_checksum: InlineArray[UInt8, 16],
    substitution: Span[UInt8, substitution_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    block_offset: Int,
):
    var first_pointer = first.unsafe_ptr()
    var second_pointer = second.unsafe_ptr()
    var substitution_pointer = substitution.unsafe_ptr()
    var first_t = first_checksum[15]
    var second_t = second_checksum[15]
    for i in range(16):
        var first_value = first_pointer.unsafe_load(block_offset + i)
        var second_value = second_pointer.unsafe_load(block_offset + i)
        first_state[16 + i] = first_value
        second_state[16 + i] = second_value
        first_state[32 + i] = first_value ^ first_state[i]
        second_state[32 + i] = second_value ^ second_state[i]
        first_checksum[i] ^= substitution_pointer.unsafe_load(
            Int(first_value ^ first_t)
        )
        second_checksum[i] ^= substitution_pointer.unsafe_load(
            Int(second_value ^ second_t)
        )
        first_t = first_checksum[i]
        second_t = second_checksum[i]
    first_t = 0
    second_t = 0
    for round in range(18):
        for i in range(48):
            first_state[i] ^= substitution_pointer.unsafe_load(Int(first_t))
            second_state[i] ^= substitution_pointer.unsafe_load(Int(second_t))
            first_t = first_state[i]
            second_t = second_state[i]
        first_t = UInt8((Int(first_t) + round) & 0xFF)
        second_t = UInt8((Int(second_t) + round) & 0xFF)


def md2_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) != 16:
        raise Error("MD2 output span must be 16 bytes")
    var state = InlineArray[UInt8, 48](fill=0)
    var checksum = InlineArray[UInt8, 16](fill=0)
    var substitution = _md2_sbox()
    var offset = 0
    while offset + 16 <= len(data):
        _md2_block(state, checksum, Span(substitution), data, offset)
        offset += 16
    var remaining = len(data) - offset
    var padding = UInt8(16 - remaining)
    var final_block = InlineArray[UInt8, 16](fill=padding)
    for i in range(remaining):
        final_block[i] = data[offset + i]
    _md2_block(state, checksum, Span(substitution), Span(final_block), 0)
    var checksum_block = checksum.copy()
    _md2_block(state, checksum, Span(substitution), Span(checksum_block), 0)
    output.unsafe_ptr().unsafe_store[width=16](
        Span(state).unsafe_ptr().unsafe_load[width=16]()
    )


def md2_two_into[
    first_origin: Origin,
    second_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
](
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
) raises:
    if len(second) != len(first):
        raise Error("two-way MD2 inputs must have equal lengths")
    if len(first_output) != 16 or len(second_output) != 16:
        raise Error("two-way MD2 output span must be 16 bytes")
    var first_state = InlineArray[UInt8, 48](fill=0)
    var first_checksum = InlineArray[UInt8, 16](fill=0)
    var second_state = InlineArray[UInt8, 48](fill=0)
    var second_checksum = InlineArray[UInt8, 16](fill=0)
    var substitution = _md2_sbox()
    var offset = 0
    while offset + 16 <= len(first):
        _md2_block_two(
            first_state,
            first_checksum,
            second_state,
            second_checksum,
            Span(substitution),
            first,
            second,
            offset,
        )
        offset += 16
    var remainder = len(first) - offset
    var padding = UInt8(16 - remainder)
    var first_final = InlineArray[UInt8, 16](fill=padding)
    var second_final = InlineArray[UInt8, 16](fill=padding)
    for i in range(remainder):
        first_final[i] = first[offset + i]
        second_final[i] = second[offset + i]
    _md2_block_two(
        first_state,
        first_checksum,
        second_state,
        second_checksum,
        Span(substitution),
        Span(first_final),
        Span(second_final),
        0,
    )
    var first_checksum_block = first_checksum.copy()
    var second_checksum_block = second_checksum.copy()
    _md2_block_two(
        first_state,
        first_checksum,
        second_state,
        second_checksum,
        Span(substitution),
        Span(first_checksum_block),
        Span(second_checksum_block),
        0,
    )
    first_output.unsafe_ptr().unsafe_store[width=16](
        Span(first_state).unsafe_ptr().unsafe_load[width=16]()
    )
    second_output.unsafe_ptr().unsafe_store[width=16](
        Span(second_state).unsafe_ptr().unsafe_load[width=16]()
    )


def md2[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    md2_into(data, Span(output))
    return output^


@always_inline("nodebug")
def _rotl32(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _compress_md4[
    origin: Origin
](mut state: InlineArray[UInt32, 4], block: Span[UInt8, origin], offset: Int,):
    comptime order2: InlineArray[Int, 16] = [
        0,
        4,
        8,
        12,
        1,
        5,
        9,
        13,
        2,
        6,
        10,
        14,
        3,
        7,
        11,
        15,
    ]
    comptime order3: InlineArray[Int, 16] = [
        0,
        8,
        4,
        12,
        2,
        10,
        6,
        14,
        1,
        9,
        5,
        13,
        3,
        11,
        7,
        15,
    ]
    comptime shifts1: InlineArray[Int, 4] = [3, 7, 11, 19]
    comptime shifts2: InlineArray[Int, 4] = [3, 5, 9, 13]
    comptime shifts3: InlineArray[Int, 4] = [3, 9, 11, 15]
    var words = InlineArray[UInt32, 16](uninitialized=True)
    var block_pointer = block.unsafe_ptr()
    comptime for i in range(16):
        words[i] = bitcast[DType.uint32, 1](
            block_pointer.unsafe_load[width=4](offset + i * 4)
        )[0]
    var registers = state.copy()
    comptime for i in range(16):
        comptime target = (-i) % 4
        var b = registers[(target + 1) % 4]
        var c = registers[(target + 2) % 4]
        var d = registers[(target + 3) % 4]
        registers[target] = _rotl32(
            registers[target] + ((b & c) | ((~b) & d)) + words[i],
            materialize[shifts1[i % 4]](),
        )
    comptime for i in range(16):
        comptime target = (-i) % 4
        var b = registers[(target + 1) % 4]
        var c = registers[(target + 2) % 4]
        var d = registers[(target + 3) % 4]
        registers[target] = _rotl32(
            registers[target]
            + ((b & c) | (b & d) | (c & d))
            + words[materialize[order2[i]]()]
            + 0x5A827999,
            materialize[shifts2[i % 4]](),
        )
    comptime for i in range(16):
        comptime target = (-i) % 4
        var b = registers[(target + 1) % 4]
        var c = registers[(target + 2) % 4]
        var d = registers[(target + 3) % 4]
        registers[target] = _rotl32(
            registers[target]
            + (b ^ c ^ d)
            + words[materialize[order3[i]]()]
            + 0x6ED9EBA1,
            materialize[shifts3[i % 4]](),
        )
    comptime for i in range(4):
        state[i] += registers[i]


def md4[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var state: InlineArray[UInt32, 4] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
    ]
    var data_length = len(data)
    var offset = 0
    while offset + 64 <= data_length:
        _compress_md4(state, data, offset)
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
    _compress_md4(state, tail_span, 0)
    if final_size == 128:
        _compress_md4(state, tail_span, 64)
    var output = List[UInt8](length=16, fill=0)
    Span(output).unsafe_ptr().unsafe_store[width=16](
        0,
        bitcast[DType.uint8, 16](
            Span(state).unsafe_ptr().unsafe_load[width=4]()
        ),
    )
    return output^
