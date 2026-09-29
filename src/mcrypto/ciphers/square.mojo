"""Square 128-bit block cipher."""

from ..internal.bytes import load_be32, store_be32
from std.builtin.globals import global_constant

comptime _SBOX: InlineArray[UInt8, 256] = [
    177,
    206,
    195,
    149,
    90,
    173,
    231,
    2,
    77,
    68,
    251,
    145,
    12,
    135,
    161,
    80,
    203,
    103,
    84,
    221,
    70,
    143,
    225,
    78,
    240,
    253,
    252,
    235,
    249,
    196,
    26,
    110,
    94,
    245,
    204,
    141,
    28,
    86,
    67,
    254,
    7,
    97,
    248,
    117,
    89,
    255,
    3,
    34,
    138,
    209,
    19,
    238,
    136,
    0,
    14,
    52,
    21,
    128,
    148,
    227,
    237,
    181,
    83,
    35,
    75,
    71,
    23,
    167,
    144,
    53,
    171,
    216,
    184,
    223,
    79,
    87,
    154,
    146,
    219,
    27,
    60,
    200,
    153,
    4,
    142,
    224,
    215,
    125,
    133,
    187,
    64,
    44,
    58,
    69,
    241,
    66,
    101,
    32,
    65,
    24,
    114,
    37,
    147,
    112,
    54,
    5,
    242,
    11,
    163,
    121,
    236,
    8,
    39,
    49,
    50,
    182,
    124,
    176,
    10,
    115,
    91,
    123,
    183,
    129,
    210,
    13,
    106,
    38,
    158,
    88,
    156,
    131,
    116,
    179,
    172,
    48,
    122,
    105,
    119,
    15,
    174,
    33,
    222,
    208,
    46,
    151,
    16,
    164,
    152,
    168,
    212,
    104,
    45,
    98,
    41,
    109,
    22,
    73,
    118,
    199,
    232,
    193,
    150,
    55,
    229,
    202,
    244,
    233,
    99,
    18,
    194,
    166,
    20,
    188,
    211,
    40,
    175,
    47,
    230,
    36,
    82,
    198,
    160,
    9,
    189,
    140,
    207,
    93,
    17,
    95,
    1,
    197,
    159,
    61,
    162,
    155,
    201,
    59,
    190,
    81,
    25,
    31,
    63,
    92,
    178,
    239,
    74,
    205,
    191,
    186,
    111,
    100,
    217,
    243,
    62,
    180,
    170,
    220,
    213,
    6,
    192,
    126,
    246,
    102,
    108,
    132,
    113,
    56,
    185,
    29,
    127,
    157,
    72,
    139,
    42,
    218,
    165,
    51,
    130,
    57,
    214,
    120,
    134,
    250,
    228,
    43,
    169,
    30,
    137,
    96,
    107,
    234,
    85,
    76,
    247,
    226,
]
comptime _ISBOX: InlineArray[UInt8, 256] = [
    53,
    190,
    7,
    46,
    83,
    105,
    219,
    40,
    111,
    183,
    118,
    107,
    12,
    125,
    54,
    139,
    146,
    188,
    169,
    50,
    172,
    56,
    156,
    66,
    99,
    200,
    30,
    79,
    36,
    229,
    247,
    201,
    97,
    141,
    47,
    63,
    179,
    101,
    127,
    112,
    175,
    154,
    234,
    245,
    91,
    152,
    144,
    177,
    135,
    113,
    114,
    237,
    55,
    69,
    104,
    163,
    227,
    239,
    92,
    197,
    80,
    193,
    214,
    202,
    90,
    98,
    95,
    38,
    9,
    93,
    20,
    65,
    232,
    157,
    206,
    64,
    253,
    8,
    23,
    74,
    15,
    199,
    180,
    62,
    18,
    252,
    37,
    75,
    129,
    44,
    4,
    120,
    203,
    187,
    32,
    189,
    249,
    41,
    153,
    168,
    211,
    96,
    223,
    17,
    151,
    137,
    126,
    250,
    224,
    155,
    31,
    210,
    103,
    226,
    100,
    119,
    132,
    43,
    158,
    138,
    241,
    109,
    136,
    121,
    116,
    87,
    221,
    230,
    57,
    123,
    238,
    131,
    225,
    88,
    242,
    13,
    52,
    248,
    48,
    233,
    185,
    35,
    84,
    21,
    68,
    11,
    77,
    102,
    58,
    3,
    162,
    145,
    148,
    82,
    76,
    195,
    130,
    231,
    128,
    192,
    182,
    14,
    194,
    108,
    147,
    236,
    171,
    67,
    149,
    246,
    216,
    70,
    134,
    5,
    140,
    176,
    117,
    0,
    204,
    133,
    215,
    61,
    115,
    122,
    72,
    228,
    209,
    89,
    173,
    184,
    198,
    208,
    220,
    161,
    170,
    2,
    29,
    191,
    181,
    159,
    81,
    196,
    165,
    16,
    34,
    207,
    1,
    186,
    143,
    49,
    124,
    174,
    150,
    218,
    240,
    86,
    71,
    212,
    235,
    78,
    217,
    19,
    142,
    73,
    85,
    22,
    255,
    59,
    244,
    164,
    178,
    6,
    160,
    167,
    251,
    27,
    110,
    60,
    51,
    205,
    24,
    94,
    106,
    213,
    166,
    33,
    222,
    254,
    42,
    28,
    243,
    10,
    26,
    25,
    39,
    45,
]
comptime _G: InlineArray[UInt8, 16] = [
    2,
    1,
    1,
    3,
    3,
    2,
    1,
    1,
    1,
    3,
    2,
    1,
    1,
    1,
    3,
    2,
]
comptime _IG: InlineArray[UInt8, 16] = [
    14,
    9,
    13,
    11,
    11,
    14,
    9,
    13,
    13,
    11,
    14,
    9,
    9,
    13,
    11,
    14,
]


@always_inline("nodebug")
def _mul(a: UInt8, b: UInt8) -> UInt8:
    var x = a
    var y = b
    var result = UInt8(0)
    comptime for _ in range(8):
        var bit_mask = UInt8(0) - (y & 1)
        result ^= x & bit_mask
        var high_mask = UInt8(0) - (x >> 7)
        x = (x << 1) ^ (UInt8(0xF5) & high_mask)
        y >>= 1
    return result


def _precomputed_tables[decrypt: Bool]() -> InlineArray[UInt32, 1280]:
    var sbox = materialize[_SBOX]()
    var inverse_sbox = materialize[_ISBOX]()
    var coefficients = materialize[_IG]() if decrypt else materialize[_G]()
    var tables = InlineArray[UInt32, 1280](fill=0)
    comptime for lane in range(4):
        comptime for value in range(256):
            var substituted = inverse_sbox[value] if decrypt else sbox[value]
            var word = UInt32(0)
            comptime for output_byte in range(4):
                word |= UInt32(
                    _mul(
                        substituted,
                        coefficients[lane * 4 + output_byte],
                    )
                ) << UInt32(24 - 8 * output_byte)
            tables[lane * 256 + value] = word
    comptime for value in range(256):
        tables[1024 + value] = UInt32(
            inverse_sbox[value] if decrypt else sbox[value]
        )
    return tables^


comptime _ENCRYPT_TABLES = _precomputed_tables[False]()
comptime _DECRYPT_TABLES = _precomputed_tables[True]()


@always_inline("nodebug")
def _byte(value: UInt32, index: Int) -> UInt8:
    return UInt8(value >> UInt32(24 - 8 * index))


def _transform_words(mut words: List[UInt32]):
    var g = materialize[_G]()
    for i in range(4):
        var output = UInt32(0)
        for j in range(4):
            var value = UInt8(0)
            for k in range(4):
                value ^= _mul(_byte(words[i], k), g[k * 4 + j])
            output |= UInt32(value) << UInt32(24 - 8 * j)
        words[i] = output


def _expand[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> List[UInt32]:
    var keys = List[UInt32](length=36, fill=0)
    for i in range(4):
        keys[i] = load_be32(key, i * 4)
    var offset = UInt32(0x01000000)
    for round in range(1, 9):
        var previous = (round - 1) * 4
        var current = round * 4
        var rotated = (keys[previous + 3] << 8) | (keys[previous + 3] >> 24)
        keys[current] = keys[previous] ^ rotated ^ offset
        keys[current + 1] = keys[previous + 1] ^ keys[current]
        keys[current + 2] = keys[previous + 2] ^ keys[current + 1]
        keys[current + 3] = keys[previous + 3] ^ keys[current + 2]
        offset <<= 1
    if decrypt:
        for round in range(4):
            for j in range(4):
                var a = round * 4 + j
                var b = (8 - round) * 4 + j
                var temporary = keys[a]
                keys[a] = keys[b]
                keys[b] = temporary
        var last = List[UInt32](length=4, fill=0)
        for j in range(4):
            last[j] = keys[32 + j]
        _transform_words(last)
        for j in range(4):
            keys[32 + j] = last[j]
    else:
        for round in range(8):
            var transformed = List[UInt32](length=4, fill=0)
            for j in range(4):
                transformed[j] = keys[round * 4 + j]
            _transform_words(transformed)
            for j in range(4):
                keys[round * 4 + j] = transformed[j]
    return keys^


def prepare_tables(decrypt: Bool) -> List[UInt32]:
    # Rounds select immutable constant storage using the explicit mode.
    return List[UInt32]()


@always_inline("nodebug")
def _round_word_fixed(
    state0: UInt32,
    state1: UInt32,
    state2: UInt32,
    state3: UInt32,
    column: Int,
    tables: InlineArray[UInt32, 1280],
) -> UInt32:
    var table_pointer = Span(tables).unsafe_ptr()
    return (
        table_pointer.unsafe_load(Int(_byte(state0, column)))
        ^ table_pointer.unsafe_load(256 + Int(_byte(state1, column)))
        ^ table_pointer.unsafe_load(512 + Int(_byte(state2, column)))
        ^ table_pointer.unsafe_load(768 + Int(_byte(state3, column)))
    )


@always_inline("nodebug")
def _final_word_fixed(
    state0: UInt32,
    state1: UInt32,
    state2: UInt32,
    state3: UInt32,
    column: Int,
    tables: InlineArray[UInt32, 1280],
) -> UInt32:
    var table_pointer = Span(tables).unsafe_ptr()
    return (
        table_pointer.unsafe_load(1024 + Int(_byte(state0, column))) << 24
        ^ table_pointer.unsafe_load(1024 + Int(_byte(state1, column))) << 16
        ^ table_pointer.unsafe_load(1024 + Int(_byte(state2, column))) << 8
        ^ table_pointer.unsafe_load(1024 + Int(_byte(state3, column)))
    )


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> List[UInt32]:
    if len(key) != 16:
        raise Error("Square requires a 16-byte key")
    return _expand(key, decrypt)


@always_inline("nodebug")
def _process_fixed_into[
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    tables: InlineArray[UInt32, 1280],
) raises:
    var state0 = load_be32(block, 0) ^ keys[0]
    var state1 = load_be32(block, 4) ^ keys[1]
    var state2 = load_be32(block, 8) ^ keys[2]
    var state3 = load_be32(block, 12) ^ keys[3]
    comptime for round in range(1, 8):
        var next0 = (
            _round_word_fixed(state0, state1, state2, state3, 0, tables)
            ^ keys[round * 4]
        )
        var next1 = (
            _round_word_fixed(state0, state1, state2, state3, 1, tables)
            ^ keys[round * 4 + 1]
        )
        var next2 = (
            _round_word_fixed(state0, state1, state2, state3, 2, tables)
            ^ keys[round * 4 + 2]
        )
        var next3 = (
            _round_word_fixed(state0, state1, state2, state3, 3, tables)
            ^ keys[round * 4 + 3]
        )
        state0 = next0
        state1 = next1
        state2 = next2
        state3 = next3
    store_be32(
        _final_word_fixed(state0, state1, state2, state3, 0, tables) ^ keys[32],
        output,
        output_offset,
    )
    store_be32(
        _final_word_fixed(state0, state1, state2, state3, 1, tables) ^ keys[33],
        output,
        output_offset + 4,
    )
    store_be32(
        _final_word_fixed(state0, state1, state2, state3, 2, tables) ^ keys[34],
        output,
        output_offset + 8,
    )
    store_be32(
        _final_word_fixed(state0, state1, state2, state3, 3, tables) ^ keys[35],
        output,
        output_offset + 12,
    )


def process_prepared_tables_into[
    block_origin: Origin,
    output_origin: MutOrigin,
](
    decrypt: Bool,
    keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 36 or len(tables) != 0 or len(block) != 16:
        raise Error("Square requires a prepared key and 16-byte block")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("Square output span is too short")
    if decrypt:
        ref constant_tables = global_constant[_DECRYPT_TABLES]()
        _process_fixed_into(keys, block, output, output_offset, constant_tables)
    else:
        ref constant_tables = global_constant[_ENCRYPT_TABLES]()
        _process_fixed_into(keys, block, output, output_offset, constant_tables)


def process_prepared_tables[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared_tables_into(decrypt, keys, tables, block, Span(output), 0)
    return output^


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var tables = prepare_tables(decrypt)
    return process_prepared_tables(decrypt, keys, tables, block)


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var keys = prepare(key, decrypt)
    var tables = prepare_tables(decrypt)
    return process_prepared_tables(decrypt, keys, tables, block)
