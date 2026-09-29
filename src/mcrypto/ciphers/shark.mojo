"""SHARK-E 64-bit block cipher."""

from ..internal.bytes import load_be64, store_be64
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
comptime _G: InlineArray[UInt8, 64] = [
    206,
    149,
    87,
    130,
    138,
    25,
    176,
    1,
    231,
    254,
    5,
    210,
    82,
    193,
    136,
    241,
    185,
    218,
    77,
    209,
    158,
    23,
    131,
    134,
    208,
    157,
    38,
    44,
    93,
    159,
    109,
    117,
    82,
    169,
    7,
    108,
    185,
    143,
    112,
    23,
    135,
    40,
    58,
    90,
    244,
    51,
    11,
    108,
    116,
    81,
    21,
    207,
    9,
    164,
    98,
    9,
    11,
    49,
    127,
    134,
    190,
    5,
    131,
    52,
]
comptime _IG: InlineArray[UInt8, 64] = [
    231,
    48,
    144,
    133,
    208,
    75,
    145,
    65,
    83,
    149,
    155,
    165,
    150,
    188,
    161,
    104,
    2,
    69,
    247,
    101,
    92,
    31,
    182,
    82,
    162,
    202,
    34,
    148,
    68,
    99,
    42,
    162,
    252,
    103,
    142,
    16,
    41,
    117,
    133,
    113,
    36,
    69,
    162,
    207,
    47,
    34,
    193,
    14,
    161,
    241,
    113,
    64,
    145,
    39,
    24,
    165,
    86,
    244,
    175,
    50,
    210,
    164,
    220,
    113,
]
comptime _FIXED: InlineArray[UInt64, 7] = [
    0x060D838F16F3A365,
    0xA68857EE5CAE56F6,
    0xEBF516353C2C4D89,
    0x652174BE88E85BDC,
    0x0D4E9A8086C17921,
    0x27BA7D33CFFA58A1,
    0x88D9E104A237B530,
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


def _precomputed_tables[decrypt: Bool]() -> InlineArray[UInt64, 2304]:
    var sbox = materialize[_SBOX]()
    var inverse_sbox = materialize[_ISBOX]()
    var coefficients = materialize[_IG]() if decrypt else materialize[_G]()
    var tables = InlineArray[UInt64, 2304](fill=0)
    comptime for lane in range(8):
        comptime for value in range(256):
            var substituted = inverse_sbox[value] if decrypt else sbox[value]
            var word = UInt64(0)
            comptime for output_byte in range(8):
                word |= UInt64(
                    _mul(
                        coefficients[output_byte * 8 + lane],
                        substituted,
                    )
                ) << UInt64(56 - 8 * output_byte)
            tables[lane * 256 + value] = word
    comptime for value in range(256):
        tables[2048 + value] = UInt64(
            inverse_sbox[value] if decrypt else sbox[value]
        )
    return tables^


comptime _ENCRYPT_TABLES = _precomputed_tables[False]()
comptime _DECRYPT_TABLES = _precomputed_tables[True]()


@always_inline("nodebug")
def _transform[inverse: Bool](value: UInt64) -> UInt64:
    var output = UInt64(0)
    comptime for i in range(8):
        var byte = UInt8(0)
        comptime for j in range(8):
            comptime index = i * 8 + j
            comptime if inverse:
                byte ^= _mul(
                    materialize[_IG[index]](),
                    UInt8(value >> UInt64(56 - 8 * j)),
                )
            else:
                byte ^= _mul(
                    materialize[_G[index]](),
                    UInt8(value >> UInt64(56 - 8 * j)),
                )
        output |= UInt64(byte) << UInt64(56 - 8 * i)
    return output


@always_inline("nodebug")
def _round_static(value: UInt64, tables: InlineArray[UInt64, 2304]) -> UInt64:
    var table_pointer = Span(tables).unsafe_ptr()
    return (
        table_pointer.unsafe_load(Int(UInt8(value >> 56)))
        ^ table_pointer.unsafe_load(256 + Int(UInt8(value >> 48)))
        ^ table_pointer.unsafe_load(512 + Int(UInt8(value >> 40)))
        ^ table_pointer.unsafe_load(768 + Int(UInt8(value >> 32)))
        ^ table_pointer.unsafe_load(1024 + Int(UInt8(value >> 24)))
        ^ table_pointer.unsafe_load(1280 + Int(UInt8(value >> 16)))
        ^ table_pointer.unsafe_load(1536 + Int(UInt8(value >> 8)))
        ^ table_pointer.unsafe_load(1792 + Int(UInt8(value)))
    )


@always_inline("nodebug")
def _last_static(value: UInt64, tables: InlineArray[UInt64, 2304]) -> UInt64:
    var table_pointer = Span(tables).unsafe_ptr()
    return (
        table_pointer.unsafe_load(2048 + Int(UInt8(value >> 56))) << 56
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value >> 48))) << 48
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value >> 40))) << 40
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value >> 32))) << 32
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value >> 24))) << 24
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value >> 16))) << 16
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value >> 8))) << 8
        ^ table_pointer.unsafe_load(2048 + Int(UInt8(value)))
    )


@always_inline("nodebug")
def _cipher_static_fixed(
    value: UInt64,
    keys: InlineArray[UInt64, 7],
    tables: InlineArray[UInt64, 2304],
) -> UInt64:
    var state = value ^ keys[0]
    comptime for round in range(1, 6):
        state = _round_static(state, tables) ^ keys[round]
    return _last_static(state, tables) ^ keys[6]


@always_inline("nodebug")
def _cipher_static_keys(
    value: UInt64,
    keys: List[UInt64],
    tables: InlineArray[UInt64, 2304],
) -> UInt64:
    var key_pointer = Span(keys).unsafe_ptr()
    var state = value ^ key_pointer[unsafe_offset=0]
    comptime for round in range(1, 6):
        state = _round_static(state, tables) ^ key_pointer[unsafe_offset=round]
    return _last_static(state, tables) ^ key_pointer[unsafe_offset=6]


def prepare_tables(decrypt: Bool) -> List[UInt64]:
    # Preserve the selected transform without copying the 18 KiB immutable
    # table into every prepared cipher.
    return [UInt64(1) if decrypt else UInt64(0)]


def _expand_with_tables[
    decrypting: Bool, key_origin: Origin
](
    key: Span[UInt8, key_origin],
    tables: InlineArray[UInt64, 2304],
) raises -> List[UInt64]:
    var fixed = InlineArray[UInt64, 7](uninitialized=True)
    comptime for i in range(7):
        fixed[i] = materialize[_FIXED[i]]()
    fixed[6] = _transform[True](fixed[6])
    var keys = List[UInt64](length=7, fill=0)
    var key_pointer = Span(keys).unsafe_ptr()
    var key0 = load_be64(key, 0)
    var key1 = load_be64(key, 8)
    var feedback = UInt64(0)
    comptime for i in range(7):
        comptime if i % 2 == 0:
            feedback = key0 ^ _cipher_static_fixed(feedback, fixed, tables)
        else:
            feedback = key1 ^ _cipher_static_fixed(feedback, fixed, tables)
        key_pointer[unsafe_offset=i] = feedback
    key_pointer[unsafe_offset=6] = _transform[True](
        key_pointer[unsafe_offset=6]
    )
    comptime if decrypting:
        comptime for i in range(3):
            var temporary = key_pointer[unsafe_offset=i]
            key_pointer[unsafe_offset=i] = key_pointer[unsafe_offset=6 - i]
            key_pointer[unsafe_offset=6 - i] = temporary
        comptime for i in range(1, 6):
            key_pointer[unsafe_offset=i] = _transform[True](
                key_pointer[unsafe_offset=i]
            )
    return keys^


def _expand[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> List[UInt64]:
    ref tables = global_constant[_ENCRYPT_TABLES]()
    if decrypt:
        return _expand_with_tables[True](key, tables)
    return _expand_with_tables[False](key, tables)


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> List[UInt64]:
    if len(key) != 16:
        raise Error("SHARK requires a 16-byte key")
    return _expand(key, decrypt)


def process_prepared_tables_into[
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt64],
    tables: List[UInt64],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 7 or len(tables) != 1 or len(block) != 8:
        raise Error("SHARK requires a prepared key, mode, and 8-byte block")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("SHARK output span is too short")
    var value: UInt64
    if tables[0] != 0:
        ref constant_tables = global_constant[_DECRYPT_TABLES]()
        value = _cipher_static_keys(load_be64(block, 0), keys, constant_tables)
    else:
        ref constant_tables = global_constant[_ENCRYPT_TABLES]()
        value = _cipher_static_keys(load_be64(block, 0), keys, constant_tables)
    store_be64(value, output, output_offset)


def process_prepared_tables[
    block_origin: Origin
](
    keys: List[UInt64],
    tables: List[UInt64],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared_tables_into(keys, tables, block, Span(output), 0)
    return output^


def _process_static[
    decrypting: Bool,
    block_origin: Origin,
](keys: List[UInt64], block: Span[UInt8, block_origin],) raises -> List[UInt8]:
    if len(keys) != 7 or len(block) != 8:
        raise Error("SHARK requires a prepared key, tables, and 8-byte block")
    comptime values = (_DECRYPT_TABLES if decrypting else _ENCRYPT_TABLES)
    ref tables = global_constant[values]()
    var output = List[UInt8](length=8, fill=0)
    store_be64(
        _cipher_static_keys(load_be64(block, 0), keys, tables),
        Span(output),
        0,
    )
    return output^


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt64],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if decrypt:
        return _process_static[True](keys, block)
    return _process_static[False](keys, block)


def _process_one_shot[
    decrypting: Bool,
    key_origin: Origin,
    block_origin: Origin,
](
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(key) != 16:
        raise Error("SHARK requires a 16-byte key")
    ref encryption_tables = global_constant[_ENCRYPT_TABLES]()
    var keys = _expand_with_tables[decrypting](key, encryption_tables)
    if len(block) != 8:
        raise Error("SHARK requires a prepared key, tables, and 8-byte block")
    var output = List[UInt8](length=8, fill=0)
    comptime if decrypting:
        ref decryption_tables = global_constant[_DECRYPT_TABLES]()
        store_be64(
            _cipher_static_keys(load_be64(block, 0), keys, decryption_tables),
            Span(output),
            0,
        )
    else:
        store_be64(
            _cipher_static_keys(load_be64(block, 0), keys, encryption_tables),
            Span(output),
            0,
        )
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if decrypt:
        return _process_one_shot[True](key, block)
    return _process_one_shot[False](key, block)
