"""RFC 2268 RC2 block cipher in pure Mojo."""


comptime _PI: InlineArray[UInt8, 256] = [
    217,
    120,
    249,
    196,
    25,
    221,
    181,
    237,
    40,
    233,
    253,
    121,
    74,
    160,
    216,
    157,
    198,
    126,
    55,
    131,
    43,
    118,
    83,
    142,
    98,
    76,
    100,
    136,
    68,
    139,
    251,
    162,
    23,
    154,
    89,
    245,
    135,
    179,
    79,
    19,
    97,
    69,
    109,
    141,
    9,
    129,
    125,
    50,
    189,
    143,
    64,
    235,
    134,
    183,
    123,
    11,
    240,
    149,
    33,
    34,
    92,
    107,
    78,
    130,
    84,
    214,
    101,
    147,
    206,
    96,
    178,
    28,
    115,
    86,
    192,
    20,
    167,
    140,
    241,
    220,
    18,
    117,
    202,
    31,
    59,
    190,
    228,
    209,
    66,
    61,
    212,
    48,
    163,
    60,
    182,
    38,
    111,
    191,
    14,
    218,
    70,
    105,
    7,
    87,
    39,
    242,
    29,
    155,
    188,
    148,
    67,
    3,
    248,
    17,
    199,
    246,
    144,
    239,
    62,
    231,
    6,
    195,
    213,
    47,
    200,
    102,
    30,
    215,
    8,
    232,
    234,
    222,
    128,
    82,
    238,
    247,
    132,
    170,
    114,
    172,
    53,
    77,
    106,
    42,
    150,
    26,
    210,
    113,
    90,
    21,
    73,
    116,
    75,
    159,
    208,
    94,
    4,
    24,
    164,
    236,
    194,
    224,
    65,
    110,
    15,
    81,
    203,
    204,
    36,
    145,
    175,
    80,
    161,
    244,
    112,
    57,
    153,
    124,
    58,
    133,
    35,
    184,
    180,
    122,
    252,
    2,
    54,
    91,
    37,
    85,
    151,
    49,
    45,
    93,
    250,
    152,
    227,
    138,
    146,
    174,
    5,
    223,
    41,
    16,
    103,
    108,
    186,
    201,
    211,
    0,
    230,
    207,
    225,
    158,
    168,
    44,
    99,
    22,
    1,
    63,
    88,
    226,
    137,
    169,
    13,
    56,
    52,
    27,
    171,
    51,
    255,
    176,
    187,
    72,
    12,
    95,
    185,
    177,
    205,
    46,
    197,
    243,
    219,
    71,
    229,
    165,
    156,
    119,
    10,
    166,
    32,
    104,
    254,
    127,
    193,
    173,
]


@always_inline("nodebug")
def _rol16(value: UInt16, amount: Int) -> UInt16:
    return (value << UInt16(amount)) | (value >> UInt16(16 - amount))


@always_inline("nodebug")
def _ror16(value: UInt16, amount: Int) -> UInt16:
    return (value >> UInt16(amount)) | (value << UInt16(16 - amount))


def _schedule[
    key_origin: Origin
](key: Span[UInt8, key_origin], effective_bits: Int,) raises -> List[UInt16]:
    if len(key) < 1 or len(key) > 128:
        raise Error("RC2 key must contain 1 through 128 bytes")
    if effective_bits < 1 or effective_bits > 1024:
        raise Error("RC2 effective key length must be 1 through 1024 bits")
    var pi = materialize[_PI]()
    var expanded = List[UInt8](length=128, fill=0)
    for i in range(len(key)):
        expanded[i] = key[i]
    for i in range(len(key), 128):
        expanded[i] = pi[Int((expanded[i - 1] + expanded[i - len(key)]))]
    var effective_bytes = (effective_bits + 7) // 8
    var mask = UInt8(255 >> ((8 - (effective_bits % 8)) % 8))
    expanded[128 - effective_bytes] = pi[
        Int(expanded[128 - effective_bytes] & mask)
    ]
    for offset in range(128 - effective_bytes):
        var i = 127 - effective_bytes - offset
        expanded[i] = pi[Int(expanded[i + 1] ^ expanded[i + effective_bytes])]
    var words = List[UInt16](length=64, fill=0)
    for i in range(64):
        words[i] = UInt16(expanded[2 * i]) | (UInt16(expanded[2 * i + 1]) << 8)
    return words^


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], effective_bits: Int = 1024) raises -> List[
    UInt16
]:
    return _schedule(key, effective_bits)


def process_prepared_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt16],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 64:
        raise Error("invalid RC2 prepared key")
    if len(block) != 8:
        raise Error("RC2 block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("RC2 output span is too short")
    var r0 = UInt16(block[0]) | (UInt16(block[1]) << 8)
    var r1 = UInt16(block[2]) | (UInt16(block[3]) << 8)
    var r2 = UInt16(block[4]) | (UInt16(block[5]) << 8)
    var r3 = UInt16(block[6]) | (UInt16(block[7]) << 8)
    comptime if decrypt:
        comptime for offset in range(16):
            comptime round = 15 - offset
            comptime if round == 4 or round == 10:
                r3 -= keys[Int(r2 & 63)]
                r2 -= keys[Int(r1 & 63)]
                r1 -= keys[Int(r0 & 63)]
                r0 -= keys[Int(r3 & 63)]
            r3 = _ror16(r3, 5)
            r3 -= (r0 & ~r2) + (r1 & r2) + keys[4 * round + 3]
            r2 = _ror16(r2, 3)
            r2 -= (r3 & ~r1) + (r0 & r1) + keys[4 * round + 2]
            r1 = _ror16(r1, 2)
            r1 -= (r2 & ~r0) + (r3 & r0) + keys[4 * round + 1]
            r0 = _ror16(r0, 1)
            r0 -= (r1 & ~r3) + (r2 & r3) + keys[4 * round]
    else:
        comptime for round in range(16):
            r0 += (r1 & ~r3) + (r2 & r3) + keys[4 * round]
            r0 = _rol16(r0, 1)
            r1 += (r2 & ~r0) + (r3 & r0) + keys[4 * round + 1]
            r1 = _rol16(r1, 2)
            r2 += (r3 & ~r1) + (r0 & r1) + keys[4 * round + 2]
            r2 = _rol16(r2, 3)
            r3 += (r0 & ~r2) + (r1 & r2) + keys[4 * round + 3]
            r3 = _rol16(r3, 5)
            comptime if round == 4 or round == 10:
                r0 += keys[Int(r3 & 63)]
                r1 += keys[Int(r0 & 63)]
                r2 += keys[Int(r1 & 63)]
                r3 += keys[Int(r2 & 63)]
    var values: InlineArray[UInt16, 4] = [r0, r1, r2, r3]
    comptime for i in range(4):
        output[output_offset + 2 * i] = UInt8(values[i])
        output[output_offset + 2 * i + 1] = UInt8(values[i] >> 8)


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt16],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    if decrypt:
        process_prepared_into[True](keys, block, Span(output), 0)
    else:
        process_prepared_into[False](keys, block, Span(output), 0)
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    effective_bits: Int = 1024,
) raises -> List[UInt8]:
    var keys = prepare(key, effective_bits)
    return process_prepared(decrypt, keys, block)
