"""SAFER-K and SAFER-SK 64-bit block ciphers in pure Mojo.

Supported variants are ``safer_k`` and ``safer_sk``. Both accept 8- or
16-byte keys and an 8-byte block. Pass ``rounds=0`` to select the standard round count.
"""

from std.builtin.globals import global_constant


comptime _EXP: InlineArray[UInt8, 256] = [
    1,
    45,
    226,
    147,
    190,
    69,
    21,
    174,
    120,
    3,
    135,
    164,
    184,
    56,
    207,
    63,
    8,
    103,
    9,
    148,
    235,
    38,
    168,
    107,
    189,
    24,
    52,
    27,
    187,
    191,
    114,
    247,
    64,
    53,
    72,
    156,
    81,
    47,
    59,
    85,
    227,
    192,
    159,
    216,
    211,
    243,
    141,
    177,
    255,
    167,
    62,
    220,
    134,
    119,
    215,
    166,
    17,
    251,
    244,
    186,
    146,
    145,
    100,
    131,
    241,
    51,
    239,
    218,
    44,
    181,
    178,
    43,
    136,
    209,
    153,
    203,
    140,
    132,
    29,
    20,
    129,
    151,
    113,
    202,
    95,
    163,
    139,
    87,
    60,
    130,
    196,
    82,
    92,
    28,
    232,
    160,
    4,
    180,
    133,
    74,
    246,
    19,
    84,
    182,
    223,
    12,
    26,
    142,
    222,
    224,
    57,
    252,
    32,
    155,
    36,
    78,
    169,
    152,
    158,
    171,
    242,
    96,
    208,
    108,
    234,
    250,
    199,
    217,
    0,
    212,
    31,
    110,
    67,
    188,
    236,
    83,
    137,
    254,
    122,
    93,
    73,
    201,
    50,
    194,
    249,
    154,
    248,
    109,
    22,
    219,
    89,
    150,
    68,
    233,
    205,
    230,
    70,
    66,
    143,
    10,
    193,
    204,
    185,
    101,
    176,
    210,
    198,
    172,
    30,
    65,
    98,
    41,
    46,
    14,
    116,
    80,
    2,
    90,
    195,
    37,
    123,
    138,
    42,
    91,
    240,
    6,
    13,
    71,
    111,
    112,
    157,
    126,
    16,
    206,
    18,
    39,
    213,
    76,
    79,
    214,
    121,
    48,
    104,
    54,
    117,
    125,
    228,
    237,
    128,
    106,
    144,
    55,
    162,
    94,
    118,
    170,
    197,
    127,
    61,
    175,
    165,
    229,
    25,
    97,
    253,
    77,
    124,
    183,
    11,
    238,
    173,
    75,
    34,
    245,
    231,
    115,
    35,
    33,
    200,
    5,
    225,
    102,
    221,
    179,
    88,
    105,
    99,
    86,
    15,
    161,
    49,
    149,
    23,
    7,
    58,
    40,
]
comptime _LOG: InlineArray[UInt8, 256] = [
    128,
    0,
    176,
    9,
    96,
    239,
    185,
    253,
    16,
    18,
    159,
    228,
    105,
    186,
    173,
    248,
    192,
    56,
    194,
    101,
    79,
    6,
    148,
    252,
    25,
    222,
    106,
    27,
    93,
    78,
    168,
    130,
    112,
    237,
    232,
    236,
    114,
    179,
    21,
    195,
    255,
    171,
    182,
    71,
    68,
    1,
    172,
    37,
    201,
    250,
    142,
    65,
    26,
    33,
    203,
    211,
    13,
    110,
    254,
    38,
    88,
    218,
    50,
    15,
    32,
    169,
    157,
    132,
    152,
    5,
    156,
    187,
    34,
    140,
    99,
    231,
    197,
    225,
    115,
    198,
    175,
    36,
    91,
    135,
    102,
    39,
    247,
    87,
    244,
    150,
    177,
    183,
    92,
    139,
    213,
    84,
    121,
    223,
    170,
    246,
    62,
    163,
    241,
    17,
    202,
    245,
    209,
    23,
    123,
    147,
    131,
    188,
    189,
    82,
    30,
    235,
    174,
    204,
    214,
    53,
    8,
    200,
    138,
    180,
    226,
    205,
    191,
    217,
    208,
    80,
    89,
    63,
    77,
    98,
    52,
    10,
    72,
    136,
    181,
    86,
    76,
    46,
    107,
    158,
    210,
    61,
    60,
    3,
    19,
    251,
    151,
    81,
    117,
    74,
    145,
    113,
    35,
    190,
    118,
    42,
    95,
    249,
    212,
    85,
    11,
    220,
    55,
    49,
    22,
    116,
    215,
    119,
    167,
    230,
    7,
    219,
    164,
    47,
    70,
    243,
    97,
    69,
    103,
    227,
    12,
    162,
    59,
    28,
    133,
    24,
    4,
    29,
    41,
    160,
    143,
    178,
    90,
    216,
    166,
    126,
    238,
    141,
    83,
    75,
    161,
    154,
    193,
    14,
    122,
    73,
    165,
    44,
    129,
    196,
    199,
    54,
    43,
    127,
    67,
    149,
    51,
    242,
    108,
    104,
    109,
    240,
    2,
    40,
    206,
    221,
    155,
    234,
    94,
    153,
    124,
    20,
    134,
    207,
    229,
    66,
    184,
    64,
    120,
    45,
    58,
    233,
    100,
    31,
    146,
    144,
    125,
    57,
    111,
    224,
    137,
    48,
]


@always_inline("nodebug")
def _rol8(value: UInt8, amount: Int) -> UInt8:
    return (value << UInt8(amount)) | (value >> UInt8(8 - amount))


@always_inline("nodebug")
def _pht(mut x: UInt8, mut y: UInt8) -> Tuple[UInt8, UInt8]:
    y += x
    x += y
    return (x, y)


@always_inline("nodebug")
def _ipht(mut x: UInt8, mut y: UInt8) -> Tuple[UInt8, UInt8]:
    x -= y
    y -= x
    return (x, y)


def _schedule[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    strengthened: Bool,
    rounds: Int,
) raises -> List[UInt8]:
    if len(key) != 8 and len(key) != 16:
        raise Error("SAFER key must be 8 or 16 bytes")
    if rounds < 1 or rounds > 13:
        raise Error("SAFER rounds must be between 1 and 13")
    ref exp = global_constant[_EXP]()
    var ka = List[UInt8](length=9, fill=0)
    var kb = List[UInt8](length=9, fill=0)
    var schedule = List[UInt8](capacity=8 + 16 * rounds)
    for j in range(8):
        ka[j] = _rol8(key[j], 5)
        ka[8] ^= ka[j]
        kb[j] = key[j if len(key) == 8 else j + 8]
        kb[8] ^= kb[j]
        schedule.append(kb[j])
    for i in range(1, rounds + 1):
        for j in range(9):
            ka[j] = _rol8(ka[j], 6)
            kb[j] = _rol8(kb[j], 6)
        for j in range(8):
            var source = (j + 2 * i - 1) % 9 if strengthened else j
            schedule.append(ka[source] + exp[Int(exp[18 * i + j + 1])])
        for j in range(8):
            var source = (j + 2 * i) % 9 if strengthened else j
            schedule.append(kb[source] + exp[Int(exp[18 * i + j + 10])])
    return schedule^


def prepare[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    strengthened: Bool = True,
    requested_rounds: Int = 0,
) raises -> Tuple[List[UInt8], Int]:
    var rounds = requested_rounds
    if rounds == 0:
        rounds = (8 if strengthened else 6) if len(key) == 8 else 10
    return (_schedule(key, strengthened, rounds), rounds)


def _process_prepared_value[
    decrypting: Bool,
    round_count: Int,
    block_origin: Origin,
](
    keys: List[UInt8],
    block: Span[UInt8, block_origin],
) raises -> InlineArray[
    UInt8, 8
]:
    if len(block) != 8:
        raise Error("SAFER block must be 8 bytes")
    if len(keys) != 8 + 16 * round_count:
        raise Error("invalid SAFER prepared key")
    ref exp = global_constant[_EXP]()
    ref log = global_constant[_LOG]()
    var a = block[0]
    var b = block[1]
    var c = block[2]
    var d = block[3]
    var e = block[4]
    var f = block[5]
    var g = block[6]
    var h = block[7]
    comptime if decrypting:
        var base = 16 * round_count
        h ^= keys[base + 7]
        g -= keys[base + 6]
        f -= keys[base + 5]
        e ^= keys[base + 4]
        d ^= keys[base + 3]
        c -= keys[base + 2]
        b -= keys[base + 1]
        a ^= keys[base]
        comptime for offset in range(round_count):
            comptime round = round_count - 1 - offset
            base = 16 * round
            var t = e
            e = b
            b = c
            c = t
            t = f
            f = d
            d = g
            g = t
            a, e = _ipht(a, e)
            b, f = _ipht(b, f)
            c, g = _ipht(c, g)
            d, h = _ipht(d, h)
            a, c = _ipht(a, c)
            e, g = _ipht(e, g)
            b, d = _ipht(b, d)
            f, h = _ipht(f, h)
            a, b = _ipht(a, b)
            c, d = _ipht(c, d)
            e, f = _ipht(e, f)
            g, h = _ipht(g, h)
            h -= keys[base + 15]
            g ^= keys[base + 14]
            f ^= keys[base + 13]
            e -= keys[base + 12]
            d -= keys[base + 11]
            c ^= keys[base + 10]
            b ^= keys[base + 9]
            a -= keys[base + 8]
            h = log[Int(h)] ^ keys[base + 7]
            g = exp[Int(g)] - keys[base + 6]
            f = exp[Int(f)] - keys[base + 5]
            e = log[Int(e)] ^ keys[base + 4]
            d = log[Int(d)] ^ keys[base + 3]
            c = exp[Int(c)] - keys[base + 2]
            b = exp[Int(b)] - keys[base + 1]
            a = log[Int(a)] ^ keys[base]
    else:
        comptime for round in range(round_count):
            comptime base = 16 * round
            a ^= keys[base]
            b += keys[base + 1]
            c += keys[base + 2]
            d ^= keys[base + 3]
            e ^= keys[base + 4]
            f += keys[base + 5]
            g += keys[base + 6]
            h ^= keys[base + 7]
            a = exp[Int(a)] + keys[base + 8]
            b = log[Int(b)] ^ keys[base + 9]
            c = log[Int(c)] ^ keys[base + 10]
            d = exp[Int(d)] + keys[base + 11]
            e = exp[Int(e)] + keys[base + 12]
            f = log[Int(f)] ^ keys[base + 13]
            g = log[Int(g)] ^ keys[base + 14]
            h = exp[Int(h)] + keys[base + 15]
            a, b = _pht(a, b)
            c, d = _pht(c, d)
            e, f = _pht(e, f)
            g, h = _pht(g, h)
            a, c = _pht(a, c)
            e, g = _pht(e, g)
            b, d = _pht(b, d)
            f, h = _pht(f, h)
            a, e = _pht(a, e)
            b, f = _pht(b, f)
            c, g = _pht(c, g)
            d, h = _pht(d, h)
            var t = b
            b = e
            e = c
            c = t
            t = d
            d = f
            f = g
            g = t
        comptime base = 16 * round_count
        a ^= keys[base]
        b += keys[base + 1]
        c += keys[base + 2]
        d ^= keys[base + 3]
        e ^= keys[base + 4]
        f += keys[base + 5]
        g += keys[base + 6]
        h ^= keys[base + 7]
    return [a, b, c, d, e, f, g, h]


@always_inline("nodebug")
def _lookup_eight(
    table: InlineArray[UInt8, 256],
    indices: SIMD[DType.uint8, 8],
) -> SIMD[DType.uint8, 8]:
    var output = SIMD[DType.uint8, 8](0)
    comptime for lane in range(8):
        output[lane] = table[Int(indices[lane])]
    return output


def process_eight_encrypt[
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt8],
    round_count: Int,
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    """Encrypt eight independent SAFER blocks in SIMD lanes."""
    if round_count < 1 or round_count > 13:
        raise Error("SAFER rounds must be between 1 and 13")
    if len(keys) != 8 + 16 * round_count:
        raise Error("invalid SAFER prepared key")
    if len(blocks) != 64:
        raise Error("eight SAFER blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SAFER output span is too short")
    var a = SIMD[DType.uint8, 8](0)
    var b = SIMD[DType.uint8, 8](0)
    var c = SIMD[DType.uint8, 8](0)
    var d = SIMD[DType.uint8, 8](0)
    var e = SIMD[DType.uint8, 8](0)
    var f = SIMD[DType.uint8, 8](0)
    var g = SIMD[DType.uint8, 8](0)
    var h = SIMD[DType.uint8, 8](0)
    comptime for lane in range(8):
        a[lane] = blocks[lane * 8]
        b[lane] = blocks[lane * 8 + 1]
        c[lane] = blocks[lane * 8 + 2]
        d[lane] = blocks[lane * 8 + 3]
        e[lane] = blocks[lane * 8 + 4]
        f[lane] = blocks[lane * 8 + 5]
        g[lane] = blocks[lane * 8 + 6]
        h[lane] = blocks[lane * 8 + 7]
    ref exp = global_constant[_EXP]()
    ref log = global_constant[_LOG]()
    for round in range(round_count):
        var base = 16 * round
        a ^= SIMD[DType.uint8, 8](keys[base])
        b += SIMD[DType.uint8, 8](keys[base + 1])
        c += SIMD[DType.uint8, 8](keys[base + 2])
        d ^= SIMD[DType.uint8, 8](keys[base + 3])
        e ^= SIMD[DType.uint8, 8](keys[base + 4])
        f += SIMD[DType.uint8, 8](keys[base + 5])
        g += SIMD[DType.uint8, 8](keys[base + 6])
        h ^= SIMD[DType.uint8, 8](keys[base + 7])
        a = _lookup_eight(exp, a) + SIMD[DType.uint8, 8](keys[base + 8])
        b = _lookup_eight(log, b) ^ SIMD[DType.uint8, 8](keys[base + 9])
        c = _lookup_eight(log, c) ^ SIMD[DType.uint8, 8](keys[base + 10])
        d = _lookup_eight(exp, d) + SIMD[DType.uint8, 8](keys[base + 11])
        e = _lookup_eight(exp, e) + SIMD[DType.uint8, 8](keys[base + 12])
        f = _lookup_eight(log, f) ^ SIMD[DType.uint8, 8](keys[base + 13])
        g = _lookup_eight(log, g) ^ SIMD[DType.uint8, 8](keys[base + 14])
        h = _lookup_eight(exp, h) + SIMD[DType.uint8, 8](keys[base + 15])
        b += a
        a += b
        d += c
        c += d
        f += e
        e += f
        h += g
        g += h
        c += a
        a += c
        g += e
        e += g
        d += b
        b += d
        h += f
        f += h
        e += a
        a += e
        f += b
        b += f
        g += c
        c += g
        h += d
        d += h
        var temporary = b
        b = e
        e = c
        c = temporary
        temporary = d
        d = f
        f = g
        g = temporary
    var base = 16 * round_count
    a ^= SIMD[DType.uint8, 8](keys[base])
    b += SIMD[DType.uint8, 8](keys[base + 1])
    c += SIMD[DType.uint8, 8](keys[base + 2])
    d ^= SIMD[DType.uint8, 8](keys[base + 3])
    e ^= SIMD[DType.uint8, 8](keys[base + 4])
    f += SIMD[DType.uint8, 8](keys[base + 5])
    g += SIMD[DType.uint8, 8](keys[base + 6])
    h ^= SIMD[DType.uint8, 8](keys[base + 7])
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        output_pointer.unsafe_store(output_offset + lane * 8, a[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 1, b[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 2, c[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 3, d[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 4, e[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 5, f[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 6, g[lane])
        output_pointer.unsafe_store(output_offset + lane * 8 + 7, h[lane])


def _dispatch_prepared[
    decrypting: Bool,
    block_origin: Origin,
](
    keys: List[UInt8],
    rounds: Int,
    block: Span[UInt8, block_origin],
) raises -> InlineArray[UInt8, 8]:
    if rounds == 1:
        return _process_prepared_value[decrypting, 1](keys, block)
    if rounds == 2:
        return _process_prepared_value[decrypting, 2](keys, block)
    if rounds == 3:
        return _process_prepared_value[decrypting, 3](keys, block)
    if rounds == 4:
        return _process_prepared_value[decrypting, 4](keys, block)
    if rounds == 5:
        return _process_prepared_value[decrypting, 5](keys, block)
    if rounds == 6:
        return _process_prepared_value[decrypting, 6](keys, block)
    if rounds == 7:
        return _process_prepared_value[decrypting, 7](keys, block)
    if rounds == 8:
        return _process_prepared_value[decrypting, 8](keys, block)
    if rounds == 9:
        return _process_prepared_value[decrypting, 9](keys, block)
    if rounds == 10:
        return _process_prepared_value[decrypting, 10](keys, block)
    if rounds == 11:
        return _process_prepared_value[decrypting, 11](keys, block)
    if rounds == 12:
        return _process_prepared_value[decrypting, 12](keys, block)
    if rounds == 13:
        return _process_prepared_value[decrypting, 13](keys, block)
    raise Error("SAFER rounds must be between 1 and 13")


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt8],
    rounds: Int,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var value = _dispatch_prepared[True](
        keys, rounds, block
    ) if decrypt else _dispatch_prepared[False](keys, rounds, block)
    var output = List[UInt8](capacity=8)
    for byte in value:
        output.append(byte)
    return output^


def process_prepared_into[
    block_origin: Origin,
    output_origin: MutOrigin,
](
    decrypt: Bool,
    keys: List[UInt8],
    rounds: Int,
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("SAFER output span is too short")
    var value = _dispatch_prepared[True](
        keys, rounds, block
    ) if decrypt else _dispatch_prepared[False](keys, rounds, block)
    comptime for i in range(8):
        output[output_offset + i] = value[i]


def _process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    strengthened: Bool,
    requested_rounds: Int,
) raises -> List[UInt8]:
    var prepared = prepare(key, strengthened, requested_rounds)
    return process_prepared(decrypt, prepared[0], prepared[1], block)


def safer_k[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    rounds: Int = 0,
) raises -> List[UInt8]:
    return _process(decrypt, key, block, False, rounds)


def safer_sk[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    rounds: Int = 0,
) raises -> List[UInt8]:
    return _process(decrypt, key, block, True, rounds)
