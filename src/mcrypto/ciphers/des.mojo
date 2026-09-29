"""DES, DES-XEX3, and two- and three-key Triple-DES in pure Mojo."""

from ..internal.bytes import load_be64, store_be64
from .algorithm import BlockCipherAlgorithm
from .des_tables import SP


comptime _IP: InlineArray[UInt8, 64] = [
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    64,
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
]

comptime _FP: InlineArray[UInt8, 64] = [
    40,
    8,
    48,
    16,
    56,
    24,
    64,
    32,
    39,
    7,
    47,
    15,
    55,
    23,
    63,
    31,
    38,
    6,
    46,
    14,
    54,
    22,
    62,
    30,
    37,
    5,
    45,
    13,
    53,
    21,
    61,
    29,
    36,
    4,
    44,
    12,
    52,
    20,
    60,
    28,
    35,
    3,
    43,
    11,
    51,
    19,
    59,
    27,
    34,
    2,
    42,
    10,
    50,
    18,
    58,
    26,
    33,
    1,
    41,
    9,
    49,
    17,
    57,
    25,
]

comptime _E: InlineArray[UInt8, 48] = [
    32,
    1,
    2,
    3,
    4,
    5,
    4,
    5,
    6,
    7,
    8,
    9,
    8,
    9,
    10,
    11,
    12,
    13,
    12,
    13,
    14,
    15,
    16,
    17,
    16,
    17,
    18,
    19,
    20,
    21,
    20,
    21,
    22,
    23,
    24,
    25,
    24,
    25,
    26,
    27,
    28,
    29,
    28,
    29,
    30,
    31,
    32,
    1,
]

comptime _P: InlineArray[UInt8, 32] = [
    16,
    7,
    20,
    21,
    29,
    12,
    28,
    17,
    1,
    15,
    23,
    26,
    5,
    18,
    31,
    10,
    2,
    8,
    24,
    14,
    32,
    27,
    3,
    9,
    19,
    13,
    30,
    6,
    22,
    11,
    4,
    25,
]

comptime _PC1: InlineArray[UInt8, 56] = [
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    60,
    52,
    44,
    36,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    28,
    20,
    12,
    4,
]

comptime _PC2: InlineArray[UInt8, 48] = [
    14,
    17,
    11,
    24,
    1,
    5,
    3,
    28,
    15,
    6,
    21,
    10,
    23,
    19,
    12,
    4,
    26,
    8,
    16,
    7,
    27,
    20,
    13,
    2,
    41,
    52,
    31,
    37,
    47,
    55,
    30,
    40,
    51,
    45,
    33,
    48,
    44,
    49,
    39,
    56,
    34,
    53,
    46,
    42,
    50,
    36,
    29,
    32,
]

comptime _SHIFTS: InlineArray[UInt8, 16] = [
    1,
    1,
    2,
    2,
    2,
    2,
    2,
    2,
    1,
    2,
    2,
    2,
    2,
    2,
    2,
    1,
]

comptime _SBOX: InlineArray[UInt8, 512] = [
    14,
    4,
    13,
    1,
    2,
    15,
    11,
    8,
    3,
    10,
    6,
    12,
    5,
    9,
    0,
    7,
    0,
    15,
    7,
    4,
    14,
    2,
    13,
    1,
    10,
    6,
    12,
    11,
    9,
    5,
    3,
    8,
    4,
    1,
    14,
    8,
    13,
    6,
    2,
    11,
    15,
    12,
    9,
    7,
    3,
    10,
    5,
    0,
    15,
    12,
    8,
    2,
    4,
    9,
    1,
    7,
    5,
    11,
    3,
    14,
    10,
    0,
    6,
    13,
    15,
    1,
    8,
    14,
    6,
    11,
    3,
    4,
    9,
    7,
    2,
    13,
    12,
    0,
    5,
    10,
    3,
    13,
    4,
    7,
    15,
    2,
    8,
    14,
    12,
    0,
    1,
    10,
    6,
    9,
    11,
    5,
    0,
    14,
    7,
    11,
    10,
    4,
    13,
    1,
    5,
    8,
    12,
    6,
    9,
    3,
    2,
    15,
    13,
    8,
    10,
    1,
    3,
    15,
    4,
    2,
    11,
    6,
    7,
    12,
    0,
    5,
    14,
    9,
    10,
    0,
    9,
    14,
    6,
    3,
    15,
    5,
    1,
    13,
    12,
    7,
    11,
    4,
    2,
    8,
    13,
    7,
    0,
    9,
    3,
    4,
    6,
    10,
    2,
    8,
    5,
    14,
    12,
    11,
    15,
    1,
    13,
    6,
    4,
    9,
    8,
    15,
    3,
    0,
    11,
    1,
    2,
    12,
    5,
    10,
    14,
    7,
    1,
    10,
    13,
    0,
    6,
    9,
    8,
    7,
    4,
    15,
    14,
    3,
    11,
    5,
    2,
    12,
    7,
    13,
    14,
    3,
    0,
    6,
    9,
    10,
    1,
    2,
    8,
    5,
    11,
    12,
    4,
    15,
    13,
    8,
    11,
    5,
    6,
    15,
    0,
    3,
    4,
    7,
    2,
    12,
    1,
    10,
    14,
    9,
    10,
    6,
    9,
    0,
    12,
    11,
    7,
    13,
    15,
    1,
    3,
    14,
    5,
    2,
    8,
    4,
    3,
    15,
    0,
    6,
    10,
    1,
    13,
    8,
    9,
    4,
    5,
    11,
    12,
    7,
    2,
    14,
    2,
    12,
    4,
    1,
    7,
    10,
    11,
    6,
    8,
    5,
    3,
    15,
    13,
    0,
    14,
    9,
    14,
    11,
    2,
    12,
    4,
    7,
    13,
    1,
    5,
    0,
    15,
    10,
    3,
    9,
    8,
    6,
    4,
    2,
    1,
    11,
    10,
    13,
    7,
    8,
    15,
    9,
    12,
    5,
    6,
    3,
    0,
    14,
    11,
    8,
    12,
    7,
    1,
    14,
    2,
    13,
    6,
    15,
    0,
    9,
    10,
    4,
    5,
    3,
    12,
    1,
    10,
    15,
    9,
    2,
    6,
    8,
    0,
    13,
    3,
    4,
    14,
    7,
    5,
    11,
    10,
    15,
    4,
    2,
    7,
    12,
    9,
    5,
    6,
    1,
    13,
    14,
    0,
    11,
    3,
    8,
    9,
    14,
    15,
    5,
    2,
    8,
    12,
    3,
    7,
    0,
    4,
    10,
    1,
    13,
    11,
    6,
    4,
    3,
    2,
    12,
    9,
    5,
    15,
    10,
    11,
    14,
    1,
    7,
    6,
    0,
    8,
    13,
    4,
    11,
    2,
    14,
    15,
    0,
    8,
    13,
    3,
    12,
    9,
    7,
    5,
    10,
    6,
    1,
    13,
    0,
    11,
    7,
    4,
    9,
    1,
    10,
    14,
    3,
    5,
    12,
    2,
    15,
    8,
    6,
    1,
    4,
    11,
    13,
    12,
    3,
    7,
    14,
    10,
    15,
    6,
    8,
    0,
    5,
    9,
    2,
    6,
    11,
    13,
    8,
    1,
    4,
    10,
    7,
    9,
    5,
    0,
    15,
    14,
    2,
    3,
    12,
    13,
    2,
    8,
    4,
    6,
    15,
    11,
    1,
    10,
    9,
    3,
    14,
    5,
    0,
    12,
    7,
    1,
    15,
    13,
    8,
    10,
    3,
    7,
    4,
    12,
    5,
    6,
    11,
    0,
    14,
    9,
    2,
    7,
    11,
    4,
    1,
    9,
    12,
    14,
    2,
    0,
    6,
    10,
    13,
    15,
    3,
    5,
    8,
    2,
    1,
    14,
    7,
    4,
    10,
    8,
    13,
    15,
    12,
    9,
    0,
    3,
    5,
    6,
    11,
]


@always_inline("nodebug")
def _permute[
    N: Int
](value: UInt64, input_bits: Int, table: Array[UInt8, N]) -> UInt64:
    var output = UInt64(0)
    comptime for i in range(N):
        output = (output << 1) | (
            (value >> UInt64(input_bits - Int(table[i]))) & 1
        )
    return output


@always_inline("nodebug")
def _rotl1(value: UInt32) -> UInt32:
    return (value << 1) | (value >> 31)


@always_inline("nodebug")
def _rotr1(value: UInt32) -> UInt32:
    return (value >> 1) | (value << 31)


@always_inline("nodebug")
def _initial_permute(value: UInt64) -> UInt64:
    var left = UInt32(value >> 32)
    var right = UInt32(value)
    var work = ((left >> 4) ^ right) & 0x0F0F0F0F
    right ^= work
    left ^= work << 4
    work = ((left >> 16) ^ right) & 0x0000FFFF
    right ^= work
    left ^= work << 16
    work = ((right >> 2) ^ left) & 0x33333333
    left ^= work
    right ^= work << 2
    work = ((right >> 8) ^ left) & 0x00FF00FF
    left ^= work
    right ^= work << 8
    right = _rotl1(right)
    work = (left ^ right) & 0xAAAAAAAA
    left ^= work
    right ^= work
    left = _rotl1(left)
    return (UInt64(_rotr1(left)) << 32) | UInt64(_rotr1(right))


@always_inline("nodebug")
def _final_permute(value: UInt64) -> UInt64:
    var left = _rotl1(UInt32(value))
    var right = _rotl1(UInt32(value >> 32))
    right = _rotr1(right)
    var work = (left ^ right) & 0xAAAAAAAA
    right ^= work
    left = (left >> 9) | (left << 23)
    left ^= (work >> 9) | (work << 23)
    work = (left ^ right) & 0x00FF00FF
    right ^= work
    left = ((left ^ work) << 6) | ((left ^ work) >> 26)
    work = (left ^ right) & 0x33333333
    right ^= work
    left = ((left ^ work) << 18) | ((left ^ work) >> 14)
    work = (left ^ right) & 0xFFFF0000
    right ^= work
    left = ((left ^ work) << 20) | ((left ^ work) >> 12)
    work = (left ^ right) & 0xF0F0F0F0
    right ^= work
    left = ((left ^ work) >> 4) | ((left ^ work) << 28)
    return (UInt64(right) << 32) | UInt64(left)


def _schedule(key: List[UInt8]) -> List[UInt64]:
    var pc1 = materialize[_PC1]()
    var pc2 = materialize[_PC2]()
    var shifts = materialize[_SHIFTS]()
    var word = UInt64(0)
    for byte in key:
        word = (word << 8) | UInt64(byte)
    var selected = _permute(word, 64, pc1)
    var c = UInt32((selected >> 28) & 0x0FFFFFFF)
    var d = UInt32(selected & 0x0FFFFFFF)
    var output = List[UInt64](capacity=16)
    for round in range(16):
        var shift = UInt32(shifts[round])
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        output.append(_permute((UInt64(c) << 28) | UInt64(d), 56, pc2))
    return output^


@always_inline("nodebug")
def _round_function(
    right: UInt32,
    subkey: UInt64,
    tables: InlineArray[UInt32, 512],
) -> UInt32:
    var table = Span(tables).unsafe_ptr()
    var output = table.unsafe_load(
        Int(
            (((right & 1) << 5) | ((right >> 27) & 31))
            ^ UInt32((subkey >> 42) & 63)
        )
    )
    comptime for box in range(1, 7):
        output |= table.unsafe_load(
            box * 64
            + Int(
                ((right >> UInt32(27 - 4 * box)) & 63)
                ^ UInt32((subkey >> UInt64(42 - 6 * box)) & 63)
            )
        )
    output |= table.unsafe_load(
        448 + Int((((right & 31) << 1) | (right >> 31)) ^ UInt32(subkey & 63))
    )
    return output


def _key_part[
    key_origin: Origin
](key: Span[UInt8, key_origin], offset: Int) -> List[UInt8]:
    var output = List[UInt8](capacity=8)
    comptime for i in range(8):
        output.append(key[offset + i])
    return output^


@always_inline("nodebug")
def _des_prepared[
    decrypting: Bool
](block: UInt64, keys: List[UInt64]) -> UInt64:
    var tables = materialize[SP]()
    var state = _initial_permute(block)
    var left = UInt32(state >> 32)
    var right = UInt32(state)
    comptime for round in range(16):
        comptime index = 15 - round if decrypting else round
        var next = left ^ _round_function(right, keys[index], tables)
        left = right
        right = next
    return _final_permute((UInt64(right) << 32) | UInt64(left))


def prepare[
    key_origin: Origin
](
    algorithm: BlockCipherAlgorithm, key: Span[UInt8, key_origin]
) raises -> Tuple[
    List[UInt64],
    List[UInt64],
    List[UInt64],
    UInt64,
    UInt64,
]:
    var required: Int
    if algorithm == BlockCipherAlgorithm.DES:
        required = 8
    elif algorithm == BlockCipherAlgorithm.DES_EDE2:
        required = 16
    elif (
        algorithm == BlockCipherAlgorithm.DES_EDE3
        or algorithm == BlockCipherAlgorithm.DES_XEX3
    ):
        required = 24
    else:
        raise Error("unknown DES family cipher")
    if len(key) != required:
        raise Error("DES family key must be " + String(required) + " bytes")
    var xex3 = algorithm == BlockCipherAlgorithm.DES_XEX3
    var first_offset = 8 if xex3 else 0
    var first = _schedule(_key_part(key, first_offset))
    var second = List[UInt64]()
    var third = List[UInt64]()
    if (
        algorithm == BlockCipherAlgorithm.DES_EDE2
        or algorithm == BlockCipherAlgorithm.DES_EDE3
    ):
        second = _schedule(_key_part(key, 8))
        third = _schedule(
            _key_part(
                key,
                0 if algorithm == BlockCipherAlgorithm.DES_EDE2 else 16,
            )
        )
    var whitening0 = load_be64(key, 0) if xex3 else UInt64(0)
    var whitening1 = load_be64(key, 16) if xex3 else UInt64(0)
    return (first^, second^, third^, whitening0, whitening1)


def process_prepared_into[
    block_origin: Origin, output_origin: MutOrigin
](
    algorithm: BlockCipherAlgorithm,
    decrypt: Bool,
    first: List[UInt64],
    second: List[UInt64],
    third: List[UInt64],
    whitening0: UInt64,
    whitening1: UInt64,
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 8:
        raise Error("DES family block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("DES family output span is too short")
    var value = load_be64(block, 0)
    if algorithm == BlockCipherAlgorithm.DES:
        value = _des_prepared[True](value, first) if decrypt else _des_prepared[
            False
        ](value, first)
    elif algorithm == BlockCipherAlgorithm.DES_XEX3:
        value ^= whitening1 if decrypt else whitening0
        value = _des_prepared[True](value, first) if decrypt else _des_prepared[
            False
        ](value, first)
        value ^= whitening0 if decrypt else whitening1
    elif decrypt:
        value = _des_prepared[True](value, third)
        value = _des_prepared[False](value, second)
        value = _des_prepared[True](value, first)
    else:
        value = _des_prepared[False](value, first)
        value = _des_prepared[True](value, second)
        value = _des_prepared[False](value, third)
    store_be64(value, output, output_offset)


def process_prepared[
    block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    decrypt: Bool,
    first: List[UInt64],
    second: List[UInt64],
    third: List[UInt64],
    whitening0: UInt64,
    whitening1: UInt64,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared_into(
        algorithm,
        decrypt,
        first,
        second,
        third,
        whitening0,
        whitening1,
        block,
        Span(output),
        0,
    )
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var schedule = prepare(algorithm, key)
    return process_prepared(
        algorithm,
        decrypt,
        schedule[0],
        schedule[1],
        schedule[2],
        schedule[3],
        schedule[4],
        block,
    )
