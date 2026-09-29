"""Serpent 128-bit block cipher in pure Mojo."""

from ..internal.bytes import load_le32, store_le32
from std.bit import rotate_bits_left


comptime _SBOX: InlineArray[UInt8, 128] = [
    3,
    8,
    15,
    1,
    10,
    6,
    5,
    11,
    14,
    13,
    4,
    2,
    7,
    0,
    9,
    12,
    15,
    12,
    2,
    7,
    9,
    0,
    5,
    10,
    1,
    11,
    14,
    8,
    6,
    13,
    3,
    4,
    8,
    6,
    7,
    9,
    3,
    12,
    10,
    15,
    13,
    1,
    14,
    4,
    0,
    11,
    5,
    2,
    0,
    15,
    11,
    8,
    12,
    9,
    6,
    3,
    13,
    1,
    2,
    4,
    10,
    7,
    5,
    14,
    1,
    15,
    8,
    3,
    12,
    0,
    11,
    6,
    2,
    5,
    4,
    10,
    9,
    14,
    7,
    13,
    15,
    5,
    2,
    11,
    4,
    10,
    9,
    12,
    0,
    3,
    14,
    8,
    13,
    6,
    7,
    1,
    7,
    2,
    12,
    5,
    8,
    4,
    6,
    11,
    14,
    9,
    1,
    15,
    13,
    3,
    10,
    0,
    1,
    13,
    15,
    0,
    14,
    8,
    2,
    11,
    7,
    4,
    12,
    10,
    9,
    3,
    5,
    6,
]

comptime _ISBOX: InlineArray[UInt8, 128] = [
    13,
    3,
    11,
    0,
    10,
    6,
    5,
    12,
    1,
    14,
    4,
    7,
    15,
    9,
    8,
    2,
    5,
    8,
    2,
    14,
    15,
    6,
    12,
    3,
    11,
    4,
    7,
    9,
    1,
    13,
    10,
    0,
    12,
    9,
    15,
    4,
    11,
    14,
    1,
    2,
    0,
    3,
    6,
    13,
    5,
    8,
    10,
    7,
    0,
    9,
    10,
    7,
    11,
    14,
    6,
    13,
    3,
    5,
    12,
    2,
    4,
    8,
    15,
    1,
    5,
    0,
    8,
    3,
    10,
    9,
    7,
    14,
    2,
    12,
    11,
    6,
    4,
    15,
    13,
    1,
    8,
    15,
    2,
    9,
    4,
    1,
    13,
    14,
    11,
    6,
    5,
    3,
    7,
    12,
    10,
    0,
    15,
    10,
    1,
    13,
    5,
    3,
    6,
    0,
    4,
    9,
    14,
    7,
    2,
    12,
    8,
    11,
    3,
    0,
    6,
    13,
    9,
    14,
    15,
    8,
    5,
    12,
    11,
    7,
    10,
    1,
    4,
    2,
]
comptime _SBOX_ANF: InlineArray[UInt16, 64] = [
    0x61FB,
    0x64E3,
    0x45AC,
    0x0316,
    0x7247,
    0x6D3B,
    0x011D,
    0x6B25,
    0x0134,
    0x3AD6,
    0x3D46,
    0x0497,
    0x7346,
    0x3A26,
    0x0D9A,
    0x31BE,
    0x071D,
    0x7562,
    0x5CDA,
    0x0E56,
    0x071D,
    0x1D1B,
    0x7925,
    0x2397,
    0x49F7,
    0x0215,
    0x5CDB,
    0x51BC,
    0x7619,
    0x2B7C,
    0x4F96,
    0x02B6,
    0x7E59,
    0x6436,
    0x011F,
    0x7943,
    0x648F,
    0x6794,
    0x21E7,
    0x0512,
    0x0456,
    0x3A1C,
    0x2F1B,
    0x21C9,
    0x4752,
    0x63D4,
    0x3E68,
    0x1AB6,
    0x3B17,
    0x2338,
    0x0DBF,
    0x1A1C,
    0x0942,
    0x0BE6,
    0x2C1A,
    0x029D,
    0x49EB,
    0x0135,
    0x5C47,
    0x5BDD,
    0x5C47,
    0x6753,
    0x3924,
    0x0E98,
]


@always_inline("nodebug")
def _rol(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


@always_inline("nodebug")
def _ror(x: UInt32, n: Int) -> UInt32:
    return (x >> UInt32(n)) | (x << UInt32(32 - n))


@always_inline("nodebug")
def _sub[box: Int, inverse: Bool](mut words: InlineArray[UInt32, 4]):
    var input = words.copy()
    comptime table_offset = 32 if inverse else 0
    comptime for output_bit in range(4):
        comptime mask_index = table_offset + box * 4 + output_bit
        var result = UInt32(0)
        comptime if _SBOX_ANF[mask_index] & 1:
            result = ~result
        comptime for monomial in range(1, 16):
            comptime if (_SBOX_ANF[mask_index] >> UInt16(monomial)) & 1:
                var term = ~UInt32(0)
                comptime for input_bit in range(4):
                    comptime if monomial & (1 << input_bit):
                        term &= input[input_bit]
                result ^= term
        words[output_bit] = result


@always_inline("nodebug")
def _linear(mut words: InlineArray[UInt32, 4]):
    var x0 = _rol(words[0], 13)
    var x2 = _rol(words[2], 3)
    var x1 = words[1] ^ x0 ^ x2
    var x3 = words[3] ^ x2 ^ (x0 << 3)
    x1 = _rol(x1, 1)
    x3 = _rol(x3, 7)
    x0 ^= x1 ^ x3

    x2 ^= x3 ^ (x1 << 7)
    words[0] = _rol(x0, 5)
    words[1] = x1
    words[2] = _rol(x2, 22)
    words[3] = x3


@always_inline("nodebug")
def _inverse_linear(mut words: InlineArray[UInt32, 4]):
    var x2 = _ror(words[2], 22)
    var x0 = _ror(words[0], 5)
    x2 ^= words[3] ^ (words[1] << 7)
    x0 ^= words[1] ^ words[3]
    var x3 = _ror(words[3], 7)
    var x1 = _ror(words[1], 1)
    x3 ^= x2 ^ (x0 << 3)
    x1 ^= x0 ^ x2
    words[0] = _ror(x0, 13)
    words[1] = x1
    words[2] = _ror(x2, 3)
    words[3] = x3


@always_inline("nodebug")
def _sub_eight[
    box: Int, inverse: Bool
](mut words: InlineArray[SIMD[DType.uint32, 8], 4]):
    var input = words.copy()
    comptime table_offset = 32 if inverse else 0
    comptime for output_bit in range(4):
        comptime mask_index = table_offset + box * 4 + output_bit
        var result = SIMD[DType.uint32, 8](0)
        comptime if _SBOX_ANF[mask_index] & 1:
            result = ~result
        comptime for monomial in range(1, 16):
            comptime if (_SBOX_ANF[mask_index] >> UInt16(monomial)) & 1:
                var term = ~SIMD[DType.uint32, 8](0)
                comptime for input_bit in range(4):
                    comptime if monomial & (1 << input_bit):
                        term &= input[input_bit]
                result ^= term
        words[output_bit] = result


@always_inline("nodebug")
def _linear_eight(mut words: InlineArray[SIMD[DType.uint32, 8], 4]):
    var x0 = rotate_bits_left[13](words[0])
    var x2 = rotate_bits_left[3](words[2])
    var x1 = words[1] ^ x0 ^ x2
    var x3 = words[3] ^ x2 ^ (x0 << 3)
    x1 = rotate_bits_left[1](x1)
    x3 = rotate_bits_left[7](x3)
    x0 ^= x1 ^ x3
    x2 ^= x3 ^ (x1 << 7)
    words[0] = rotate_bits_left[5](x0)
    words[1] = x1
    words[2] = rotate_bits_left[22](x2)
    words[3] = x3


@always_inline("nodebug")
def _inverse_linear_eight(mut words: InlineArray[SIMD[DType.uint32, 8], 4]):
    var x2 = rotate_bits_left[10](words[2])
    var x0 = rotate_bits_left[27](words[0])
    x2 ^= words[3] ^ (words[1] << 7)
    x0 ^= words[1] ^ words[3]
    var x3 = rotate_bits_left[25](words[3])
    var x1 = rotate_bits_left[31](words[1])
    x3 ^= x2 ^ (x0 << 3)
    x1 ^= x0 ^ x2
    words[0] = rotate_bits_left[19](x0)
    words[1] = x1
    words[2] = rotate_bits_left[29](x2)
    words[3] = x3


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("Serpent key must be 16, 24, or 32 bytes")
    var padded = List[UInt8](length=32, fill=0)
    for i in range(len(key)):
        padded[i] = key[i]
    if len(key) < 32:
        padded[len(key)] = 1
    var w = List[UInt32](length=140, fill=0)
    for i in range(8):
        w[i] = load_le32(Span(padded), 4 * i)
    for i in range(132):
        w[i + 8] = _rol(
            w[i]
            ^ w[i + 3]
            ^ w[i + 5]
            ^ w[i + 7]
            ^ UInt32(0x9E3779B9)
            ^ UInt32(i),
            11,
        )
    var keys = List[UInt32](capacity=132)
    comptime for round in range(33):
        var group = InlineArray[UInt32, 4](
            w[8 + 4 * round],
            w[9 + 4 * round],
            w[10 + 4 * round],
            w[11 + 4 * round],
            __list_literal__=None,
        )
        _sub[(3 - round) % 8, False](group)
        comptime for lane in range(4):
            keys.append(group[lane])
    return keys^


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    """Encrypt or decrypt one 16-byte block using a prepared key."""
    if len(block) != 16:
        raise Error("Serpent block must be 16 bytes")
    var state = InlineArray[UInt32, 4](
        load_le32(block, 0),
        load_le32(block, 4),
        load_le32(block, 8),
        load_le32(block, 12),
        __list_literal__=None,
    )
    if not decrypt:
        comptime for round in range(32):
            comptime for lane in range(4):
                state[lane] ^= keys[4 * round + lane]
            _sub[round % 8, False](state)
            comptime if round != 31:
                _linear(state)
        comptime for lane in range(4):
            state[lane] ^= keys[128 + lane]
    else:
        comptime for lane in range(4):
            state[lane] ^= keys[128 + lane]
        comptime for step in range(32):
            comptime round = 31 - step
            comptime if round != 31:
                _inverse_linear(state)
            _sub[round % 8, True](state)
            comptime for lane in range(4):
                state[lane] ^= keys[4 * round + lane]
    var output = List[UInt8](length=16, fill=0)
    var output_span = Span(output)
    for lane in range(4):
        store_le32(state[lane], output_span, 4 * lane)
    return output^


def process_eight[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    keys: List[UInt32],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 128:
        raise Error("eight Serpent blocks must total 128 bytes")
    if output_offset < 0 or output_offset + 128 > len(output):
        raise Error("Serpent output span is too short")
    var state = InlineArray[SIMD[DType.uint32, 8], 4](
        fill=SIMD[DType.uint32, 8](0)
    )
    comptime for lane in range(8):
        comptime for word in range(4):
            state[word][lane] = load_le32(blocks, lane * 16 + word * 4)
    if not decrypt:
        comptime for round in range(32):
            comptime for word in range(4):
                state[word] ^= keys[4 * round + word]
            _sub_eight[round % 8, False](state)
            comptime if round != 31:
                _linear_eight(state)
        comptime for word in range(4):
            state[word] ^= keys[128 + word]
    else:
        comptime for word in range(4):
            state[word] ^= keys[128 + word]
        comptime for step in range(32):
            comptime round = 31 - step
            comptime if round != 31:
                _inverse_linear_eight(state)
            _sub_eight[round % 8, True](state)
            comptime for word in range(4):
                state[word] ^= keys[4 * round + word]
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        comptime for word in range(4):
            var value = UInt32(state[word][lane])
            comptime for byte in range(4):
                output_pointer.unsafe_store(
                    output_offset + lane * 16 + word * 4 + byte,
                    UInt8(value >> UInt32(byte * 8)),
                )


def serpent_process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var keys = prepare(key)
    return process_prepared(decrypt, keys, block)


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    return serpent_process(decrypt, key, block)
