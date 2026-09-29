"""Threefish-256, Threefish-512, and Threefish-1024 block ciphers."""

from std.bit import rotate_bits_left, rotate_bits_right
from ..internal.bytes import load_le64, store_le64


comptime _ROTATION_256: InlineArray[Int, 16] = [
    14,
    16,
    52,
    57,
    23,
    40,
    5,
    37,
    25,
    33,
    46,
    12,
    58,
    22,
    32,
    32,
]
comptime _ROTATION_512: InlineArray[Int, 32] = [
    46,
    36,
    19,
    37,
    33,
    27,
    14,
    42,
    17,
    49,
    36,
    39,
    44,
    9,
    54,
    56,
    39,
    30,
    34,
    24,
    13,
    50,
    10,
    17,
    25,
    29,
    39,
    43,
    8,
    35,
    56,
    22,
]
comptime _ROTATION_1024: InlineArray[Int, 64] = [
    24,
    13,
    8,
    47,
    8,
    17,
    22,
    37,
    38,
    19,
    10,
    55,
    49,
    18,
    23,
    52,
    33,
    4,
    51,
    13,
    34,
    41,
    59,
    17,
    5,
    20,
    48,
    41,
    47,
    28,
    16,
    25,
    41,
    9,
    37,
    31,
    12,
    47,
    44,
    30,
    16,
    34,
    56,
    51,
    4,
    53,
    42,
    41,
    31,
    44,
    47,
    46,
    19,
    42,
    44,
    25,
    9,
    48,
    35,
    52,
    23,
    31,
    37,
    20,
]


@always_inline("nodebug")
def _rol[amount: Int](value: UInt64) -> UInt64:
    return rotate_bits_left[amount](value)


@always_inline("nodebug")
def _ror[amount: Int](value: UInt64) -> UInt64:
    return rotate_bits_right[amount](value)


@always_inline("nodebug")
def _rotation[words: Int, row: Int, pair: Int]() -> Int:
    comptime if words == 4:
        return materialize[_ROTATION_256]()[row * 2 + pair]
    elif words == 8:
        return materialize[_ROTATION_512]()[row * 4 + pair]
    else:
        return materialize[_ROTATION_1024]()[row * 8 + pair]


@always_inline("nodebug")
def _permute_in_place[
    words: Int, inverse: Bool
](mut state: InlineArray[UInt64, words]):
    comptime if words == 4:
        var saved = state[1]
        state[1] = state[3]
        state[3] = saved
    elif words == 8:
        var saved0 = state[0]
        var saved3 = state[3]
        comptime if inverse:
            state[0] = state[6]
            state[6] = state[4]
            state[4] = state[2]
            state[2] = saved0
        else:
            state[0] = state[2]
            state[2] = state[4]
            state[4] = state[6]
            state[6] = saved0
        state[3] = state[7]
        state[7] = saved3
    else:
        var saved1 = state[1]
        var saved3 = state[3]
        var saved4 = state[4]
        var saved8 = state[8]
        comptime if inverse:
            state[1] = state[15]
            state[15] = state[7]
            state[7] = state[9]
            state[9] = saved1
            state[3] = state[11]
            state[11] = state[5]
            state[5] = state[13]
            state[13] = saved3
            state[8] = state[14]
            state[14] = state[12]
            state[12] = state[10]
            state[10] = saved8
        else:
            state[1] = state[9]
            state[9] = state[7]
            state[7] = state[15]
            state[15] = saved1
            state[3] = state[13]
            state[13] = state[5]
            state[5] = state[11]
            state[11] = saved3
            state[8] = state[10]
            state[10] = state[12]
            state[12] = state[14]
            state[14] = saved8
        state[4] = state[6]
        state[6] = saved4


@always_inline("nodebug")
def _subkey[
    words: Int, key_words: Int, step: Int, subtract: Bool
](
    mut state: InlineArray[UInt64, words],
    key: InlineArray[UInt64, key_words],
    tweak: InlineArray[UInt64, 3],
):
    comptime for i in range(words):
        comptime key_index = (step + i) % (words + 1)
        var value = key[key_index]
        comptime if i == words - 3:
            value += tweak[step % 3]
        elif i == words - 2:
            value += tweak[(step + 1) % 3]
        elif i == words - 1:
            value += UInt64(step)
        comptime if subtract:
            state[i] -= value
        else:
            state[i] += value


def _prepare_width[
    words: Int, key_origin: Origin, tweak_origin: Origin
](
    key_bytes: Span[UInt8, key_origin],
    tweak_bytes: Span[UInt8, tweak_origin],
) raises -> Tuple[InlineArray[UInt64, 17], InlineArray[UInt64, 3], Int]:
    var key = InlineArray[UInt64, 17](fill=0)
    var parity = UInt64(0x1BD11BDAA9FC1A22)
    comptime for i in range(words):
        var word = load_le64(key_bytes, i * 8)
        key[i] = word
        parity ^= word
    key[words] = parity
    var tweak = InlineArray[UInt64, 3](uninitialized=True)
    tweak[0] = load_le64(tweak_bytes, 0)
    tweak[1] = load_le64(tweak_bytes, 8)
    tweak[2] = tweak[0] ^ tweak[1]
    return (key.copy(), tweak.copy(), words)


def prepare[
    key_origin: Origin, tweak_origin: Origin
](
    key_bytes: Span[UInt8, key_origin],
    tweak_bytes: Span[UInt8, tweak_origin],
) raises -> Tuple[InlineArray[UInt64, 17], InlineArray[UInt64, 3], Int]:
    var words = len(key_bytes) // 8
    if words != 4 and words != 8 and words != 16:
        raise Error("Threefish key must be 32, 64, or 128 bytes")
    if len(tweak_bytes) != 16:
        raise Error("Threefish tweak must be 16 bytes")
    if words == 4:
        return _prepare_width[4](key_bytes, tweak_bytes)
    if words == 8:
        return _prepare_width[8](key_bytes, tweak_bytes)
    return _prepare_width[16](key_bytes, tweak_bytes)


def _process_kernel[
    words: Int,
    key_words: Int,
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    key: InlineArray[UInt64, key_words],
    tweak: InlineArray[UInt64, 3],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    var state = InlineArray[UInt64, words](uninitialized=True)
    comptime for i in range(words):
        state[i] = load_le64(block, i * 8)
    comptime rounds = 80 if words == 16 else 72
    comptime if decrypt:
        comptime for offset in range(rounds):
            comptime round = rounds - 1 - offset
            comptime if (round + 1) % 4 == 0:
                _subkey[words, key_words, (round + 1) // 4, True](
                    state, key, tweak
                )
            _permute_in_place[words, True](state)
            comptime for pair in range(words // 2):
                comptime index = 2 * pair
                var a = state[index]
                var b = _ror[_rotation[words, round % 8, pair]()](
                    state[index + 1] ^ a
                )
                state[index] = a - b
                state[index + 1] = b
        _subkey[words, key_words, 0, True](state, key, tweak)
    else:
        _subkey[words, key_words, 0, False](state, key, tweak)
        comptime for round in range(rounds):
            comptime for pair in range(words // 2):
                comptime index = 2 * pair
                state[index] += state[index + 1]
                state[index + 1] = (
                    _rol[_rotation[words, round % 8, pair]()](state[index + 1])
                    ^ state[index]
                )
            _permute_in_place[words, False](state)
            comptime if (round + 1) % 4 == 0:
                _subkey[words, key_words, (round + 1) // 4, False](
                    state, key, tweak
                )
    comptime for i in range(words):
        store_le64(state[i], output, output_offset + i * 8)


def process_prepared_into[
    words: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    decrypt: Bool,
    key: InlineArray[UInt64, 17],
    tweak: InlineArray[UInt64, 3],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != words * 8:
        raise Error("Threefish block has invalid length")
    if output_offset < 0 or output_offset + words * 8 > len(output):
        raise Error("Threefish output span is too short")
    if decrypt:
        _process_kernel[words, 17, True](
            key, tweak, block, output, output_offset
        )
    else:
        _process_kernel[words, 17, False](
            key, tweak, block, output, output_offset
        )


def process_prepared[
    words: Int, block_origin: Origin
](
    decrypt: Bool,
    key: InlineArray[UInt64, 17],
    tweak: InlineArray[UInt64, 3],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != words * 8:
        raise Error("Threefish block has invalid length")
    var output = List[UInt8](length=words * 8, fill=0)
    if decrypt:
        _process_kernel[words, 17, True](key, tweak, block, Span(output), 0)
    else:
        _process_kernel[words, 17, False](key, tweak, block, Span(output), 0)
    return output^


def _process_width[
    words: Int,
    key_origin: Origin,
    tweak_origin: Origin,
    block_origin: Origin,
](
    decrypt: Bool,
    key_bytes: Span[UInt8, key_origin],
    tweak_bytes: Span[UInt8, tweak_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != words * 8:
        raise Error("Threefish block has invalid length")
    var key = InlineArray[UInt64, words + 1](uninitialized=True)
    var parity = UInt64(0x1BD11BDAA9FC1A22)
    comptime for i in range(words):
        var word = load_le64(key_bytes, i * 8)
        key[i] = word
        parity ^= word
    key[words] = parity
    var tweak = InlineArray[UInt64, 3](uninitialized=True)
    tweak[0] = load_le64(tweak_bytes, 0)
    tweak[1] = load_le64(tweak_bytes, 8)
    tweak[2] = tweak[0] ^ tweak[1]
    var output = List[UInt8](length=words * 8, fill=0)
    comptime key_words = words + 1
    if decrypt:
        _process_kernel[words, key_words, True](
            key, tweak, block, Span(output), 0
        )
    else:
        _process_kernel[words, key_words, False](
            key, tweak, block, Span(output), 0
        )
    return output^


def process[
    key_origin: Origin, tweak_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key_bytes: Span[UInt8, key_origin],
    tweak_bytes: Span[UInt8, tweak_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var words = len(key_bytes) // 8
    if words != 4 and words != 8 and words != 16:
        raise Error("Threefish key must be 32, 64, or 128 bytes")
    if len(tweak_bytes) != 16:
        raise Error("Threefish tweak must be 16 bytes")
    if words == 4:
        return _process_width[4](decrypt, key_bytes, tweak_bytes, block)
    if words == 8:
        return _process_width[8](decrypt, key_bytes, tweak_bytes, block)
    return _process_width[16](decrypt, key_bytes, tweak_bytes, block)
