"""Sosemanuk synchronous stream cipher (Serpent24 setup)."""

from ..internal.bytes import load_le32, store_le32
from .serpent import _sub as _serpent_sub, _sub_eight as _serpent_sub_eight
from std.builtin.globals import global_constant
from std.bit import rotate_bits_left


@always_inline("nodebug")
def _rol(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


@always_inline("nodebug")
def _sub(mut words: InlineArray[UInt32, 4], box: Int):
    if box == 0:
        _serpent_sub[0, False](words)
    elif box == 1:
        _serpent_sub[1, False](words)
    elif box == 2:
        _serpent_sub[2, False](words)
    elif box == 3:
        _serpent_sub[3, False](words)
    elif box == 4:
        _serpent_sub[4, False](words)
    elif box == 5:
        _serpent_sub[5, False](words)
    elif box == 6:
        _serpent_sub[6, False](words)
    else:
        _serpent_sub[7, False](words)


def _linear(words: InlineArray[UInt32, 4]) -> InlineArray[UInt32, 4]:
    var x0 = _rol(words[0], 13)
    var x2 = _rol(words[2], 3)
    var x1 = words[1] ^ x0 ^ x2
    var x3 = words[3] ^ x2 ^ (x0 << 3)
    x1 = _rol(x1, 1)
    x3 = _rol(x3, 7)
    x0 ^= x1 ^ x3
    x2 ^= x3 ^ (x1 << 7)
    x0 = _rol(x0, 5)
    x2 = _rol(x2, 22)
    var output: InlineArray[UInt32, 4] = [x0, x1, x2, x3]
    return output^


def _round_keys[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> InlineArray[UInt32, 100]:
    var padded = InlineArray[UInt8, 32](fill=0)
    for i in range(len(key)):
        padded[i] = key[i]
    if len(key) < 32:
        padded[len(key)] = 1
    var words = InlineArray[UInt32, 108](fill=0)
    for i in range(8):
        words[i] = load_le32(Span(padded), 4 * i)
    for i in range(100):
        words[i + 8] = _rol(
            words[i]
            ^ words[i + 3]
            ^ words[i + 5]
            ^ words[i + 7]
            ^ UInt32(0x9E3779B9)
            ^ UInt32(i),
            11,
        )
    var keys = InlineArray[UInt32, 100](fill=0)
    for round in range(25):
        var group: InlineArray[UInt32, 4] = [
            words[8 + 4 * round],
            words[9 + 4 * round],
            words[10 + 4 * round],
            words[11 + 4 * round],
        ]
        _sub(group, (3 - round) % 8)
        for lane in range(4):
            keys[4 * round + lane] = group[lane]
    return keys^


def _serpent24[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
) raises -> InlineArray[UInt32, 12]:
    var keys = _round_keys(key)
    var state: InlineArray[UInt32, 4] = [
        load_le32(nonce, 0),
        load_le32(nonce, 4),
        load_le32(nonce, 8),
        load_le32(nonce, 12),
    ]
    var result = InlineArray[UInt32, 12](fill=0)
    for round in range(24):
        for lane in range(4):
            state[lane] ^= keys[4 * round + lane]
        _sub(state, round % 8)
        state = _linear(state)
        if round == 11:
            result[9] = state[0]
            result[8] = state[1]
            result[7] = state[2]
            result[6] = state[3]
        elif round == 17:
            result[10] = state[0]
            result[4] = state[1]
            result[11] = state[2]
            result[5] = state[3]
    for lane in range(4):
        state[lane] ^= keys[96 + lane]
    result[3] = state[0]
    result[2] = state[1]
    result[1] = state[2]
    result[0] = state[3]
    return result^


def _alpha_tables() -> InlineArray[UInt32, 512]:
    var table = InlineArray[UInt32, 512](uninitialized=True)
    comptime for byte in range(256):
        var x = UInt32(byte)
        var multiply = UInt32(0)
        multiply ^= UInt32(0xE19FCF13) & (UInt32(0) - (x & 1))
        multiply ^= UInt32(0x6B973726) & (UInt32(0) - ((x >> 1) & 1))
        multiply ^= UInt32(0xD6876E4C) & (UInt32(0) - ((x >> 2) & 1))
        multiply ^= UInt32(0x05A7DC98) & (UInt32(0) - ((x >> 3) & 1))
        multiply ^= UInt32(0x0AE71199) & (UInt32(0) - ((x >> 4) & 1))
        multiply ^= UInt32(0x1467229B) & (UInt32(0) - ((x >> 5) & 1))
        multiply ^= UInt32(0x28CE449F) & (UInt32(0) - ((x >> 6) & 1))
        multiply ^= UInt32(0x50358897) & (UInt32(0) - ((x >> 7) & 1))
        table[byte] = multiply
        var divide = UInt32(0)
        divide ^= UInt32(0x180F40CD) & (UInt32(0) - (x & 1))
        divide ^= UInt32(0x301E8033) & (UInt32(0) - ((x >> 1) & 1))
        divide ^= UInt32(0x603CA966) & (UInt32(0) - ((x >> 2) & 1))
        divide ^= UInt32(0xC078FBCC) & (UInt32(0) - ((x >> 3) & 1))
        divide ^= UInt32(0x29F05F31) & (UInt32(0) - ((x >> 4) & 1))
        divide ^= UInt32(0x5249BE62) & (UInt32(0) - ((x >> 5) & 1))
        divide ^= UInt32(0xA492D5C4) & (UInt32(0) - ((x >> 6) & 1))
        divide ^= UInt32(0xE18D0321) & (UInt32(0) - ((x >> 7) & 1))
        table[256 + byte] = divide
    return table^


comptime _ALPHA_TABLES = _alpha_tables()


@always_inline("nodebug")
def _mul_alpha(x: UInt32) -> UInt32:
    ref tables = global_constant[_ALPHA_TABLES]()
    return (x << 8) ^ tables[Int(x >> 24)]


@always_inline("nodebug")
def _div_alpha(x: UInt32) -> UInt32:
    ref tables = global_constant[_ALPHA_TABLES]()
    return (x >> 8) ^ tables[256 + Int(x & 0xFF)]


@always_inline("nodebug")
def _lfsr_step(
    mut s0: UInt32,
    mut s1: UInt32,
    mut s2: UInt32,
    mut s3: UInt32,
    mut s4: UInt32,
    mut s5: UInt32,
    mut s6: UInt32,
    mut s7: UInt32,
    mut s8: UInt32,
    mut s9: UInt32,
    mut r1: UInt32,
    mut r2: UInt32,
) -> Tuple[UInt32, UInt32]:
    var old_r1 = r1
    var mux_mask = UInt32(0) - (old_r1 & 1)
    r1 = r2 + (s1 ^ (s8 & mux_mask))
    r2 = _rol(old_r1 * UInt32(0x54655307), 7)
    var generated = (s9 + r1) ^ r2
    var source = s0
    var next_lfsr = _mul_alpha(source) ^ _div_alpha(s3) ^ s9
    s0 = s1
    s1 = s2
    s2 = s3
    s3 = s4
    s4 = s5
    s5 = s6
    s6 = s7
    s7 = s8
    s8 = s9
    s9 = next_lfsr
    return (generated, source)


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    """XOR input with Sosemanuk; keys are 1..32 bytes and the IV is 16 bytes."""
    if len(key) < 1 or len(key) > 32:
        raise Error("Sosemanuk key must contain 1 to 32 bytes")
    if len(nonce) != 16:
        raise Error("Sosemanuk IV must contain 16 bytes")
    var initial = _serpent24(key, nonce)
    var s0 = initial[0]
    var s1 = initial[1]
    var s2 = initial[2]
    var s3 = initial[3]
    var s4 = initial[4]
    var s5 = initial[5]
    var s6 = initial[6]
    var s7 = initial[7]
    var s8 = initial[8]
    var s9 = initial[9]
    var r1 = initial[10]
    var r2 = initial[11]
    var output = List[UInt8](unsafe_uninit_length=len(input))
    var output_span = Span(output)
    var u = InlineArray[UInt32, 4](fill=0)
    var v = InlineArray[UInt32, 4](fill=0)
    for offset in range(0, len(input), 16):
        comptime for step in range(4):
            var generated = _lfsr_step(
                s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, r1, r2
            )
            u[step] = generated[0]
            v[step] = generated[1]
        _serpent_sub[2, False](u)
        if offset + 16 <= len(input):
            for i in range(4):
                store_le32(
                    (u[i] ^ v[i]) ^ load_le32(input, offset + 4 * i),
                    output_span,
                    offset + 4 * i,
                )
        else:
            for i in range(len(input) - offset):
                var word = u[i // 4] ^ v[i // 4]
                output[offset + i] = input[offset + i] ^ UInt8(
                    word >> UInt32(8 * (i & 3))
                )
    return output^


@always_inline("nodebug")
def _mul_alpha_eight(
    value: SIMD[DType.uint32, 8],
) -> SIMD[DType.uint32, 8]:
    ref tables = global_constant[_ALPHA_TABLES]()
    var output = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        output[lane] = (value[lane] << 8) ^ tables[Int(value[lane] >> 24)]
    return output


@always_inline("nodebug")
def _div_alpha_eight(
    value: SIMD[DType.uint32, 8],
) -> SIMD[DType.uint32, 8]:
    ref tables = global_constant[_ALPHA_TABLES]()
    var output = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        output[lane] = (value[lane] >> 8) ^ tables[
            256 + Int(value[lane] & 0xFF)
        ]
    return output


@always_inline("nodebug")
def _lfsr_step_eight(
    mut s0: SIMD[DType.uint32, 8],
    mut s1: SIMD[DType.uint32, 8],
    mut s2: SIMD[DType.uint32, 8],
    mut s3: SIMD[DType.uint32, 8],
    mut s4: SIMD[DType.uint32, 8],
    mut s5: SIMD[DType.uint32, 8],
    mut s6: SIMD[DType.uint32, 8],
    mut s7: SIMD[DType.uint32, 8],
    mut s8: SIMD[DType.uint32, 8],
    mut s9: SIMD[DType.uint32, 8],
    mut r1: SIMD[DType.uint32, 8],
    mut r2: SIMD[DType.uint32, 8],
) -> Tuple[SIMD[DType.uint32, 8], SIMD[DType.uint32, 8]]:
    var old_r1 = r1
    var mux_mask = SIMD[DType.uint32, 8](0) - (
        old_r1 & SIMD[DType.uint32, 8](1)
    )
    r1 = r2 + (s1 ^ (s8 & mux_mask))
    r2 = rotate_bits_left[7](old_r1 * SIMD[DType.uint32, 8](0x54655307))
    var generated = (s9 + r1) ^ r2
    var source = s0
    var next_lfsr = _mul_alpha_eight(source) ^ _div_alpha_eight(s3) ^ s9
    s0 = s1
    s1 = s2
    s2 = s3
    s3 = s4
    s4 = s5
    s5 = s6
    s6 = s7
    s7 = s8
    s8 = s9
    s9 = next_lfsr
    return (generated, source)


def xor_eight[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    """XOR eight independent equal-length messages in SIMD lanes."""
    if len(key) < 1 or len(key) > 32 or len(nonces) != 8 or len(inputs) != 8:
        raise Error("eight-way Sosemanuk batch has invalid dimensions")
    var input_length = len(inputs[0])
    var states = InlineArray[InlineArray[UInt32, 12], 8](uninitialized=True)
    var outputs = List[List[UInt8]](capacity=8)
    comptime for lane in range(8):
        if len(nonces[lane]) != 16 or len(inputs[lane]) != input_length:
            raise Error("eight-way Sosemanuk input has invalid dimensions")
        states[lane] = _serpent24(key, Span(nonces[lane]))
        outputs.append(List[UInt8](unsafe_uninit_length=input_length))
    var s0 = SIMD[DType.uint32, 8](0)
    var s1 = SIMD[DType.uint32, 8](0)
    var s2 = SIMD[DType.uint32, 8](0)
    var s3 = SIMD[DType.uint32, 8](0)
    var s4 = SIMD[DType.uint32, 8](0)
    var s5 = SIMD[DType.uint32, 8](0)
    var s6 = SIMD[DType.uint32, 8](0)
    var s7 = SIMD[DType.uint32, 8](0)
    var s8 = SIMD[DType.uint32, 8](0)
    var s9 = SIMD[DType.uint32, 8](0)
    var r1 = SIMD[DType.uint32, 8](0)
    var r2 = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        s0[lane] = states[lane][0]
        s1[lane] = states[lane][1]
        s2[lane] = states[lane][2]
        s3[lane] = states[lane][3]
        s4[lane] = states[lane][4]
        s5[lane] = states[lane][5]
        s6[lane] = states[lane][6]
        s7[lane] = states[lane][7]
        s8[lane] = states[lane][8]
        s9[lane] = states[lane][9]
        r1[lane] = states[lane][10]
        r2[lane] = states[lane][11]
    var u = InlineArray[SIMD[DType.uint32, 8], 4](fill=SIMD[DType.uint32, 8](0))
    var v = InlineArray[SIMD[DType.uint32, 8], 4](fill=SIMD[DType.uint32, 8](0))
    for offset in range(0, input_length, 16):
        comptime for step in range(4):
            var generated = _lfsr_step_eight(
                s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, r1, r2
            )
            u[step] = generated[0]
            v[step] = generated[1]
        _serpent_sub_eight[2, False](u)
        var count = min(16, input_length - offset)
        comptime for lane in range(8):
            var input_span = Span(inputs[lane])
            var output_span = Span(outputs[lane])
            if count == 16:
                comptime for word in range(4):
                    store_le32(
                        (u[word][lane] ^ v[word][lane])
                        ^ load_le32(input_span, offset + 4 * word),
                        output_span,
                        offset + 4 * word,
                    )
            else:
                for i in range(count):
                    var word = u[i // 4][lane] ^ v[i // 4][lane]
                    output_span[offset + i] = input_span[offset + i] ^ UInt8(
                        word >> UInt32(8 * (i & 3))
                    )
    return outputs^
