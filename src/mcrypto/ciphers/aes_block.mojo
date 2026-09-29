"""FIPS 197 AES-128, AES-192, and AES-256 block cipher."""

from std.memory import bitcast

from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic

from ..internal.bytes import load_le64, store_le64

comptime _HAS_ARM_AES = (
    not CompilationTarget.is_x86()
    and CompilationTarget._has_feature["aes"]()
    and CompilationTarget.has_neon()
)


comptime _SBOX: InlineArray[UInt8, 256] = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

comptime _INV_SBOX: InlineArray[UInt8, 256] = [
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
]


@always_inline("nodebug")
def _sub(value: UInt8) -> UInt8:
    var table = materialize[_SBOX]()
    return table[Int(value)]


@always_inline("nodebug")
def _inv_sub(value: UInt8) -> UInt8:
    var table = materialize[_INV_SBOX]()
    return table[Int(value)]


@always_inline("nodebug")
def _xtime(value: UInt8) -> UInt8:
    return UInt8((UInt16(value) << 1) ^ (UInt16(0x11B) if value & 0x80 else 0))


def _multiply(a: UInt8, b: UInt8) -> UInt8:
    var x = a
    var y = b
    var output = UInt8(0)
    for _ in range(8):
        if y & 1:
            output ^= x
        x = _xtime(x)
        y >>= 1
    return output


def _expand[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt8]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("AES key must be 16, 24, or 32 bytes")
    var nk = len(key) // 4
    var rounds = nk + 6
    var expanded = List[UInt8](length=16 * (rounds + 1), fill=0)
    for i in range(len(key)):
        expanded[i] = key[i]
    var generated = len(key)
    var rcon = UInt8(1)
    var temporary = InlineArray[UInt8, 4](uninitialized=True)
    while generated < len(expanded):
        for i in range(4):
            temporary[i] = expanded[generated - 4 + i]
        if generated % len(key) == 0:
            var first = temporary[0]
            temporary[0] = _sub(temporary[1]) ^ rcon
            temporary[1] = _sub(temporary[2])
            temporary[2] = _sub(temporary[3])
            temporary[3] = _sub(first)
            rcon = _xtime(rcon)
        elif nk > 6 and generated % len(key) == 16:
            for i in range(4):
                temporary[i] = _sub(temporary[i])
        for i in range(4):
            expanded[generated] = expanded[generated - len(key)] ^ temporary[i]
            generated += 1
    return expanded^


def _add_key(mut state: List[UInt8], expanded: List[UInt8], round_number: Int):
    for i in range(16):
        state[i] ^= expanded[round_number * 16 + i]


def _shift(mut state: InlineArray[UInt8, 16], inverse: Bool):
    var temporary = state[1]
    if inverse:
        state[1] = state[13]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = temporary
    else:
        state[1] = state[5]
        state[5] = state[9]
        state[9] = state[13]
        state[13] = temporary
    temporary = state[2]
    state[2] = state[10]
    state[10] = temporary
    temporary = state[6]
    state[6] = state[14]
    state[14] = temporary
    temporary = state[3]
    if inverse:
        state[3] = state[7]
        state[7] = state[11]
        state[11] = state[15]
        state[15] = temporary
    else:
        state[3] = state[15]
        state[15] = state[11]
        state[11] = state[7]
        state[7] = temporary


def _mix(mut state: InlineArray[UInt8, 16], inverse: Bool):
    comptime for column in range(4):
        var i = 4 * column
        var a = state[i]
        var b = state[i + 1]
        var c = state[i + 2]
        var d = state[i + 3]
        if inverse:
            var even = _xtime(_xtime(a ^ c))
            var odd = _xtime(_xtime(b ^ d))
            a ^= even
            b ^= odd
            c ^= even
            d ^= odd
        var total = a ^ b ^ c ^ d
        state[i] = a ^ total ^ _xtime(a ^ b)
        state[i + 1] = b ^ total ^ _xtime(b ^ c)
        state[i + 2] = c ^ total ^ _xtime(c ^ d)
        state[i + 3] = d ^ total ^ _xtime(d ^ a)


@always_inline("nodebug")
def _software_aes_round(
    state: SIMD[DType.uint64, 2],
    round_key: SIMD[DType.uint64, 2],
    inverse: Bool,
    mix: Bool,
) -> SIMD[DType.uint64, 2]:
    var input = bitcast[DType.uint8, 16](state)
    var key = bitcast[DType.uint8, 16](round_key)
    var working = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        working[i] = input[i]
    if inverse:
        _shift(working, True)
        comptime for i in range(16):
            working[i] = _inv_sub(working[i])
    else:
        comptime for i in range(16):
            working[i] = _sub(working[i])
        _shift(working, False)
    if mix:
        _mix(working, inverse)
    var output = SIMD[DType.uint8, 16](0)
    comptime for i in range(16):
        output[i] = working[i] ^ key[i]
    return bitcast[DType.uint64, 2](output)


@always_inline("nodebug")
def _software_inverse_key(
    round_key: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var input = bitcast[DType.uint8, 16](round_key)
    var working = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        working[i] = input[i]
    _mix(working, True)
    var output = SIMD[DType.uint8, 16](0)
    comptime for i in range(16):
        output[i] = working[i]
    return bitcast[DType.uint64, 2](output)


@always_inline("nodebug")
def _aesni_round(
    state: SIMD[DType.uint64, 2],
    round_key: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    comptime if CompilationTarget.is_x86():
        return llvm_intrinsic[
            "llvm.x86.aesni.aesenc",
            SIMD[DType.uint64, 2],
            has_side_effect=False,
        ](state, round_key)
    elif _HAS_ARM_AES:
        var zero = SIMD[DType.uint8, 16](0)
        var transformed = llvm_intrinsic[
            "llvm.aarch64.crypto.aese",
            SIMD[DType.uint8, 16],
            has_side_effect=False,
        ](bitcast[DType.uint8, 16](state), zero)
        transformed = llvm_intrinsic[
            "llvm.aarch64.crypto.aesmc",
            SIMD[DType.uint8, 16],
            has_side_effect=False,
        ](transformed)
        return bitcast[DType.uint64, 2](transformed) ^ round_key
    else:
        return _software_aes_round(state, round_key, False, True)


@always_inline("nodebug")
def _aesni_last_round(
    state: SIMD[DType.uint64, 2],
    round_key: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    comptime if CompilationTarget.is_x86():
        return llvm_intrinsic[
            "llvm.x86.aesni.aesenclast",
            SIMD[DType.uint64, 2],
            has_side_effect=False,
        ](state, round_key)
    elif _HAS_ARM_AES:
        var transformed = llvm_intrinsic[
            "llvm.aarch64.crypto.aese",
            SIMD[DType.uint8, 16],
            has_side_effect=False,
        ](
            bitcast[DType.uint8, 16](state),
            SIMD[DType.uint8, 16](0),
        )
        return bitcast[DType.uint64, 2](transformed) ^ round_key
    else:
        return _software_aes_round(state, round_key, False, False)


@always_inline("nodebug")
def _load_aesni[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> SIMD[DType.uint64, 2]:
    return bitcast[DType.uint64, 2](
        data.unsafe_ptr().unsafe_load[width=16](offset)
    )


@always_inline("nodebug")
def _aes_schedule_transform(
    value: SIMD[DType.uint64, 2], rcon: UInt8, rotate: Bool
) -> UInt32:
    var source = bitcast[DType.uint8, 16](value)
    if rotate:
        return (
            UInt32(_sub(source[13]) ^ rcon)
            | (UInt32(_sub(source[14])) << 8)
            | (UInt32(_sub(source[15])) << 16)
            | (UInt32(_sub(source[12])) << 24)
        )
    return (
        UInt32(_sub(source[12]))
        | (UInt32(_sub(source[13])) << 8)
        | (UInt32(_sub(source[14])) << 16)
        | (UInt32(_sub(source[15])) << 24)
    )


@always_inline("nodebug")
def _aesni_expand128_round[
    rcon: Int
](round_key: SIMD[DType.uint64, 2],) -> SIMD[DType.uint64, 2]:
    var words = bitcast[DType.uint32, 4](round_key)
    comptime if CompilationTarget.is_x86():
        var assist = bitcast[DType.uint32, 4](
            llvm_intrinsic[
                "llvm.x86.aesni.aeskeygenassist",
                SIMD[DType.uint64, 2],
                has_side_effect=False,
            ](round_key, UInt8(rcon))
        )
        words[0] ^= assist[3]
    else:
        words[0] ^= _aes_schedule_transform(round_key, UInt8(rcon), True)
    words[1] ^= words[0]
    words[2] ^= words[1]
    words[3] ^= words[2]
    return bitcast[DType.uint64, 2](words)


def _prepare_aesni128[
    origin: Origin
](key: Span[UInt8, origin]) raises -> List[SIMD[DType.uint64, 2]]:
    if len(key) != 16:
        raise Error("AES-128 key must be 16 bytes")
    var keys = List[SIMD[DType.uint64, 2]](capacity=11)
    var current = _load_aesni(key, 0)
    keys.append(current)
    current = _aesni_expand128_round[0x01](current)
    keys.append(current)
    current = _aesni_expand128_round[0x02](current)
    keys.append(current)
    current = _aesni_expand128_round[0x04](current)
    keys.append(current)
    current = _aesni_expand128_round[0x08](current)
    keys.append(current)
    current = _aesni_expand128_round[0x10](current)
    keys.append(current)
    current = _aesni_expand128_round[0x20](current)
    keys.append(current)
    current = _aesni_expand128_round[0x40](current)
    keys.append(current)
    current = _aesni_expand128_round[0x80](current)
    keys.append(current)
    current = _aesni_expand128_round[0x1B](current)
    keys.append(current)
    current = _aesni_expand128_round[0x36](current)
    keys.append(current)
    return keys^


def _prepare_aesni[
    origin: Origin
](expanded: Span[UInt8, origin]) raises -> List[SIMD[DType.uint64, 2]]:
    var rounds = len(expanded) // 16
    var keys = List[SIMD[DType.uint64, 2]](capacity=rounds)
    for round in range(rounds):
        keys.append(_load_aesni(expanded, round * 16))
    return keys^


@always_inline("nodebug")
def _encrypt_aesni_prepared_value(
    keys: List[SIMD[DType.uint64, 2]],
    input_state: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var state = input_state
    var key_pointer = Span(keys).unsafe_ptr()
    state ^= key_pointer[unsafe_offset=0]
    state = _aesni_round(state, key_pointer[unsafe_offset=1])
    state = _aesni_round(state, key_pointer[unsafe_offset=2])
    state = _aesni_round(state, key_pointer[unsafe_offset=3])
    state = _aesni_round(state, key_pointer[unsafe_offset=4])
    state = _aesni_round(state, key_pointer[unsafe_offset=5])
    state = _aesni_round(state, key_pointer[unsafe_offset=6])
    state = _aesni_round(state, key_pointer[unsafe_offset=7])
    state = _aesni_round(state, key_pointer[unsafe_offset=8])
    state = _aesni_round(state, key_pointer[unsafe_offset=9])
    if len(keys) == 11:
        return _aesni_last_round(state, key_pointer[unsafe_offset=10])
    state = _aesni_round(state, key_pointer[unsafe_offset=10])
    state = _aesni_round(state, key_pointer[unsafe_offset=11])
    if len(keys) == 13:
        return _aesni_last_round(state, key_pointer[unsafe_offset=12])
    state = _aesni_round(state, key_pointer[unsafe_offset=12])
    state = _aesni_round(state, key_pointer[unsafe_offset=13])
    return _aesni_last_round(state, key_pointer[unsafe_offset=14])


@always_inline("nodebug")
def _encrypt_aesni_four_prepared_values(
    keys: List[SIMD[DType.uint64, 2]],
    mut first: SIMD[DType.uint64, 2],
    mut second: SIMD[DType.uint64, 2],
    mut third: SIMD[DType.uint64, 2],
    mut fourth: SIMD[DType.uint64, 2],
):
    """Interleave four AES-NI dependency chains to hide instruction latency."""
    var key_pointer = Span(keys).unsafe_ptr()
    var round_key = key_pointer[unsafe_offset=0]
    first ^= round_key
    second ^= round_key
    third ^= round_key
    fourth ^= round_key
    for round in range(1, len(keys) - 1):
        round_key = key_pointer[unsafe_offset=round]
        first = _aesni_round(first, round_key)
        second = _aesni_round(second, round_key)
        third = _aesni_round(third, round_key)
        fourth = _aesni_round(fourth, round_key)
    round_key = key_pointer[unsafe_offset=len(keys) - 1]
    first = _aesni_last_round(first, round_key)
    second = _aesni_last_round(second, round_key)
    third = _aesni_last_round(third, round_key)
    fourth = _aesni_last_round(fourth, round_key)


@always_inline("nodebug")
def _encrypt_aesni_prepared_state[
    data_origin: Origin
](
    keys: List[SIMD[DType.uint64, 2]],
    data: Span[UInt8, data_origin],
    offset: Int,
) -> SIMD[DType.uint64, 2]:
    return _encrypt_aesni_prepared_value(keys, _load_aesni(data, offset))


@always_inline("nodebug")
def _encrypt_aesni_prepared_eight[
    blocks_origin: Origin,
    input_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[SIMD[DType.uint64, 2]],
    blocks: Span[UInt8, blocks_origin],
    block_offset: Int,
    input: Span[UInt8, input_origin],
    input_offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var key_pointer = Span(keys).unsafe_ptr()
    var key = key_pointer[unsafe_offset=0]
    var state0 = _load_aesni(blocks, block_offset) ^ key
    var state1 = _load_aesni(blocks, block_offset + 16) ^ key
    var state2 = _load_aesni(blocks, block_offset + 32) ^ key
    var state3 = _load_aesni(blocks, block_offset + 48) ^ key
    var state4 = _load_aesni(blocks, block_offset + 64) ^ key
    var state5 = _load_aesni(blocks, block_offset + 80) ^ key
    var state6 = _load_aesni(blocks, block_offset + 96) ^ key
    var state7 = _load_aesni(blocks, block_offset + 112) ^ key
    comptime for round in range(1, 10):
        key = key_pointer[unsafe_offset=round]
        state0 = _aesni_round(state0, key)
        state1 = _aesni_round(state1, key)
        state2 = _aesni_round(state2, key)
        state3 = _aesni_round(state3, key)
        state4 = _aesni_round(state4, key)
        state5 = _aesni_round(state5, key)
        state6 = _aesni_round(state6, key)
        state7 = _aesni_round(state7, key)
    var rounds = len(keys) - 1
    for round in range(10, rounds):
        key = key_pointer[unsafe_offset=round]
        state0 = _aesni_round(state0, key)
        state1 = _aesni_round(state1, key)
        state2 = _aesni_round(state2, key)
        state3 = _aesni_round(state3, key)
        state4 = _aesni_round(state4, key)
        state5 = _aesni_round(state5, key)
        state6 = _aesni_round(state6, key)
        state7 = _aesni_round(state7, key)
    key = key_pointer[unsafe_offset=rounds]
    var result0 = bitcast[DType.uint8, 16](_aesni_last_round(state0, key))
    var result1 = bitcast[DType.uint8, 16](_aesni_last_round(state1, key))
    var result2 = bitcast[DType.uint8, 16](_aesni_last_round(state2, key))
    var result3 = bitcast[DType.uint8, 16](_aesni_last_round(state3, key))
    var result4 = bitcast[DType.uint8, 16](_aesni_last_round(state4, key))
    var result5 = bitcast[DType.uint8, 16](_aesni_last_round(state5, key))
    var result6 = bitcast[DType.uint8, 16](_aesni_last_round(state6, key))
    var result7 = bitcast[DType.uint8, 16](_aesni_last_round(state7, key))
    var input_pointer = input.unsafe_ptr()
    result0 ^= input_pointer.unsafe_load[width=16](input_offset)
    result1 ^= input_pointer.unsafe_load[width=16](input_offset + 16)
    result2 ^= input_pointer.unsafe_load[width=16](input_offset + 32)
    result3 ^= input_pointer.unsafe_load[width=16](input_offset + 48)
    result4 ^= input_pointer.unsafe_load[width=16](input_offset + 64)
    result5 ^= input_pointer.unsafe_load[width=16](input_offset + 80)
    result6 ^= input_pointer.unsafe_load[width=16](input_offset + 96)
    result7 ^= input_pointer.unsafe_load[width=16](input_offset + 112)
    var output_pointer = output.unsafe_ptr()
    output_pointer.unsafe_store[width=16](output_offset, result0)
    output_pointer.unsafe_store[width=16](output_offset + 16, result1)
    output_pointer.unsafe_store[width=16](output_offset + 32, result2)
    output_pointer.unsafe_store[width=16](output_offset + 48, result3)
    output_pointer.unsafe_store[width=16](output_offset + 64, result4)
    output_pointer.unsafe_store[width=16](output_offset + 80, result5)
    output_pointer.unsafe_store[width=16](output_offset + 96, result6)
    output_pointer.unsafe_store[width=16](output_offset + 112, result7)


@always_inline("nodebug")
def _encrypt_aesni_prepared_four[
    blocks_origin: Origin,
    input_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[SIMD[DType.uint64, 2]],
    blocks: Span[UInt8, blocks_origin],
    block_offset: Int,
    input: Span[UInt8, input_origin],
    input_offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var first = _load_aesni(blocks, block_offset)
    var second = _load_aesni(blocks, block_offset + 16)
    var third = _load_aesni(blocks, block_offset + 32)
    var fourth = _load_aesni(blocks, block_offset + 48)
    _encrypt_aesni_four_prepared_values(keys, first, second, third, fourth)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    output_pointer.unsafe_store[width=16](
        output_offset,
        bitcast[DType.uint8, 16](first)
        ^ input_pointer.unsafe_load[width=16](input_offset),
    )
    output_pointer.unsafe_store[width=16](
        output_offset + 16,
        bitcast[DType.uint8, 16](second)
        ^ input_pointer.unsafe_load[width=16](input_offset + 16),
    )
    output_pointer.unsafe_store[width=16](
        output_offset + 32,
        bitcast[DType.uint8, 16](third)
        ^ input_pointer.unsafe_load[width=16](input_offset + 32),
    )
    output_pointer.unsafe_store[width=16](
        output_offset + 48,
        bitcast[DType.uint8, 16](fourth)
        ^ input_pointer.unsafe_load[width=16](input_offset + 48),
    )


def _encrypt_aesni_state[
    schedule_origin: Origin, data_origin: Origin
](
    expanded: Span[UInt8, schedule_origin],
    data: Span[UInt8, data_origin],
    offset: Int,
) raises -> SIMD[DType.uint64, 2]:
    var rounds = len(expanded) // 16 - 1
    var state = _load_aesni(data, offset) ^ _load_aesni(expanded, 0)
    for round_number in range(1, rounds):
        state = _aesni_round(state, _load_aesni(expanded, round_number * 16))
    return _aesni_last_round(state, _load_aesni(expanded, rounds * 16))


def _encrypt_aesni[
    schedule_origin: Origin, block_origin: Origin
](
    expanded: Span[UInt8, schedule_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var state = _encrypt_aesni_state(expanded, block, 0)
    var output = List[UInt8](length=16, fill=0)
    var output_span = Span(output)
    store_le64(UInt64(state[0]), output_span, 0)
    store_le64(UInt64(state[1]), output_span, 8)
    return output^


@always_inline("nodebug")
def _aesni_inverse_key(
    round_key: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    comptime if CompilationTarget.is_x86():
        return llvm_intrinsic[
            "llvm.x86.aesni.aesimc",
            SIMD[DType.uint64, 2],
            has_side_effect=False,
        ](round_key)
    elif _HAS_ARM_AES:
        return bitcast[DType.uint64, 2](
            llvm_intrinsic[
                "llvm.aarch64.crypto.aesimc",
                SIMD[DType.uint8, 16],
                has_side_effect=False,
            ](bitcast[DType.uint8, 16](round_key))
        )
    else:
        return _software_inverse_key(round_key)


@always_inline("nodebug")
def _aesni_decrypt_round(
    state: SIMD[DType.uint64, 2],
    round_key: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    comptime if CompilationTarget.is_x86():
        return llvm_intrinsic[
            "llvm.x86.aesni.aesdec",
            SIMD[DType.uint64, 2],
            has_side_effect=False,
        ](state, round_key)
    elif _HAS_ARM_AES:
        var transformed = llvm_intrinsic[
            "llvm.aarch64.crypto.aesd",
            SIMD[DType.uint8, 16],
            has_side_effect=False,
        ](
            bitcast[DType.uint8, 16](state),
            SIMD[DType.uint8, 16](0),
        )
        transformed = llvm_intrinsic[
            "llvm.aarch64.crypto.aesimc",
            SIMD[DType.uint8, 16],
            has_side_effect=False,
        ](transformed)
        return bitcast[DType.uint64, 2](transformed) ^ round_key
    else:
        return _software_aes_round(state, round_key, True, True)


@always_inline("nodebug")
def _aesni_decrypt_last_round(
    state: SIMD[DType.uint64, 2],
    round_key: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    comptime if CompilationTarget.is_x86():
        return llvm_intrinsic[
            "llvm.x86.aesni.aesdeclast",
            SIMD[DType.uint64, 2],
            has_side_effect=False,
        ](state, round_key)
    elif _HAS_ARM_AES:
        var transformed = llvm_intrinsic[
            "llvm.aarch64.crypto.aesd",
            SIMD[DType.uint8, 16],
            has_side_effect=False,
        ](
            bitcast[DType.uint8, 16](state),
            SIMD[DType.uint8, 16](0),
        )
        return bitcast[DType.uint64, 2](transformed) ^ round_key
    else:
        return _software_aes_round(state, round_key, True, False)


@always_inline("nodebug")
def _decrypt_aesni_prepared_state[
    data_origin: Origin
](
    keys: List[SIMD[DType.uint64, 2]],
    data: Span[UInt8, data_origin],
    offset: Int,
) -> SIMD[DType.uint64, 2]:
    var rounds = len(keys) - 1
    var state = _load_aesni(data, offset) ^ keys[rounds]
    for key_offset in range(1, rounds):
        state = _aesni_decrypt_round(
            state, _aesni_inverse_key(keys[rounds - key_offset])
        )
    return _aesni_decrypt_last_round(state, keys[0])


@always_inline("nodebug")
def _decrypt_aesni_prepared_four_into[
    data_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[SIMD[DType.uint64, 2]],
    data: Span[UInt8, data_origin],
    offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var rounds = len(keys) - 1
    var round_key = keys[rounds]
    var first = _load_aesni(data, offset) ^ round_key
    var second = _load_aesni(data, offset + 16) ^ round_key
    var third = _load_aesni(data, offset + 32) ^ round_key
    var fourth = _load_aesni(data, offset + 48) ^ round_key
    for key_offset in range(1, rounds):
        round_key = _aesni_inverse_key(keys[rounds - key_offset])
        first = _aesni_decrypt_round(first, round_key)
        second = _aesni_decrypt_round(second, round_key)
        third = _aesni_decrypt_round(third, round_key)
        fourth = _aesni_decrypt_round(fourth, round_key)
    round_key = keys[0]
    first = _aesni_decrypt_last_round(first, round_key)
    second = _aesni_decrypt_last_round(second, round_key)
    third = _aesni_decrypt_last_round(third, round_key)
    fourth = _aesni_decrypt_last_round(fourth, round_key)
    var output_pointer = output.unsafe_ptr()
    output_pointer.unsafe_store[width=16](
        output_offset, bitcast[DType.uint8, 16](first)
    )
    output_pointer.unsafe_store[width=16](
        output_offset + 16, bitcast[DType.uint8, 16](second)
    )
    output_pointer.unsafe_store[width=16](
        output_offset + 32, bitcast[DType.uint8, 16](third)
    )
    output_pointer.unsafe_store[width=16](
        output_offset + 48, bitcast[DType.uint8, 16](fourth)
    )


def _decrypt_aesni[
    schedule_origin: Origin, block_origin: Origin
](
    expanded: Span[UInt8, schedule_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var rounds = len(expanded) // 16 - 1
    var state = _load_aesni(block, 0) ^ _load_aesni(expanded, rounds * 16)
    for offset in range(1, rounds):
        var round_number = rounds - offset
        state = _aesni_decrypt_round(
            state,
            _aesni_inverse_key(_load_aesni(expanded, round_number * 16)),
        )
    state = _aesni_decrypt_last_round(state, _load_aesni(expanded, 0))
    var output = List[UInt8](length=16, fill=0)
    var output_span = Span(output)
    store_le64(UInt64(state[0]), output_span, 0)
    store_le64(UInt64(state[1]), output_span, 8)
    return output^


def encrypt_expanded_into[
    schedule_origin: Origin,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    expanded: Span[UInt8, schedule_origin],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int = 0,
) raises:
    if len(block) != 16:
        raise Error("AES block must be 16 bytes")
    if len(expanded) != 176 and len(expanded) != 208 and len(expanded) != 240:
        raise Error("invalid AES expanded key")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("AES output span is too short")
    comptime if (
        CompilationTarget.is_x86() or CompilationTarget._has_feature["aes"]()
    ):
        var state = _encrypt_aesni_state(expanded, block, 0)
        output.unsafe_ptr().unsafe_store[width=16](
            output_offset, bitcast[DType.uint8, 16](state)
        )
        return
    var rounds = len(expanded) // 16 - 1
    var state = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        state[i] = block[i] ^ expanded[i]
    for round_number in range(1, rounds):
        comptime for i in range(16):
            state[i] = _sub(state[i])
        _shift(state, False)
        _mix(state, False)
        comptime for i in range(16):
            state[i] ^= expanded[round_number * 16 + i]
    comptime for i in range(16):
        state[i] = _sub(state[i])
    _shift(state, False)
    comptime for i in range(16):
        output[output_offset + i] = state[i] ^ expanded[rounds * 16 + i]


def encrypt_expanded[
    schedule_origin: Origin, block_origin: Origin
](
    expanded: Span[UInt8, schedule_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    encrypt_expanded_into(expanded, block, Span(output))
    return output^


def encrypt_block[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    var expanded = _expand(key)
    return encrypt_expanded(Span(expanded), block)


def decrypt_expanded[
    schedule_origin: Origin, block_origin: Origin
](
    expanded: Span[UInt8, schedule_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != 16:
        raise Error("AES block must be 16 bytes")
    if len(expanded) != 176 and len(expanded) != 208 and len(expanded) != 240:
        raise Error("invalid AES expanded key")
    comptime if (
        CompilationTarget.is_x86() or CompilationTarget._has_feature["aes"]()
    ):
        return _decrypt_aesni(expanded, block)
    var rounds = len(expanded) // 16 - 1
    var state = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        state[i] = block[i]
    comptime for i in range(16):
        state[i] ^= expanded[rounds * 16 + i]
    for offset in range(1, rounds):
        var round_number = rounds - offset
        _shift(state, True)
        comptime for i in range(16):
            state[i] = _inv_sub(state[i])
        comptime for i in range(16):
            state[i] ^= expanded[round_number * 16 + i]
        _mix(state, True)
    _shift(state, True)
    comptime for i in range(16):
        state[i] = _inv_sub(state[i])
        state[i] ^= expanded[i]
    var output = List[UInt8](capacity=16)
    for byte in state:
        output.append(byte)
    return output^


def decrypt_block[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    var expanded = _expand(key)
    return decrypt_expanded(Span(expanded), block)


def expand_key[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt8]:
    return _expand(key)
