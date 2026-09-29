"""AEGIS-128L and AEGIS-256 authenticated encryption in pure Mojo."""
from .algorithm import AegisAlgorithm

from std.memory import bitcast

from std.sys import CompilationTarget


from ..ciphers.aes_block import _aesni_round, _sub, _xtime
from ..traits import constant_time_equal


comptime _C0: InlineArray[UInt8, 16] = [
    0x00,
    0x01,
    0x01,
    0x02,
    0x03,
    0x05,
    0x08,
    0x0D,
    0x15,
    0x22,
    0x37,
    0x59,
    0x90,
    0xE9,
    0x79,
    0x62,
]
comptime _C1: InlineArray[UInt8, 16] = [
    0xDB,
    0x3D,
    0x18,
    0x55,
    0x6D,
    0xC2,
    0x2F,
    0xF1,
    0x20,
    0x11,
    0x31,
    0x42,
    0x73,
    0xB5,
    0x28,
    0xDD,
]


def _block[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> List[UInt8]:
    var output = List[UInt8](capacity=16)
    for i in range(16):
        output.append(data[offset + i])
    return output^


def _set_block[
    origin: Origin
](mut state: List[UInt8], offset: Int, value: Span[UInt8, origin]):
    for i in range(16):
        state[offset + i] = value[i]


def _xor_block[
    origin: Origin
](mut state: List[UInt8], offset: Int, value: Span[UInt8, origin]):
    for i in range(16):
        state[offset + i] ^= value[i]


def _xor2[
    a_origin: Origin, b_origin: Origin
](a: Span[UInt8, a_origin], b: Span[UInt8, b_origin]) -> List[UInt8]:
    var output = List[UInt8](capacity=16)
    for i in range(16):
        output.append(a[i] ^ b[i])
    return output^


def _shift_round(mut state: InlineArray[UInt8, 16]):
    var temporary = state[1]
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
    state[3] = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = temporary


def _mix_round(mut state: InlineArray[UInt8, 16]):
    for column in range(4):
        var i = 4 * column
        var a = state[i]
        var b = state[i + 1]
        var c = state[i + 2]
        var d = state[i + 3]
        var total = a ^ b ^ c ^ d
        state[i] = a ^ total ^ _xtime(a ^ b)
        state[i + 1] = b ^ total ^ _xtime(b ^ c)
        state[i + 2] = c ^ total ^ _xtime(c ^ d)
        state[i + 3] = d ^ total ^ _xtime(d ^ a)


def _aes_round(
    mut block: InlineArray[UInt8, 16],
    state: List[UInt8],
    key_offset: Int,
):
    comptime if CompilationTarget.is_x86():
        var block_pointer = Span(block).unsafe_ptr()
        var data = bitcast[DType.uint64, 2](
            block_pointer.unsafe_load[width=16](0)
        )
        var round_key = bitcast[DType.uint64, 2](
            Span(state).unsafe_ptr().unsafe_load[width=16](key_offset)
        )
        data = _aesni_round(data, round_key)
        block_pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](data))
        return
    for i in range(16):
        block[i] = _sub(block[i])
    _shift_round(block)
    _mix_round(block)
    for i in range(16):
        block[i] ^= state[key_offset + i]


def _update128l[
    d0_origin: Origin, d1_origin: Origin
](
    mut state: List[UInt8],
    d0: Span[UInt8, d0_origin],
    d1: Span[UInt8, d1_origin],
):
    comptime if CompilationTarget.is_x86():
        var state_pointer = Span(state).unsafe_ptr()
        var last = bitcast[DType.uint64, 2](
            state_pointer.unsafe_load[width=16](7 * 16)
        )
        var index = 7
        while index > 0:
            var block = bitcast[DType.uint64, 2](
                state_pointer.unsafe_load[width=16]((index - 1) * 16)
            )
            var round_key = bitcast[DType.uint64, 2](
                state_pointer.unsafe_load[width=16](index * 16)
            )
            state_pointer.unsafe_store[width=16](
                index * 16,
                bitcast[DType.uint8, 16](_aesni_round(block, round_key)),
            )
            index -= 1
        var first = _aesni_round(
            last,
            bitcast[DType.uint64, 2](state_pointer.unsafe_load[width=16](0)),
        )
        first ^= bitcast[DType.uint64, 2](
            d0.unsafe_ptr().unsafe_load[width=16](0)
        )
        state_pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](first))
        var fourth = bitcast[DType.uint64, 2](
            state_pointer.unsafe_load[width=16](4 * 16)
        )
        fourth ^= bitcast[DType.uint64, 2](
            d1.unsafe_ptr().unsafe_load[width=16](0)
        )
        state_pointer.unsafe_store[width=16](
            4 * 16, bitcast[DType.uint8, 16](fourth)
        )
        return
    var last = InlineArray[UInt8, 16](fill=0)
    for i in range(16):
        last[i] = state[7 * 16 + i]
    var index = 7
    while index > 0:
        var block = InlineArray[UInt8, 16](fill=0)
        for i in range(16):
            block[i] = state[(index - 1) * 16 + i]
        _aes_round(block, state, index * 16)
        for i in range(16):
            state[index * 16 + i] = block[i]
        index -= 1
    _aes_round(last, state, 0)
    for i in range(16):
        state[i] = last[i] ^ d0[i]
        state[4 * 16 + i] ^= d1[i]


def _update256[
    d_origin: Origin
](mut state: List[UInt8], data_block: Span[UInt8, d_origin]):
    comptime if CompilationTarget.is_x86():
        var state_pointer = Span(state).unsafe_ptr()
        var last = bitcast[DType.uint64, 2](
            state_pointer.unsafe_load[width=16](5 * 16)
        )
        var index = 5
        while index > 0:
            var block = bitcast[DType.uint64, 2](
                state_pointer.unsafe_load[width=16]((index - 1) * 16)
            )
            var round_key = bitcast[DType.uint64, 2](
                state_pointer.unsafe_load[width=16](index * 16)
            )
            state_pointer.unsafe_store[width=16](
                index * 16,
                bitcast[DType.uint8, 16](_aesni_round(block, round_key)),
            )
            index -= 1
        var first = _aesni_round(
            last,
            bitcast[DType.uint64, 2](state_pointer.unsafe_load[width=16](0)),
        )
        first ^= bitcast[DType.uint64, 2](
            data_block.unsafe_ptr().unsafe_load[width=16](0)
        )
        state_pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](first))
        return
    var last = InlineArray[UInt8, 16](fill=0)
    for i in range(16):
        last[i] = state[5 * 16 + i]
    var index = 5
    while index > 0:
        var block = InlineArray[UInt8, 16](fill=0)
        for i in range(16):
            block[i] = state[(index - 1) * 16 + i]
        _aes_round(block, state, index * 16)
        for i in range(16):
            state[index * 16 + i] = block[i]
        index -= 1
    _aes_round(last, state, 0)
    for i in range(16):
        state[i] = last[i] ^ data_block[i]


def _init128l[
    key_origin: Origin, nonce_origin: Origin
](key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]) -> List[
    UInt8
]:
    var c0 = List[UInt8](materialize[_C0]())
    var c1 = List[UInt8](materialize[_C1]())
    var key_nonce = _xor2(key, nonce)
    var state = List[UInt8](length=8 * 16, fill=0)
    _set_block(state, 0, Span(key_nonce))
    _set_block(state, 16, Span(c1))
    _set_block(state, 32, Span(c0))
    _set_block(state, 48, Span(c1))
    _set_block(state, 64, Span(key_nonce))
    var key_c0 = _xor2(key, Span(c0))
    var key_c1 = _xor2(key, Span(c1))
    _set_block(state, 80, Span(key_c0))
    _set_block(state, 96, Span(key_c1))
    _set_block(state, 112, Span(key_c0))
    for _ in range(10):
        _update128l(state, nonce, key)

    return state^


def _init256[
    key_origin: Origin, nonce_origin: Origin
](key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]) -> List[
    UInt8
]:
    var c0 = List[UInt8](materialize[_C0]())
    var c1 = List[UInt8](materialize[_C1]())
    var k0 = _block(key, 0)
    var k1 = _block(key, 16)
    var n0 = _block(nonce, 0)
    var n1 = _block(nonce, 16)
    var k0_n0 = _xor2(Span(k0), Span(n0))
    var k1_n1 = _xor2(Span(k1), Span(n1))
    var state = List[UInt8](length=6 * 16, fill=0)
    _set_block(state, 0, Span(k0_n0))
    _set_block(state, 16, Span(k1_n1))
    _set_block(state, 32, Span(c1))
    _set_block(state, 48, Span(c0))
    var k0_c0 = _xor2(Span(k0), Span(c0))
    var k1_c1 = _xor2(Span(k1), Span(c1))
    _set_block(state, 64, Span(k0_c0))
    _set_block(state, 80, Span(k1_c1))
    for _ in range(4):
        _update256(state, Span(k0))
        _update256(state, Span(k1))
        _update256(state, Span(k0_n0))
        _update256(state, Span(k1_n1))
    return state^


def _padded_block[
    origin: Origin
](data: Span[UInt8, origin], offset: Int, size: Int) -> List[UInt8]:
    var output = List[UInt8](length=size, fill=0)
    var remaining = len(data) - offset
    var take = remaining if remaining < size else size
    for i in range(take):
        output[i] = data[offset + i]
    return output^


def _absorb128l[
    origin: Origin
](mut state: List[UInt8], aad: Span[UInt8, origin]):
    var first = List[UInt8](length=16, fill=0)
    var second = List[UInt8](length=16, fill=0)
    var offset = 0
    while offset + 32 <= len(aad):
        _set_block(first, 0, aad[offset : offset + 16])
        _set_block(second, 0, aad[offset + 16 : offset + 32])
        _update128l(state, Span(first), Span(second))
        offset += 32
    if offset < len(aad):
        var padded = _padded_block(aad, offset, 32)
        _set_block(first, 0, Span(padded)[0:16])
        _set_block(second, 0, Span(padded)[16:32])
        _update128l(state, Span(first), Span(second))


def _absorb256[
    origin: Origin
](mut state: List[UInt8], aad: Span[UInt8, origin]):
    var offset = 0
    while offset + 16 <= len(aad):
        _update256(state, aad[offset : offset + 16])
        offset += 16
    if offset < len(aad):
        var padded = _padded_block(aad, offset, 16)
        _update256(state, Span(padded))


def _keystream128l_into[
    m0_origin: Origin, m1_origin: Origin, output_origin: MutOrigin
](
    mut state: List[UInt8],
    message0: Span[UInt8, m0_origin],
    message1: Span[UInt8, m1_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    count0: Int,
    count1: Int,
):
    for i in range(count0):
        output[output_offset + i] = (
            message0[i]
            ^ state[6 * 16 + i]
            ^ state[1 * 16 + i]
            ^ (state[2 * 16 + i] & state[3 * 16 + i])
        )
    for i in range(count1):
        output[output_offset + 16 + i] = (
            message1[i]
            ^ state[5 * 16 + i]
            ^ state[2 * 16 + i]
            ^ (state[6 * 16 + i] & state[7 * 16 + i])
        )
    _update128l(state, message0, message1)


def _keystream256_into[
    message_origin: Origin, output_origin: MutOrigin
](
    mut state: List[UInt8],
    message: Span[UInt8, message_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    count: Int,
):
    for i in range(count):
        output[output_offset + i] = (
            message[i]
            ^ state[5 * 16 + i]
            ^ state[4 * 16 + i]
            ^ state[1 * 16 + i]
            ^ (state[2 * 16 + i] & state[3 * 16 + i])
        )
    _update256(state, message)


def _length_block(aad_bytes: Int, message_bytes: Int) -> List[UInt8]:
    var output = List[UInt8](unsafe_uninit_length=16)
    var aad_bits = UInt64(aad_bytes) << 3
    var message_bits = UInt64(message_bytes) << 3
    for i in range(8):
        output[i] = UInt8(aad_bits >> UInt64(8 * i))
        output[8 + i] = UInt8(message_bits >> UInt64(8 * i))
    return output^


def _tag128l(
    mut state: List[UInt8], aad_bytes: Int, message_bytes: Int, tag_bytes: Int
) -> List[UInt8]:
    var lengths = _length_block(aad_bytes, message_bytes)
    for i in range(16):
        lengths[i] ^= state[2 * 16 + i]
    var lengths_copy = lengths.copy()
    for _ in range(7):
        _update128l(state, Span(lengths), Span(lengths_copy))
    var tag = List[UInt8](length=tag_bytes, fill=0)
    if tag_bytes == 16:
        for i in range(16):
            tag[i] = (
                state[i]
                ^ state[16 + i]
                ^ state[32 + i]
                ^ state[48 + i]
                ^ state[64 + i]
                ^ state[80 + i]
                ^ state[96 + i]
            )
    else:
        for i in range(16):
            tag[i] = state[i] ^ state[16 + i] ^ state[32 + i] ^ state[48 + i]
            tag[16 + i] = (
                state[64 + i] ^ state[80 + i] ^ state[96 + i] ^ state[112 + i]
            )
    return tag^


def _tag256(
    mut state: List[UInt8], aad_bytes: Int, message_bytes: Int, tag_bytes: Int
) -> List[UInt8]:
    var lengths = _length_block(aad_bytes, message_bytes)
    for i in range(16):
        lengths[i] ^= state[3 * 16 + i]
    for _ in range(7):
        _update256(state, Span(lengths))
    var tag = List[UInt8](length=tag_bytes, fill=0)
    if tag_bytes == 16:
        for i in range(16):
            tag[i] = (
                state[i]
                ^ state[16 + i]
                ^ state[32 + i]
                ^ state[48 + i]
                ^ state[64 + i]
                ^ state[80 + i]
            )
    else:
        for i in range(16):
            tag[i] = state[i] ^ state[16 + i] ^ state[32 + i]
            tag[16 + i] = state[48 + i] ^ state[64 + i] ^ state[80 + i]
    return tag^


@always_inline("nodebug")
def _simd_block[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> SIMD[DType.uint64, 2]:
    return bitcast[DType.uint64, 2](
        data.unsafe_ptr().unsafe_load[width=16](offset)
    )


@always_inline("nodebug")
def _simd_partial[
    origin: Origin
](data: Span[UInt8, origin], offset: Int, count: Int) -> SIMD[DType.uint64, 2]:
    if count == 16:
        return _simd_block(data, offset)
    var bytes = SIMD[DType.uint8, 16](0)
    var pointer = data.unsafe_ptr()
    for i in range(count):
        bytes[i] = pointer.unsafe_load(offset + i)
    return bitcast[DType.uint64, 2](bytes)


@always_inline("nodebug")
def _zero_simd_tail(
    value: SIMD[DType.uint64, 2], count: Int
) -> SIMD[DType.uint64, 2]:
    if count == 16:
        return value
    var bytes = bitcast[DType.uint8, 16](value)
    for i in range(count, 16):
        bytes[i] = 0
    return bitcast[DType.uint64, 2](bytes)


@always_inline("nodebug")
def _store_simd[
    origin: MutOrigin
](
    value: SIMD[DType.uint64, 2],
    output: Span[mut=True, UInt8, origin],
    offset: Int,
    count: Int,
):
    var pointer = output.unsafe_ptr()
    var bytes = bitcast[DType.uint8, 16](value)
    if count == 16:
        pointer.unsafe_store[width=16](offset, bytes)
    else:
        for i in range(count):
            pointer.unsafe_store(offset + i, bytes[i])


@always_inline("nodebug")
def _constant0() -> SIMD[DType.uint64, 2]:
    var value = SIMD[DType.uint64, 2](0)
    value[0] = 0x0D08050302010100
    value[1] = 0x6279E99059372215
    return value


@always_inline("nodebug")
def _constant1() -> SIMD[DType.uint64, 2]:
    var value = SIMD[DType.uint64, 2](0)
    value[0] = 0xF12FC26D55183DDB
    value[1] = 0xDD28B57342311120
    return value


@always_inline("nodebug")
def _update128l_hardware(
    mut state: InlineArray[SIMD[DType.uint64, 2], 8],
    data0: SIMD[DType.uint64, 2],
    data1: SIMD[DType.uint64, 2],
):
    var s0 = state[0]
    var s1 = state[1]
    var s2 = state[2]
    var s3 = state[3]
    var s4 = state[4]
    var s5 = state[5]
    var s6 = state[6]
    var s7 = state[7]
    state[7] = _aesni_round(s6, s7)
    state[6] = _aesni_round(s5, s6)
    state[5] = _aesni_round(s4, s5)
    state[4] = _aesni_round(s3, s4) ^ data1
    state[3] = _aesni_round(s2, s3)
    state[2] = _aesni_round(s1, s2)
    state[1] = _aesni_round(s0, s1)
    state[0] = _aesni_round(s7, s0) ^ data0


@always_inline("nodebug")
def _update256_hardware(
    mut state: InlineArray[SIMD[DType.uint64, 2], 6],
    data: SIMD[DType.uint64, 2],
):
    var s0 = state[0]
    var s1 = state[1]
    var s2 = state[2]
    var s3 = state[3]
    var s4 = state[4]
    var s5 = state[5]
    state[5] = _aesni_round(s4, s5)
    state[4] = _aesni_round(s3, s4)
    state[3] = _aesni_round(s2, s3)
    state[2] = _aesni_round(s1, s2)
    state[1] = _aesni_round(s0, s1)
    state[0] = _aesni_round(s5, s0) ^ data


def _init128l_hardware[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) -> InlineArray[SIMD[DType.uint64, 2], 8]:
    var k = _simd_block(key, 0)
    var n = _simd_block(nonce, 0)
    var c0 = _constant0()
    var c1 = _constant1()
    var key_nonce = k ^ n
    var state = InlineArray[SIMD[DType.uint64, 2], 8](
        fill=SIMD[DType.uint64, 2](0)
    )
    state[0] = key_nonce
    state[1] = c1
    state[2] = c0
    state[3] = c1
    state[4] = key_nonce
    state[5] = k ^ c0
    state[6] = k ^ c1
    state[7] = k ^ c0
    for _ in range(10):
        _update128l_hardware(state, n, k)
    return state^


def _init256_hardware[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) -> InlineArray[SIMD[DType.uint64, 2], 6]:
    var k0 = _simd_block(key, 0)
    var k1 = _simd_block(key, 16)
    var n0 = _simd_block(nonce, 0)
    var n1 = _simd_block(nonce, 16)
    var c0 = _constant0()
    var c1 = _constant1()
    var state = InlineArray[SIMD[DType.uint64, 2], 6](
        fill=SIMD[DType.uint64, 2](0)
    )
    state[0] = k0 ^ n0
    state[1] = k1 ^ n1
    state[2] = c1
    state[3] = c0
    state[4] = k0 ^ c0
    state[5] = k1 ^ c1
    for _ in range(4):
        _update256_hardware(state, k0)
        _update256_hardware(state, k1)
        _update256_hardware(state, k0 ^ n0)
        _update256_hardware(state, k1 ^ n1)
    return state^


def _absorb128l_hardware[
    origin: Origin
](mut state: InlineArray[SIMD[DType.uint64, 2], 8], data: Span[UInt8, origin],):
    var offset = 0
    while offset + 32 <= len(data):
        _update128l_hardware(
            state, _simd_block(data, offset), _simd_block(data, offset + 16)
        )
        offset += 32
    if offset < len(data):
        var count = len(data) - offset
        var first = min(16, count)
        var second = count - first
        _update128l_hardware(
            state,
            _simd_partial(data, offset, first),
            _simd_partial(data, offset + first, second),
        )


def _absorb256_hardware[
    origin: Origin
](mut state: InlineArray[SIMD[DType.uint64, 2], 6], data: Span[UInt8, origin],):
    var offset = 0
    while offset + 16 <= len(data):
        _update256_hardware(state, _simd_block(data, offset))
        offset += 16
    if offset < len(data):
        _update256_hardware(
            state, _simd_partial(data, offset, len(data) - offset)
        )


def _tag128l_hardware(
    mut state: InlineArray[SIMD[DType.uint64, 2], 8],
    aad_bytes: Int,
    message_bytes: Int,
    tag_bytes: Int,
) -> List[UInt8]:
    var lengths = SIMD[DType.uint64, 2](0)
    lengths[0] = UInt64(aad_bytes) << 3
    lengths[1] = UInt64(message_bytes) << 3
    lengths ^= state[2]
    for _ in range(7):
        _update128l_hardware(state, lengths, lengths)
    var first = state[0] ^ state[1] ^ state[2] ^ state[3]
    var output = List[UInt8](unsafe_uninit_length=tag_bytes)
    var output_span = Span(output)
    if tag_bytes == 16:
        first ^= state[4] ^ state[5] ^ state[6]
        _store_simd(first, output_span, 0, 16)
    else:
        _store_simd(first, output_span, 0, 16)
        _store_simd(
            state[4] ^ state[5] ^ state[6] ^ state[7],
            output_span,
            16,
            16,
        )
    return output^


def _tag256_hardware(
    mut state: InlineArray[SIMD[DType.uint64, 2], 6],
    aad_bytes: Int,
    message_bytes: Int,
    tag_bytes: Int,
) -> List[UInt8]:
    var lengths = SIMD[DType.uint64, 2](0)
    lengths[0] = UInt64(aad_bytes) << 3
    lengths[1] = UInt64(message_bytes) << 3
    lengths ^= state[3]
    for _ in range(7):
        _update256_hardware(state, lengths)
    var first = state[0] ^ state[1] ^ state[2]
    var output = List[UInt8](unsafe_uninit_length=tag_bytes)
    var output_span = Span(output)
    if tag_bytes == 16:
        first ^= state[3] ^ state[4] ^ state[5]
        _store_simd(first, output_span, 0, 16)
    else:
        _store_simd(first, output_span, 0, 16)
        _store_simd(state[3] ^ state[4] ^ state[5], output_span, 16, 16)
    return output^


def _encrypt128l_hardware_into[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
    cipher_origin: MutOrigin,
    tag_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    ciphertext: Span[mut=True, UInt8, cipher_origin],
    tag: Span[mut=True, UInt8, tag_origin],
):
    var k = _simd_block(key, 0)
    var n = _simd_block(nonce, 0)
    var c0 = _constant0()
    var c1 = _constant1()
    var s0 = k ^ n
    var s1 = c1
    var s2 = c0
    var s3 = c1
    var s4 = k ^ n
    var s5 = k ^ c0
    var s6 = k ^ c1
    var s7 = k ^ c0
    comptime for _ in range(10):
        var next0 = _aesni_round(s7, s0) ^ n
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4) ^ k
        var next5 = _aesni_round(s4, s5)
        var next6 = _aesni_round(s5, s6)
        var next7 = _aesni_round(s6, s7)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        s6 = next6
        s7 = next7
    var aad_offset = 0
    while aad_offset < len(aad):
        var take = min(32, len(aad) - aad_offset)
        var first = min(16, take)
        var data0 = _simd_partial(aad, aad_offset, first)
        var data1 = _simd_partial(aad, aad_offset + first, take - first)
        var next0 = _aesni_round(s7, s0) ^ data0
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4) ^ data1
        var next5 = _aesni_round(s4, s5)
        var next6 = _aesni_round(s5, s6)
        var next7 = _aesni_round(s6, s7)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        s6 = next6
        s7 = next7
        aad_offset += take
    var output_span = ciphertext
    var offset = 0
    var message_pointer = message.unsafe_ptr()
    var output_pointer = output_span.unsafe_ptr()
    while offset + 32 <= len(message):
        var message0 = bitcast[DType.uint64, 2](
            message_pointer.unsafe_load[width=16](offset)
        )
        var message1 = bitcast[DType.uint64, 2](
            message_pointer.unsafe_load[width=16](offset + 16)
        )
        var cipher0 = message0 ^ s6 ^ s1 ^ (s2 & s3)
        var cipher1 = message1 ^ s5 ^ s2 ^ (s6 & s7)
        output_pointer.unsafe_store[width=16](
            offset, bitcast[DType.uint8, 16](cipher0)
        )
        output_pointer.unsafe_store[width=16](
            offset + 16, bitcast[DType.uint8, 16](cipher1)
        )
        var next0 = _aesni_round(s7, s0) ^ message0
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4) ^ message1
        var next5 = _aesni_round(s4, s5)
        var next6 = _aesni_round(s5, s6)
        var next7 = _aesni_round(s6, s7)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        s6 = next6
        s7 = next7
        offset += 32
    if offset < len(message):
        var take = len(message) - offset
        var count0 = min(16, take)
        var count1 = take - count0
        var message0 = _simd_partial(message, offset, count0)
        var message1 = _simd_partial(message, offset + count0, count1)
        var cipher0 = message0 ^ s6 ^ s1 ^ (s2 & s3)
        var cipher1 = message1 ^ s5 ^ s2 ^ (s6 & s7)
        _store_simd(cipher0, output_span, offset, count0)
        _store_simd(cipher1, output_span, offset + count0, count1)
        var next0 = _aesni_round(s7, s0) ^ message0
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4) ^ message1
        var next5 = _aesni_round(s4, s5)
        var next6 = _aesni_round(s5, s6)
        var next7 = _aesni_round(s6, s7)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        s6 = next6
        s7 = next7
    var lengths = SIMD[DType.uint64, 2](0)
    lengths[0] = UInt64(len(aad)) << 3
    lengths[1] = UInt64(len(message)) << 3
    lengths ^= s2
    comptime for _ in range(7):
        var next0 = _aesni_round(s7, s0) ^ lengths
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4) ^ lengths
        var next5 = _aesni_round(s4, s5)
        var next6 = _aesni_round(s5, s6)
        var next7 = _aesni_round(s6, s7)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        s6 = next6
        s7 = next7
    var tag_span = tag
    var tag0 = s0 ^ s1 ^ s2 ^ s3
    if len(tag) == 16:
        tag0 ^= s4 ^ s5 ^ s6
        _store_simd(tag0, tag_span, 0, 16)
    else:
        _store_simd(tag0, tag_span, 0, 16)
        _store_simd(s4 ^ s5 ^ s6 ^ s7, tag_span, 16, 16)


def _encrypt256_hardware_into[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
    cipher_origin: MutOrigin,
    tag_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    ciphertext: Span[mut=True, UInt8, cipher_origin],
    tag: Span[mut=True, UInt8, tag_origin],
):
    var k0 = _simd_block(key, 0)
    var k1 = _simd_block(key, 16)
    var n0 = _simd_block(nonce, 0)
    var n1 = _simd_block(nonce, 16)
    var c0 = _constant0()
    var c1 = _constant1()
    var s0 = k0 ^ n0
    var s1 = k1 ^ n1
    var s2 = c1
    var s3 = c0
    var s4 = k0 ^ c0
    var s5 = k1 ^ c1
    comptime for phase in range(16):
        var data = k0
        comptime if phase % 4 == 1:
            data = k1
        elif phase % 4 == 2:
            data = k0 ^ n0
        elif phase % 4 == 3:
            data = k1 ^ n1
        var next0 = _aesni_round(s5, s0) ^ data
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4)
        var next5 = _aesni_round(s4, s5)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
    var aad_offset = 0
    while aad_offset < len(aad):
        var take = min(16, len(aad) - aad_offset)
        var data = _simd_partial(aad, aad_offset, take)
        var next0 = _aesni_round(s5, s0) ^ data
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4)
        var next5 = _aesni_round(s4, s5)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        aad_offset += take
    var output_span = ciphertext
    var offset = 0
    var message_pointer = message.unsafe_ptr()
    var output_pointer = output_span.unsafe_ptr()
    while offset + 16 <= len(message):
        var message_block = bitcast[DType.uint64, 2](
            message_pointer.unsafe_load[width=16](offset)
        )
        var cipher = message_block ^ s5 ^ s4 ^ s1 ^ (s2 & s3)
        output_pointer.unsafe_store[width=16](
            offset, bitcast[DType.uint8, 16](cipher)
        )
        var next0 = _aesni_round(s5, s0) ^ message_block
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4)
        var next5 = _aesni_round(s4, s5)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        offset += 16
    if offset < len(message):
        var take = len(message) - offset
        var message_block = _simd_partial(message, offset, take)
        var cipher = message_block ^ s5 ^ s4 ^ s1 ^ (s2 & s3)
        _store_simd(cipher, output_span, offset, take)
        var next0 = _aesni_round(s5, s0) ^ message_block
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4)
        var next5 = _aesni_round(s4, s5)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
    var lengths = SIMD[DType.uint64, 2](0)
    lengths[0] = UInt64(len(aad)) << 3
    lengths[1] = UInt64(len(message)) << 3
    lengths ^= s3
    comptime for _ in range(7):
        var next0 = _aesni_round(s5, s0) ^ lengths
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4)
        var next5 = _aesni_round(s4, s5)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
    var tag_span = tag
    var tag0 = s0 ^ s1 ^ s2
    if len(tag) == 16:
        tag0 ^= s3 ^ s4 ^ s5
        _store_simd(tag0, tag_span, 0, 16)
    else:
        _store_simd(tag0, tag_span, 0, 16)
        _store_simd(s3 ^ s4 ^ s5, tag_span, 16, 16)


def _decrypt128l_hardware[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    var state = _init128l_hardware(key, nonce)
    _absorb128l_hardware(state, aad)
    var output = List[UInt8](unsafe_uninit_length=len(ciphertext))
    var output_span = Span(output)
    var s0 = state[0]
    var s1 = state[1]
    var s2 = state[2]
    var s3 = state[3]
    var s4 = state[4]
    var s5 = state[5]
    var s6 = state[6]
    var s7 = state[7]
    var offset = 0
    var cipher_pointer = ciphertext.unsafe_ptr()
    var output_pointer = output_span.unsafe_ptr()
    while offset + 32 <= len(ciphertext):
        var cipher0 = bitcast[DType.uint64, 2](
            cipher_pointer.unsafe_load[width=16](offset)
        )
        var cipher1 = bitcast[DType.uint64, 2](
            cipher_pointer.unsafe_load[width=16](offset + 16)
        )
        var message0 = cipher0 ^ s6 ^ s1 ^ (s2 & s3)
        var message1 = cipher1 ^ s5 ^ s2 ^ (s6 & s7)
        output_pointer.unsafe_store[width=16](
            offset, bitcast[DType.uint8, 16](message0)
        )
        output_pointer.unsafe_store[width=16](
            offset + 16, bitcast[DType.uint8, 16](message1)
        )
        message0 = _aesni_round(s7, s0) ^ message0
        cipher0 = _aesni_round(s0, s1)
        cipher1 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        message1 = _aesni_round(s3, s4) ^ message1
        var next5 = _aesni_round(s4, s5)
        var next6 = _aesni_round(s5, s6)
        var next7 = _aesni_round(s6, s7)
        s0 = message0
        s1 = cipher0
        s2 = cipher1
        s3 = next3
        s4 = message1
        s5 = next5
        s6 = next6
        s7 = next7
        offset += 32
    while offset < len(ciphertext):
        var take = min(32, len(ciphertext) - offset)
        var count0 = min(16, take)
        var count1 = take - count0
        var cipher0 = _simd_partial(ciphertext, offset, count0)
        var cipher1 = _simd_partial(ciphertext, offset + count0, count1)
        var message0 = _zero_simd_tail(cipher0 ^ s6 ^ s1 ^ (s2 & s3), count0)
        var message1 = _zero_simd_tail(cipher1 ^ s5 ^ s2 ^ (s6 & s7), count1)
        _store_simd(message0, output_span, offset, count0)
        _store_simd(message1, output_span, offset + count0, count1)
        var last = s7
        s7 = _aesni_round(s6, s7)
        s6 = _aesni_round(s5, s6)
        s5 = _aesni_round(s4, s5)
        s4 = _aesni_round(s3, s4) ^ message1
        s3 = _aesni_round(s2, s3)
        s2 = _aesni_round(s1, s2)
        s1 = _aesni_round(s0, s1)
        s0 = _aesni_round(last, s0) ^ message0
        offset += take
    state[0] = s0
    state[1] = s1
    state[2] = s2
    state[3] = s3
    state[4] = s4
    state[5] = s5
    state[6] = s6
    state[7] = s7
    var expected = _tag128l_hardware(state, len(aad), len(ciphertext), len(tag))
    if not constant_time_equal(Span(expected), tag):
        raise Error("AEGIS authentication failed")
    return output^


def _decrypt256_hardware[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    var state = _init256_hardware(key, nonce)
    _absorb256_hardware(state, aad)
    var output = List[UInt8](unsafe_uninit_length=len(ciphertext))
    var output_span = Span(output)
    var s0 = state[0]
    var s1 = state[1]
    var s2 = state[2]
    var s3 = state[3]
    var s4 = state[4]
    var s5 = state[5]
    var offset = 0
    var cipher_pointer = ciphertext.unsafe_ptr()
    var output_pointer = output_span.unsafe_ptr()
    while offset + 16 <= len(ciphertext):
        var cipher = bitcast[DType.uint64, 2](
            cipher_pointer.unsafe_load[width=16](offset)
        )
        var message_block = cipher ^ s5 ^ s4 ^ s1 ^ (s2 & s3)
        output_pointer.unsafe_store[width=16](
            offset, bitcast[DType.uint8, 16](message_block)
        )
        var next0 = _aesni_round(s5, s0) ^ message_block
        var next1 = _aesni_round(s0, s1)
        var next2 = _aesni_round(s1, s2)
        var next3 = _aesni_round(s2, s3)
        var next4 = _aesni_round(s3, s4)
        var next5 = _aesni_round(s4, s5)
        s0 = next0
        s1 = next1
        s2 = next2
        s3 = next3
        s4 = next4
        s5 = next5
        offset += 16
    while offset < len(ciphertext):
        var take = min(16, len(ciphertext) - offset)
        var cipher = _simd_partial(ciphertext, offset, take)
        var message_block = _zero_simd_tail(
            cipher ^ s5 ^ s4 ^ s1 ^ (s2 & s3), take
        )
        _store_simd(message_block, output_span, offset, take)
        var last = s5
        s5 = _aesni_round(s4, s5)
        s4 = _aesni_round(s3, s4)
        s3 = _aesni_round(s2, s3)
        s2 = _aesni_round(s1, s2)
        s1 = _aesni_round(s0, s1)
        s0 = _aesni_round(last, s0) ^ message_block
        offset += take
    state[0] = s0
    state[1] = s1
    state[2] = s2
    state[3] = s3
    state[4] = s4
    state[5] = s5
    var expected = _tag256_hardware(state, len(aad), len(ciphertext), len(tag))
    if not constant_time_equal(Span(expected), tag):
        raise Error("AEGIS authentication failed")
    return output^


def _parameters(
    algorithm: AegisAlgorithm,
    key_bytes: Int,
    nonce_bytes: Int,
    tag_bytes: Int,
) raises -> Bool:
    if tag_bytes != 16 and tag_bytes != 32:
        raise Error("AEGIS tag must be 16 or 32 bytes")
    if algorithm == AegisAlgorithm.AEGIS128L:
        if key_bytes != 16 or nonce_bytes != 16:
            raise Error("AEGIS-128L key and nonce must be 16 bytes")
        return True
    if algorithm == AegisAlgorithm.AEGIS256:
        if key_bytes != 32 or nonce_bytes != 32:
            raise Error("AEGIS-256 key and nonce must be 32 bytes")
        return False
    raise Error("AEAD algorithm is not an AEGIS variant")


def _encrypt128l[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int,
) -> Tuple[List[UInt8], List[UInt8]]:
    var state = _init128l(key, nonce)
    _absorb128l(state, aad)
    var ciphertext = List[UInt8](length=len(message), fill=0)
    var ciphertext_span = Span(ciphertext)
    var first = List[UInt8](length=16, fill=0)
    var second = List[UInt8](length=16, fill=0)
    var offset = 0
    while offset + 32 <= len(message):
        _set_block(first, 0, message[offset : offset + 16])
        _set_block(second, 0, message[offset + 16 : offset + 32])
        _keystream128l_into(
            state,
            Span(first),
            Span(second),
            ciphertext_span,
            offset,
            16,
            16,
        )
        offset += 32
    if offset < len(message):
        var padded = _padded_block(message, offset, 32)
        var take = len(message) - offset
        var count0 = min(16, take)
        _set_block(first, 0, Span(padded)[0:16])
        _set_block(second, 0, Span(padded)[16:32])
        _keystream128l_into(
            state,
            Span(first),
            Span(second),
            ciphertext_span,
            offset,
            count0,
            take - count0,
        )
    var tag = _tag128l(state, len(aad), len(message), tag_bytes)
    return (ciphertext^, tag^)


def _encrypt256[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int,
) -> Tuple[List[UInt8], List[UInt8]]:
    var state = _init256(key, nonce)
    _absorb256(state, aad)
    var ciphertext = List[UInt8](length=len(message), fill=0)
    var ciphertext_span = Span(ciphertext)
    var offset = 0
    while offset + 16 <= len(message):
        _keystream256_into(
            state,
            message[offset : offset + 16],
            ciphertext_span,
            offset,
            16,
        )
        offset += 16
    if offset < len(message):
        var padded = _padded_block(message, offset, 16)
        _keystream256_into(
            state,
            Span(padded),
            ciphertext_span,
            offset,
            len(message) - offset,
        )
    var tag = _tag256(state, len(aad), len(message), tag_bytes)
    return (ciphertext^, tag^)


def encrypt_into[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
    cipher_origin: MutOrigin,
    tag_origin: MutOrigin,
](
    algorithm: AegisAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    ciphertext: Span[mut=True, UInt8, cipher_origin],
    tag: Span[mut=True, UInt8, tag_origin],
) raises:
    var is_128l = _parameters(algorithm, len(key), len(nonce), len(tag))
    if len(ciphertext) != len(message):
        raise Error("AEGIS ciphertext and message lengths must match")
    comptime if CompilationTarget.is_x86():
        if is_128l:
            _encrypt128l_hardware_into(
                key, nonce, aad, message, ciphertext, tag
            )
        else:
            _encrypt256_hardware_into(key, nonce, aad, message, ciphertext, tag)
        return
    if is_128l:
        var parts = _encrypt128l(key, nonce, aad, message, len(tag))
        for i in range(len(ciphertext)):
            ciphertext[i] = parts[0][i]
        for i in range(len(tag)):
            tag[i] = parts[1][i]
        return
    var parts = _encrypt256(key, nonce, aad, message, len(tag))
    for i in range(len(ciphertext)):
        ciphertext[i] = parts[0][i]
    for i in range(len(tag)):
        tag[i] = parts[1][i]


def encrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    algorithm: AegisAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int = 32,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    var ciphertext = List[UInt8](unsafe_uninit_length=len(message))
    var tag = List[UInt8](unsafe_uninit_length=tag_bytes)
    encrypt_into(
        algorithm,
        key,
        nonce,
        aad,
        message,
        Span(ciphertext),
        Span(tag),
    )
    return (ciphertext^, tag^)


def _decrypt128l[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    var state = _init128l(key, nonce)
    _absorb128l(state, aad)
    var message = List[UInt8](length=len(ciphertext), fill=0)
    var padded_message = List[UInt8](length=32, fill=0)
    var first = List[UInt8](length=16, fill=0)
    var second = List[UInt8](length=16, fill=0)
    var offset = 0
    while offset < len(ciphertext):
        var take = min(32, len(ciphertext) - offset)
        for i in range(take):
            var stream: UInt8
            if i < 16:
                stream = (
                    state[6 * 16 + i]
                    ^ state[1 * 16 + i]
                    ^ (state[2 * 16 + i] & state[3 * 16 + i])
                )
            else:
                var lane = i - 16
                stream = (
                    state[5 * 16 + lane]
                    ^ state[2 * 16 + lane]
                    ^ (state[6 * 16 + lane] & state[7 * 16 + lane])
                )
            padded_message[i] = ciphertext[offset + i] ^ stream
            message[offset + i] = padded_message[i]
        for i in range(take, 32):
            padded_message[i] = 0
        _set_block(first, 0, Span(padded_message)[0:16])
        _set_block(second, 0, Span(padded_message)[16:32])
        _update128l(state, Span(first), Span(second))
        offset += take
    var expected = _tag128l(state, len(aad), len(ciphertext), len(tag))
    if not constant_time_equal(Span(expected), tag):
        raise Error("AEGIS authentication failed")
    return message^


def _decrypt256[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    var state = _init256(key, nonce)
    _absorb256(state, aad)
    var message = List[UInt8](length=len(ciphertext), fill=0)
    var padded_message = List[UInt8](length=16, fill=0)
    var offset = 0
    while offset < len(ciphertext):
        var take = min(16, len(ciphertext) - offset)
        for i in range(take):
            padded_message[i] = ciphertext[offset + i] ^ (
                state[5 * 16 + i]
                ^ state[4 * 16 + i]
                ^ state[1 * 16 + i]
                ^ (state[2 * 16 + i] & state[3 * 16 + i])
            )
            message[offset + i] = padded_message[i]
        for i in range(take, 16):
            padded_message[i] = 0
        _update256(state, Span(padded_message))
        offset += take
    var expected = _tag256(state, len(aad), len(ciphertext), len(tag))
    if not constant_time_equal(Span(expected), tag):
        raise Error("AEGIS authentication failed")
    return message^


def decrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    algorithm: AegisAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    var is_128l = _parameters(algorithm, len(key), len(nonce), len(tag))
    comptime if CompilationTarget.is_x86():
        if is_128l:
            return _decrypt128l_hardware(key, nonce, aad, ciphertext, tag)
        return _decrypt256_hardware(key, nonce, aad, ciphertext, tag)
    if is_128l:
        return _decrypt128l(key, nonce, aad, ciphertext, tag)
    return _decrypt256(key, nonce, aad, ciphertext, tag)
