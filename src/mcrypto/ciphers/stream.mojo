"""ChaCha, XChaCha, Salsa20, and XSalsa20 stream ciphers in pure Mojo."""

from .algorithm import Chacha20Stream, StreamCipherAlgorithm
from std.memory import bitcast

from std.bit import rotate_bits_left
from ..internal.bytes import store_le32
from .legacy_stream import arc4, wake
from .panama_stream import xor as panama_xor
from .seal import xor as seal_xor
from .rabbit import xor as rabbit_xor
from .hc128 import xor as hc128_xor
from .hc256 import xor as hc256_xor
from .sosemanuk import xor as sosemanuk_xor, xor_eight as sosemanuk_xor_eight


@always_inline("nodebug")
def _load_le32_unchecked[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> UInt32:
    return bitcast[DType.uint32, 1](
        data.unsafe_ptr().unsafe_load[width=4](offset)
    )[0]


@always_inline("nodebug")
def _qr[a: Int, b: Int, c: Int, d: Int](mut state: InlineArray[UInt32, 16]):
    state[a] += state[b]
    state[d] = rotate_bits_left[16](state[d] ^ state[a])
    state[c] += state[d]
    state[b] = rotate_bits_left[12](state[b] ^ state[c])
    state[a] += state[b]
    state[d] = rotate_bits_left[8](state[d] ^ state[a])
    state[c] += state[d]
    state[b] = rotate_bits_left[7](state[b] ^ state[c])


@always_inline("nodebug")
def _chacha_round_vectors[
    round_count: Int
](
    mut a: SIMD[DType.uint32, 4],
    mut b: SIMD[DType.uint32, 4],
    mut c: SIMD[DType.uint32, 4],
    mut d: SIMD[DType.uint32, 4],
):
    comptime for _ in range(round_count // 2):
        a += b
        d = rotate_bits_left[16](d ^ a)
        c += d
        b = rotate_bits_left[12](b ^ c)
        a += b
        d = rotate_bits_left[8](d ^ a)
        c += d
        b = rotate_bits_left[7](b ^ c)

        b = b.shuffle[1, 2, 3, 0]()
        c = c.shuffle[2, 3, 0, 1]()
        d = d.shuffle[3, 0, 1, 2]()
        a += b
        d = rotate_bits_left[16](d ^ a)
        c += d
        b = rotate_bits_left[12](b ^ c)
        a += b
        d = rotate_bits_left[8](d ^ a)
        c += d
        b = rotate_bits_left[7](b ^ c)
        b = b.shuffle[3, 0, 1, 2]()
        c = c.shuffle[2, 3, 0, 1]()
        d = d.shuffle[1, 2, 3, 0]()


@always_inline("nodebug")
def _chacha_permute[
    round_count: Int
](state: InlineArray[UInt32, 16],) -> InlineArray[UInt32, 16]:
    var a = SIMD[DType.uint32, 4](state[0], state[1], state[2], state[3])
    var b = SIMD[DType.uint32, 4](state[4], state[5], state[6], state[7])
    var c = SIMD[DType.uint32, 4](state[8], state[9], state[10], state[11])
    var d = SIMD[DType.uint32, 4](state[12], state[13], state[14], state[15])
    _chacha_round_vectors[round_count](a, b, c, d)
    var working = InlineArray[UInt32, 16](uninitialized=True)
    comptime for lane in range(4):
        working[lane] = a[lane]
        working[4 + lane] = b[lane]
        working[8 + lane] = c[lane]
        working[12 + lane] = d[lane]
    return working^


@always_inline("nodebug")
def _chacha_block[
    round_count: Int
](state: InlineArray[UInt32, 16],) -> InlineArray[UInt32, 16]:
    var working = _chacha_permute[round_count](state)
    comptime for i in range(16):
        working[i] += state[i]
    return working^


@always_inline("nodebug")
def _chacha_block_chunks[
    round_count: Int
](state: InlineArray[UInt32, 16]) -> InlineArray[SIMD[DType.uint32, 4], 4]:
    var original = InlineArray[SIMD[DType.uint32, 4], 4](uninitialized=True)
    original[0] = SIMD[DType.uint32, 4](state[0], state[1], state[2], state[3])
    original[1] = SIMD[DType.uint32, 4](state[4], state[5], state[6], state[7])
    original[2] = SIMD[DType.uint32, 4](
        state[8], state[9], state[10], state[11]
    )
    original[3] = SIMD[DType.uint32, 4](
        state[12], state[13], state[14], state[15]
    )
    var a = original[0]
    var b = original[1]
    var c = original[2]
    var d = original[3]
    _chacha_round_vectors[round_count](a, b, c, d)
    original[0] += a
    original[1] += b
    original[2] += c
    original[3] += d
    return original^


@always_inline("nodebug")
def _hchacha_inline[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> InlineArray[UInt8, 32]:
    var state = InlineArray[UInt32, 16](fill=0)
    state[0] = 0x61707865
    state[1] = 0x3320646E
    state[2] = 0x79622D32
    state[3] = 0x6B206574
    comptime for i in range(8):
        state[4 + i] = _load_le32_unchecked(key, i * 4)
    comptime for i in range(4):
        state[12 + i] = _load_le32_unchecked(nonce, i * 4)
    state = _chacha_permute[20](state)
    var out = InlineArray[UInt8, 32](uninitialized=True)
    var first = SIMD[DType.uint32, 4](0)
    var second = SIMD[DType.uint32, 4](0)
    comptime for i in range(4):
        first[i] = state[i]
        second[i] = state[12 + i]
    var pointer = Span(out).unsafe_ptr()
    pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](first))
    pointer.unsafe_store[width=16](16, bitcast[DType.uint8, 16](second))
    return out^


@always_inline("nodebug")
def _hchacha[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> List[UInt8]:
    var block = _hchacha_inline(key, nonce)
    var out = List[UInt8](length=32, fill=0)
    Span(out).unsafe_ptr().unsafe_store[width=32](
        0, Span(block).unsafe_ptr().unsafe_load[width=32](0)
    )
    return out^


@always_inline("nodebug")
def _qr_eight[
    a: Int, b: Int, c: Int, d: Int
](mut state: InlineArray[SIMD[DType.uint32, 8], 16],):
    state[a] += state[b]
    state[d] = rotate_bits_left[16](state[d] ^ state[a])
    state[c] += state[d]
    state[b] = rotate_bits_left[12](state[b] ^ state[c])
    state[a] += state[b]
    state[d] = rotate_bits_left[8](state[d] ^ state[a])
    state[c] += state[d]
    state[b] = rotate_bits_left[7](state[b] ^ state[c])


@always_inline("nodebug")
def _chacha_eight[
    round_count: Int,
    ietf_mode: Bool,
](state: InlineArray[UInt32, 16],) -> InlineArray[SIMD[DType.uint32, 8], 16]:
    var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
        fill=SIMD[DType.uint32, 8](0)
    )
    comptime for word in range(16):
        lanes[word] = SIMD[DType.uint32, 8](state[word])
    var low = state[12]
    var high = state[13]
    comptime for lane in range(8):
        var counter = low + UInt32(lane)
        lanes[12][lane] = counter
        comptime if not ietf_mode:
            lanes[13][lane] = high + UInt32(counter < low)
    var working = lanes.copy()
    comptime for _ in range(round_count // 2):
        _qr_eight[0, 4, 8, 12](working)
        _qr_eight[1, 5, 9, 13](working)
        _qr_eight[2, 6, 10, 14](working)
        _qr_eight[3, 7, 11, 15](working)
        _qr_eight[0, 5, 10, 15](working)
        _qr_eight[1, 6, 11, 12](working)
        _qr_eight[2, 7, 8, 13](working)
        _qr_eight[3, 4, 9, 14](working)
    comptime for word in range(16):
        working[word] += lanes[word]
    return working^


def _chacha[
    round_count: Int,
    ietf_mode: Bool,
    key_origin: Origin,
    nonce_origin: Origin,
    input_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
    initial_counter: UInt32 = 0,
) raises -> List[UInt8]:
    var state = InlineArray[UInt32, 16](fill=0)
    state[0] = 0x61707865
    state[1] = 0x3320646E
    state[2] = 0x79622D32
    state[3] = 0x6B206574
    comptime for i in range(8):
        state[4 + i] = _load_le32_unchecked(key, i * 4)
    comptime if ietf_mode:
        comptime for i in range(3):
            state[13 + i] = _load_le32_unchecked(nonce, i * 4)
    else:
        state[14] = _load_le32_unchecked(nonce, 0)
        state[15] = _load_le32_unchecked(nonce, 4)
    state[12] = initial_counter
    var out = List[UInt8](length=len(input), fill=0)
    var out_pointer = Span(out).unsafe_ptr()
    var input_pointer = input.unsafe_ptr()
    var offset = 0
    while offset + 512 <= len(input):
        var stream = _chacha_eight[round_count, ietf_mode](state)
        comptime for block in range(8):
            comptime for chunk in range(4):
                var words = SIMD[DType.uint32, 4](
                    stream[chunk * 4][block],
                    stream[chunk * 4 + 1][block],
                    stream[chunk * 4 + 2][block],
                    stream[chunk * 4 + 3][block],
                )
                var position = offset + block * 64 + chunk * 16
                out_pointer.unsafe_store[width=16](
                    position,
                    input_pointer.unsafe_load[width=16](position)
                    ^ bitcast[DType.uint8, 16](words),
                )
        var previous = state[12]
        state[12] += 8
        comptime if not ietf_mode:
            if state[12] < previous:
                state[13] += 1
        offset += 512
    while offset < len(input):
        var chunks = _chacha_block_chunks[round_count](state)
        var count = min(64, len(input) - offset)
        var full_chunks = count // 16
        for chunk in range(full_chunks):
            var position = offset + chunk * 16
            out_pointer.unsafe_store[width=16](
                position,
                input_pointer.unsafe_load[width=16](position)
                ^ bitcast[DType.uint8, 16](chunks[chunk]),
            )
        for i in range(full_chunks * 16, count):
            var word = chunks[i >> 4][(i >> 2) & 3]
            out_pointer.unsafe_store(
                offset + i,
                input_pointer.unsafe_load(offset + i)
                ^ UInt8(word >> UInt32(8 * (i & 3))),
            )
        state[12] += 1
        comptime if not ietf_mode:
            if state[12] == 0:
                state[13] += 1
        offset += 64
    return out^


@always_inline("nodebug")
def _rol(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _salsa_round_vectors[
    round_count: Int
](
    mut a: SIMD[DType.uint32, 4],
    mut b: SIMD[DType.uint32, 4],
    mut c: SIMD[DType.uint32, 4],
    mut d: SIMD[DType.uint32, 4],
):
    comptime for _ in range(round_count // 2):
        b ^= rotate_bits_left[7](a + d)
        c ^= rotate_bits_left[9](b + a)
        d ^= rotate_bits_left[13](c + b)
        a ^= rotate_bits_left[18](d + c)

        var row_b = d.shuffle[1, 2, 3, 0]()
        var row_c = c.shuffle[2, 3, 0, 1]()
        var row_d = b.shuffle[3, 0, 1, 2]()
        row_b ^= rotate_bits_left[7](a + row_d)
        row_c ^= rotate_bits_left[9](row_b + a)
        row_d ^= rotate_bits_left[13](row_c + row_b)
        a ^= rotate_bits_left[18](row_d + row_c)
        b = row_d.shuffle[1, 2, 3, 0]()
        c = row_c.shuffle[2, 3, 0, 1]()
        d = row_b.shuffle[3, 0, 1, 2]()


@always_inline("nodebug")
def _salsa_rounds[round_count: Int](mut x: InlineArray[UInt32, 16]):
    var a = SIMD[DType.uint32, 4](x[0], x[5], x[10], x[15])
    var b = SIMD[DType.uint32, 4](x[4], x[9], x[14], x[3])
    var c = SIMD[DType.uint32, 4](x[8], x[13], x[2], x[7])
    var d = SIMD[DType.uint32, 4](x[12], x[1], x[6], x[11])
    _salsa_round_vectors[round_count](a, b, c, d)
    x[0] = a[0]
    x[5] = a[1]
    x[10] = a[2]
    x[15] = a[3]
    x[4] = b[0]
    x[9] = b[1]
    x[14] = b[2]
    x[3] = b[3]
    x[8] = c[0]
    x[13] = c[1]
    x[2] = c[2]
    x[7] = c[3]
    x[12] = d[0]
    x[1] = d[1]
    x[6] = d[2]
    x[11] = d[3]


@always_inline("nodebug")
def _salsa_block_chunks[
    round_count: Int
](state: InlineArray[UInt32, 16]) -> InlineArray[SIMD[DType.uint32, 4], 4]:
    var a = SIMD[DType.uint32, 4](state[0], state[5], state[10], state[15])
    var b = SIMD[DType.uint32, 4](state[4], state[9], state[14], state[3])
    var c = SIMD[DType.uint32, 4](state[8], state[13], state[2], state[7])
    var d = SIMD[DType.uint32, 4](state[12], state[1], state[6], state[11])
    _salsa_round_vectors[round_count](a, b, c, d)
    var chunks = InlineArray[SIMD[DType.uint32, 4], 4](uninitialized=True)
    chunks[0] = SIMD[DType.uint32, 4](
        a[0] + state[0],
        d[1] + state[1],
        c[2] + state[2],
        b[3] + state[3],
    )
    chunks[1] = SIMD[DType.uint32, 4](
        b[0] + state[4],
        a[1] + state[5],
        d[2] + state[6],
        c[3] + state[7],
    )
    chunks[2] = SIMD[DType.uint32, 4](
        c[0] + state[8],
        b[1] + state[9],
        a[2] + state[10],
        d[3] + state[11],
    )
    chunks[3] = SIMD[DType.uint32, 4](
        d[0] + state[12],
        c[1] + state[13],
        b[2] + state[14],
        a[3] + state[15],
    )
    return chunks^


@always_inline("nodebug")
def _salsa_rounds_eight[
    round_count: Int
](mut x: InlineArray[SIMD[DType.uint32, 8], 16],):
    comptime for _ in range(round_count // 2):
        x[4] ^= rotate_bits_left[7](x[0] + x[12])
        x[8] ^= rotate_bits_left[9](x[4] + x[0])
        x[12] ^= rotate_bits_left[13](x[8] + x[4])
        x[0] ^= rotate_bits_left[18](x[12] + x[8])
        x[9] ^= rotate_bits_left[7](x[5] + x[1])
        x[13] ^= rotate_bits_left[9](x[9] + x[5])
        x[1] ^= rotate_bits_left[13](x[13] + x[9])
        x[5] ^= rotate_bits_left[18](x[1] + x[13])
        x[14] ^= rotate_bits_left[7](x[10] + x[6])
        x[2] ^= rotate_bits_left[9](x[14] + x[10])
        x[6] ^= rotate_bits_left[13](x[2] + x[14])
        x[10] ^= rotate_bits_left[18](x[6] + x[2])
        x[3] ^= rotate_bits_left[7](x[15] + x[11])
        x[7] ^= rotate_bits_left[9](x[3] + x[15])
        x[11] ^= rotate_bits_left[13](x[7] + x[3])
        x[15] ^= rotate_bits_left[18](x[11] + x[7])
        x[1] ^= rotate_bits_left[7](x[0] + x[3])
        x[2] ^= rotate_bits_left[9](x[1] + x[0])
        x[3] ^= rotate_bits_left[13](x[2] + x[1])
        x[0] ^= rotate_bits_left[18](x[3] + x[2])
        x[6] ^= rotate_bits_left[7](x[5] + x[4])
        x[7] ^= rotate_bits_left[9](x[6] + x[5])
        x[4] ^= rotate_bits_left[13](x[7] + x[6])
        x[5] ^= rotate_bits_left[18](x[4] + x[7])
        x[11] ^= rotate_bits_left[7](x[10] + x[9])
        x[8] ^= rotate_bits_left[9](x[11] + x[10])
        x[9] ^= rotate_bits_left[13](x[8] + x[11])
        x[10] ^= rotate_bits_left[18](x[9] + x[8])
        x[12] ^= rotate_bits_left[7](x[15] + x[14])
        x[13] ^= rotate_bits_left[9](x[12] + x[15])
        x[14] ^= rotate_bits_left[13](x[13] + x[12])
        x[15] ^= rotate_bits_left[18](x[14] + x[13])


@always_inline("nodebug")
def _salsa_state[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> InlineArray[UInt32, 16]:
    var state = InlineArray[UInt32, 16](fill=0)
    var key_words = bitcast[DType.uint32, 8](
        key.unsafe_ptr().unsafe_load[width=32](0)
    )
    var nonce_words = bitcast[DType.uint32, 2](
        nonce.unsafe_ptr().unsafe_load[width=8](0)
    )
    state[0] = 0x61707865
    comptime for i in range(4):
        state[1 + i] = key_words[i]
    state[5] = 0x3320646E
    state[6] = nonce_words[0]
    state[7] = nonce_words[1]
    state[10] = 0x79622D32
    comptime for i in range(4):
        state[11 + i] = key_words[4 + i]
    state[15] = 0x6B206574
    return state^


@always_inline("nodebug")
def _hsalsa_inline[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> InlineArray[UInt8, 32]:
    var s = _salsa_state(key, nonce[0:8])
    s[8] = _load_le32_unchecked(nonce, 8)
    s[9] = _load_le32_unchecked(nonce, 12)
    var x = s.copy()
    _salsa_rounds[20](x)
    var out = InlineArray[UInt8, 32](uninitialized=True)
    var first = SIMD[DType.uint32, 4](x[0], x[5], x[10], x[15])
    var second = SIMD[DType.uint32, 4](x[6], x[7], x[8], x[9])
    var pointer = Span(out).unsafe_ptr()
    pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](first))
    pointer.unsafe_store[width=16](16, bitcast[DType.uint8, 16](second))
    return out^


@always_inline("nodebug")
def _hsalsa[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> List[UInt8]:
    var block = _hsalsa_inline(key, nonce)
    var out = List[UInt8](length=32, fill=0)
    Span(out).unsafe_ptr().unsafe_store[width=32](
        0, Span(block).unsafe_ptr().unsafe_load[width=32](0)
    )
    return out^


def _salsa[
    round_count: Int,
    key_origin: Origin,
    nonce_origin: Origin,
    input_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    var state = _salsa_state(key, nonce)
    var out = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(out).unsafe_ptr()
    var offset = 0
    while offset + 512 <= len(input):
        var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
            fill=SIMD[DType.uint32, 8](0)
        )
        comptime for word in range(16):
            lanes[word] = SIMD[DType.uint32, 8](state[word])
        var low = state[8]
        var high = state[9]
        comptime for lane in range(8):
            var counter = low + UInt32(lane)
            lanes[8][lane] = counter
            lanes[9][lane] = high + UInt32(counter < low)
        var x = lanes.copy()
        _salsa_rounds_eight[round_count](x)
        comptime for word in range(16):
            x[word] += lanes[word]
        comptime for block in range(8):
            comptime for chunk in range(4):
                var words = SIMD[DType.uint32, 4](
                    x[chunk * 4][block],
                    x[chunk * 4 + 1][block],
                    x[chunk * 4 + 2][block],
                    x[chunk * 4 + 3][block],
                )
                var position = offset + block * 64 + chunk * 16
                output_pointer.unsafe_store[width=16](
                    position,
                    input_pointer.unsafe_load[width=16](position)
                    ^ bitcast[DType.uint8, 16](words),
                )
        var old_low = state[8]
        state[8] += 8
        if state[8] < old_low:
            state[9] += 1
        offset += 512
    while offset < len(input):
        var chunks = _salsa_block_chunks[round_count](state)
        var count = min(64, len(input) - offset)
        var full_chunks = count // 16
        for chunk in range(full_chunks):
            var position = offset + chunk * 16
            output_pointer.unsafe_store[width=16](
                position,
                input_pointer.unsafe_load[width=16](position)
                ^ bitcast[DType.uint8, 16](chunks[chunk]),
            )
        for i in range(full_chunks * 16, count):
            var word = chunks[i >> 4][(i >> 2) & 3]
            output_pointer.unsafe_store(
                offset + i,
                input_pointer.unsafe_load(offset + i)
                ^ UInt8(word >> UInt32(8 * (i & 3))),
            )
        state[8] += 1
        if state[8] == 0:
            state[9] += 1
        offset += 64
    return out^


@always_inline("nodebug")
def _xchacha_nonce_inline[
    nonce_origin: Origin
](nonce: Span[UInt8, nonce_origin]) -> InlineArray[UInt8, 12]:
    var derived = InlineArray[UInt8, 12](fill=0)
    Span(derived).unsafe_ptr().unsafe_store[width=8](
        4, nonce.unsafe_ptr().unsafe_load[width=8](16)
    )
    return derived^


def xor_chacha_from_counter[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    algorithm: Chacha20Stream,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
    initial_counter: UInt32,
) raises -> List[UInt8]:
    if len(key) != 32:
        raise Error("stream key has invalid length")
    if algorithm == Chacha20Stream.CHACHA20 and len(nonce) == 8:
        return _chacha[20, False](key, nonce, input, initial_counter)
    if algorithm == Chacha20Stream.CHACHA20_IETF and len(nonce) == 12:
        return _chacha[20, True](key, nonce, input, initial_counter)
    if algorithm == Chacha20Stream.XCHACHA20 and len(nonce) == 24:
        var subkey = _hchacha_inline(key, nonce[0:16])
        var derived_nonce = _xchacha_nonce_inline(nonce)
        return _chacha[20, True](
            Span(subkey), Span(derived_nonce), input, initial_counter
        )
    raise Error("unknown ChaCha stream or invalid nonce length")


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    algorithm: StreamCipherAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) == 32:
        if algorithm == StreamCipherAlgorithm.CHACHA20 and len(nonce) == 8:
            return _chacha[20, False](key, nonce, input)
        if (
            algorithm == StreamCipherAlgorithm.CHACHA20_IETF
            and len(nonce) == 12
        ):
            return _chacha[20, True](key, nonce, input)
        if algorithm == StreamCipherAlgorithm.CHACHA12 and len(nonce) == 8:
            return _chacha[12, False](key, nonce, input)
        if algorithm == StreamCipherAlgorithm.CHACHA8 and len(nonce) == 8:
            return _chacha[8, False](key, nonce, input)
        if (
            algorithm == StreamCipherAlgorithm.XCHACHA20_COUNTER1
            and len(nonce) == 24
        ):
            var subkey = _hchacha_inline(key, nonce[0:16])
            var n = _xchacha_nonce_inline(nonce)
            return _chacha[20, True](Span(subkey), Span(n), input, 1)
        if algorithm == StreamCipherAlgorithm.XCHACHA20 and len(nonce) == 24:
            var subkey = _hchacha_inline(key, nonce[0:16])
            var n = _xchacha_nonce_inline(nonce)
            return _chacha[20, True](Span(subkey), Span(n), input)
        if algorithm == StreamCipherAlgorithm.SALSA20 and len(nonce) == 8:
            return _salsa[20](key, nonce, input)
        if algorithm == StreamCipherAlgorithm.SALSA20_12 and len(nonce) == 8:
            return _salsa[12](key, nonce, input)
        if algorithm == StreamCipherAlgorithm.SALSA20_8 and len(nonce) == 8:
            return _salsa[8](key, nonce, input)
        if algorithm == StreamCipherAlgorithm.XSALSA20 and len(nonce) == 24:
            var subkey = _hsalsa_inline(key, nonce[0:16])
            return _salsa[20](Span(subkey), nonce[16:24], input)
    if algorithm == StreamCipherAlgorithm.ARC4:
        return arc4(key, input)
    if (
        algorithm == StreamCipherAlgorithm.PANAMA
        and len(key) == 32
        and len(nonce) == 32
    ):
        return panama_xor(False, key, nonce, input)
    if (
        algorithm == StreamCipherAlgorithm.PANAMA_BE
        and len(key) == 32
        and len(nonce) == 32
    ):
        return panama_xor(True, key, nonce, input)
    if (
        algorithm == StreamCipherAlgorithm.SEAL
        and len(key) == 20
        and len(nonce) == 4
    ):
        return seal_xor(False, key, nonce, input)
    if (
        algorithm == StreamCipherAlgorithm.SEAL_LE
        and len(key) == 20
        and len(nonce) == 4
    ):
        return seal_xor(True, key, nonce, input)
    if (
        algorithm == StreamCipherAlgorithm.WAKE_OFB
        and len(key) == 32
        and len(nonce) == 0
    ):
        return wake(False, key, input)
    if algorithm == StreamCipherAlgorithm.RABBIT:
        return rabbit_xor(key, nonce, input)
    if algorithm == StreamCipherAlgorithm.HC128:
        return hc128_xor(key, nonce, input)
    if algorithm == StreamCipherAlgorithm.HC256:
        return hc256_xor(key, nonce, input)
    if algorithm == StreamCipherAlgorithm.SOSEMANUK:
        return sosemanuk_xor(key, nonce, input)
    if len(key) != 32:
        raise Error("stream key has invalid length")
    raise Error("unknown stream or invalid nonce length")


def _chacha_eight_messages_from_lanes[
    round_count: Int, ietf_mode: Bool
](
    mut lanes: InlineArray[SIMD[DType.uint32, 8], 16],
    inputs: List[List[UInt8]],
) -> List[List[UInt8]]:
    var outputs = List[List[UInt8]](capacity=8)
    comptime for _ in range(8):
        outputs.append(List[UInt8](length=len(inputs[0]), fill=0))
    var offset = 0
    while offset < len(inputs[0]):
        var working = lanes.copy()
        comptime for _ in range(round_count // 2):
            _qr_eight[0, 4, 8, 12](working)
            _qr_eight[1, 5, 9, 13](working)
            _qr_eight[2, 6, 10, 14](working)
            _qr_eight[3, 7, 11, 15](working)
            _qr_eight[0, 5, 10, 15](working)
            _qr_eight[1, 6, 11, 12](working)
            _qr_eight[2, 7, 8, 13](working)
            _qr_eight[3, 4, 9, 14](working)
        comptime for word in range(16):
            working[word] += lanes[word]
        var count = min(64, len(inputs[0]) - offset)
        comptime for lane in range(8):
            var input_pointer = Span(inputs[lane]).unsafe_ptr()
            var output_pointer = Span(outputs[lane]).unsafe_ptr()
            var lane_words = SIMD[DType.uint32, 16](0)
            comptime for word in range(16):
                lane_words[word] = working[word][lane]
            var keystream = bitcast[DType.uint8, 64](lane_words)
            if count == 64:
                output_pointer.unsafe_store[width=64](
                    offset,
                    input_pointer.unsafe_load[width=64](offset) ^ keystream,
                )
            else:
                for i in range(count):
                    output_pointer.unsafe_store(
                        offset + i,
                        input_pointer.unsafe_load(offset + i) ^ keystream[i],
                    )
        var previous = lanes[12]
        lanes[12] += SIMD[DType.uint32, 8](1)
        comptime if not ietf_mode:
            comptime for lane in range(8):
                if lanes[12][lane] < previous[lane]:
                    lanes[13][lane] += 1
        offset += 64
    return outputs^


def _chacha_eight_messages[
    round_count: Int, ietf_mode: Bool, key_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
    initial_counter: UInt32 = 0,
) -> List[List[UInt8]]:
    var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
        fill=SIMD[DType.uint32, 8](0)
    )
    lanes[0] = SIMD[DType.uint32, 8](0x61707865)
    lanes[1] = SIMD[DType.uint32, 8](0x3320646E)
    lanes[2] = SIMD[DType.uint32, 8](0x79622D32)
    lanes[3] = SIMD[DType.uint32, 8](0x6B206574)
    comptime for word in range(8):
        lanes[4 + word] = SIMD[DType.uint32, 8](
            _load_le32_unchecked(key, word * 4)
        )
    lanes[12] = SIMD[DType.uint32, 8](initial_counter)
    comptime for lane in range(8):
        comptime if ietf_mode:
            comptime for word in range(3):
                lanes[13 + word][lane] = _load_le32_unchecked(
                    Span(nonces[lane]), word * 4
                )
        else:
            lanes[14][lane] = _load_le32_unchecked(Span(nonces[lane]), 0)
            lanes[15][lane] = _load_le32_unchecked(Span(nonces[lane]), 4)
    return _chacha_eight_messages_from_lanes[round_count, ietf_mode](
        lanes, inputs
    )


def _xchacha_eight_messages[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
    initial_counter: UInt32,
) raises -> List[List[UInt8]]:
    var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
        fill=SIMD[DType.uint32, 8](0)
    )
    lanes[0] = SIMD[DType.uint32, 8](0x61707865)
    lanes[1] = SIMD[DType.uint32, 8](0x3320646E)
    lanes[2] = SIMD[DType.uint32, 8](0x79622D32)
    lanes[3] = SIMD[DType.uint32, 8](0x6B206574)
    lanes[12] = SIMD[DType.uint32, 8](initial_counter)
    comptime for lane in range(8):
        var subkey = _hchacha_inline(key, Span(nonces[lane])[0:16])
        comptime for word in range(8):
            lanes[4 + word][lane] = _load_le32_unchecked(Span(subkey), word * 4)
        lanes[13][lane] = 0
        lanes[14][lane] = _load_le32_unchecked(Span(nonces[lane]), 16)
        lanes[15][lane] = _load_le32_unchecked(Span(nonces[lane]), 20)
    return _chacha_eight_messages_from_lanes[20, True](lanes, inputs)


def _salsa_eight_messages_from_lanes[
    round_count: Int
](
    mut lanes: InlineArray[SIMD[DType.uint32, 8], 16],
    inputs: List[List[UInt8]],
) -> List[List[UInt8]]:
    var outputs = List[List[UInt8]](capacity=8)
    comptime for _ in range(8):
        outputs.append(List[UInt8](length=len(inputs[0]), fill=0))
    var offset = 0
    while offset < len(inputs[0]):
        var working = lanes.copy()
        _salsa_rounds_eight[round_count](working)
        comptime for word in range(16):
            working[word] += lanes[word]
        var count = min(64, len(inputs[0]) - offset)
        comptime for lane in range(8):
            var input_pointer = Span(inputs[lane]).unsafe_ptr()
            var output_pointer = Span(outputs[lane]).unsafe_ptr()
            var lane_words = SIMD[DType.uint32, 16](0)
            comptime for word in range(16):
                lane_words[word] = working[word][lane]
            var keystream = bitcast[DType.uint8, 64](lane_words)
            if count == 64:
                output_pointer.unsafe_store[width=64](
                    offset,
                    input_pointer.unsafe_load[width=64](offset) ^ keystream,
                )
            else:
                for i in range(count):
                    output_pointer.unsafe_store(
                        offset + i,
                        input_pointer.unsafe_load(offset + i) ^ keystream[i],
                    )
        var previous = lanes[8]
        lanes[8] += SIMD[DType.uint32, 8](1)
        comptime for lane in range(8):
            if lanes[8][lane] < previous[lane]:
                lanes[9][lane] += 1
        offset += 64
    return outputs^


def _salsa_eight_messages[
    round_count: Int, key_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
        fill=SIMD[DType.uint32, 8](0)
    )
    comptime for lane in range(8):
        var state = _salsa_state(key, Span(nonces[lane]))
        comptime for word in range(16):
            lanes[word][lane] = state[word]
    return _salsa_eight_messages_from_lanes[round_count](lanes, inputs)


def _xsalsa_eight_messages[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
        fill=SIMD[DType.uint32, 8](0)
    )
    comptime for lane in range(8):
        var subkey = _hsalsa_inline(key, Span(nonces[lane])[0:16])
        var state = _salsa_state(Span(subkey), Span(nonces[lane])[16:24])
        comptime for word in range(16):
            lanes[word][lane] = state[word]
    return _salsa_eight_messages_from_lanes[20](lanes, inputs)


def xor_eight[
    key_origin: Origin
](
    algorithm: StreamCipherAlgorithm,
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    """Process eight independent messages with SIMD lanes.

    Each message has its own nonce. Callers must preserve the usual nonce
    uniqueness requirements for the selected stream cipher.
    """
    if (
        len(nonces) != 8
        or len(inputs) != 8
        or (algorithm != StreamCipherAlgorithm.SOSEMANUK and len(key) != 32)
    ):
        raise Error("eight-way stream batch has invalid dimensions")
    var input_length = len(inputs[0])
    for lane in range(8):
        if len(inputs[lane]) != input_length:
            raise Error("eight-way stream inputs must have equal lengths")
    if (
        algorithm == StreamCipherAlgorithm.CHACHA20
        or algorithm == StreamCipherAlgorithm.CHACHA12
        or algorithm == StreamCipherAlgorithm.CHACHA8
    ):
        for lane in range(8):
            if len(nonces[lane]) != 8:
                raise Error("eight-way ChaCha nonce has invalid length")
        if algorithm == StreamCipherAlgorithm.CHACHA20:
            return _chacha_eight_messages[20, False](key, nonces, inputs)
        if algorithm == StreamCipherAlgorithm.CHACHA12:
            return _chacha_eight_messages[12, False](key, nonces, inputs)
        return _chacha_eight_messages[8, False](key, nonces, inputs)
    if algorithm == StreamCipherAlgorithm.CHACHA20_IETF:
        for lane in range(8):
            if len(nonces[lane]) != 12:
                raise Error("eight-way IETF ChaCha nonce has invalid length")
        return _chacha_eight_messages[20, True](key, nonces, inputs)
    if (
        algorithm == StreamCipherAlgorithm.XCHACHA20
        or algorithm == StreamCipherAlgorithm.XCHACHA20_COUNTER1
    ):
        for lane in range(8):
            if len(nonces[lane]) != 24:
                raise Error("eight-way XChaCha nonce has invalid length")
        return _xchacha_eight_messages(
            key,
            nonces,
            inputs,
            UInt32(
                1 if algorithm
                == StreamCipherAlgorithm.XCHACHA20_COUNTER1 else 0
            ),
        )
    if (
        algorithm == StreamCipherAlgorithm.SALSA20
        or algorithm == StreamCipherAlgorithm.SALSA20_12
        or algorithm == StreamCipherAlgorithm.SALSA20_8
    ):
        for lane in range(8):
            if len(nonces[lane]) != 8:
                raise Error("eight-way Salsa nonce has invalid length")
        if algorithm == StreamCipherAlgorithm.SALSA20:
            return _salsa_eight_messages[20](key, nonces, inputs)
        if algorithm == StreamCipherAlgorithm.SALSA20_12:
            return _salsa_eight_messages[12](key, nonces, inputs)
        return _salsa_eight_messages[8](key, nonces, inputs)
    if algorithm == StreamCipherAlgorithm.XSALSA20:
        for lane in range(8):
            if len(nonces[lane]) != 24:
                raise Error("eight-way XSalsa nonce has invalid length")
        return _xsalsa_eight_messages(key, nonces, inputs)
    if algorithm == StreamCipherAlgorithm.SOSEMANUK:
        return sosemanuk_xor_eight(key, nonces, inputs)
    raise Error("unknown eight-way stream cipher")


def xor_chacha_eight_from_counter[
    key_origin: Origin
](
    algorithm: Chacha20Stream,
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    inputs: List[List[UInt8]],
    initial_counter: UInt32,
) raises -> List[List[UInt8]]:
    """Process eight ChaCha-family messages from the same initial counter."""
    if len(key) != 32 or len(nonces) != 8 or len(inputs) != 8:
        raise Error("eight-way ChaCha batch has invalid dimensions")
    var input_length = len(inputs[0])
    for lane in range(8):
        if len(inputs[lane]) != input_length:
            raise Error("eight-way ChaCha inputs must have equal lengths")
    if algorithm == Chacha20Stream.CHACHA20:
        for lane in range(8):
            if len(nonces[lane]) != 8:
                raise Error("eight-way ChaCha nonce has invalid length")
        return _chacha_eight_messages[20, False](
            key, nonces, inputs, initial_counter
        )
    if algorithm == Chacha20Stream.CHACHA20_IETF:
        for lane in range(8):
            if len(nonces[lane]) != 12:
                raise Error("eight-way IETF ChaCha nonce has invalid length")
        return _chacha_eight_messages[20, True](
            key, nonces, inputs, initial_counter
        )
    if algorithm == Chacha20Stream.XCHACHA20:
        for lane in range(8):
            if len(nonces[lane]) != 24:
                raise Error("eight-way XChaCha nonce has invalid length")
        return _xchacha_eight_messages(key, nonces, inputs, initial_counter)
    raise Error("unknown eight-way ChaCha stream")
