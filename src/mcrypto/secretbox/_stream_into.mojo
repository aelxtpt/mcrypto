"""Prepared stream helpers for the secretbox composition layers."""

from std.memory import bitcast

from ..ciphers.stream import (
    _chacha_block,
    _chacha_eight,
    _hchacha_inline,
    _hsalsa_inline,
    _salsa_rounds,
    _salsa_rounds_eight,
    _salsa_state,
)
from ..internal.bytes import load_le32


def chacha20_ietf_state[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> InlineArray[UInt32, 16]:
    if len(key) != 32 or len(nonce) != 12:
        raise Error(
            "ChaCha20-IETF state requires a 32-byte key and 12-byte nonce"
        )
    var state = InlineArray[UInt32, 16](fill=0)
    state[0] = 0x61707865
    state[1] = 0x3320646E
    state[2] = 0x79622D32
    state[3] = 0x6B206574
    comptime for i in range(8):
        state[4 + i] = load_le32(key, 4 * i)
    comptime for i in range(3):
        state[13 + i] = load_le32(nonce, 4 * i)
    return state^


def xchacha20_state[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> InlineArray[UInt32, 16]:
    if len(key) != 32 or len(nonce) != 24:
        raise Error("XChaCha20 state requires a 32-byte key and 24-byte nonce")
    var subkey = _hchacha_inline(key, nonce[0:16])
    var state = InlineArray[UInt32, 16](fill=0)
    state[0] = 0x61707865
    state[1] = 0x3320646E
    state[2] = 0x79622D32
    state[3] = 0x6B206574
    comptime for i in range(8):
        state[4 + i] = load_le32(Span(subkey), 4 * i)
    state[13] = 0
    state[14] = load_le32(nonce, 16)
    state[15] = load_le32(nonce, 20)
    return state^


def xsalsa20_state[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin]
) raises -> InlineArray[UInt32, 16]:
    if len(key) != 32 or len(nonce) != 24:
        raise Error("XSalsa20 state requires a 32-byte key and 24-byte nonce")
    var subkey = _hsalsa_inline(key, nonce[0:16])
    return _salsa_state(Span(subkey), nonce[16:24])


@always_inline("nodebug")
def _chacha_word_byte(block: InlineArray[UInt32, 16], byte_index: Int) -> UInt8:
    return UInt8(block[byte_index >> 2] >> UInt32(8 * (byte_index & 3)))


@always_inline("nodebug")
def _salsa_word_byte(
    block: InlineArray[UInt32, 16],
    state: InlineArray[UInt32, 16],
    byte_index: Int,
) -> UInt8:
    var word_index = byte_index >> 2
    return UInt8(
        (block[word_index] + state[word_index]) >> UInt32(8 * (byte_index & 3))
    )


@always_inline("nodebug")
def _store_chacha_block[
    output_origin: MutOrigin
](
    block: InlineArray[UInt32, 16],
    output: Span[mut=True, UInt8, output_origin],
):
    var output_pointer = output.unsafe_ptr()
    comptime for chunk in range(4):
        var words = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            words[lane] = block[chunk * 4 + lane]
        output_pointer.unsafe_store[width=16](
            chunk * 16, bitcast[DType.uint8, 16](words)
        )


@always_inline("nodebug")
def _store_salsa_block[
    output_origin: MutOrigin
](
    block: InlineArray[UInt32, 16],
    state: InlineArray[UInt32, 16],
    output: Span[mut=True, UInt8, output_origin],
):
    var output_pointer = output.unsafe_ptr()
    comptime for chunk in range(4):
        var words = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            comptime index = chunk * 4 + lane
            words[lane] = block[index] + state[index]
        output_pointer.unsafe_store[width=16](
            chunk * 16, bitcast[DType.uint8, 16](words)
        )


def chacha20_ietf_xor_into[
    input_origin: Origin, output_origin: MutOrigin
](
    state: InlineArray[UInt32, 16],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    stream_offset: Int = 0,
) raises:
    if (
        stream_offset < 0
        or output_offset < 0
        or output_offset + len(input) > len(output)
    ):
        raise Error("ChaCha20 output span is too short")
    var current = state.copy()
    current[12] = UInt32(stream_offset >> 6)
    var position = 0
    var within = stream_offset & 63
    var input_pointer = input.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    if within != 0 and position < len(input):
        var block = _chacha_block[20](current)
        var count = min(64 - within, len(input))
        for i in range(count):
            output_pointer.unsafe_store(
                output_offset + i,
                input_pointer.unsafe_load(i)
                ^ _chacha_word_byte(block, within + i),
            )
        position = count
        current[12] += 1
    while position + 512 <= len(input):
        var blocks = _chacha_eight[20, True](current)
        comptime for block_index in range(8):
            comptime for chunk in range(4):
                var words = SIMD[DType.uint32, 4](0)
                comptime for lane in range(4):
                    words[lane] = blocks[chunk * 4 + lane][block_index]
                var offset = position + block_index * 64 + chunk * 16
                output_pointer.unsafe_store[width=16](
                    output_offset + offset,
                    input_pointer.unsafe_load[width=16](offset)
                    ^ bitcast[DType.uint8, 16](words),
                )
        current[12] += 8
        position += 512
    while position < len(input):
        var block = _chacha_block[20](current)
        var count = min(64, len(input) - position)
        var chunks = count // 16
        for chunk in range(chunks):
            var words = SIMD[DType.uint32, 4](0)
            comptime for lane in range(4):
                words[lane] = block[chunk * 4 + lane]
            var offset = position + chunk * 16
            output_pointer.unsafe_store[width=16](
                output_offset + offset,
                input_pointer.unsafe_load[width=16](offset)
                ^ bitcast[DType.uint8, 16](words),
            )
        for i in range(chunks * 16, count):
            output_pointer.unsafe_store(
                output_offset + position + i,
                input_pointer.unsafe_load(position + i)
                ^ _chacha_word_byte(block, i),
            )
        current[12] += 1
        position += count


def salsa20_xor_into[
    input_origin: Origin, output_origin: MutOrigin
](
    state: InlineArray[UInt32, 16],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    stream_offset: Int = 0,
) raises:
    if (
        stream_offset < 0
        or output_offset < 0
        or output_offset + len(input) > len(output)
    ):
        raise Error("Salsa20 output span is too short")
    var current = state.copy()
    var counter = UInt64(stream_offset >> 6)
    current[8] = UInt32(counter)
    current[9] = UInt32(counter >> 32)
    var position = 0
    var within = stream_offset & 63
    var input_pointer = input.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    if within != 0 and position < len(input):
        var block = current.copy()
        _salsa_rounds[20](block)
        var count = min(64 - within, len(input))
        for i in range(count):
            output_pointer.unsafe_store(
                output_offset + i,
                input_pointer.unsafe_load(i)
                ^ _salsa_word_byte(block, current, within + i),
            )
        position = count
        current[8] += 1
        if current[8] == 0:
            current[9] += 1
    while position + 512 <= len(input):
        var lanes = InlineArray[SIMD[DType.uint32, 8], 16](
            fill=SIMD[DType.uint32, 8](0)
        )
        comptime for word in range(16):
            lanes[word] = SIMD[DType.uint32, 8](current[word])
        var low = current[8]
        var high = current[9]
        comptime for lane in range(8):
            var next = low + UInt32(lane)
            lanes[8][lane] = next
            lanes[9][lane] = high + UInt32(next < low)
        var blocks = lanes.copy()
        _salsa_rounds_eight[20](blocks)
        comptime for word in range(16):
            blocks[word] += lanes[word]
        comptime for block_index in range(8):
            comptime for chunk in range(4):
                var words = SIMD[DType.uint32, 4](0)
                comptime for lane in range(4):
                    words[lane] = blocks[chunk * 4 + lane][block_index]
                var offset = position + block_index * 64 + chunk * 16
                output_pointer.unsafe_store[width=16](
                    output_offset + offset,
                    input_pointer.unsafe_load[width=16](offset)
                    ^ bitcast[DType.uint8, 16](words),
                )
        var old_low = current[8]
        current[8] += 8
        if current[8] < old_low:
            current[9] += 1
        position += 512
    while position < len(input):
        var block = current.copy()
        _salsa_rounds[20](block)
        var count = min(64, len(input) - position)
        var chunks = count // 16
        for chunk in range(chunks):
            var words = SIMD[DType.uint32, 4](0)
            comptime for lane in range(4):
                words[lane] = (
                    block[chunk * 4 + lane] + current[chunk * 4 + lane]
                )
            var offset = position + chunk * 16
            output_pointer.unsafe_store[width=16](
                output_offset + offset,
                input_pointer.unsafe_load[width=16](offset)
                ^ bitcast[DType.uint8, 16](words),
            )
        for i in range(chunks * 16, count):
            output_pointer.unsafe_store(
                output_offset + position + i,
                input_pointer.unsafe_load(position + i)
                ^ _salsa_word_byte(block, current, i),
            )
        current[8] += 1
        if current[8] == 0:
            current[9] += 1
        position += count


def chacha20_secretbox_block0_into[
    block_origin: MutOrigin, poly_origin: MutOrigin
](
    state: InlineArray[UInt32, 16],
    block0: Span[mut=True, UInt8, block_origin],
    poly_key: Span[mut=True, UInt8, poly_origin],
) raises:
    if len(block0) != 64 or len(poly_key) != 32:
        raise Error("invalid secretbox block-zero output span")
    var block = _chacha_block[20](state)
    _store_chacha_block(block, block0)
    var block_pointer = block0.unsafe_ptr()
    var key_pointer = poly_key.unsafe_ptr()
    comptime for chunk in range(2):
        key_pointer.unsafe_store[width=16](
            chunk * 16, block_pointer.unsafe_load[width=16](chunk * 16)
        )


def chacha20_secretstream_material_into[
    decrypt: Bool,
    poly_origin: MutOrigin,
    block_origin: MutOrigin,
](
    state: InlineArray[UInt32, 16],
    tag: UInt8,
    poly_key: Span[mut=True, UInt8, poly_origin],
    tag_block: Span[mut=True, UInt8, block_origin],
) raises -> UInt8:
    """Generate the Poly1305 key and encrypted-tag block in two ChaCha calls."""
    if len(poly_key) != 32 or len(tag_block) != 64:
        raise Error("invalid secretstream material output span")
    var block0 = _chacha_block[20](state)
    var key_pointer = poly_key.unsafe_ptr()
    comptime for chunk in range(2):
        var words = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            words[lane] = block0[chunk * 4 + lane]
        key_pointer.unsafe_store[width=16](
            chunk * 16, bitcast[DType.uint8, 16](words)
        )
    var next = state.copy()
    next[12] += 1
    var block1 = _chacha_block[20](next)
    _store_chacha_block(block1, tag_block)
    var stream_tag = tag_block[0]
    comptime if decrypt:
        tag_block[0] = tag
    else:
        tag_block[0] = tag ^ stream_tag
    return tag ^ stream_tag


def chacha20_secretbox_payload_into[
    input_origin: Origin,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    state: InlineArray[UInt32, 16],
    block0: Span[UInt8, block_origin],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if (
        len(block0) != 64
        or output_offset < 0
        or output_offset + len(input) > len(output)
    ):
        raise Error("invalid secretbox payload output span")
    var prefix = min(32, len(input))
    var chunks = prefix // 16
    var input_pointer = input.unsafe_ptr()
    var block_pointer = block0.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    for chunk in range(chunks):
        var offset = chunk * 16
        output_pointer.unsafe_store[width=16](
            output_offset + offset,
            input_pointer.unsafe_load[width=16](offset)
            ^ block_pointer.unsafe_load[width=16](32 + offset),
        )
    for i in range(chunks * 16, prefix):
        output_pointer.unsafe_store(
            output_offset + i,
            input_pointer.unsafe_load(i) ^ block_pointer.unsafe_load(32 + i),
        )
    if prefix < len(input):
        chacha20_ietf_xor_into(
            state,
            input[prefix:],
            output,
            output_offset + prefix,
            64,
        )


def chacha20_secretbox_into[
    input_origin: Origin,
    output_origin: MutOrigin,
    poly_origin: MutOrigin,
](
    state: InlineArray[UInt32, 16],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    poly_key: Span[mut=True, UInt8, poly_origin],
) raises:
    var block0 = InlineArray[UInt8, 64](fill=0)
    chacha20_secretbox_block0_into(state, Span(block0), poly_key)
    chacha20_secretbox_payload_into(
        state, Span(block0), input, output, output_offset
    )


def salsa20_secretbox_block0_into[
    block_origin: MutOrigin, poly_origin: MutOrigin
](
    state: InlineArray[UInt32, 16],
    block0: Span[mut=True, UInt8, block_origin],
    poly_key: Span[mut=True, UInt8, poly_origin],
) raises:
    if len(block0) != 64 or len(poly_key) != 32:
        raise Error("invalid secretbox block-zero output span")
    var block = state.copy()
    _salsa_rounds[20](block)
    _store_salsa_block(block, state, block0)
    var block_pointer = block0.unsafe_ptr()
    var key_pointer = poly_key.unsafe_ptr()
    comptime for chunk in range(2):
        key_pointer.unsafe_store[width=16](
            chunk * 16, block_pointer.unsafe_load[width=16](chunk * 16)
        )


def salsa20_secretbox_payload_into[
    input_origin: Origin,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    state: InlineArray[UInt32, 16],
    block0: Span[UInt8, block_origin],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if (
        len(block0) != 64
        or output_offset < 0
        or output_offset + len(input) > len(output)
    ):
        raise Error("invalid secretbox payload output span")
    var prefix = min(32, len(input))
    var chunks = prefix // 16
    var input_pointer = input.unsafe_ptr()
    var block_pointer = block0.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    for chunk in range(chunks):
        var offset = chunk * 16
        output_pointer.unsafe_store[width=16](
            output_offset + offset,
            input_pointer.unsafe_load[width=16](offset)
            ^ block_pointer.unsafe_load[width=16](32 + offset),
        )
    for i in range(chunks * 16, prefix):
        output_pointer.unsafe_store(
            output_offset + i,
            input_pointer.unsafe_load(i) ^ block_pointer.unsafe_load(32 + i),
        )
    if prefix < len(input):
        salsa20_xor_into(
            state,
            input[prefix:],
            output,
            output_offset + prefix,
            64,
        )


def salsa20_secretbox_into[
    input_origin: Origin,
    output_origin: MutOrigin,
    poly_origin: MutOrigin,
](
    state: InlineArray[UInt32, 16],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    poly_key: Span[mut=True, UInt8, poly_origin],
) raises:
    var block0 = InlineArray[UInt8, 64](fill=0)
    salsa20_secretbox_block0_into(state, Span(block0), poly_key)
    salsa20_secretbox_payload_into(
        state, Span(block0), input, output, output_offset
    )
