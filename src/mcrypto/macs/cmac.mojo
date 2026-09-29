"""NIST SP 800-38B CMAC over the library's 64- and 128-bit block ciphers."""

from ..ciphers.algorithm import BlockCipherAlgorithm
from std.memory import bitcast
from std.sys import CompilationTarget
from ..ciphers.modes import _PreparedCipher, block_size


@always_inline("nodebug")
def _double16(
    block: InlineArray[UInt8, 16], mut output: InlineArray[UInt8, 16]
):
    var carry = UInt8(0)
    comptime for offset in range(16):
        comptime i = 15 - offset
        var next_carry = block[i] >> 7
        output[i] = (block[i] << 1) | carry
        carry = next_carry
    output[15] ^= (UInt8(0) - carry) & 0x87


def _authenticate_aes_prepared[
    message_origin: Origin
](
    prepared: _PreparedCipher,
    message: Span[UInt8, message_origin],
    tag_size: Int,
) raises -> List[UInt8]:
    var l_value = prepared.aes.encrypt_value(SIMD[DType.uint64, 2](0))
    var l = InlineArray[UInt8, 16](fill=0)
    Span(l).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](l_value)
    )
    var k1 = InlineArray[UInt8, 16](fill=0)
    var k2 = InlineArray[UInt8, 16](fill=0)
    _double16(l, k1)
    _double16(k1, k2)
    var blocks = max(1, (len(message) + 15) // 16)
    var state = SIMD[DType.uint64, 2](0)
    var message_pointer = message.unsafe_ptr()
    for block_index in range(blocks - 1):
        state = prepared.aes.encrypt_value(
            state
            ^ bitcast[DType.uint64, 2](
                message_pointer.unsafe_load[width=16](block_index * 16)
            ),
        )
    var final = InlineArray[UInt8, 16](fill=0)
    var offset = (blocks - 1) * 16
    var complete = len(message) != 0 and len(message) % 16 == 0
    if complete:
        comptime for i in range(16):
            final[i] = message[offset + i] ^ k1[i]
    else:
        var remaining = len(message) - offset
        for i in range(remaining):
            final[i] = message[offset + i]
        final[remaining] = 0x80
        comptime for i in range(16):
            final[i] ^= k2[i]
    var final_value = state ^ bitcast[DType.uint64, 2](
        Span(final).unsafe_ptr().unsafe_load[width=16](0)
    )
    final_value = prepared.aes.encrypt_value(final_value)
    Span(final).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](final_value)
    )
    var output = List[UInt8](capacity=tag_size)
    for i in range(tag_size):
        output.append(final[i])
    return output^


def _authenticate_aes_four_prepared_into[
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    prepared: _PreparedCipher,
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    var l_value = prepared.aes.encrypt_value(SIMD[DType.uint64, 2](0))
    var l = InlineArray[UInt8, 16](fill=0)
    Span(l).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](l_value)
    )
    var k1 = InlineArray[UInt8, 16](fill=0)
    var k2 = InlineArray[UInt8, 16](fill=0)
    _double16(l, k1)
    _double16(k1, k2)
    var blocks = max(1, (len(first) + 15) // 16)
    var first_state = SIMD[DType.uint64, 2](0)
    var second_state = SIMD[DType.uint64, 2](0)
    var third_state = SIMD[DType.uint64, 2](0)
    var fourth_state = SIMD[DType.uint64, 2](0)
    var first_pointer = first.unsafe_ptr()
    var second_pointer = second.unsafe_ptr()
    var third_pointer = third.unsafe_ptr()
    var fourth_pointer = fourth.unsafe_ptr()
    for block_index in range(blocks - 1):
        var offset = block_index * 16
        first_state ^= bitcast[DType.uint64, 2](
            first_pointer.unsafe_load[width=16](offset)
        )
        second_state ^= bitcast[DType.uint64, 2](
            second_pointer.unsafe_load[width=16](offset)
        )
        third_state ^= bitcast[DType.uint64, 2](
            third_pointer.unsafe_load[width=16](offset)
        )
        fourth_state ^= bitcast[DType.uint64, 2](
            fourth_pointer.unsafe_load[width=16](offset)
        )
        prepared.aes.encrypt_four_values(
            first_state,
            second_state,
            third_state,
            fourth_state,
        )
    var first_final = InlineArray[UInt8, 16](fill=0)
    var second_final = InlineArray[UInt8, 16](fill=0)
    var third_final = InlineArray[UInt8, 16](fill=0)
    var fourth_final = InlineArray[UInt8, 16](fill=0)
    var offset = (blocks - 1) * 16
    var complete = len(first) != 0 and len(first) % 16 == 0
    if complete:
        comptime for i in range(16):
            first_final[i] = first[offset + i] ^ k1[i]
            second_final[i] = second[offset + i] ^ k1[i]
            third_final[i] = third[offset + i] ^ k1[i]
            fourth_final[i] = fourth[offset + i] ^ k1[i]
    else:
        var remaining = len(first) - offset
        for i in range(remaining):
            first_final[i] = first[offset + i]
            second_final[i] = second[offset + i]
            third_final[i] = third[offset + i]
            fourth_final[i] = fourth[offset + i]
        first_final[remaining] = 0x80
        second_final[remaining] = 0x80
        third_final[remaining] = 0x80
        fourth_final[remaining] = 0x80
        comptime for i in range(16):
            first_final[i] ^= k2[i]
            second_final[i] ^= k2[i]
            third_final[i] ^= k2[i]
            fourth_final[i] ^= k2[i]
    first_state ^= bitcast[DType.uint64, 2](
        Span(first_final).unsafe_ptr().unsafe_load[width=16]()
    )
    second_state ^= bitcast[DType.uint64, 2](
        Span(second_final).unsafe_ptr().unsafe_load[width=16]()
    )
    third_state ^= bitcast[DType.uint64, 2](
        Span(third_final).unsafe_ptr().unsafe_load[width=16]()
    )
    fourth_state ^= bitcast[DType.uint64, 2](
        Span(fourth_final).unsafe_ptr().unsafe_load[width=16]()
    )
    prepared.aes.encrypt_four_values(
        first_state,
        second_state,
        third_state,
        fourth_state,
    )
    var first_bytes = bitcast[DType.uint8, 16](first_state)
    var second_bytes = bitcast[DType.uint8, 16](second_state)
    var third_bytes = bitcast[DType.uint8, 16](third_state)
    var fourth_bytes = bitcast[DType.uint8, 16](fourth_state)
    for i in range(len(first_output)):
        first_output[i] = first_bytes[i]
        second_output[i] = second_bytes[i]
        third_output[i] = third_bytes[i]
        fourth_output[i] = fourth_bytes[i]


def _double[origin: Origin](block: Span[UInt8, origin]) raises -> List[UInt8]:
    var size = len(block)
    if size != 8 and size != 16:
        raise Error("CMAC requires a 64- or 128-bit block cipher")
    var output = List[UInt8](length=size, fill=0)
    var carry = UInt8(0)
    for offset in range(size):
        var i = size - 1 - offset
        var next_carry = block[i] >> 7
        output[i] = (block[i] << 1) | carry
        carry = next_carry
    output[size - 1] ^= (UInt8(0) - carry) & UInt8(0x1B if size == 8 else 0x87)
    return output^


def authenticate_prepared[
    message_origin: Origin,
](
    algorithm: BlockCipherAlgorithm,
    prepared: _PreparedCipher,
    message: Span[UInt8, message_origin],
    tag_size: Int = 0,
) raises -> List[UInt8]:
    var size = block_size(algorithm)
    if size != 8 and size != 16:
        raise Error("CMAC requires a 64- or 128-bit block cipher")
    var effective_size = tag_size
    if effective_size == 0:
        effective_size = size
    if effective_size < 1 or effective_size > size:
        raise Error("invalid CMAC tag size")
    comptime if CompilationTarget.is_x86():
        if algorithm == BlockCipherAlgorithm.AES:
            return _authenticate_aes_prepared(prepared, message, effective_size)
    var zero = List[UInt8](length=size, fill=0)
    var aes_fast = algorithm == BlockCipherAlgorithm.AES
    var l = List[UInt8](length=size, fill=0)
    if aes_fast:
        prepared.encrypt_aes_into(Span(zero), Span(l), 0)
    else:
        prepared.encrypt_into(Span(zero), Span(l), 0)
    var k1 = _double(Span(l))
    var k2 = _double(Span(k1))
    var blocks = max(1, (len(message) + size - 1) // size)
    var complete = len(message) != 0 and len(message) % size == 0
    var state = List[UInt8](length=size, fill=0)
    var block = List[UInt8](length=size, fill=0)
    if aes_fast:
        comptime if CompilationTarget.is_x86():
            var state_value = SIMD[DType.uint64, 2](0)
            var message_pointer = message.unsafe_ptr()
            for block_index in range(blocks - 1):
                state_value = prepared.aes.encrypt_value(
                    state_value
                    ^ bitcast[DType.uint64, 2](
                        message_pointer.unsafe_load[width=16](block_index * 16)
                    ),
                )
            Span(state).unsafe_ptr().unsafe_store[width=16](
                0, bitcast[DType.uint8, 16](state_value)
            )
        else:
            for block_index in range(blocks - 1):
                for i in range(size):
                    block[i] = state[i] ^ message[block_index * size + i]
                prepared.encrypt_aes_into(Span(block), Span(state), 0)
    else:
        for block_index in range(blocks - 1):
            for i in range(size):
                block[i] = state[i] ^ message[block_index * size + i]
            prepared.encrypt_into(Span(block), Span(state), 0)
    var final = List[UInt8](length=size, fill=0)
    var offset = (blocks - 1) * size
    if complete:
        for i in range(size):
            final[i] = message[offset + i] ^ k1[i]
    else:
        var remaining = len(message) - offset
        for i in range(remaining):
            final[i] = message[offset + i]
        final[remaining] = 0x80
        for i in range(size):
            final[i] ^= k2[i]
    for i in range(size):
        final[i] ^= state[i]
    var full = List[UInt8](length=size, fill=0)
    if aes_fast:
        prepared.encrypt_aes_into(Span(final), Span(full), 0)
    else:
        prepared.encrypt_into(Span(final), Span(full), 0)
    var output = List[UInt8](capacity=effective_size)
    for i in range(effective_size):
        output.append(full[i])
    return output^


def _authenticate[
    key_origin: Origin,
    message_origin: Origin,
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int,
) raises -> List[UInt8]:
    var prepared = _PreparedCipher(algorithm, key)
    return authenticate_prepared(algorithm, prepared, message, tag_size)


def authenticate[
    key_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int = 0,
) raises -> List[UInt8]:
    """Compute AES-CMAC, preserving the original two-argument API."""
    return _authenticate(BlockCipherAlgorithm.AES, key, message, tag_size)


def authenticate[
    key_origin: Origin,
    message_origin: Origin,
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int = 0,
) raises -> List[UInt8]:
    """Compute CMAC using a named block cipher."""
    return _authenticate(algorithm, key, message, tag_size)


def authenticate_four_into[
    key_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Authenticate four equal-length messages using interleaved AES-NI."""
    if (
        len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way CMAC inputs must have equal lengths")
    var tag_size = len(first_output)
    if (
        tag_size < 1
        or tag_size > 16
        or len(second_output) != tag_size
        or len(third_output) != tag_size
        or len(fourth_output) != tag_size
    ):
        raise Error("four-way CMAC output span has invalid length")
    comptime if CompilationTarget.is_x86():
        var prepared = _PreparedCipher(BlockCipherAlgorithm.AES, key)
        _authenticate_aes_four_prepared_into(
            prepared,
            first,
            second,
            third,
            fourth,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
    else:
        var first_tag = authenticate(key, first, tag_size)
        var second_tag = authenticate(key, second, tag_size)
        var third_tag = authenticate(key, third, tag_size)
        var fourth_tag = authenticate(key, fourth, tag_size)
        for i in range(tag_size):
            first_output[i] = first_tag[i]
            second_output[i] = second_tag[i]
            third_output[i] = third_tag[i]
            fourth_output[i] = fourth_tag[i]


def verify[
    key_origin: Origin,
    message_origin: Origin,
    tag_origin: Origin,
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag: Span[UInt8, tag_origin],
) -> Bool:
    if len(tag) == 0:
        return False
    try:
        var expected = _authenticate(algorithm, key, message, len(tag))
        var difference = UInt8(0)
        for i in range(len(tag)):
            difference |= expected[i] ^ tag[i]
        return difference == 0
    except:
        return False
