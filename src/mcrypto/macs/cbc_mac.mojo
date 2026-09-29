"""CBC-MAC over named pure-Mojo block ciphers.

CBC-MAC is secure only when every authenticated message has the same length.
The final partial block is zero-filled.
"""

from ..ciphers.algorithm import BlockCipherAlgorithm
from std.memory import bitcast
from std.sys import CompilationTarget
from ..ciphers.modes import _PreparedCipher, block_size


def _authenticate_aes_prepared[
    message_origin: Origin
](
    prepared: _PreparedCipher,
    message: Span[UInt8, message_origin],
    tag_size: Int,
) raises -> List[UInt8]:
    var state = SIMD[DType.uint64, 2](0)
    var message_pointer = message.unsafe_ptr()
    var offset = 0
    while offset + 16 <= len(message):
        state = prepared.aes.encrypt_value(
            state
            ^ bitcast[DType.uint64, 2](
                message_pointer.unsafe_load[width=16](offset)
            ),
        )
        offset += 16
    if offset < len(message):
        var tail = SIMD[DType.uint8, 16](0)
        for i in range(len(message) - offset):
            tail[i] = message_pointer.unsafe_load(offset + i)
        state = prepared.aes.encrypt_value(
            state ^ bitcast[DType.uint64, 2](tail),
        )
    var full = InlineArray[UInt8, 16](fill=0)
    Span(full).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](state)
    )
    var output = List[UInt8](capacity=tag_size)
    for i in range(tag_size):
        output.append(full[i])
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
    var effective_size = tag_size
    if effective_size == 0:
        effective_size = size
    if effective_size < 1 or effective_size > size:
        raise Error("invalid CBC-MAC tag size")
    comptime if CompilationTarget.is_x86():
        if algorithm == BlockCipherAlgorithm.AES:
            return _authenticate_aes_prepared(prepared, message, effective_size)
    var aes_fast = algorithm == BlockCipherAlgorithm.AES
    var state = List[UInt8](length=size, fill=0)
    var block = List[UInt8](length=size, fill=0)
    var offset = 0
    if aes_fast:
        var state_pointer = Span(state).unsafe_ptr()
        var block_pointer = Span(block).unsafe_ptr()
        var message_pointer = message.unsafe_ptr()
        comptime if CompilationTarget.is_x86():
            var state_value = SIMD[DType.uint64, 2](0)
            while offset + 16 <= len(message):
                state_value = prepared.aes.encrypt_value(
                    state_value
                    ^ bitcast[DType.uint64, 2](
                        message_pointer.unsafe_load[width=16](offset)
                    ),
                )
                offset += 16
            if offset < len(message):
                block_pointer.unsafe_store[width=16](
                    0, bitcast[DType.uint8, 16](state_value)
                )
                for i in range(len(message) - offset):
                    block_pointer.unsafe_store(
                        i,
                        block_pointer.unsafe_load(i)
                        ^ message_pointer.unsafe_load(offset + i),
                    )
                state_value = prepared.aes.encrypt_value(
                    bitcast[DType.uint64, 2](
                        block_pointer.unsafe_load[width=16](0)
                    ),
                )
            state_pointer.unsafe_store[width=16](
                0, bitcast[DType.uint8, 16](state_value)
            )
        else:
            while offset + 16 <= len(message):
                block_pointer.unsafe_store[width=16](
                    0,
                    state_pointer.unsafe_load[width=16](0)
                    ^ message_pointer.unsafe_load[width=16](offset),
                )
                prepared.encrypt_aes_into(Span(block), Span(state), 0)
                offset += 16
            if offset < len(message):
                block_pointer.unsafe_store[width=16](
                    0, state_pointer.unsafe_load[width=16](0)
                )
                for i in range(len(message) - offset):
                    block_pointer.unsafe_store(
                        i,
                        block_pointer.unsafe_load(i)
                        ^ message_pointer.unsafe_load(offset + i),
                    )
                prepared.encrypt_aes_into(Span(block), Span(state), 0)
    else:
        while offset < len(message):
            var count = min(size, len(message) - offset)
            for i in range(size):
                block[i] = state[i]
            for i in range(count):
                block[i] ^= message[offset + i]
            prepared.encrypt_into(Span(block), Span(state), 0)
            offset += count
    var output = List[UInt8](capacity=effective_size)
    for i in range(effective_size):
        output.append(state[i])
    return output^


def authenticate[
    key_origin: Origin,
    message_origin: Origin,
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int = 0,
) raises -> List[UInt8]:
    var prepared = _PreparedCipher(algorithm, key)
    return authenticate_prepared(algorithm, prepared, message, tag_size)


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
    """Authenticate four equal-length messages with interleaved AES-NI."""
    if (
        len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way CBC-MAC inputs must have equal lengths")
    var tag_size = len(first_output)
    if (
        tag_size < 1
        or tag_size > 16
        or len(second_output) != tag_size
        or len(third_output) != tag_size
        or len(fourth_output) != tag_size
    ):
        raise Error("four-way CBC-MAC output span has invalid length")
    comptime if CompilationTarget.is_x86():
        var prepared = _PreparedCipher(BlockCipherAlgorithm.AES, key)
        var first_state = SIMD[DType.uint64, 2](0)
        var second_state = SIMD[DType.uint64, 2](0)
        var third_state = SIMD[DType.uint64, 2](0)
        var fourth_state = SIMD[DType.uint64, 2](0)
        var first_pointer = first.unsafe_ptr()
        var second_pointer = second.unsafe_ptr()
        var third_pointer = third.unsafe_ptr()
        var fourth_pointer = fourth.unsafe_ptr()
        var offset = 0
        while offset + 16 <= len(first):
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
            offset += 16
        if offset < len(first):
            var first_tail = SIMD[DType.uint8, 16](0)
            var second_tail = SIMD[DType.uint8, 16](0)
            var third_tail = SIMD[DType.uint8, 16](0)
            var fourth_tail = SIMD[DType.uint8, 16](0)
            for i in range(len(first) - offset):
                first_tail[i] = first_pointer.unsafe_load(offset + i)
                second_tail[i] = second_pointer.unsafe_load(offset + i)
                third_tail[i] = third_pointer.unsafe_load(offset + i)
                fourth_tail[i] = fourth_pointer.unsafe_load(offset + i)
            first_state ^= bitcast[DType.uint64, 2](first_tail)
            second_state ^= bitcast[DType.uint64, 2](second_tail)
            third_state ^= bitcast[DType.uint64, 2](third_tail)
            fourth_state ^= bitcast[DType.uint64, 2](fourth_tail)
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
        for i in range(tag_size):
            first_output[i] = first_bytes[i]
            second_output[i] = second_bytes[i]
            third_output[i] = third_bytes[i]
            fourth_output[i] = fourth_bytes[i]
    else:
        var first_tag = authenticate(
            BlockCipherAlgorithm.AES, key, first, tag_size
        )
        var second_tag = authenticate(
            BlockCipherAlgorithm.AES, key, second, tag_size
        )
        var third_tag = authenticate(
            BlockCipherAlgorithm.AES, key, third, tag_size
        )
        var fourth_tag = authenticate(
            BlockCipherAlgorithm.AES, key, fourth, tag_size
        )
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
        var expected = authenticate(algorithm, key, message, len(tag))
        var difference = UInt8(0)
        for i in range(len(tag)):
            difference |= expected[i] ^ tag[i]
        return difference == 0
    except:
        return False
