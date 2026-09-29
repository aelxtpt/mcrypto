"""Petrank-Rackoff DMAC over named pure-Mojo block ciphers."""

from ..ciphers.algorithm import BlockCipherAlgorithm
from std.memory import bitcast
from std.sys import CompilationTarget

from ..ciphers.aes_block import (
    _encrypt_aesni_prepared_state,
    _encrypt_aesni_prepared_value,
    _prepare_aesni,
    _prepare_aesni128,
    expand_key as aes_expand_key,
)

from ..ciphers.modes import _PreparedCipher, block_size


def _prepare_aes_keys[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[SIMD[DType.uint64, 2]]:
    if len(key) == 16:
        return _prepare_aesni128(key)
    var expanded = aes_expand_key(key)
    return _prepare_aesni(Span(expanded))


def _authenticate_aes[
    key_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int,
) raises -> List[UInt8]:
    var keys = _prepare_aes_keys(key)
    var zero = InlineArray[UInt8, 16](fill=0)
    var one = InlineArray[UInt8, 16](fill=0)
    one[15] = 1
    var first_value = _encrypt_aesni_prepared_state(keys, Span(zero), 0)
    var second_value = _encrypt_aesni_prepared_state(keys, Span(one), 0)
    var first_key = InlineArray[UInt8, 16](fill=0)
    var second_key = InlineArray[UInt8, 16](fill=0)
    Span(first_key).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](first_value)
    )
    Span(second_key).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](second_value)
    )
    var first_keys = _prepare_aesni128(Span(first_key))
    var state = SIMD[DType.uint64, 2](0)
    var message_pointer = message.unsafe_ptr()
    var full_blocks = len(message) // 16
    for block_index in range(full_blocks):
        state = _encrypt_aesni_prepared_value(
            first_keys,
            state
            ^ bitcast[DType.uint64, 2](
                message_pointer.unsafe_load[width=16](block_index * 16)
            ),
        )
    var remainder = len(message) % 16
    var final_block = InlineArray[UInt8, 16](fill=UInt8(16 - remainder))
    for i in range(remainder):
        final_block[i] = message[full_blocks * 16 + i]
    state = _encrypt_aesni_prepared_value(
        first_keys,
        state
        ^ bitcast[DType.uint64, 2](
            Span(final_block).unsafe_ptr().unsafe_load[width=16](0)
        ),
    )
    var second_keys = _prepare_aesni128(Span(second_key))
    state = _encrypt_aesni_prepared_value(second_keys, state)
    var full = InlineArray[UInt8, 16](fill=0)
    Span(full).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](state)
    )
    var output = List[UInt8](capacity=tag_size)
    for i in range(tag_size):
        output.append(full[i])
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
    var size = block_size(algorithm)
    var effective_size = tag_size
    if effective_size == 0:
        effective_size = size
    if effective_size < 1 or effective_size > size:
        raise Error("invalid DMAC tag size")
    comptime if CompilationTarget.is_x86():
        if algorithm == BlockCipherAlgorithm.AES:
            return _authenticate_aes(key, message, effective_size)
    # DMAC derives K1=E_K(0) and K2=E_K(0...01), then uses each
    # derived block as a cipher key of the cipher's valid block-size key length.
    var zero = List[UInt8](length=size, fill=0)
    var one = List[UInt8](length=size, fill=0)
    one[size - 1] = 1
    var prepared = _PreparedCipher(algorithm, key)
    var first_key = prepared.encrypt(Span(zero))
    var second_key = prepared.encrypt(Span(one))
    var inner_cipher = _PreparedCipher(algorithm, Span(first_key))
    var state = List[UInt8](length=size, fill=0)
    var block = List[UInt8](length=size, fill=0)
    var full_blocks = len(message) // size
    for block_index in range(full_blocks):
        for i in range(size):
            block[i] = state[i] ^ message[block_index * size + i]
        inner_cipher.encrypt_into(Span(block), Span(state), 0)
    var remainder = len(message) % size
    var pad_byte = UInt8(size - remainder)
    for i in range(size):
        block[i] = state[i] ^ (
            message[full_blocks * size + i] if i < remainder else pad_byte
        )
    inner_cipher.encrypt_into(Span(block), Span(state), 0)
    var final_cipher = _PreparedCipher(algorithm, Span(second_key))
    var full = List[UInt8](length=size, fill=0)
    final_cipher.encrypt_into(Span(state), Span(full), 0)
    var output = List[UInt8](capacity=effective_size)
    for i in range(effective_size):
        output.append(full[i])
    return output^


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
