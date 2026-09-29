"""NIST SP 800-38D GMAC using the shared pure-Mojo AES-GCM GHASH."""
from std.memory import bitcast
from std.sys import CompilationTarget

from ..aead.aes_gcm import (
    _carryless_multiply,
    _ghash,
    _ghash_table,
    _initial_counter,
    _multiply_hardware_reversed,
    _reverse_byte_bits,
    _validate,
)
from ..ciphers.aes_block import (
    _encrypt_aesni_prepared_state,
    _prepare_aesni,
    _prepare_aesni128,
    encrypt_expanded_into,
    expand_key,
)


@always_inline("nodebug")
def _reduce_product(
    low_product: SIMD[DType.uint64, 2],
    high_product: SIMD[DType.uint64, 2],
    cross_product: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var low0 = UInt64(low_product[0])
    var low1 = UInt64(low_product[1]) ^ UInt64(cross_product[0])
    var high0 = UInt64(high_product[0]) ^ UInt64(cross_product[1])
    var high1 = UInt64(high_product[1])
    var result0 = low0 ^ high0 ^ (high0 << 1) ^ (high0 << 2) ^ (high0 << 7)
    var result1 = (
        low1
        ^ high1
        ^ (high1 << 1)
        ^ (high0 >> 63)
        ^ (high1 << 2)
        ^ (high0 >> 62)
        ^ (high1 << 7)
        ^ (high0 >> 57)
    )
    var overflow = (high1 >> 63) ^ (high1 >> 62) ^ (high1 >> 57)
    result0 ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7)
    var result = SIMD[DType.uint64, 2](0)
    result[0] = result0
    result[1] = result1
    return result


@always_inline("nodebug")
def _multiply_four(
    left0: SIMD[DType.uint64, 2],
    right0: SIMD[DType.uint64, 2],
    left1: SIMD[DType.uint64, 2],
    right1: SIMD[DType.uint64, 2],
    left2: SIMD[DType.uint64, 2],
    right2: SIMD[DType.uint64, 2],
    left3: SIMD[DType.uint64, 2],
    right3: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    # GHASH reduction is linear, so accumulate four 256-bit carryless
    # products and reduce only once.
    var low = (
        _carryless_multiply(left0, right0, 0)
        ^ _carryless_multiply(left1, right1, 0)
        ^ _carryless_multiply(left2, right2, 0)
        ^ _carryless_multiply(left3, right3, 0)
    )
    var high = (
        _carryless_multiply(left0, right0, 0x11)
        ^ _carryless_multiply(left1, right1, 0x11)
        ^ _carryless_multiply(left2, right2, 0x11)
        ^ _carryless_multiply(left3, right3, 0x11)
    )
    var cross = (
        _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left0[0]) ^ UInt64(left0[1])),
            SIMD[DType.uint64, 2](UInt64(right0[0]) ^ UInt64(right0[1])),
            0,
        )
        ^ _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left1[0]) ^ UInt64(left1[1])),
            SIMD[DType.uint64, 2](UInt64(right1[0]) ^ UInt64(right1[1])),
            0,
        )
        ^ _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left2[0]) ^ UInt64(left2[1])),
            SIMD[DType.uint64, 2](UInt64(right2[0]) ^ UInt64(right2[1])),
            0,
        )
        ^ _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left3[0]) ^ UInt64(left3[1])),
            SIMD[DType.uint64, 2](UInt64(right3[0]) ^ UInt64(right3[1])),
            0,
        )
        ^ low
        ^ high
    )
    return _reduce_product(low, high, cross)


def _ghash_message_x86[
    message_origin: Origin, h_origin: Origin
](message: Span[UInt8, message_origin], h_bytes: Span[UInt8, h_origin]) -> SIMD[
    DType.uint8, 16
]:
    var h = bitcast[DType.uint64, 2](
        _reverse_byte_bits(h_bytes.unsafe_ptr().unsafe_load[width=16](0))
    )
    var h2 = _multiply_hardware_reversed(h, h)
    var h3 = _multiply_hardware_reversed(h2, h)
    var h4 = _multiply_hardware_reversed(h3, h)
    var state = SIMD[DType.uint64, 2](0)
    var pointer = message.unsafe_ptr()
    var offset = 0
    while offset + 64 <= len(message):
        var block0 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset))
        )
        var block1 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset + 16))
        )
        var block2 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset + 32))
        )
        var block3 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset + 48))
        )
        state = _multiply_four(
            state ^ block0, h4, block1, h3, block2, h2, block3, h
        )
        offset += 64
    while offset + 16 <= len(message):
        var block = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset))
        )
        state = _multiply_hardware_reversed(state ^ block, h)
        offset += 16
    if offset < len(message):
        var tail = SIMD[DType.uint8, 16](0)
        for i in range(len(message) - offset):
            tail[i] = pointer.unsafe_load(offset + i)
        state = _multiply_hardware_reversed(
            state ^ bitcast[DType.uint64, 2](_reverse_byte_bits(tail)), h
        )
    var lengths = SIMD[DType.uint8, 16](0)
    var bit_length = UInt64(len(message)) * 8
    comptime for i in range(8):
        lengths[i] = UInt8(bit_length >> UInt64(56 - i * 8))
    state = _multiply_hardware_reversed(
        state ^ bitcast[DType.uint64, 2](_reverse_byte_bits(lengths)), h
    )
    return _reverse_byte_bits(bitcast[DType.uint8, 16](state))


def authenticate[
    key_origin: Origin,
    nonce_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int = 16,
) raises -> List[UInt8]:
    _validate(key, nonce, tag_size)
    var schedule = List[UInt8]()
    var keys = List[SIMD[DType.uint64, 2]]()
    var zero = InlineArray[UInt8, 16](fill=0)
    var h = InlineArray[UInt8, 16](fill=0)
    comptime if CompilationTarget.is_x86():
        if len(key) == 16:
            keys = _prepare_aesni128(key)
        else:
            schedule = expand_key(key)
            keys = _prepare_aesni(Span(schedule))
        var h_value = _encrypt_aesni_prepared_state(keys, Span(zero), 0)
        Span(h).unsafe_ptr().unsafe_store[width=16](
            0, bitcast[DType.uint8, 16](h_value)
        )
    else:
        schedule = expand_key(key)
        encrypt_expanded_into(Span(schedule), Span(zero), Span(h))
    comptime if CompilationTarget.is_x86():
        if len(nonce) == 12:
            # The standard 96-bit nonce needs no GHASH-derived counter, so do
            # not build the 256-byte software multiplication table.
            var initial96 = InlineArray[UInt8, 16](fill=0)
            for i in range(12):
                initial96[i] = nonce[i]
            initial96[15] = 1
            var mask96 = InlineArray[UInt8, 16](fill=0)
            var mask96_value = _encrypt_aesni_prepared_state(
                keys, Span(initial96), 0
            )
            Span(mask96).unsafe_ptr().unsafe_store[width=16](
                0, bitcast[DType.uint8, 16](mask96_value)
            )
            var hash96 = _ghash_message_x86(message, Span(h))
            var output96 = List[UInt8](capacity=tag_size)
            for i in range(tag_size):
                output96.append(mask96[i] ^ hash96[i])
            return output96^
    var table = _ghash_table(Span(h))
    var initial = _initial_counter(nonce, table)
    comptime if CompilationTarget.is_x86():
        var mask = InlineArray[UInt8, 16](fill=0)
        var mask_value = _encrypt_aesni_prepared_state(keys, Span(initial), 0)
        Span(mask).unsafe_ptr().unsafe_store[width=16](
            0, bitcast[DType.uint8, 16](mask_value)
        )
        var hash = _ghash_message_x86(message, Span(h))
        var output = List[UInt8](capacity=tag_size)
        for i in range(tag_size):
            output.append(mask[i] ^ hash[i])
        return output^
    else:
        var mask = InlineArray[UInt8, 16](fill=0)
        encrypt_expanded_into(Span(schedule), Span(initial), Span(mask))
        var empty = List[UInt8]()
        var hash = _ghash(table, message, Span(empty))
        var output = List[UInt8](capacity=tag_size)
        for i in range(tag_size):
            output.append(mask[i] ^ hash[i])
        return output^


def verify[
    key_origin: Origin,
    nonce_origin: Origin,
    message_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    message: Span[UInt8, message_origin],
    tag: Span[UInt8, tag_origin],
) -> Bool:
    if len(tag) == 0:
        return False
    try:
        var expected = authenticate(key, nonce, message, len(tag))
        var difference = UInt8(0)
        for i in range(len(tag)):
            difference |= expected[i] ^ tag[i]
        return difference == 0
    except:
        return False
