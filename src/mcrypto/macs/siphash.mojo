"""SipHash-2-4, SipHash-4-8, and SipHash-x-2-4 in pure Mojo."""
from std.bit import rotate_bits_left
from .algorithm import SipHashAlgorithm
from std.memory import bitcast
from std.sys import CompilationTarget

from ..internal.bytes import load_le64, store_le64


@always_inline("nodebug")
def _load_word[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> UInt64:
    comptime if CompilationTarget.is_x86():
        return bitcast[DType.uint64, 1](
            data.unsafe_ptr().unsafe_load[width=8](offset)
        )[0]
    else:
        return load_le64(data, offset)


@always_inline("nodebug")
def _round(mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64):
    v0 += v1
    v2 += v3
    v1 = rotate_bits_left[13](v1)
    v3 = rotate_bits_left[16](v3)
    v1 ^= v0
    v3 ^= v2
    v0 = rotate_bits_left[32](v0)
    v0 += v3
    v2 += v1
    v3 = rotate_bits_left[21](v3)
    v1 = rotate_bits_left[17](v1)
    v3 ^= v0
    v1 ^= v2
    v2 = rotate_bits_left[32](v2)


@always_inline("nodebug")
def _rounds[
    count: Int
](mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64):
    comptime for _ in range(count):
        _round(v0, v1, v2, v3)


def _hash_into[
    compression_rounds: Int,
    final_rounds: Int,
    extended: Bool,
    key_origin: Origin,
    message_origin: Origin,
    output_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(key) != 16:
        raise Error("SipHash key must be 16 bytes")
    comptime if extended:
        if len(output) != 16:
            raise Error("SipHash-x-2-4 output must be 16 bytes")
    else:
        if len(output) != 8:
            raise Error("SipHash output must be 8 bytes")
    var k0 = _load_word(key, 0)
    var k1 = _load_word(key, 8)
    var v0 = UInt64(0x736F6D6570736575) ^ k0
    var v1 = (
        UInt64(0x646F72616E646F83) if extended else UInt64(0x646F72616E646F6D)
    ) ^ k1
    var v2 = UInt64(0x6C7967656E657261) ^ k0
    var v3 = UInt64(0x7465646279746573) ^ k1
    var offset = 0
    while offset + 8 <= len(message):
        var word = _load_word(message, offset)
        v3 ^= word
        _rounds[compression_rounds](v0, v1, v2, v3)
        v0 ^= word
        offset += 8
    var final_word = UInt64(len(message)) << 56
    for i in range(len(message) - offset):
        final_word |= UInt64(message[offset + i]) << UInt64(8 * i)
    v3 ^= final_word
    _rounds[compression_rounds](v0, v1, v2, v3)
    v0 ^= final_word
    v2 ^= UInt64(0xEE) if extended else UInt64(0xFF)
    _rounds[final_rounds](v0, v1, v2, v3)
    store_le64(v0 ^ v1 ^ v2 ^ v3, output, 0)
    comptime if extended:
        v1 ^= 0xDD
        _rounds[final_rounds](v0, v1, v2, v3)
        store_le64(v0 ^ v1 ^ v2 ^ v3, output, 8)


def hash_into[
    key_origin: Origin,
    message_origin: Origin,
    output_origin: MutOrigin,
](
    algorithm: SipHashAlgorithm,
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if algorithm == SipHashAlgorithm.SIPHASH_2_4:
        _hash_into[2, 4, False](key, message, output)
        return
    if algorithm == SipHashAlgorithm.SIPHASH_4_8:
        _hash_into[4, 8, False](key, message, output)
        return
    _hash_into[2, 4, True](key, message, output)


def hash[
    key_origin: Origin, message_origin: Origin
](
    algorithm: SipHashAlgorithm,
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](
        length=16 if algorithm == SipHashAlgorithm.SIPHASH_X_2_4 else 8,
        fill=0,
    )
    hash_into(algorithm, key, message, Span(output))
    return output^
