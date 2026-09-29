"""Original Bernstein Poly1305-AES construction."""

from std.memory import bitcast
from std.sys import CompilationTarget
from ..ciphers.aes_block import (
    _encrypt_aesni_prepared_state,
    _prepare_aesni128,
    encrypt_block,
)
from .poly1305 import authenticate as poly1305


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
    if len(key) != 32:
        raise Error("Poly1305-AES key must be 32 bytes")
    if len(nonce) != 16:
        raise Error("Poly1305-AES nonce must be 16 bytes")
    if tag_size < 1 or tag_size > 16:
        raise Error("invalid Poly1305-AES tag size")
    var one_time_key = InlineArray[UInt8, 32](uninitialized=True)
    for i in range(16):
        one_time_key[i] = key[16 + i]
    comptime if CompilationTarget.is_x86():
        var keys = _prepare_aesni128(key[0:16])
        var pad = bitcast[DType.uint8, 16](
            _encrypt_aesni_prepared_state(keys, nonce, 0)
        )
        for i in range(16):
            one_time_key[16 + i] = pad[i]
    else:
        var pad = encrypt_block(key[0:16], nonce)
        for i in range(16):
            one_time_key[16 + i] = pad[i]
    var full = poly1305(Span(one_time_key), message)
    if tag_size == 16:
        return full^
    var output = List[UInt8](capacity=tag_size)
    for i in range(tag_size):
        output.append(full[i])
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
