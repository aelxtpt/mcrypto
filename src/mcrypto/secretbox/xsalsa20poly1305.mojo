"""XSalsa20-Poly1305 secretbox in pure Mojo."""

from ..macs.poly1305 import authenticate, authenticate_into
from ..traits import constant_time_equal
from ._stream_into import (
    salsa20_secretbox_block0_into,
    salsa20_secretbox_into,
    salsa20_secretbox_payload_into,
    xsalsa20_state,
)


def encrypt_into[
    message_origin: Origin,
    nonce_origin: Origin,
    key_origin: Origin,
    output_origin: MutOrigin,
](
    message: Span[UInt8, message_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int = 0,
) raises:
    if len(key) != 32 or len(nonce) != 24:
        raise Error("secretbox requires a 32-byte key and 24-byte nonce")
    if output_offset < 0 or output_offset + 16 + len(message) > len(output):
        raise Error("secretbox output span is too short")
    var state = xsalsa20_state(key, nonce)
    var poly_key = InlineArray[UInt8, 32](fill=0)
    salsa20_secretbox_into(
        state, message, output, output_offset + 16, Span(poly_key)
    )
    var tag = InlineArray[UInt8, 16](fill=0)
    authenticate_into(
        Span(poly_key),
        output[output_offset + 16 : output_offset + 16 + len(message)],
        Span(tag),
    )
    output.unsafe_ptr().unsafe_store[width=16](
        output_offset, Span(tag).unsafe_ptr().unsafe_load[width=16](0)
    )


def encrypt[
    message_origin: Origin, nonce_origin: Origin, key_origin: Origin
](
    message: Span[UInt8, message_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](unsafe_uninit_length=16 + len(message))
    encrypt_into(message, nonce, key, Span(output))
    return output^


def encrypt_detached[
    message_origin: Origin, nonce_origin: Origin, key_origin: Origin
](
    message: Span[UInt8, message_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if len(key) != 32 or len(nonce) != 24:
        raise Error("secretbox requires a 32-byte key and 24-byte nonce")
    var state = xsalsa20_state(key, nonce)
    var poly_key = InlineArray[UInt8, 32](fill=0)
    var ciphertext = List[UInt8](unsafe_uninit_length=len(message))
    salsa20_secretbox_into(state, message, Span(ciphertext), 0, Span(poly_key))
    var tag = authenticate(Span(poly_key), Span(ciphertext))
    return (ciphertext^, tag^)


def decrypt_detached[
    cipher_origin: Origin,
    tag_origin: Origin,
    nonce_origin: Origin,
    key_origin: Origin,
](
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    if len(key) != 32 or len(nonce) != 24 or len(tag) != 16:
        raise Error("invalid secretbox parameters")
    var state = xsalsa20_state(key, nonce)
    var block0 = InlineArray[UInt8, 64](fill=0)
    var poly_key = InlineArray[UInt8, 32](fill=0)
    salsa20_secretbox_block0_into(state, Span(block0), Span(poly_key))
    var expected = InlineArray[UInt8, 16](fill=0)
    authenticate_into(Span(poly_key), ciphertext, Span(expected))
    if not constant_time_equal(Span(expected), tag):
        raise Error("secretbox authentication failed")
    var output = List[UInt8](unsafe_uninit_length=len(ciphertext))
    salsa20_secretbox_payload_into(
        state, Span(block0), ciphertext, Span(output), 0
    )
    return output^


def decrypt[
    cipher_origin: Origin, nonce_origin: Origin, key_origin: Origin
](
    ciphertext: Span[UInt8, cipher_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    if len(ciphertext) < 16:
        raise Error("invalid secretbox parameters")
    var tag = InlineArray[UInt8, 16](fill=0)
    Span(tag).unsafe_ptr().unsafe_store[width=16](
        0, ciphertext.unsafe_ptr().unsafe_load[width=16](0)
    )
    return decrypt_detached(ciphertext[16:], Span(tag), nonce, key)


def encrypt_eight[
    key_origin: Origin
](
    messages: List[List[UInt8]],
    nonces: List[List[UInt8]],
    key: Span[UInt8, key_origin],
) raises -> List[List[UInt8]]:
    """Encrypt eight independent secretboxes with one shared key."""
    if len(messages) != 8 or len(nonces) != 8 or len(key) != 32:
        raise Error("eight-way XSalsa secretbox batch has invalid dimensions")
    var outputs = List[List[UInt8]](capacity=8)
    for lane in range(8):
        outputs.append(encrypt(Span(messages[lane]), Span(nonces[lane]), key))
    return outputs^


def decrypt_eight[
    key_origin: Origin
](
    ciphertexts: List[List[UInt8]],
    nonces: List[List[UInt8]],
    key: Span[UInt8, key_origin],
) raises -> List[List[UInt8]]:
    """Authenticate and decrypt eight secretboxes with one shared key."""
    if len(ciphertexts) != 8 or len(nonces) != 8 or len(key) != 32:
        raise Error("eight-way XSalsa secretbox batch has invalid dimensions")
    var outputs = List[List[UInt8]](capacity=8)
    for lane in range(8):
        outputs.append(
            decrypt(Span(ciphertexts[lane]), Span(nonces[lane]), key)
        )
    return outputs^
