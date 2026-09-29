"""Combined pure-Mojo AEAD dispatcher."""

from .algorithm import AeadAlgorithm, ChachaAeadAlgorithm
from .detached import encrypt as detached_encrypt, decrypt as detached_decrypt
from .chacha20poly1305 import encrypt_eight as chacha_encrypt_eight
from ..internal.bytes import copy_into


def _default_tag_bytes(algorithm: AeadAlgorithm) raises -> Int:
    if (
        algorithm == AeadAlgorithm.AEGIS128L
        or algorithm == AeadAlgorithm.AEGIS256
    ):
        return 32
    if (
        algorithm == AeadAlgorithm.GCM
        or algorithm == AeadAlgorithm.CCM
        or algorithm == AeadAlgorithm.EAX
        or algorithm == AeadAlgorithm.AES256_GCM
        or algorithm == AeadAlgorithm.CHACHA20_POLY1305
        or algorithm == AeadAlgorithm.CHACHA20_POLY1305_IETF
        or algorithm == AeadAlgorithm.XCHACHA20_POLY1305_IETF
    ):
        return 16
    raise Error("invalid AEAD selector")


def encrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    algorithm: AeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int = 0,
) raises -> List[UInt8]:
    var size = _default_tag_bytes(algorithm) if tag_bytes == 0 else tag_bytes
    var parts = detached_encrypt(algorithm, key, nonce, aad, message, size)
    var output = List[UInt8](length=len(parts[0]) + len(parts[1]), fill=0)
    copy_into(Span(parts[0]), Span(output), 0)
    copy_into(Span(parts[1]), Span(output), len(parts[0]))
    return output^


def encrypt_chacha_eight[
    key_origin: Origin
](
    algorithm: ChachaAeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    aads: List[List[UInt8]],
    messages: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    """Return eight combined ChaCha-family ciphertexts and tags."""
    var parts = chacha_encrypt_eight(algorithm, key, nonces, aads, messages)
    var outputs = List[List[UInt8]](capacity=8)
    for lane in range(8):
        var cipher_size = len(parts[0][lane])
        var tag_size = len(parts[1][lane])
        var output = List[UInt8](length=cipher_size + tag_size, fill=0)
        copy_into(Span(parts[0][lane]), Span(output), 0)
        copy_into(Span(parts[1][lane]), Span(output), cipher_size)
        outputs.append(output^)
    return outputs^


def decrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
](
    algorithm: AeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag_bytes: Int = 0,
) raises -> List[UInt8]:
    var size = _default_tag_bytes(algorithm) if tag_bytes == 0 else tag_bytes
    if size <= 0 or len(ciphertext) < size:
        raise Error("AEAD ciphertext is shorter than its tag")
    var body_bytes = len(ciphertext) - size
    var tag = List[UInt8](length=size, fill=0)
    copy_into(ciphertext[body_bytes:], Span(tag), 0)
    return detached_decrypt(
        algorithm,
        key,
        nonce,
        aad,
        ciphertext[0:body_bytes],
        Span(tag),
    )
