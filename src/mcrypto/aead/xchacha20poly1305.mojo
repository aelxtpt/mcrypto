"""XChaCha20-Poly1305-IETF combined-mode helpers in pure Mojo."""
from .algorithm import AeadAlgorithm

from .combined import encrypt as combined_encrypt, decrypt as combined_decrypt

comptime KEY_BYTES = 32
comptime NONCE_BYTES = 24
comptime TAG_BYTES = 16


def encrypt[
    message_origin: Origin,
    aad_origin: Origin,
    nonce_origin: Origin,
    key_origin: Origin,
](
    message: Span[UInt8, message_origin],
    aad: Span[UInt8, aad_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    return combined_encrypt(
        AeadAlgorithm.XCHACHA20_POLY1305_IETF, key, nonce, aad, message
    )


def decrypt[
    cipher_origin: Origin,
    aad_origin: Origin,
    nonce_origin: Origin,
    key_origin: Origin,
](
    ciphertext: Span[UInt8, cipher_origin],
    aad: Span[UInt8, aad_origin],
    nonce: Span[UInt8, nonce_origin],
    key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    return combined_decrypt(
        AeadAlgorithm.XCHACHA20_POLY1305_IETF, key, nonce, aad, ciphertext
    )
