"""Detached pure-Mojo AEAD dispatcher."""

from .algorithm import (
    AeadAlgorithm,
    as_aegis_algorithm,
    as_chacha_aead_algorithm,
)
from .chacha20poly1305 import (
    encrypt as chacha_encrypt,
    decrypt as chacha_decrypt,
)
from .aes_gcm import encrypt as gcm_encrypt, decrypt as gcm_decrypt
from .aes_ccm import encrypt as ccm_encrypt, decrypt as ccm_decrypt
from .aes_eax import encrypt as eax_encrypt, decrypt as eax_decrypt
from .aegis import encrypt as aegis_encrypt, decrypt as aegis_decrypt


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
    tag_bytes: Int = 16,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if algorithm == AeadAlgorithm.AES256_GCM and len(key) != 32:
        raise Error("AES-256-GCM requires a 32-byte key")
    if algorithm == AeadAlgorithm.GCM or algorithm == AeadAlgorithm.AES256_GCM:
        return gcm_encrypt(key, nonce, aad, message, tag_bytes)
    if algorithm == AeadAlgorithm.CCM:
        return ccm_encrypt(key, nonce, aad, message, tag_bytes)
    if algorithm == AeadAlgorithm.EAX:
        return eax_encrypt(key, nonce, aad, message, tag_bytes)
    if (
        algorithm == AeadAlgorithm.AEGIS128L
        or algorithm == AeadAlgorithm.AEGIS256
    ):
        return aegis_encrypt(
            as_aegis_algorithm(algorithm),
            key,
            nonce,
            aad,
            message,
            tag_bytes,
        )
    if tag_bytes != 16:
        raise Error("ChaCha AEAD requires a 16-byte tag")
    return chacha_encrypt(
        as_chacha_aead_algorithm(algorithm), key, nonce, aad, message
    )


def decrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    algorithm: AeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    if algorithm == AeadAlgorithm.AES256_GCM and len(key) != 32:
        raise Error("AES-256-GCM requires a 32-byte key")
    if algorithm == AeadAlgorithm.GCM or algorithm == AeadAlgorithm.AES256_GCM:
        return gcm_decrypt(key, nonce, aad, ciphertext, tag)
    if algorithm == AeadAlgorithm.CCM:
        return ccm_decrypt(key, nonce, aad, ciphertext, tag)
    if algorithm == AeadAlgorithm.EAX:
        return eax_decrypt(key, nonce, aad, ciphertext, tag)
    if (
        algorithm == AeadAlgorithm.AEGIS128L
        or algorithm == AeadAlgorithm.AEGIS256
    ):
        return aegis_decrypt(
            as_aegis_algorithm(algorithm),
            key,
            nonce,
            aad,
            ciphertext,
            tag,
        )
    return chacha_decrypt(
        as_chacha_aead_algorithm(algorithm),
        key,
        nonce,
        aad,
        ciphertext,
        tag,
    )
