"""Curve25519-XSalsa20-Poly1305 authenticated boxes in pure Mojo."""

from ..key_exchange.x25519 import public_key
from ..random.entropy import system_entropy
from .box_variants import (
    xsalsa20poly1305_encrypt_easy,
    xsalsa20poly1305_decrypt_easy,
)


def keypair() raises -> Tuple[List[UInt8], List[UInt8]]:
    var secret_key = system_entropy(32)
    var public = public_key(Span(secret_key))
    return (public^, secret_key^)


def encrypt[
    message_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    message: Span[UInt8, message_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    return xsalsa20poly1305_encrypt_easy(
        message, nonce, peer_public_key, secret_key
    )


def decrypt[
    ciphertext_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    ciphertext: Span[UInt8, ciphertext_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    return xsalsa20poly1305_decrypt_easy(
        ciphertext, nonce, peer_public_key, secret_key
    )
