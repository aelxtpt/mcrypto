"""Pure-Mojo interop-compatible Curve25519 box variants and sealed boxes."""

from ..ciphers.stream import _hsalsa_inline, _hchacha_inline
from ..hashes.blake2 import blake2b
from ..key_exchange.x25519 import agree, public_key
from ..random.entropy import system_entropy
from ..internal.bytes import copy_into
from ..secretbox.xsalsa20poly1305 import (
    encrypt as xsalsa_secretbox_encrypt,
    encrypt_eight as xsalsa_secretbox_encrypt_eight,
    decrypt as xsalsa_secretbox_decrypt,
    decrypt_eight as xsalsa_secretbox_decrypt_eight,
    encrypt_into as xsalsa_secretbox_encrypt_into,
    encrypt_detached as xsalsa_secretbox_encrypt_detached,
    decrypt_detached as xsalsa_secretbox_decrypt_detached,
)
from ..secretbox.xchacha20poly1305 import (
    encrypt as xchacha_secretbox_encrypt,
    encrypt_eight as xchacha_secretbox_encrypt_eight,
    decrypt as xchacha_secretbox_decrypt,
    decrypt_eight as xchacha_secretbox_decrypt_eight,
    encrypt_into as xchacha_secretbox_encrypt_into,
    encrypt_detached as xchacha_secretbox_encrypt_detached,
    decrypt_detached as xchacha_secretbox_decrypt_detached,
)

comptime PUBLIC_KEY_BYTES = 32
comptime SECRET_KEY_BYTES = 32
comptime NONCE_BYTES = 24
comptime MAC_BYTES = 16
comptime SEAL_BYTES = 48


def _validate_keys[
    public_origin: Origin, secret_origin: Origin
](
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises:
    if (
        len(peer_public_key) != PUBLIC_KEY_BYTES
        or len(secret_key) != SECRET_KEY_BYTES
    ):
        raise Error("box requires 32-byte public and secret keys")


def _raw_shared[
    public_origin: Origin, secret_origin: Origin
](
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    _validate_keys(peer_public_key, secret_key)
    var shared = agree(secret_key, peer_public_key)
    var nonzero = UInt8(0)
    comptime for i in range(32):
        nonzero |= shared[i]
    if nonzero == 0:
        raise Error("box rejected an invalid peer public key")
    return shared^


def _xsalsa_shared[
    public_origin: Origin, secret_origin: Origin
](
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> InlineArray[UInt8, 32]:
    var shared = _raw_shared(peer_public_key, secret_key)
    var zero = InlineArray[UInt8, 16](fill=0)
    return _hsalsa_inline(Span(shared), Span(zero))


def _xchacha_shared[
    public_origin: Origin, secret_origin: Origin
](
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> InlineArray[UInt8, 32]:
    var shared = _raw_shared(peer_public_key, secret_key)
    var zero = InlineArray[UInt8, 16](fill=0)
    return _hchacha_inline(Span(shared), Span(zero))


def xsalsa20poly1305_encrypt_easy[
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
    if len(nonce) != NONCE_BYTES:
        raise Error("box nonce must be 24 bytes")
    var key = _xsalsa_shared(peer_public_key, secret_key)
    return xsalsa_secretbox_encrypt(message, nonce, Span(key))


def xsalsa20poly1305_encrypt_eight[
    public_origin: Origin, secret_origin: Origin
](
    messages: List[List[UInt8]],
    nonces: List[List[UInt8]],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[List[UInt8]]:
    """Encrypt eight boxes while reusing one X25519 agreement."""
    var key = _xsalsa_shared(peer_public_key, secret_key)
    return xsalsa_secretbox_encrypt_eight(messages, nonces, Span(key))


def xsalsa20poly1305_decrypt_eight[
    public_origin: Origin, secret_origin: Origin
](
    ciphertexts: List[List[UInt8]],
    nonces: List[List[UInt8]],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[List[UInt8]]:
    """Decrypt eight boxes while reusing one X25519 agreement."""
    var key = _xsalsa_shared(peer_public_key, secret_key)
    return xsalsa_secretbox_decrypt_eight(ciphertexts, nonces, Span(key))


def xsalsa20poly1305_decrypt_easy[
    cipher_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    combined: Span[UInt8, cipher_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    if len(combined) < MAC_BYTES or len(nonce) != NONCE_BYTES:
        raise Error("invalid box ciphertext or nonce")
    var key = _xsalsa_shared(peer_public_key, secret_key)
    return xsalsa_secretbox_decrypt(combined, nonce, Span(key))


def xsalsa20poly1305_encrypt_detached[
    message_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    message: Span[UInt8, message_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if len(nonce) != NONCE_BYTES:
        raise Error("box nonce must be 24 bytes")
    var key = _xsalsa_shared(peer_public_key, secret_key)
    return xsalsa_secretbox_encrypt_detached(message, nonce, Span(key))


def xsalsa20poly1305_decrypt_detached[
    cipher_origin: Origin,
    tag_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    if len(tag) != MAC_BYTES:
        raise Error("box authentication tag must be 16 bytes")
    if len(nonce) != NONCE_BYTES:
        raise Error("invalid box ciphertext or nonce")
    var key = _xsalsa_shared(peer_public_key, secret_key)
    return xsalsa_secretbox_decrypt_detached(ciphertext, tag, nonce, Span(key))


def xchacha20poly1305_encrypt_easy[
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
    if len(nonce) != NONCE_BYTES:
        raise Error("box nonce must be 24 bytes")
    var key = _xchacha_shared(peer_public_key, secret_key)
    return xchacha_secretbox_encrypt(message, nonce, Span(key))


def xchacha20poly1305_encrypt_eight[
    public_origin: Origin, secret_origin: Origin
](
    messages: List[List[UInt8]],
    nonces: List[List[UInt8]],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[List[UInt8]]:
    """Encrypt eight boxes while reusing one X25519 agreement."""
    var key = _xchacha_shared(peer_public_key, secret_key)
    return xchacha_secretbox_encrypt_eight(messages, nonces, Span(key))


def xchacha20poly1305_decrypt_eight[
    public_origin: Origin, secret_origin: Origin
](
    ciphertexts: List[List[UInt8]],
    nonces: List[List[UInt8]],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[List[UInt8]]:
    """Decrypt eight boxes while reusing one X25519 agreement."""
    var key = _xchacha_shared(peer_public_key, secret_key)
    return xchacha_secretbox_decrypt_eight(ciphertexts, nonces, Span(key))


def xchacha20poly1305_decrypt_easy[
    cipher_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    combined: Span[UInt8, cipher_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    if len(combined) < MAC_BYTES or len(nonce) != NONCE_BYTES:
        raise Error("invalid box ciphertext or nonce")
    var key = _xchacha_shared(peer_public_key, secret_key)
    return xchacha_secretbox_decrypt(combined, nonce, Span(key))


def xchacha20poly1305_encrypt_detached[
    message_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    message: Span[UInt8, message_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if len(nonce) != NONCE_BYTES:
        raise Error("box nonce must be 24 bytes")
    var key = _xchacha_shared(peer_public_key, secret_key)
    return xchacha_secretbox_encrypt_detached(message, nonce, Span(key))


def xchacha20poly1305_decrypt_detached[
    cipher_origin: Origin,
    tag_origin: Origin,
    nonce_origin: Origin,
    public_origin: Origin,
    secret_origin: Origin,
](
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
    nonce: Span[UInt8, nonce_origin],
    peer_public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    if len(nonce) != NONCE_BYTES:
        raise Error("box nonce must be 24 bytes")
    var key = _xchacha_shared(peer_public_key, secret_key)
    return xchacha_secretbox_decrypt_detached(ciphertext, tag, nonce, Span(key))


def _seal_nonce[
    first_public_origin: Origin, second_public_origin: Origin
](
    ephemeral_public_key: Span[UInt8, first_public_origin],
    recipient_public_key: Span[UInt8, second_public_origin],
) raises -> List[UInt8]:
    if (
        len(ephemeral_public_key) != PUBLIC_KEY_BYTES
        or len(recipient_public_key) != PUBLIC_KEY_BYTES
    ):
        raise Error("sealed box requires 32-byte public keys")
    var input = InlineArray[UInt8, 2 * PUBLIC_KEY_BYTES](fill=0)
    copy_into(ephemeral_public_key, Span(input))
    copy_into(recipient_public_key, Span(input), PUBLIC_KEY_BYTES)
    return blake2b(Span(input), NONCE_BYTES)


def xsalsa20poly1305_seal_deterministic[
    message_origin: Origin, public_origin: Origin, ephemeral_origin: Origin
](
    message: Span[UInt8, message_origin],
    recipient_public_key: Span[UInt8, public_origin],
    ephemeral_secret_key: Span[UInt8, ephemeral_origin],
) raises -> List[UInt8]:
    if len(ephemeral_secret_key) != SECRET_KEY_BYTES:
        raise Error("sealed box ephemeral secret key must be 32 bytes")
    var ephemeral_public_key = public_key(ephemeral_secret_key)
    var nonce = _seal_nonce(Span(ephemeral_public_key), recipient_public_key)
    var key = _xsalsa_shared(recipient_public_key, ephemeral_secret_key)
    var output = List[UInt8](
        length=PUBLIC_KEY_BYTES + MAC_BYTES + len(message), fill=0
    )
    copy_into(Span(ephemeral_public_key), Span(output))
    xsalsa_secretbox_encrypt_into(
        message, Span(nonce), Span(key), Span(output), PUBLIC_KEY_BYTES
    )
    return output^


def xsalsa20poly1305_seal[
    message_origin: Origin, public_origin: Origin
](
    message: Span[UInt8, message_origin],
    recipient_public_key: Span[UInt8, public_origin],
) raises -> List[UInt8]:
    var ephemeral_secret_key = system_entropy(SECRET_KEY_BYTES)
    return xsalsa20poly1305_seal_deterministic(
        message, recipient_public_key, Span(ephemeral_secret_key)
    )


def xsalsa20poly1305_seal_open[
    cipher_origin: Origin, public_origin: Origin, secret_origin: Origin
](
    sealed: Span[UInt8, cipher_origin],
    recipient_public_key: Span[UInt8, public_origin],
    recipient_secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    if len(sealed) < SEAL_BYTES:
        raise Error("sealed box ciphertext is shorter than 48 bytes")
    _validate_keys(recipient_public_key, recipient_secret_key)
    var ephemeral_public_key = sealed[0:PUBLIC_KEY_BYTES]
    var nonce = _seal_nonce(ephemeral_public_key, recipient_public_key)
    var key = _xsalsa_shared(ephemeral_public_key, recipient_secret_key)
    return xsalsa_secretbox_decrypt(
        sealed[PUBLIC_KEY_BYTES:], Span(nonce), Span(key)
    )


def xchacha20poly1305_seal_deterministic[
    message_origin: Origin, public_origin: Origin, ephemeral_origin: Origin
](
    message: Span[UInt8, message_origin],
    recipient_public_key: Span[UInt8, public_origin],
    ephemeral_secret_key: Span[UInt8, ephemeral_origin],
) raises -> List[UInt8]:
    if len(ephemeral_secret_key) != SECRET_KEY_BYTES:
        raise Error("sealed box ephemeral secret key must be 32 bytes")
    var ephemeral_public_key = public_key(ephemeral_secret_key)
    var nonce = _seal_nonce(Span(ephemeral_public_key), recipient_public_key)
    var key = _xchacha_shared(recipient_public_key, ephemeral_secret_key)
    var output = List[UInt8](
        length=PUBLIC_KEY_BYTES + MAC_BYTES + len(message), fill=0
    )
    copy_into(Span(ephemeral_public_key), Span(output))
    xchacha_secretbox_encrypt_into(
        message, Span(nonce), Span(key), Span(output), PUBLIC_KEY_BYTES
    )
    return output^


def xchacha20poly1305_seal[
    message_origin: Origin, public_origin: Origin
](
    message: Span[UInt8, message_origin],
    recipient_public_key: Span[UInt8, public_origin],
) raises -> List[UInt8]:
    var ephemeral_secret_key = system_entropy(SECRET_KEY_BYTES)
    return xchacha20poly1305_seal_deterministic(
        message, recipient_public_key, Span(ephemeral_secret_key)
    )


def xchacha20poly1305_seal_open[
    cipher_origin: Origin, public_origin: Origin, secret_origin: Origin
](
    sealed: Span[UInt8, cipher_origin],
    recipient_public_key: Span[UInt8, public_origin],
    recipient_secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    if len(sealed) < SEAL_BYTES:
        raise Error("sealed box ciphertext is shorter than 48 bytes")
    _validate_keys(recipient_public_key, recipient_secret_key)
    var ephemeral_public_key = sealed[0:PUBLIC_KEY_BYTES]
    var nonce = _seal_nonce(ephemeral_public_key, recipient_public_key)
    var key = _xchacha_shared(ephemeral_public_key, recipient_secret_key)
    return xchacha_secretbox_decrypt(
        sealed[PUBLIC_KEY_BYTES:], Span(nonce), Span(key)
    )


def seal[
    message_origin: Origin, public_origin: Origin
](
    message: Span[UInt8, message_origin],
    recipient_public_key: Span[UInt8, public_origin],
) raises -> List[UInt8]:
    """The interop default sealed box (Curve25519-XSalsa20-Poly1305)."""
    return xsalsa20poly1305_seal(message, recipient_public_key)


def seal_deterministic[
    message_origin: Origin, public_origin: Origin, ephemeral_origin: Origin
](
    message: Span[UInt8, message_origin],
    recipient_public_key: Span[UInt8, public_origin],
    ephemeral_secret_key: Span[UInt8, ephemeral_origin],
) raises -> List[UInt8]:
    """Deterministic sealed-box helper for known-answer tests."""
    return xsalsa20poly1305_seal_deterministic(
        message, recipient_public_key, ephemeral_secret_key
    )


def seal_open[
    cipher_origin: Origin, public_origin: Origin, secret_origin: Origin
](
    sealed: Span[UInt8, cipher_origin],
    recipient_public_key: Span[UInt8, public_origin],
    recipient_secret_key: Span[UInt8, secret_origin],
) raises -> List[UInt8]:
    return xsalsa20poly1305_seal_open(
        sealed, recipient_public_key, recipient_secret_key
    )
