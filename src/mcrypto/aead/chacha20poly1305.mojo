"""ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD in pure Mojo."""

from .algorithm import ChachaAeadAlgorithm

from ..ciphers.algorithm import Chacha20Stream, StreamCipherAlgorithm
from ..ciphers.stream import (
    _chacha,
    _hchacha,
    xor as stream_xor,
    xor_chacha_from_counter,
)
from ..macs.poly1305 import (
    authenticate_legacy_parts,
    authenticate_padded_parts,
)
from ..traits import constant_time_equal


def _zeros(size: Int) -> List[UInt8]:
    return List[UInt8](length=size, fill=0)


def _stream_algorithm(
    algorithm: ChachaAeadAlgorithm,
) raises -> StreamCipherAlgorithm:
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305:
        return StreamCipherAlgorithm.CHACHA20
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF:
        return StreamCipherAlgorithm.CHACHA20_IETF
    if algorithm == ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF:
        return StreamCipherAlgorithm.XCHACHA20
    raise Error("invalid ChaCha AEAD selector")


def _counter_algorithm(
    algorithm: ChachaAeadAlgorithm,
) raises -> Chacha20Stream:
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305:
        return Chacha20Stream.CHACHA20
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF:
        return Chacha20Stream.CHACHA20_IETF
    if algorithm == ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF:
        return Chacha20Stream.XCHACHA20
    raise Error("invalid ChaCha AEAD selector")


def _parameters(
    algorithm: ChachaAeadAlgorithm, key_bytes: Int, nonce_bytes: Int
) raises:
    if key_bytes != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305 and nonce_bytes == 8:
        return
    if (
        algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF
        and nonce_bytes == 12
    ):
        return
    if (
        algorithm == ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF
        and nonce_bytes == 24
    ):
        return
    raise Error(
        "AEAD algorithm is not ChaCha-family or nonce length is invalid"
    )


def encrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    algorithm: ChachaAeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    _parameters(algorithm, len(key), len(nonce))
    var stream_algorithm = _stream_algorithm(algorithm)
    var prefix = _zeros(32)
    var key_stream: List[UInt8]
    var ciphertext: List[UInt8]
    if algorithm == ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF:
        var subkey = _hchacha(key, nonce[0:16])
        var derived_nonce = List[UInt8](length=12, fill=0)
        for i in range(8):
            derived_nonce[4 + i] = nonce[16 + i]
        key_stream = _chacha[20, True](
            Span(subkey), Span(derived_nonce), Span(prefix)
        )
        ciphertext = _chacha[20, True](
            Span(subkey), Span(derived_nonce), message, 1
        )
    else:
        key_stream = stream_xor(stream_algorithm, key, nonce, Span(prefix))
        ciphertext = xor_chacha_from_counter(
            _counter_algorithm(algorithm), key, nonce, message, 1
        )
    var tag: List[UInt8]
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305:
        tag = authenticate_legacy_parts(Span(key_stream), aad, Span(ciphertext))
    else:
        tag = authenticate_padded_parts(Span(key_stream), aad, Span(ciphertext))
    return (ciphertext^, tag^)


def decrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    algorithm: ChachaAeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    _parameters(algorithm, len(key), len(nonce))
    if len(tag) != 16:
        raise Error("ChaCha20-Poly1305 tag must be 16 bytes")
    var stream_algorithm = _stream_algorithm(algorithm)
    var prefix = _zeros(32)
    var key_stream: List[UInt8]
    var effective_key = List[UInt8]()
    var effective_nonce = List[UInt8]()
    if algorithm == ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF:
        effective_key = _hchacha(key, nonce[0:16])
        effective_nonce = List[UInt8](length=12, fill=0)
        for i in range(8):
            effective_nonce[4 + i] = nonce[16 + i]
        key_stream = _chacha[20, True](
            Span(effective_key), Span(effective_nonce), Span(prefix)
        )
    else:
        key_stream = stream_xor(stream_algorithm, key, nonce, Span(prefix))
    var expected: List[UInt8]
    if algorithm == ChachaAeadAlgorithm.CHACHA20_POLY1305:
        expected = authenticate_legacy_parts(Span(key_stream), aad, ciphertext)
    else:
        expected = authenticate_padded_parts(Span(key_stream), aad, ciphertext)
    if not constant_time_equal(Span(expected), tag):
        raise Error("AEAD authentication failed")
    if algorithm == ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF:
        return _chacha[20, True](
            Span(effective_key), Span(effective_nonce), ciphertext, 1
        )
    return xor_chacha_from_counter(
        _counter_algorithm(algorithm), key, nonce, ciphertext, 1
    )


def encrypt_eight[
    key_origin: Origin
](
    algorithm: ChachaAeadAlgorithm,
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    aads: List[List[UInt8]],
    messages: List[List[UInt8]],
) raises -> Tuple[List[List[UInt8]], List[List[UInt8]]]:
    """Encrypt eight independent messages with one shared key."""
    if len(nonces) != 8 or len(aads) != 8 or len(messages) != 8:
        raise Error("eight-way ChaCha AEAD batch has invalid dimensions")
    var ciphertexts = List[List[UInt8]](capacity=8)
    var tags = List[List[UInt8]](capacity=8)
    for lane in range(8):
        var parts = encrypt(
            algorithm,
            key,
            Span(nonces[lane]),
            Span(aads[lane]),
            Span(messages[lane]),
        )
        ciphertexts.append(parts[0].copy())
        tags.append(parts[1].copy())
    return (ciphertexts^, tags^)
