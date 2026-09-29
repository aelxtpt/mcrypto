from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.aead.combined import (
    decrypt as aead_decrypt,
    encrypt as aead_encrypt,
)
from mcrypto.aead.algorithm import AeadAlgorithm


def test_all_aead_algorithms() raises:
    var aad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4, 5, 6, 7]
    for algorithm, key_bytes, nonce_bytes in [
        (AeadAlgorithm.CHACHA20_POLY1305, 32, 8),
        (AeadAlgorithm.CHACHA20_POLY1305_IETF, 32, 12),
        (AeadAlgorithm.XCHACHA20_POLY1305_IETF, 32, 24),
    ]:
        var key = List[UInt8](length=key_bytes, fill=7)
        var nonce = List[UInt8](length=nonce_bytes, fill=9)
        var ciphertext = aead_encrypt(
            algorithm, Span(key), Span(nonce), Span(aad), Span(message)
        )
        assert_equal(
            aead_decrypt(
                algorithm, Span(key), Span(nonce), Span(aad), Span(ciphertext)
            ),
            message,
        )
        ciphertext[0] ^= 1
        with assert_raises():
            _ = aead_decrypt(
                algorithm, Span(key), Span(nonce), Span(aad), Span(ciphertext)
            )
    var unsupported_key = List[UInt8](length=32, fill=7)
    var unsupported_nonce = List[UInt8](length=16, fill=9)
    with assert_raises():
        _ = aead_encrypt(
            AeadAlgorithm.AEGIS128L,
            Span(unsupported_key),
            Span(unsupported_nonce),
            Span(aad),
            Span(message),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
