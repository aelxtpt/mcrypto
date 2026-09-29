from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.aead.aegis import (
    encrypt as aegis_encrypt,
    encrypt_into as aegis_encrypt_into,
)
from mcrypto.aead.chacha20poly1305 import (
    encrypt as chacha_encrypt,
    encrypt_eight as chacha_encrypt_eight,
)
from mcrypto.aead.algorithm import AegisAlgorithm, ChachaAeadAlgorithm
from mcrypto.macs.poly1305 import authenticate, authenticate_into
from mcrypto.secretbox.xchacha20poly1305 import (
    decrypt as secretbox_decrypt,
    decrypt_eight as secretbox_decrypt_eight,
    encrypt as secretbox_encrypt,
    encrypt_eight as secretbox_encrypt_eight,
    encrypt_into as secretbox_encrypt_into,
)


def test_aegis_encrypt_into_nonzero_offsets_matches_scalar() raises:
    for algorithm, width in [
        (AegisAlgorithm.AEGIS128L, 16),
        (AegisAlgorithm.AEGIS256, 32),
    ]:
        var key = List[UInt8](length=width, fill=0x11)
        var nonce = List[UInt8](length=width, fill=0x22)
        var aad = List[UInt8](length=17, fill=0x33)
        for size in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65]:
            var message = List[UInt8](length=size, fill=UInt8(size))
            var expected = aegis_encrypt(
                algorithm,
                Span(key),
                Span(nonce),
                Span(aad),
                Span(message),
                16,
            )
            var cipher_storage = List[UInt8](length=size + 10, fill=0xA5)
            var tag_storage = List[UInt8](length=26, fill=0x5A)
            aegis_encrypt_into(
                algorithm,
                Span(key),
                Span(nonce),
                Span(aad),
                Span(message),
                Span(cipher_storage)[5 : 5 + size],
                Span(tag_storage)[5:21],
            )
            assert_equal(List(Span(cipher_storage)[5 : 5 + size]), expected[0])
            assert_equal(List(Span(tag_storage)[5:21]), expected[1])
            assert_equal(cipher_storage[0], UInt8(0xA5))
            assert_equal(tag_storage[0], UInt8(0x5A))
    var key = List[UInt8](length=16, fill=0)
    var nonce = List[UInt8](length=16, fill=0)
    var empty_aad = List[UInt8]()
    var empty_message = List[UInt8]()
    var wrong_cipher = List[UInt8](length=1, fill=0)
    var tag = List[UInt8](length=16, fill=0)
    with assert_raises():
        aegis_encrypt_into(
            AegisAlgorithm.AEGIS128L,
            Span(key),
            Span(nonce),
            Span(empty_aad),
            Span(empty_message),
            Span(wrong_cipher),
            Span(tag),
        )


def test_poly1305_into_offset_and_short_output() raises:
    var key = List[UInt8](length=32, fill=0x42)
    for size in [0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257]:
        var message = List[UInt8](length=size, fill=UInt8(size))
        var storage = List[UInt8](length=26, fill=0xA5)
        authenticate_into(Span(key), Span(message), Span(storage), 5)
        assert_equal(
            List(Span(storage)[5:21]), authenticate(Span(key), Span(message))
        )
        assert_equal(storage[4], UInt8(0xA5))
        assert_equal(storage[21], UInt8(0xA5))
    var message: List[UInt8] = [1]
    var short = List[UInt8](length=15, fill=0)
    with assert_raises():
        authenticate_into(Span(key), Span(message), Span(short))


def test_chacha_aead_eight_way_matches_scalar_and_dimensions() raises:
    var key = List[UInt8](length=32, fill=0x3C)
    for algorithm, nonce_bytes in [
        (ChachaAeadAlgorithm.CHACHA20_POLY1305, 8),
        (ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF, 12),
        (ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF, 24),
    ]:
        var nonces = List[List[UInt8]](capacity=8)
        var aads = List[List[UInt8]](capacity=8)
        var messages = List[List[UInt8]](capacity=8)
        for lane in range(8):
            nonces.append(List[UInt8](length=nonce_bytes, fill=UInt8(lane)))
            aads.append(List[UInt8](length=lane, fill=UInt8(lane + 1)))
            messages.append(List[UInt8](length=63 + lane, fill=UInt8(lane + 2)))
        var outputs = chacha_encrypt_eight(
            algorithm, Span(key), nonces, aads, messages
        )
        for lane in range(8):
            var expected = chacha_encrypt(
                algorithm,
                Span(key),
                Span(nonces[lane]),
                Span(aads[lane]),
                Span(messages[lane]),
            )
            assert_equal(outputs[0][lane], expected[0])
            assert_equal(outputs[1][lane], expected[1])
    var short = List[List[UInt8]](capacity=7)
    for _ in range(7):
        short.append(List[UInt8]())
    with assert_raises():
        _ = chacha_encrypt_eight(
            ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF,
            Span(key),
            short,
            short,
            short,
        )


def test_xchacha_secretbox_into_and_eight_way_paths() raises:
    var key = List[UInt8](length=32, fill=0x7B)
    var nonce = List[UInt8](length=24, fill=0x6A)
    for size in [0, 1, 15, 16, 17, 63, 64, 65]:
        var message = List[UInt8](length=size, fill=UInt8(size))
        var storage = List[UInt8](length=size + 26, fill=0xA5)
        secretbox_encrypt_into(
            Span(message), Span(nonce), Span(key), Span(storage), 5
        )
        assert_equal(
            List(Span(storage)[5 : 21 + size]),
            secretbox_encrypt(Span(message), Span(nonce), Span(key)),
        )
    var nonces = List[List[UInt8]](capacity=8)
    var messages = List[List[UInt8]](capacity=8)
    for lane in range(8):
        nonces.append(List[UInt8](length=24, fill=UInt8(lane)))
        messages.append(List[UInt8](length=lane * 17, fill=UInt8(lane + 1)))
    var ciphertexts = secretbox_encrypt_eight(messages, nonces, Span(key))
    var plaintexts = secretbox_decrypt_eight(ciphertexts, nonces, Span(key))
    assert_equal(plaintexts, messages)
    for lane in range(8):
        assert_equal(
            ciphertexts[lane],
            secretbox_encrypt(
                Span(messages[lane]), Span(nonces[lane]), Span(key)
            ),
        )
        assert_equal(
            secretbox_decrypt(
                Span(ciphertexts[lane]), Span(nonces[lane]), Span(key)
            ),
            messages[lane],
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
