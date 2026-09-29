from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor as stream_xor
from mcrypto.hashes.generic_hash import hash
from mcrypto.hashes.xof import xof
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.hashes.xof_algorithm import XofAlgorithm
from mcrypto.macs.hmac import authenticate
from mcrypto.macs.algorithm import HmacAlgorithm
from mcrypto.secretbox.xsalsa20poly1305 import (
    decrypt as secretbox_decrypt,
    encrypt as secretbox_encrypt,
    encrypt_eight as secretbox_encrypt_eight,
    decrypt_eight as secretbox_decrypt_eight,
)


def test_hash_families() raises:
    var message: List[UInt8] = [1, 2, 3]
    assert_equal(len(hash(HashAlgorithm.SHA256, Span(message))), 32)
    assert_equal(len(hash(HashAlgorithm.SHA512, Span(message))), 64)
    assert_equal(len(hash(HashAlgorithm.SHA3_256, Span(message))), 32)
    assert_equal(len(hash(HashAlgorithm.SHA3_512, Span(message))), 64)
    assert_equal(len(hash(HashAlgorithm.BLAKE2B, Span(message))), 32)


def test_xof_families() raises:
    var message: List[UInt8] = [1, 2, 3]
    for algorithm in [
        XofAlgorithm.SHAKE128,
        XofAlgorithm.SHAKE256,
        XofAlgorithm.TURBOSHAKE128,
        XofAlgorithm.TURBOSHAKE256,
    ]:
        assert_equal(len(xof(algorithm, Span(message), 97)), 97)


def test_auth_families() raises:
    var key = List[UInt8](length=32, fill=7)
    var message: List[UInt8] = [1, 2, 3]
    assert_equal(
        len(authenticate(HmacAlgorithm.SHA256, Span(key), Span(message))), 32
    )
    assert_equal(
        len(authenticate(HmacAlgorithm.SHA512, Span(key), Span(message))), 64
    )
    assert_equal(
        len(authenticate(HmacAlgorithm.SHA512_256, Span(key), Span(message))),
        32,
    )


def test_stream_roundtrip() raises:
    var key = List[UInt8](length=32, fill=7)
    var nonce = List[UInt8](length=24, fill=9)
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var encrypted = stream_xor(
        StreamCipherAlgorithm.XCHACHA20,
        Span(key),
        Span(nonce),
        Span(message),
    )
    assert_equal(
        stream_xor(
            StreamCipherAlgorithm.XCHACHA20,
            Span(key),
            Span(nonce),
            Span(encrypted),
        ),
        message,
    )


def test_secretbox_tamper() raises:
    var key = List[UInt8](length=32, fill=7)
    var nonce = List[UInt8](length=24, fill=9)
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var encrypted = secretbox_encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(
        secretbox_decrypt(Span(encrypted), Span(nonce), Span(key)), message
    )
    encrypted[0] ^= 1
    with assert_raises():
        _ = secretbox_decrypt(Span(encrypted), Span(nonce), Span(key))


def test_eight_way_xsalsa_secretbox_matches_independent_messages() raises:
    var key = List[UInt8](length=32, fill=0xA5)
    var nonces = List[List[UInt8]](capacity=8)
    var messages = List[List[UInt8]](capacity=8)
    for lane in range(8):
        nonces.append(List[UInt8](length=24, fill=UInt8(lane)))
        messages.append(List[UInt8](length=300, fill=UInt8(0x20 + lane)))
    var outputs = secretbox_encrypt_eight(messages, nonces, Span(key))
    for lane in range(8):
        assert_equal(
            outputs[lane],
            secretbox_encrypt(
                Span(messages[lane]), Span(nonces[lane]), Span(key)
            ),
        )
    var recovered = secretbox_decrypt_eight(outputs, nonces, Span(key))
    for lane in range(8):
        assert_equal(recovered[lane], messages[lane])
    outputs[3][0] ^= 1
    with assert_raises():
        _ = secretbox_decrypt_eight(outputs, nonces, Span(key))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
