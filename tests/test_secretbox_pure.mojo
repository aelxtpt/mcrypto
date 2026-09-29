from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.secretbox.xsalsa20poly1305 import encrypt, decrypt


def test_secretbox_roundtrip_and_tamper() raises:
    var key = List[UInt8](length=32, fill=7)
    var nonce = List[UInt8](length=24, fill=9)
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(decrypt(Span(ciphertext), Span(nonce), Span(key)), message)
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(Span(ciphertext), Span(nonce), Span(key))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
