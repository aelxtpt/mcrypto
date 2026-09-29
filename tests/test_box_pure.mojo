from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.key_exchange.x25519 import public_key
from mcrypto.public_key.box import encrypt, decrypt


def test_box_roundtrip_and_tamper() raises:
    var alice_secret = List[UInt8](length=32, fill=7)
    var bob_secret = List[UInt8](length=32, fill=9)
    var alice_public = public_key(Span(alice_secret))
    var bob_public = public_key(Span(bob_secret))
    var nonce = List[UInt8](length=24, fill=3)
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var cipher = encrypt(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(
        decrypt(
            Span(cipher), Span(nonce), Span(alice_public), Span(bob_secret)
        ),
        message,
    )
    cipher[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(cipher), Span(nonce), Span(alice_public), Span(bob_secret)
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
