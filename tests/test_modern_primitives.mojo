from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.aead.xchacha20poly1305 import (
    decrypt as xchacha20poly1305_decrypt,
    encrypt as xchacha20poly1305_encrypt,
)
from mcrypto.key_exchange.x25519 import agree as x25519
from mcrypto.passwords.argon2id import derive as argon2id
from mcrypto.signatures.ed25519 import (
    keypair as ed25519_keypair,
    sign as ed25519_sign,
    verify as ed25519_verify,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var encoded = text.as_bytes()
    var digits = "0123456789abcdef".as_bytes()
    var output = List[UInt8](capacity=len(encoded) // 2)
    for i in range(0, len(encoded), 2):
        var high: UInt8 = 0
        var low: UInt8 = 0
        for j in range(16):
            if encoded[i] == digits[j]:
                high = UInt8(j)
            if encoded[i + 1] == digits[j]:
                low = UInt8(j)
        output.append((high << 4) | low)
    return output^


def test_xchacha_roundtrip_and_tamper() raises:
    var key = List[UInt8](length=32, fill=7)
    var nonce = List[UInt8](length=24, fill=9)
    var aad: List[UInt8] = [1, 2, 3]
    var plaintext: List[UInt8] = [4, 5, 6, 7, 8]
    var ciphertext = xchacha20poly1305_encrypt(
        Span(plaintext), Span(aad), Span(nonce), Span(key)
    )
    assert_equal(
        xchacha20poly1305_decrypt(
            Span(ciphertext), Span(aad), Span(nonce), Span(key)
        ),
        plaintext,
    )
    ciphertext[0] ^= 1
    with assert_raises():
        _ = xchacha20poly1305_decrypt(
            Span(ciphertext), Span(aad), Span(nonce), Span(key)
        )


def test_xchacha_rejects_lengths() raises:
    var short_key = List[UInt8](length=31, fill=0)
    var nonce = List[UInt8](length=24, fill=0)
    var message = List[UInt8]()
    var aad = List[UInt8]()
    with assert_raises():
        _ = xchacha20poly1305_encrypt(
            Span(message), Span(aad), Span(nonce), Span(short_key)
        )
    with assert_raises():
        _ = xchacha20poly1305_decrypt(
            Span(message), Span(aad), Span(nonce), Span(short_key)
        )


def test_ed25519_sign_verify_tamper() raises:
    var keys = ed25519_keypair()
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var message: List[UInt8] = [1, 3, 3, 7]
    var signature = ed25519_sign(Span(message), Span(secret_key))
    assert_true(
        ed25519_verify(Span(signature), Span(message), Span(public_key))
    )
    message[0] ^= 1
    assert_false(
        ed25519_verify(Span(signature), Span(message), Span(public_key))
    )


def test_argon2id_determinism_and_limits() raises:
    var password: List[UInt8] = [1, 2, 3, 4]
    var salt = List[UInt8](length=16, fill=5)
    var first = argon2id(Span(password), Span(salt), 32, 1, 8192)
    var second = argon2id(Span(password), Span(salt), 32, 1, 8192)
    assert_equal(first, second)
    var short_salt = List[UInt8](length=15, fill=0)
    with assert_raises():
        _ = argon2id(Span(password), Span(short_salt), 32, 1, 8192)


def test_rfc7748_x25519_vector() raises:
    var scalar = hex_bytes(
        "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44"
    )
    var point = hex_bytes(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    )
    var expected = hex_bytes(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    )
    assert_equal(x25519(Span(scalar), Span(point)), expected)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
