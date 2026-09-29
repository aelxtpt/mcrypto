from std.testing import assert_equal, assert_raises
from mcrypto.secretbox.xchacha20poly1305 import encrypt, decrypt


def main() raises:
    var key = List[UInt8](length=32, fill=0xB5)
    var nonce = List[UInt8](length=24, fill=0xC6)
    var message = List("secretbox plaintext".as_bytes())
    var ciphertext = encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(len(ciphertext), len(message) + 16)
    assert_equal(decrypt(Span(ciphertext), Span(nonce), Span(key)), message)
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(Span(ciphertext), Span(nonce), Span(key))
    print("secretbox: ok")
