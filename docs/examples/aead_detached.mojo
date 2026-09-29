from std.testing import assert_equal, assert_raises
from mcrypto.aead.detached import encrypt, decrypt
from mcrypto.aead.algorithm import AeadAlgorithm


def main() raises:
    var key = List[UInt8](length=16, fill=0x57)
    var nonce = List[UInt8](length=12, fill=0x68)
    var aad = List("detached header".as_bytes())
    var message = List("detached payload".as_bytes())
    var parts = encrypt(
        AeadAlgorithm.GCM, Span(key), Span(nonce), Span(aad), Span(message)
    )
    var ciphertext = parts[0].copy()
    var tag = parts[1].copy()
    assert_equal(len(tag), 16)
    assert_equal(
        decrypt(
            AeadAlgorithm.GCM,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
            Span(tag),
        ),
        message,
    )
    tag[0] ^= 1
    with assert_raises():
        _ = decrypt(
            AeadAlgorithm.GCM,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
            Span(tag),
        )
    print("aead-detached: ok")
