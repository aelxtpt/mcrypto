from std.testing import assert_equal, assert_raises, assert_true
from mcrypto.aead.combined import encrypt, decrypt
from mcrypto.aead.algorithm import AeadAlgorithm


def main() raises:
    var key = List[UInt8](length=32, fill=0x35)
    var nonce = List[UInt8](length=24, fill=0x46)
    var aad = List("record header".as_bytes())
    var message = List("authenticated plaintext".as_bytes())
    var combined = encrypt(
        AeadAlgorithm.XCHACHA20_POLY1305_IETF,
        Span(key),
        Span(nonce),
        Span(aad),
        Span(message),
    )
    assert_equal(len(combined), len(message) + 16)
    assert_equal(
        decrypt(
            AeadAlgorithm.XCHACHA20_POLY1305_IETF,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(combined),
        ),
        message,
    )
    combined[len(combined) - 1] ^= 1
    with assert_raises():
        _ = decrypt(
            AeadAlgorithm.XCHACHA20_POLY1305_IETF,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(combined),
        )
    print("aead-combined: ok")
