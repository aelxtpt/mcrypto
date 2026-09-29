from std.testing import assert_equal, assert_true
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor


def main() raises:
    var key = List[UInt8](length=32, fill=0x19)
    var nonce = List[UInt8](length=24, fill=0x2A)
    var message = List("stream ciphers need unique nonces".as_bytes())
    var ciphertext = xor(
        StreamCipherAlgorithm.XCHACHA20,
        Span(key),
        Span(nonce),
        Span(message),
    )
    assert_true(ciphertext != message)
    assert_equal(
        xor(
            StreamCipherAlgorithm.XCHACHA20,
            Span(key),
            Span(nonce),
            Span(ciphertext),
        ),
        message,
    )
    print("stream-ciphers: ok")
