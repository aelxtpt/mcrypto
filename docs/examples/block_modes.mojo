from std.testing import assert_equal, assert_true
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode


def main() raises:
    var key = List[UInt8](length=16, fill=0x11)
    var iv = List[UInt8](length=16, fill=0x22)
    var message = List[UInt8](length=32, fill=0)
    for i in range(len(message)):
        message[i] = UInt8(i)
    for mode in [CipherMode.CBC, CipherMode.CTR]:
        var ciphertext = process(
            BlockCipherAlgorithm.AES,
            mode,
            True,
            Span(key),
            Span(iv),
            Span(message),
        )
        assert_true(ciphertext != message)
        assert_equal(
            process(
                BlockCipherAlgorithm.AES,
                mode,
                False,
                Span(key),
                Span(iv),
                Span(ciphertext),
            ),
            message,
        )
    print("block-modes: ok")
