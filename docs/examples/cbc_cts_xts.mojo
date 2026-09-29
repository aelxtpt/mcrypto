from std.testing import assert_equal, assert_true
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode


def main() raises:
    var cbc_key = List[UInt8](length=16, fill=0x31)
    var iv = List[UInt8](length=16, fill=0x42)
    var message = List[UInt8](length=37, fill=0)
    for i in range(len(message)):
        message[i] = UInt8(i * 3 + 1)
    var cts = process(
        BlockCipherAlgorithm.AES,
        CipherMode.CBC_CTS,
        True,
        Span(cbc_key),
        Span(iv),
        Span(message),
    )
    assert_equal(len(cts), len(message))
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            False,
            Span(cbc_key),
            Span(iv),
            Span(cts),
        ),
        message,
    )

    var xts_key = List[UInt8](length=32, fill=0x53)
    var tweak = List[UInt8](length=16, fill=0x64)
    var xts = process(
        BlockCipherAlgorithm.AES,
        CipherMode.XTS,
        True,
        Span(xts_key),
        Span(tweak),
        Span(message),
    )
    assert_true(xts != message)
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.XTS,
            False,
            Span(xts_key),
            Span(tweak),
            Span(xts),
        ),
        message,
    )
    print("cbc-cts-xts: ok")
