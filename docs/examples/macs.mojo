from std.testing import assert_false, assert_true
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm
from mcrypto.macs.dispatch import authenticate
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.cmac import verify


def main() raises:
    var key = List[UInt8](length=16, fill=0x71)
    var message = List("authenticate this message".as_bytes())
    var tag = authenticate(MacAlgorithm.CMAC, Span(key), Span(message), 16)
    assert_true(
        verify(BlockCipherAlgorithm.AES, Span(key), Span(message), Span(tag))
    )
    message[0] ^= 1
    assert_false(
        verify(BlockCipherAlgorithm.AES, Span(key), Span(message), Span(tag))
    )
    print("macs: ok")
