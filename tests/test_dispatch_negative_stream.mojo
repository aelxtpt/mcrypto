from std.testing import assert_raises, TestSuite
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor


def test_every_stream_dispatch_rejects_empty_key_and_nonce() raises:
    var empty_key = List[UInt8]()
    var empty_nonce = List[UInt8]()
    var message = List[UInt8](length=1, fill=0)
    for algorithm in [
        StreamCipherAlgorithm.ARC4,
        StreamCipherAlgorithm.CHACHA12,
        StreamCipherAlgorithm.CHACHA20,
        StreamCipherAlgorithm.CHACHA20_IETF,
        StreamCipherAlgorithm.CHACHA8,
        StreamCipherAlgorithm.HC128,
        StreamCipherAlgorithm.HC256,
        StreamCipherAlgorithm.PANAMA,
        StreamCipherAlgorithm.PANAMA_BE,
        StreamCipherAlgorithm.RABBIT,
        StreamCipherAlgorithm.SEAL,
        StreamCipherAlgorithm.SEAL_LE,
        StreamCipherAlgorithm.SALSA20,
        StreamCipherAlgorithm.SALSA20_12,
        StreamCipherAlgorithm.SALSA20_8,
        StreamCipherAlgorithm.SOSEMANUK,
        StreamCipherAlgorithm.WAKE_OFB,
        StreamCipherAlgorithm.XCHACHA20,
        StreamCipherAlgorithm.XCHACHA20_COUNTER1,
        StreamCipherAlgorithm.XSALSA20,
    ]:
        with assert_raises():
            _ = xor(
                algorithm, Span(empty_key), Span(empty_nonce), Span(message)
            )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
