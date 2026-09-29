from std.testing import assert_equal
from mcrypto.random.algorithm import DrbgAlgorithm
from mcrypto.random.generator import random_bytes, drbg


def main() raises:
    var generated = random_bytes(32)
    assert_equal(len(generated), 32)

    var entropy = List[UInt8](length=48, fill=0x91)
    var nonce = List[UInt8](length=16, fill=0xA2)
    var personalization = List("docs".as_bytes())
    var additional = List("request".as_bytes())
    var first = drbg(
        DrbgAlgorithm.HMAC_SHA256,
        Span(entropy),
        Span(nonce),
        Span(personalization),
        Span(additional),
        64,
    )
    var second = drbg(
        DrbgAlgorithm.HMAC_SHA256,
        Span(entropy),
        Span(nonce),
        Span(personalization),
        Span(additional),
        64,
    )
    assert_equal(first, second)
    print("randomness-drbg: ok")
