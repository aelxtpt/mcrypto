from std.testing import TestSuite
from mcrypto.macs.dispatch import authenticate
from mcrypto.macs.algorithm import MacAlgorithm


def test_every_mac_dispatch_rejects_zero_output() raises:
    var key = List[UInt8](length=32, fill=0)
    var message = List[UInt8](length=1, fill=0)
    for algorithm in [
        MacAlgorithm.BLAKE2S_MAC,
        MacAlgorithm.BLAKE2B_MAC,
        MacAlgorithm.CBC_MAC,
        MacAlgorithm.CMAC,
        MacAlgorithm.DMAC,
        MacAlgorithm.HMAC_SHA1,
        MacAlgorithm.RIPEMD160_HMAC,
        MacAlgorithm.POLY1305,
        MacAlgorithm.SIPHASH_2_4,
        MacAlgorithm.SIPHASH_4_8,
        MacAlgorithm.TWO_TRACK_MAC,
        MacAlgorithm.PANAMA_MAC,
    ]:
        for tag_bytes in [0, -1]:
            var rejected = False
            try:
                _ = authenticate(algorithm, Span(key), Span(message), tag_bytes)
            except:
                rejected = True
            if not rejected:
                raise Error("accepted nonpositive MAC output")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
