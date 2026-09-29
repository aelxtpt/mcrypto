from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.ciphers.algorithm import Chacha20Stream
from mcrypto.ciphers.stream import (
    xor_chacha_eight_from_counter,
    xor_chacha_from_counter,
)


def test_chacha_counter_eight_way_matches_scalar() raises:
    var key = List[UInt8](length=32, fill=0x3C)
    for algorithm, nonce_bytes in [
        (Chacha20Stream.CHACHA20, 8),
        (Chacha20Stream.CHACHA20_IETF, 12),
        (Chacha20Stream.XCHACHA20, 24),
    ]:
        for size in [0, 1, 63, 64, 65, 127, 128, 129]:
            var nonces = List[List[UInt8]](capacity=8)
            var inputs = List[List[UInt8]](capacity=8)
            for lane in range(8):
                nonces.append(List[UInt8](length=nonce_bytes, fill=UInt8(lane)))
                inputs.append(List[UInt8](length=size, fill=UInt8(lane + 1)))
            var outputs = xor_chacha_eight_from_counter(
                algorithm, Span(key), nonces, inputs, UInt32(7)
            )
            for lane in range(8):
                assert_equal(
                    outputs[lane],
                    xor_chacha_from_counter(
                        algorithm,
                        Span(key),
                        Span(nonces[lane]),
                        Span(inputs[lane]),
                        UInt32(7),
                    ),
                )
    var short_nonces = List[List[UInt8]](capacity=7)
    var short_inputs = List[List[UInt8]](capacity=7)
    for _ in range(7):
        short_nonces.append(List[UInt8](length=8, fill=0))
        short_inputs.append(List[UInt8](length=64, fill=0))
    with assert_raises():
        _ = xor_chacha_eight_from_counter(
            Chacha20Stream.CHACHA20,
            Span(key),
            short_nonces,
            short_inputs,
            UInt32(0),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
