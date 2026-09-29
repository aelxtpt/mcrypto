from std.testing import assert_equal, TestSuite
from mcrypto.hashes.lsh512 import lsh384, lsh512, lsh512_256


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high = high - (48 if high <= 57 else 87)
        low = low - (48 if low <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_reference_empty_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        lsh384(Span(empty)),
        hex_bytes(
            "dbb259cf22459368ab2c52b3e1c977288b38670adcb91cae6b8b6a2d646e76f8bd53e5cab0e47c856f55249b895c1730"
        ),
    )
    assert_equal(
        lsh512_256(Span(empty)),
        hex_bytes(
            "706df4ebf100f06d5cc9f6c79be5297c3f6f515801dd10fbc1b665a2d7bdb653"
        ),
    )
    assert_equal(
        lsh512(512, Span(empty)),
        hex_bytes(
            "118a2ff2a99e3b2134125e2baf20ebe3bdd034d5a69b29c22fc4995063340b46697801d7f7fb0070568f78e8ed514215fc70af27d6f27b01aa8a1da72b14ce7c"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
