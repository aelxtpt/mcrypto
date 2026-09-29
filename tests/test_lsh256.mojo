from std.testing import assert_equal, TestSuite
from mcrypto.hashes.lsh256 import lsh224, lsh256


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


def test_reference_empty_and_short_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        lsh224(Span(empty)),
        hex_bytes("48a0d55b2b3d91f26e06f7110fe9ce8ea0e2656bbe344cb1c5930653"),
    )
    var ca: List[UInt8] = [0xCA]
    assert_equal(
        lsh224(Span(ca)),
        hex_bytes("4253e6e91b3c37f75c231d53ca6dc8464885250d2058c41d495bd08f"),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
