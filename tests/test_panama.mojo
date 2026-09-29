from std.testing import assert_equal, TestSuite
from mcrypto.hashes.panama import panama


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


def test_reference_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        panama(Span(empty)),
        hex_bytes(
            "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b"
        ),
    )
    assert_equal(
        panama("The quick brown fox jumps over the lazy dog".as_bytes()),
        hex_bytes(
            "5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
