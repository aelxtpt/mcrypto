from std.testing import assert_equal, TestSuite
from mcrypto.hashes.tiger import tiger


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
        tiger(Span(empty)),
        hex_bytes("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"),
    )
    assert_equal(
        tiger("abc".as_bytes()),
        hex_bytes("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"),
    )
    assert_equal(
        tiger("message digest".as_bytes()),
        hex_bytes("d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6"),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
