from std.testing import assert_equal, TestSuite
from mcrypto.macs.poly1305 import authenticate


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


def test_rfc8439_vector() raises:
    var key = hex_bytes(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    assert_equal(
        authenticate(
            Span(key), "Cryptographic Forum Research Group".as_bytes()
        ),
        hex_bytes("a8061dc1305136c6c22b8baf0c0127a9"),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
