from std.testing import assert_equal, TestSuite
from mcrypto.kdf.blake2b import (
    PreparedBLAKE2bKDF,
    derive,
    derive_into,
)


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


def test_interop_vector() raises:
    var context = "KDF test".as_bytes()
    var key = List[UInt8](capacity=32)
    for i in range(32):
        key.append(UInt8(i))
    var expected = hex_bytes(
        "a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d8071b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614"
    )
    assert_equal(derive(context, Span(key), 0, 64), expected)
    var output = List[UInt8](length=64, fill=0)
    derive_into(context, Span(key), 0, Span(output))
    assert_equal(output, expected)
    var prepared = PreparedBLAKE2bKDF(context, Span(key), 0, 64)
    for _ in range(2):
        prepared.derive_into(Span(output))
        assert_equal(output, expected)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
