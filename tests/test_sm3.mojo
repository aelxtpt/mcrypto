from std.testing import assert_equal, TestSuite
from mcrypto.hashes.sm3 import sm3


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_gb_sm3_vectors() raises:
    assert_equal(
        sm3("abc".as_bytes()),
        hex_bytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        ),
    )
    assert_equal(
        sm3(("abcd" * 16).as_bytes()),
        hex_bytes(
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
