from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.sm4 import process


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else 87
        c -= 48 if c <= 57 else 87
        o.append(UInt8(a * 16 + c))
    return o^


def test_sm4_standard_vector() raises:
    var key = h("0123456789abcdeffedcba9876543210")
    var plain = key.copy()
    var expected = h("681edf34d206965e86b3e94f536e4246")
    assert_equal(process(Span(key), Span(plain)), expected)
    assert_equal(process(Span(key), Span(expected), True), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
