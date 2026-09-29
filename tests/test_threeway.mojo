from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.threeway import process


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else (87 if a >= 97 else 55)
        c -= 48 if c <= 57 else (87 if c >= 97 else 55)
        o.append(UInt8(a * 16 + c))
    return o^


def test_threeway_vector() raises:
    var key = h("000000000000000000000000")
    var plain = h("000000010000000100000001")
    var cipher = h("4059c76e83ae9dc4ad21ecf7")
    assert_equal(process(False, Span(key), Span(plain)), cipher)
    assert_equal(process(True, Span(key), Span(cipher)), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
