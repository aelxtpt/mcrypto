from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.rc import rc5, rc6


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


def test_rc_vectors() raises:
    var k5 = h("00000000000000000000000000000000")
    var p5 = h("0000000000000000")
    var c5 = h("21A5DBEE154B8F6D")
    assert_equal(rc5(False, Span(k5), Span(p5), 12), c5)
    assert_equal(rc5(True, Span(k5), Span(c5), 12), p5)
    var default_cipher = rc5(False, Span(k5), Span(p5))
    assert_equal(rc5(True, Span(k5), Span(default_cipher)), p5)
    var k6 = h("00000000000000000000000000000000")
    var p6 = h("00000000000000000000000000000000")
    var c6 = h("8FC3A53656B1F778C129DF4E9848A41E")
    assert_equal(rc6(False, Span(k6), Span(p6)), c6)
    assert_equal(rc6(True, Span(k6), Span(c6)), p6)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
