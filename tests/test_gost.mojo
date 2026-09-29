from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.gost import process


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


def test_gost_vector() raises:
    var key = h(
        "BE5EC2006CFF9DCF52354959F1FF0CBFE95061B5A648C10387069C25997C0672"
    )
    var plain = h("0DF82802B741A292")
    var cipher = h("07F9027DF7F7DF89")
    assert_equal(process(False, Span(key), Span(plain)), cipher)
    assert_equal(process(True, Span(key), Span(cipher)), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
