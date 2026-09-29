from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.rabbit import xor


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


def test_rabbit_vector() raises:
    var key = List[UInt8](length=16, fill=0)
    var iv = List[UInt8]()
    var plain = List[UInt8](length=32, fill=0)
    var cipher = h(
        "02F74A1C26456BF5ECD6A536F05457B1A78AC689476C697B390C9CC515D8E888"
    )
    assert_equal(xor(Span(key), Span(iv), Span(plain)), cipher)
    assert_equal(xor(Span(key), Span(iv), Span(cipher)), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
