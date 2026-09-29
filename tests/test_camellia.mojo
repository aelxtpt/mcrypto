from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.camellia import process


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


def check(key: StaticString, cipher: StaticString) raises:
    var k = h(key)
    var p = h("0123456789abcdeffedcba9876543210")
    var c = h(cipher)
    assert_equal(process(False, Span(k), Span(p)), c)
    assert_equal(process(True, Span(k), Span(c)), p)


def test_camellia_rfc3713() raises:
    check(
        "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"
    )
    check(
        "0123456789abcdeffedcba98765432100011223344556677",
        "b4993401b3e996f84ee5cee7d79b09b9",
    )
    check(
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "9acc237dff16d76c20ef7c919e3a7509",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
