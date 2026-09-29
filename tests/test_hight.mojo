from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.hight import encrypt, decrypt


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


def test_hight_vector() raises:
    var key = h("88E34F8F081779F1E9F394370AD40589")
    var plain = h("D76D0D18327EC562")
    var cipher = h("E4BC2E312277E4DD")
    assert_equal(encrypt(Span(key), Span(plain)), cipher)
    assert_equal(decrypt(Span(key), Span(cipher)), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
