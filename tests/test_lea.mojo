from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.lea import encrypt, decrypt


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


def test_lea_vectors() raises:
    var k128 = h("07AB6305B025D83F79ADDAA63AC8AD00")
    var p128 = h("F28AE3256AAD23B415E028063B610C60")
    var c128 = h("64D908FCB7EBFEF90FD670106DE7C7C5")
    assert_equal(encrypt(Span(k128), Span(p128)), c128)
    assert_equal(decrypt(Span(k128), Span(c128)), p128)
    var k192 = h("1437AF533069BD7525C1560C78BAD2A1E534671C007EF27C")
    var p192 = h("1CB4F4CB6C4BDB5168EA8409727BFD51")
    var c192 = h("69725C6DF912F8B70EB511E6663C5870")
    assert_equal(encrypt(Span(k192), Span(p192)), c192)
    assert_equal(decrypt(Span(k192), Span(c192)), p192)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
