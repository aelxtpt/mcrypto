from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.rc2 import process


def h(text: StaticString) -> List[UInt8]:
    var b = text.as_bytes()
    var output = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var high = Int(b[i])
        var low = Int(b[i + 1])
        high -= 48 if high <= 57 else (87 if high >= 97 else 55)
        low -= 48 if low <= 57 else (87 if low >= 97 else 55)
        output.append(UInt8(high * 16 + low))
    return output^


def test_rfc2268_vectors() raises:
    var key1 = h("0000000000000000")
    var plain1 = h("0000000000000000")
    var cipher1 = h("ebb773f993278eff")
    assert_equal(process(False, Span(key1), Span(plain1), 63), cipher1)
    assert_equal(process(True, Span(key1), Span(cipher1), 63), plain1)
    var key2 = h("ffffffffffffffff")
    var plain2 = h("ffffffffffffffff")
    var cipher2 = h("278b27e42e2f0d49")
    assert_equal(process(False, Span(key2), Span(plain2), 64), cipher2)
    assert_equal(process(True, Span(key2), Span(cipher2), 64), plain2)
    var key3 = h("88")
    var plain3 = h("0000000000000000")
    var cipher3 = h("61a8a244adacccf0")
    assert_equal(process(False, Span(key3), Span(plain3), 64), cipher3)
    assert_equal(process(True, Span(key3), Span(cipher3), 64), plain3)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
