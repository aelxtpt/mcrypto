from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.idea import process


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


def test_idea_reference_vectors() raises:
    var key = h("00010002000300040005000600070008")
    var plain1 = h("0000000100020003")
    var cipher1 = h("11FBED2B01986DE5")
    assert_equal(process(False, Span(key), Span(plain1)), cipher1)
    assert_equal(process(True, Span(key), Span(cipher1)), plain1)
    var plain2 = h("0102030405060708")
    var cipher2 = h("540E5FEA18C2F8B1")
    assert_equal(process(False, Span(key), Span(plain2)), cipher2)
    assert_equal(process(True, Span(key), Span(cipher2)), plain2)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
