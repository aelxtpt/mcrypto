from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.safer import safer_k, safer_sk


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


def test_safer_k_64_reference() raises:
    var key = h("0000000000000000")
    var plain = h("0000000000000000")
    var cipher = h("032808C90EE7AB7F")
    assert_equal(safer_k(False, Span(key), Span(plain), 6), cipher)
    assert_equal(safer_k(True, Span(key), Span(cipher), 6), plain)


def test_safer_k_128_reference() raises:
    var key = h("08070605040302010807060504030201")
    var plain = h("5051525354555657")
    var cipher = h("38E64DBF6E0F896E")
    assert_equal(safer_k(False, Span(key), Span(plain), 12), cipher)
    assert_equal(safer_k(True, Span(key), Span(cipher), 12), plain)


def test_safer_sk_64_reference() raises:
    var key = h("0000000000000001")
    var plain = h("7071727374757677")
    var cipher = h("9ABE2C85BE2D7614")
    assert_equal(safer_sk(False, Span(key), Span(plain), 6), cipher)
    assert_equal(safer_sk(True, Span(key), Span(cipher), 6), plain)


def test_safer_sk_128_reference() raises:
    var key = h("00000000000000010000000000000001")
    var plain = h("9091929394959697")
    var cipher = h("9EAA4DF1E0EFF445")
    assert_equal(safer_sk(False, Span(key), Span(plain), 10), cipher)
    assert_equal(safer_sk(True, Span(key), Span(cipher), 10), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
