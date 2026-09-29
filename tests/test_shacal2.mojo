from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.shacal2 import process


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


def test_nessie_vector() raises:
    var key = h(
        "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    var plain = h(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    var cipher = h(
        "361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE"
    )
    assert_equal(process(False, Span(key), Span(plain)), cipher)
    assert_equal(process(True, Span(key), Span(cipher)), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
