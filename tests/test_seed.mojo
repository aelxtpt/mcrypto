from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.seed import process


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


def check(
    key_text: StaticString, plain_text: StaticString, cipher_text: StaticString
) raises:
    var key = h(key_text)
    var plain = h(plain_text)
    var cipher = h(cipher_text)
    assert_equal(process(False, Span(key), Span(plain)), cipher)
    assert_equal(process(True, Span(key), Span(cipher)), plain)


def test_rfc4269_vectors() raises:
    check(
        "00000000000000000000000000000000",
        "000102030405060708090A0B0C0D0E0F",
        "5EBAC6E0054E166819AFF1CC6D346CDB",
    )
    check(
        "000102030405060708090A0B0C0D0E0F",
        "00000000000000000000000000000000",
        "C11F22F20140505084483597E4370F43",
    )
    check(
        "4706480851E61BE85D74BFB3FD956185",
        "83A2F8A288641FB9A4E9A5CC2F131C7D",
        "EE54D13EBCAE706D226BC3142CD40D4A",
    )
    check(
        "28DBC3BC49FFD87DCFA509B11D422BE7",
        "B41E6BE2EBA84A148E2EED84593C5EC7",
        "9B9B7BFCD1813CB95D0B3618F40F5122",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
