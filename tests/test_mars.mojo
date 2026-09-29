from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.mars import process


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var out = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else (87 if a >= 97 else 55)
        c -= 48 if c <= 57 else (87 if c >= 97 else 55)
        out.append(UInt8(a * 16 + c))
    return out^


def check(
    key_hex: StaticString, plain_hex: StaticString, cipher_hex: StaticString
) raises:
    var key = h(key_hex)
    var plain = h(plain_hex)
    var cipher = h(cipher_hex)
    assert_equal(process(False, Span(key), Span(plain)), cipher)
    assert_equal(process(True, Span(key), Span(cipher)), plain)


def test_mars_128() raises:
    check(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "DCC07B8DFB0738D6E30A22DFCF27E886",
    )


def test_mars_192() raises:
    check(
        "000000000000000000000000000000000000000000000000",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "97778747D60E425C2B4202599DB856FB",
    )


def test_mars_256() raises:
    check(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "62E45B4CF3477F1DD65063729D9ABA8F",
        "0F4B897EA014D21FBC20F1054A42F719",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
