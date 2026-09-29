from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.twofish import process


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


def test_twofish_128() raises:
    check(
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "9F589F5CF6122C32B6BFEC2F2AE8C35A",
    )


def test_twofish_192() raises:
    check(
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "EFA71F788965BD4453F860178FC19101",
    )


def test_twofish_256() raises:
    check(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "57FF739D4DC92C1BD7FC01700CC8216F",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
