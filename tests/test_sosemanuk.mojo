from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.ciphers.sosemanuk import xor


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


def test_reference_reference_vector() raises:
    var key = h("A7C083FEB7")
    var iv = h("00112233445566778899AABBCCDDEEFF")
    var plain = List[UInt8](length=160, fill=0)
    var expected = h(
        "FE81D2162C9A100D04895C454A77515B"
        "BE6A431A935CB90E2221EBB7EF502328"
        "943539492EFF6310C871054C2889CC72"
        "8F82E86B1AFFF4334B6127A13A155C75"
        "151630BD482EB673FF5DB477FA6C53EB"
        "E1A4EC38C23C5400C315455D93A2ACED"
        "9598604727FA340D5F2A8BD757B77833"
        "F74BD2BC049313C80616B4A06268AE35"
        "0DB92EEC4FA56C171374A67A80C006D0"
        "EAD048CE7B640F17D3D5A62D1F251C21"
    )
    var cipher = xor(Span(key), Span(iv), Span(plain))
    assert_equal(cipher, expected)
    assert_equal(xor(Span(key), Span(iv), Span(cipher)), plain)


def test_reference_long_xor_digest() raises:
    var key = h(
        "0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C"
    )
    var iv = h("288FF65DC42B92F960C72E95FC63CA31")
    var plain = List[UInt8](length=131072, fill=0)
    var cipher = xor(Span(key), Span(iv), Span(plain))
    var digest = List[UInt8](length=64, fill=0)
    for i in range(len(cipher)):
        digest[i % 64] ^= cipher[i]
    assert_equal(
        digest,
        h(
            "CC09FB7405DD54BBF09407B1D2033FBBAC53F388DD387A46F2B8FCFF692A7838"
            "353523A621A55D08DA0CA5348AE96D8B0D6A028F309982EF6628054D01B9A368"
        ),
    )


def test_multiple_lengths_and_roundtrip() raises:
    var iv = h("288FF65DC42B92F960C72E95FC63CA31")
    var key1 = h("01")
    var key16 = h("00112233445566778899AABBCCDDEEFF")
    var key32 = h(
        "0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C"
    )
    var plain = List[UInt8](capacity=97)
    for i in range(97):
        plain.append(UInt8((i * 73 + 11) & 255))
    var c1 = xor(Span(key1), Span(iv), Span(plain))
    var c16 = xor(Span(key16), Span(iv), Span(plain))
    var c32 = xor(Span(key32), Span(iv), Span(plain))
    assert_equal(xor(Span(key1), Span(iv), Span(c1)), plain)
    assert_equal(xor(Span(key16), Span(iv), Span(c16)), plain)
    assert_equal(xor(Span(key32), Span(iv), Span(c32)), plain)


def test_sizes() raises:
    var empty = List[UInt8]()
    var input = List[UInt8]()
    var iv = List[UInt8](length=16, fill=0)
    var key = List[UInt8](length=16, fill=0)
    with assert_raises():
        _ = xor(Span(empty), Span(iv), Span(input))
    var long_key = List[UInt8](length=33, fill=0)
    with assert_raises():
        _ = xor(Span(long_key), Span(iv), Span(input))
    var short_iv = List[UInt8](length=15, fill=0)
    with assert_raises():
        _ = xor(Span(key), Span(short_iv), Span(input))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
