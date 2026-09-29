from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.speck import encrypt, decrypt
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else 87
        c -= 48 if c <= 57 else 87
        o.append(UInt8(a * 16 + c))
    return o^


def test_speck64_vector() raises:
    var key = h("0001020308090a0b10111213")
    var plain = h("65616e7320466174")
    var expected = h("6c947541ec52799f")
    assert_equal(
        encrypt(BlockCipherAlgorithm.SPECK64, Span(key), Span(plain)), expected
    )
    assert_equal(
        decrypt(BlockCipherAlgorithm.SPECK64, Span(key), Span(expected)), plain
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
