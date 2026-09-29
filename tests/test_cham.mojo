from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.cham import encrypt, decrypt
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


def test_cham_vectors() raises:
    var k64 = h("010003020504070609080b0a0d0c0f0e")
    var p64 = h("1100332255447766")
    var c64 = h("453c63bcdcfabf4e")
    assert_equal(
        encrypt(BlockCipherAlgorithm.CHAM64, Span(k64), Span(p64)), c64
    )
    assert_equal(
        decrypt(BlockCipherAlgorithm.CHAM64, Span(k64), Span(c64)), p64
    )
    var k128 = h("03020100070605040b0a09080f0e0d0c")
    var p128 = h("3322110077665544bbaa9988ffeeddcc")
    var c128 = h("c3746034b55700c58d64ec32489332f7")
    assert_equal(
        encrypt(BlockCipherAlgorithm.CHAM128, Span(k128), Span(p128)), c128
    )
    assert_equal(
        decrypt(BlockCipherAlgorithm.CHAM128, Span(k128), Span(c128)), p128
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
