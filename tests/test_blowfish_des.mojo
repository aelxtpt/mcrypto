from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.ciphers.blowfish import process as blowfish
from mcrypto.ciphers.des import process as des
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm


def h(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high -= 48 if high <= 57 else (87 if high >= 97 else 55)
        low -= 48 if low <= 57 else (87 if low >= 97 else 55)
        output.append(UInt8(high * 16 + low))
    return output^


def ascii(text: StaticString) -> List[UInt8]:
    var output = List[UInt8]()
    for byte in text.as_bytes():
        output.append(byte)
    return output^


def test_blowfish_reference_vectors() raises:
    var key1 = ascii("abcdefghijklmnopqrstuvwxyz")
    var plain1 = ascii("BLOWFISH")
    var cipher1 = h("324ed0fef413a203")
    assert_equal(blowfish(False, Span(key1), Span(plain1)), cipher1)
    assert_equal(blowfish(True, Span(key1), Span(cipher1)), plain1)
    var key2 = ascii("Who is John Galt?")
    var plain2 = h("fedcba9876543210")
    var cipher2 = h("cc91732b8022f684")
    assert_equal(blowfish(False, Span(key2), Span(plain2)), cipher2)
    assert_equal(blowfish(True, Span(key2), Span(cipher2)), plain2)


def test_des_reference_certification_vector() raises:
    var key = h("0101010101010101")
    var plain = h("95f8a5e5dd31d900")
    var cipher = h("8000000000000000")
    assert_equal(
        des(BlockCipherAlgorithm.DES, False, Span(key), Span(plain)), cipher
    )
    assert_equal(
        des(BlockCipherAlgorithm.DES, True, Span(key), Span(cipher)), plain
    )


def test_des_family_reference_vectors() raises:
    var plain = h("0123456789abcde7")
    var key2 = h("0123456789abcdeffedcba9876543210")
    var cipher2 = h("7f1d0a77826b8aff")
    assert_equal(
        des(BlockCipherAlgorithm.DES_EDE2, False, Span(key2), Span(plain)),
        cipher2,
    )
    assert_equal(
        des(BlockCipherAlgorithm.DES_EDE2, True, Span(key2), Span(cipher2)),
        plain,
    )
    var key3 = h("0123456789abcdeffedcba987654321089abcdef01234567")
    var cipher3 = h("de0b7c06ae5e0ed5")
    assert_equal(
        des(BlockCipherAlgorithm.DES_EDE3, False, Span(key3), Span(plain)),
        cipher3,
    )
    assert_equal(
        des(BlockCipherAlgorithm.DES_EDE3, True, Span(key3), Span(cipher3)),
        plain,
    )
    var xkey = h("0123456789ABCDEF01010101010101011011121314151617")
    var xplain = h("94DBE082549A14EF")
    var xcipher = h("9011121314151617")
    assert_equal(
        des(BlockCipherAlgorithm.DES_XEX3, False, Span(xkey), Span(xplain)),
        xcipher,
    )
    assert_equal(
        des(BlockCipherAlgorithm.DES_XEX3, True, Span(xkey), Span(xcipher)),
        xplain,
    )


def test_validation() raises:
    var block = h("0000000000000000")
    var short = h("000102")
    with assert_raises():
        _ = blowfish(False, Span(short), Span(block))
    with assert_raises():
        _ = des(BlockCipherAlgorithm.DES, False, Span(short), Span(block))
    with assert_raises():
        _ = des(BlockCipherAlgorithm.AES, False, Span(short), Span(block))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
