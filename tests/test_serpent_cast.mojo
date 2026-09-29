from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.serpent import serpent_process
from mcrypto.ciphers.cast import process as cast_process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm


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


def test_serpent_reference_vectors() raises:
    var plain = h("00112233445566778899AABBCCDDEEFF")
    var key128 = h("80000000000000000000000000000000")
    var cipher128 = h("264E5481EFF42A4606ABDA06C0BFDA3D")
    var zero = h("00000000000000000000000000000000")
    assert_equal(serpent_process(False, Span(key128), Span(zero)), cipher128)
    assert_equal(serpent_process(True, Span(key128), Span(cipher128)), zero)
    var key192 = h("000102030405060708090A0B0C0D0E0F1011121314151617")
    var plain192 = h("4528CACCB954D450655E8CFD71CBFAC7")
    assert_equal(serpent_process(False, Span(key192), Span(plain192)), plain)
    assert_equal(serpent_process(True, Span(key192), Span(plain)), plain192)
    var key256 = h(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    )
    var plain256 = h("3DA46FFA6F4D6F30CD258333E5A61369")
    assert_equal(serpent_process(False, Span(key256), Span(plain256)), plain)
    assert_equal(serpent_process(True, Span(key256), Span(plain)), plain256)


def test_cast128_reference_vectors() raises:
    var plain = h("0123456789ABCDEF")
    var k128 = h("0123456712345678234567893456789A")
    var c128 = h("238B4FE5847E44B2")
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST128, False, Span(k128), Span(plain)
        ),
        c128,
    )
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST128, True, Span(k128), Span(c128)
        ),
        plain,
    )
    var k80 = h("01234567123456782345")
    var c80 = h("EB6A711A2C02271B")
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST128, False, Span(k80), Span(plain)
        ),
        c80,
    )
    assert_equal(
        cast_process(BlockCipherAlgorithm.CAST128, True, Span(k80), Span(c80)),
        plain,
    )
    var k40 = h("0123456712")
    var c40 = h("7AC816D16E9B302E")
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST128, False, Span(k40), Span(plain)
        ),
        c40,
    )
    assert_equal(
        cast_process(BlockCipherAlgorithm.CAST128, True, Span(k40), Span(c40)),
        plain,
    )


def test_cast256_reference_vectors() raises:
    var plain = h("00000000000000000000000000000000")
    var k128 = h("2342bb9efa38542c0af75647f29f615d")
    var c128 = h("c842a08972b43d20836c91d1b7530f6b")
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST256, False, Span(k128), Span(plain)
        ),
        c128,
    )
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST256, True, Span(k128), Span(c128)
        ),
        plain,
    )
    var k192 = h("2342bb9efa38542cbed0ac83940ac298bac77a7717942863")
    var c192 = h("1b386c0210dcadcbdd0e41aa08a7a7e8")
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST256, False, Span(k192), Span(plain)
        ),
        c192,
    )
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST256, True, Span(k192), Span(c192)
        ),
        plain,
    )
    var k256 = h(
        "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"
    )
    var c256 = h("4f6a2038286897b9c9870136553317fa")
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST256, False, Span(k256), Span(plain)
        ),
        c256,
    )
    assert_equal(
        cast_process(
            BlockCipherAlgorithm.CAST256, True, Span(k256), Span(c256)
        ),
        plain,
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
