from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.kalyna import process
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


def check(
    algorithm: BlockCipherAlgorithm,
    key_text: StaticString,
    plain_text: StaticString,
    cipher_text: StaticString,
) raises:
    var key = h(key_text)
    var plain = h(plain_text)
    var cipher = h(cipher_text)
    assert_equal(process(algorithm, False, Span(key), Span(plain)), cipher)
    assert_equal(process(algorithm, True, Span(key), Span(cipher)), plain)


def test_kalyna_reference_reference_vectors() raises:
    check(
        BlockCipherAlgorithm.KALYNA128,
        "000102030405060708090A0B0C0D0E0F",
        "101112131415161718191A1B1C1D1E1F",
        "81BF1C7D779BAC20E1C9EA39B4D2AD06",
    )
    check(
        BlockCipherAlgorithm.KALYNA128,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F",
        "58EC3E091000158A1148F7166F334F14",
    )
    check(
        BlockCipherAlgorithm.KALYNA256,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C",
    )
    check(
        BlockCipherAlgorithm.KALYNA256,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        "606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9",
    )
    check(
        BlockCipherAlgorithm.KALYNA512,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
