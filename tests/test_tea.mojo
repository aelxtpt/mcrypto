from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.tea import (
    tea_encrypt,
    tea_decrypt,
    xtea_encrypt,
    xtea_decrypt,
)


def test_tea_reference_vector() raises:
    var key = List[UInt8](length=16, fill=0)
    var plain = List[UInt8](length=8, fill=0)
    var expected: List[UInt8] = [0x41, 0xEA, 0x3A, 0x0A, 0x94, 0xBA, 0xA9, 0x40]
    assert_equal(tea_encrypt(Span(key), Span(plain)), expected)
    assert_equal(tea_decrypt(Span(key), Span(expected)), plain)
    var encrypted = xtea_encrypt(Span(key), Span(plain))
    assert_equal(xtea_decrypt(Span(key), Span(encrypted)), plain)


def test_xtea_reference_32_round_vector() raises:
    var key: List[UInt8] = [
        0x27,
        0xF9,
        0x17,
        0xB1,
        0xC1,
        0xDA,
        0x89,
        0x93,
        0x60,
        0xE2,
        0xAC,
        0xAA,
        0xA6,
        0xEB,
        0x92,
        0x3D,
    ]
    var plain: List[UInt8] = [
        0xAF,
        0x20,
        0xA3,
        0x90,
        0x54,
        0x75,
        0x71,
        0xAA,
    ]
    var expected: List[UInt8] = [
        0xD2,
        0x64,
        0x28,
        0xAF,
        0x0A,
        0x20,
        0x22,
        0x83,
    ]
    assert_equal(xtea_encrypt(Span(key), Span(plain)), expected)
    assert_equal(xtea_decrypt(Span(key), Span(expected)), plain)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
