from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.math.fields import GF2_32, GF256, PrimeField64


def test_prime_field_arithmetic() raises:
    var field = PrimeField64(17)
    assert_equal(field.add(16, 5), UInt64(4))
    assert_equal(field.subtract(3, 5), UInt64(15))
    assert_equal(field.multiply(9, 11), UInt64(14))
    assert_equal(field.power(3, 16), UInt64(1))
    assert_equal(field.inverse(5), UInt64(7))
    with assert_raises():
        _ = field.inverse(0)
    var composite = PrimeField64(15)
    with assert_raises():
        _ = composite.inverse(5)


def test_gf256_aes_polynomial() raises:
    var field = GF256(0x1B)
    assert_equal(field.multiply(0x57, 0x83), UInt8(0xC1))
    for value in range(1, 256):
        var element = UInt8(value)
        assert_equal(field.multiply(element, field.inverse(element)), UInt8(1))
    with assert_raises():
        _ = field.inverse(0)


def test_gf2_32_field_laws() raises:
    var field = GF2_32()
    assert_equal(field.multiply(0x12345678, 0), UInt32(0))
    assert_equal(field.multiply(0x12345678, 1), UInt32(0x12345678))
    assert_equal(
        field.multiply(0xDEADBEEF, 0x01020304),
        field.multiply(0x01020304, 0xDEADBEEF),
    )
    var values: List[UInt32] = [1, 2, 3, 0x12345678, 0xDEADBEEF]
    for value in values:
        assert_equal(field.multiply(value, field.inverse(value)), UInt32(1))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
