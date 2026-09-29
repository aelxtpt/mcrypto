from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.math.biguint import (
    BigUInt,
    FixedBaseModularPower,
    FixedExponentLucasPower,
)


def test_add_subtract_and_multiply() raises:
    var max64 = BigUInt(UInt64(0xFFFFFFFFFFFFFFFF))
    var one = BigUInt(1)
    assert_equal(max64.add(one).to_hex(), "10000000000000000")
    assert_equal(max64.subtract(one).to_hex(), "fffffffffffffffe")
    assert_equal(
        max64.multiply(max64).to_hex(), "fffffffffffffffe0000000000000001"
    )
    with assert_raises():
        _ = one.subtract(max64)


def test_modulo_and_power() raises:
    var base = BigUInt(UInt64(0xFEDCBA9876543210))
    var modulus = BigUInt(UInt64(0xFFFFFFFF00000001))
    assert_equal(
        base.multiply(base).modulo(modulus).to_hex(), "a7c8c7a2ddb3259c"
    )
    var exponent = BigUInt(65537)
    assert_equal(
        BigUInt(42).modular_power(exponent, BigUInt(1000000007)).to_hex(),
        "6e726a9",
    )
    with assert_raises():
        _ = base.modulo(BigUInt(0))


def test_odd_limb_montgomery_power_and_inverse() raises:
    var modulus_limbs: List[UInt32] = [
        0x89ABCDEB,
        0x01234567,
        0xDEADBEEF,
    ]
    var base_limbs: List[UInt32] = [
        0x01234567,
        0x9ABCDEF0,
        0x12345678,
    ]
    var modulus = BigUInt.from_limbs(Span(modulus_limbs))
    var base = BigUInt.from_limbs(Span(base_limbs))
    assert_equal(
        base.modular_power(BigUInt(0x12345), modulus).to_hex(),
        "9afd9a4eaeb3470529ffea6e",
    )
    var value = BigUInt(UInt64(0x13579BDF2468ACE1))
    var inverse = value.modular_inverse(modulus)
    assert_equal(inverse.to_hex(), "4473d042492b89a7d971ca0c")
    assert_equal(value.modular_multiply(inverse, modulus).to_hex(), "1")
    var dividend_limbs: List[UInt32] = [
        0x12345678,
        0x89ABCDEF,
        0x01234567,
        0xDEADBEEF,
    ]
    var divisor_limbs: List[UInt32] = [0x87654321, 0x0FEDCBA9]
    var dividend = BigUInt.from_limbs(Span(dividend_limbs))
    var divisor = BigUInt.from_limbs(Span(divisor_limbs))
    assert_equal(dividend.divide(divisor).to_hex(), "dfac3c5b7ffffffff")
    assert_equal(dividend.modulo(divisor).to_hex(), "5f4e099999999")
    with assert_raises():
        _ = BigUInt(3).modular_inverse(BigUInt(15))


def test_near_modulus_montgomery_encoding() raises:
    var modulus_limbs: List[UInt32] = [
        0x8CF4E20B,
        0xACF065D2,
        0xDB736C2E,
        0x0B003FFF,
        0xF264CC1C,
        0xBBBB9251,
        0xAA0EE7F3,
        0x8BDFE114,
    ]
    var modulus = BigUInt.from_limbs(Span(modulus_limbs))
    var base = modulus.subtract(BigUInt(7))
    var expected = modulus.subtract(BigUInt(343))
    assert_equal(
        base.modular_power(BigUInt(3), modulus).to_hex(), expected.to_hex()
    )


def test_jacobi_symbol() raises:
    assert_equal(BigUInt(5).jacobi_symbol(BigUInt(11)), 1)
    assert_equal(BigUInt(2).jacobi_symbol(BigUInt(11)), -1)
    assert_equal(BigUInt(11).jacobi_symbol(BigUInt(11)), 0)
    with assert_raises():
        _ = BigUInt(3).jacobi_symbol(BigUInt(10))


def test_arbitrary_limb_width() raises:
    var limbs: List[UInt32] = [0x89ABCDEF, 0x01234567, 0xDEADBEEF]
    var value = BigUInt.from_limbs(Span(limbs))
    assert_equal(value.to_hex(), "deadbeef0123456789abcdef")
    assert_equal(value.bit_length(), 96)
    assert_equal(value.add(value).to_hex(), "1bd5b7dde02468acf13579bde")


def test_small_limb_modular_multiply_matches_long_division() raises:
    var modulus_limbs: List[UInt32] = [
        0xF1234567,
        0x89ABCDEF,
        0x76543210,
        0xFEDCBA98,
        0x13579BDF,
        0x05A5A5A5,
    ]
    var left_limbs: List[UInt32] = [
        0xFFFFFFFF,
        0x01234567,
        0x89ABCDEF,
        0xFEDCBA98,
        0x2468ACE0,
        0x04949494,
    ]
    var right_limbs: List[UInt32] = [
        0xDEADBEEF,
        0xFFFFFFFF,
        0x76543210,
        0x11111111,
        0xCAFEBABE,
        0x03838383,
    ]
    var modulus = BigUInt.from_limbs(Span(modulus_limbs))
    var left = BigUInt.from_limbs(Span(left_limbs))
    var right = BigUInt.from_limbs(Span(right_limbs))
    assert_equal(
        left.modular_multiply(right, modulus).to_hex(),
        left.multiply(right).modulo(modulus).to_hex(),
    )
    assert_equal(
        BigUInt(7).modular_multiply(BigUInt(9), modulus).to_hex(), "3f"
    )
    var fixed = FixedBaseModularPower(left, modulus, 32)
    for exponent in [0, 1, 31, 0x12345]:
        var exponent_value = BigUInt(UInt64(exponent))
        assert_equal(
            fixed.power(exponent_value).to_hex(),
            left.modular_power(exponent_value, modulus).to_hex(),
        )
    var lucas_exponent = BigUInt(UInt64(0x12345))
    var fixed_lucas = FixedExponentLucasPower(lucas_exponent, modulus)
    assert_equal(
        fixed_lucas.power(left).to_hex(),
        left.modular_lucas(lucas_exponent, modulus).to_hex(),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
