from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.math.biguint import BigUInt
from mcrypto.math.primes import (
    gcd,
    generate_probable_prime,
    generate_provable_prime,
    is_baillie_psw_prime,
    is_probable_prime,
    is_perfect_square,
    lcm,
    strong_lucas_selfridge,
    strong_miller_rabin,
    trial_division,
)


def test_known_primes_and_composites() raises:
    for value in [2, 3, 5, 7, 97, 127, 65537, 2147483647]:
        assert_true(is_probable_prime(BigUInt(UInt64(value))))
    for value in [0, 1, 4, 9, 15, 25, 49, 341, 1001, 65535]:
        assert_false(is_probable_prime(BigUInt(UInt64(value))))


def test_carmichael_and_strong_pseudoprimes() raises:
    for value in [561, 1105, 1729, 2465, 2821, 6601, 41041, 3215031751]:
        assert_false(is_baillie_psw_prime(BigUInt(UInt64(value))))
    # 2047 is a base-2 strong pseudoprime, but the Lucas half of BPSW rejects it.
    var pseudoprime = BigUInt(2047)
    assert_true(strong_miller_rabin(pseudoprime, 2))
    assert_false(strong_lucas_selfridge(pseudoprime))
    # Regression: signed Selfridge parameters exercise residues just below n.
    var wide_prime_limbs: List[UInt32] = [
        0x8CF4E20B,
        0xACF065D2,
        0xDB736C2E,
        0x0B003FFF,
        0xF264CC1C,
        0xBBBB9251,
        0xAA0EE7F3,
        0x8BDFE114,
    ]
    assert_true(
        is_baillie_psw_prime(BigUInt.from_limbs(Span(wide_prime_limbs)))
    )


def test_perfect_square_residue_filters_and_exactness() raises:
    for value in [0, 1, 4, 9, 16, 25, 144, 65536]:
        assert_true(is_perfect_square(BigUInt(UInt64(value))))
    for value in [2, 3, 5, 15, 17, 26, 1000]:
        assert_false(is_perfect_square(BigUInt(UInt64(value))))
    var root = BigUInt(UInt64(0x0123456789ABCDEF))
    var square = root.multiply(root)
    assert_true(is_perfect_square(square))
    assert_false(is_perfect_square(square.add(BigUInt(1))))


def test_trial_division_contract() raises:
    assert_true(trial_division(BigUInt(257)))
    assert_false(trial_division(BigUInt(221)))
    # Bounded trial division says no small factor, not that this value is prime.
    assert_true(trial_division(BigUInt(1022117), 251))
    assert_false(is_probable_prime(BigUInt(1022117)))


def test_gcd_and_lcm() raises:
    assert_equal(gcd(BigUInt(48), BigUInt(18)).to_hex(), "6")
    assert_equal(gcd(BigUInt(0), BigUInt(0)).to_hex(), "0")
    assert_equal(lcm(BigUInt(21), BigUInt(6)).to_hex(), "2a")
    assert_equal(lcm(BigUInt(0), BigUInt(99)).to_hex(), "0")


def test_probable_generation_width_and_oddness() raises:
    for bits in [128, 256]:
        var prime = generate_probable_prime(bits, 12)
        assert_equal(prime.bit_length(), bits)
        assert_equal(prime.bit(0), UInt32(1))
        assert_true(is_probable_prime(prime, 16))


def test_provable_generation_is_explicit_and_valid() raises:
    var prime = generate_provable_prime(64)
    assert_equal(prime.bit_length(), 64)
    assert_equal(prime.bit(0), UInt32(1))
    assert_true(is_probable_prime(prime, 16))
    with assert_raises():
        _ = generate_probable_prime(1)
    with assert_raises():
        _ = generate_provable_prime(1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
