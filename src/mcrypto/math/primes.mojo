"""Prime testing, generation, and elementary number theory.

`is_probable_prime` and `generate_probable_prime` are explicitly
probabilistic classifications.  `generate_provable_prime` uses recursive
Pocklington certificates internally; it does not return a probable prime as a
proved one.
"""

from ..random.entropy import ChaChaRNG, system_entropy
from .biguint import BigUInt, _MontgomeryContext


comptime _SMALL_PRIMES: InlineArray[UInt32, 54] = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
]

comptime _MR_BASES: InlineArray[UInt64, 32] = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
]


def _seeded_rng() raises -> ChaChaRNG:
    var seed = system_entropy(44)
    var key = List[UInt8](capacity=32)
    var nonce = List[UInt8](capacity=12)
    for i in range(32):
        key.append(seed[i])
    for i in range(12):
        nonce.append(seed[32 + i])
    return ChaChaRNG(Span(key), Span(nonce))


def _is_one(value: BigUInt) -> Bool:
    return value.compare(BigUInt(1)) == 0


def _divide_by_two(value: BigUInt) -> BigUInt:
    var limbs = value.limbs.copy()
    var carry = UInt32(0)
    for i in range(len(limbs) - 1, -1, -1):
        var next_carry = limbs[i] & 1
        limbs[i] = (limbs[i] >> 1) | (carry << 31)
        carry = next_carry
    return BigUInt.from_limbs(Span(limbs))


def _mod_small(value: BigUInt, divisor: UInt32) raises -> UInt32:
    if divisor == 0:
        raise Error("small modulo by zero")
    var remainder = UInt64(0)
    for i in range(len(value.limbs) - 1, -1, -1):
        remainder = ((remainder << 32) | UInt64(value.limbs[i])) % UInt64(
            divisor
        )
    return UInt32(remainder)


def _divmod(
    dividend: BigUInt, divisor: BigUInt
) raises -> Tuple[BigUInt, BigUInt]:
    if divisor.is_zero():
        raise Error("division by zero")
    var quotient = BigUInt()
    var remainder = BigUInt()
    for i in range(dividend.bit_length() - 1, -1, -1):
        quotient.shift_left_one()
        remainder.shift_left_one()
        remainder.add_small(dividend.bit(i))
        if remainder.compare(divisor) >= 0:
            remainder = remainder.subtract(divisor)
            quotient.add_small(1)
    return (quotient^, remainder^)


def _exact_divide(dividend: BigUInt, divisor: BigUInt) raises -> BigUInt:
    var result = _divmod(dividend, divisor)
    if not result[1].is_zero():
        raise Error("non-exact integer division")
    return result[0].copy()


def gcd(left: BigUInt, right: BigUInt) raises -> BigUInt:
    """Greatest common divisor, including gcd(0, 0) == 0."""
    var a = left.copy()
    var b = right.copy()
    while not b.is_zero():
        var remainder = a.modulo(b)
        a = b.copy()
        b = remainder^
    return a^


def lcm(left: BigUInt, right: BigUInt) raises -> BigUInt:
    """Least common multiple; zero if either operand is zero."""
    if left.is_zero() or right.is_zero():
        return BigUInt()
    var divisor = gcd(left, right)
    return _exact_divide(left, divisor).multiply(right)


def trial_division(value: BigUInt, max_divisor: UInt32 = 251) raises -> Bool:
    """Return false on a divisor at most `max_divisor`, true otherwise.

    A true result is only a primality proof when max_divisor squared is at
    least value.  This bounded predicate is intended as a cheap sieve.
    """
    if value.compare(BigUInt(2)) < 0:
        return False
    if value.compare(BigUInt(2)) == 0:
        return True
    if value.bit(0) == 0:
        return False
    var divisor = UInt32(3)
    while divisor <= max_divisor:
        var divisor_value = BigUInt(UInt64(divisor))
        if divisor_value.multiply(divisor_value).compare(value) > 0:
            return True
        if _mod_small(value, divisor) == 0:
            return value.compare(divisor_value) == 0
        divisor += 2
    return True


def _decompose_twos(value: BigUInt) raises -> Tuple[BigUInt, Int]:
    var odd = value.copy()
    var power = 0
    while odd.bit(0) == 0 and not odd.is_zero():
        odd = _divide_by_two(odd)
        power += 1
    return (odd^, power)


def strong_miller_rabin(value: BigUInt, base: UInt64) raises -> Bool:
    """One strong Miller-Rabin probable-prime test to the given base."""
    var two = BigUInt(2)
    if value.compare(two) < 0:
        return False
    if value.compare(two) == 0:
        return True
    if value.bit(0) == 0:
        return False
    var one = BigUInt(1)
    var value_minus_one = value.subtract(one)
    var decomposition = _decompose_twos(value_minus_one)
    var d = decomposition[0].copy()
    var s = decomposition[1]
    var a = BigUInt(base).modulo(value)
    if a.is_zero():
        return True
    var x = a.modular_power(d, value)
    if _is_one(x) or x.compare(value_minus_one) == 0:
        return True
    for _ in range(1, s):
        x = x.modular_multiply(x, value)
        if x.compare(value_minus_one) == 0:
            return True
        if _is_one(x):
            return False
    return False


def _jacobi(upper: BigUInt, lower: BigUInt) raises -> Int:
    if lower.is_zero() or lower.bit(0) == 0:
        raise Error("Jacobi denominator must be positive and odd")
    var a = upper.modulo(lower)
    var n = lower.copy()
    var sign = 1
    while not a.is_zero():
        while a.bit(0) == 0:
            a = _divide_by_two(a)
            var n_mod_8 = _mod_small(n, 8)
            if n_mod_8 == 3 or n_mod_8 == 5:
                sign = -sign
        var old_a = a.copy()
        a = n.copy()
        n = old_a^
        if _mod_small(a, 4) == 3 and _mod_small(n, 4) == 3:
            sign = -sign
        a = a.modulo(n)
    if _is_one(n):
        return sign
    return 0


@always_inline("nodebug")
def _unsigned_magnitude(value: Int) -> UInt64:
    # Avoid overflowing on the most-negative machine Int.
    if value >= 0:
        return UInt64(value)
    return UInt64(-(value + 1)) + 1


def jacobi_symbol(numerator: Int, denominator: BigUInt) raises -> Int:
    """Jacobi symbol for a machine-sized signed numerator."""
    if denominator.is_zero() or denominator.bit(0) == 0:
        raise Error("Jacobi denominator must be positive and odd")
    var magnitude = _unsigned_magnitude(numerator)
    var result = _jacobi(BigUInt(magnitude), denominator)
    if numerator < 0 and _mod_small(denominator, 4) == 3:
        result = -result
    return result


def _signed_small_mod(value: Int, modulus: BigUInt) raises -> BigUInt:
    var magnitude = _unsigned_magnitude(value)
    var reduced = BigUInt(magnitude).modulo(modulus)
    if value >= 0 or reduced.is_zero():
        return reduced^
    return modulus.subtract(reduced)


def _half_mod(value: BigUInt, modulus: BigUInt) -> BigUInt:
    if value.bit(0) == 0:
        return _divide_by_two(value)
    return _divide_by_two(value.add(modulus))


@always_inline("nodebug")
def _add_reduced(
    left: BigUInt, right: BigUInt, modulus: BigUInt
) raises -> BigUInt:
    var output = left.add(right)
    if output.compare(modulus) >= 0:
        output = output.subtract(modulus)
    return output^


@always_inline("nodebug")
def _sub_reduced(
    left: BigUInt, right: BigUInt, modulus: BigUInt
) raises -> BigUInt:
    if left.compare(right) >= 0:
        return left.subtract(right)
    return modulus.subtract(right.subtract(left))


def _fixed_biguint(limb_count: Int) -> BigUInt:
    var output = BigUInt()
    output.limbs = List[UInt32](unsafe_uninit_length=limb_count)
    return output^


def _lucas_sequence(
    modulus: BigUInt, d_parameter: Int, q_parameter: Int, index: BigUInt
) raises -> Tuple[BigUInt, BigUInt, BigUInt]:
    # Selfridge parameters always use P = 1. Keep every recurrence value in
    # one Montgomery domain and recycle fixed-width storage across every bit.
    var context = _MontgomeryContext(modulus)
    var one = context.encode(BigUInt(1))
    var inverse_two = context.encode(_divide_by_two(modulus.add(BigUInt(1))))
    var q_mod = context.encode(_signed_small_mod(q_parameter, modulus))
    var d_mod = context.encode(_signed_small_mod(d_parameter, modulus))
    while len(inverse_two.limbs) < context.limb_count:
        inverse_two.limbs.append(0)
    while len(q_mod.limbs) < context.limb_count:
        q_mod.limbs.append(0)
    while len(d_mod.limbs) < context.limb_count:
        d_mod.limbs.append(0)
    var u = one.copy()
    var v = one.copy()
    var q_power = q_mod.copy()
    while len(u.limbs) < context.limb_count:
        u.limbs.append(0)
    while len(v.limbs) < context.limb_count:
        v.limbs.append(0)
    while len(q_power.limbs) < context.limb_count:
        q_power.limbs.append(0)
    var scratch0 = _fixed_biguint(context.limb_count)
    var scratch1 = _fixed_biguint(context.limb_count)
    var scratch2 = _fixed_biguint(context.limb_count)
    var scratch3 = _fixed_biguint(context.limb_count)
    var scratch4 = _fixed_biguint(context.limb_count)
    var scratch5 = _fixed_biguint(context.limb_count)
    var scratch6 = _fixed_biguint(context.limb_count)
    var scratch7 = _fixed_biguint(context.limb_count)
    for bit_index in range(index.bit_length() - 2, -1, -1):
        context.multiply_into(u, v, scratch0)
        context.multiply_into(v, v, scratch1)
        q_power._reduced_add_into(
            q_power, modulus, scratch2, context.limb_count
        )
        scratch1._reduced_subtract_into(
            scratch2, modulus, scratch3, context.limb_count
        )
        context.multiply_into(q_power, q_power, scratch4)
        if index.bit(bit_index) == 0:
            u._swap_storage(scratch0)
            v._swap_storage(scratch3)
            q_power._swap_storage(scratch4)
        else:
            scratch0._reduced_add_into(
                scratch3, modulus, scratch2, context.limb_count
            )
            context.multiply_into(scratch2, inverse_two, scratch5)
            context.multiply_into(d_mod, scratch0, scratch1)
            scratch1._reduced_add_into(
                scratch3, modulus, scratch2, context.limb_count
            )
            context.multiply_into(scratch2, inverse_two, scratch6)
            context.multiply_into(scratch4, q_mod, scratch7)
            u._swap_storage(scratch5)
            v._swap_storage(scratch6)
            q_power._swap_storage(scratch7)
    return (
        context.decode(u),
        context.decode(v),
        context.decode(q_power),
    )


def is_perfect_square(value: BigUInt) raises -> Bool:
    """Exact arbitrary-precision square test."""
    if value.is_zero() or _is_one(value):
        return True
    var residue16 = _mod_small(value, 16)
    if residue16 != 0 and residue16 != 1 and residue16 != 4 and residue16 != 9:
        return False
    var residue3 = _mod_small(value, 3)
    if residue3 == 2:
        return False
    var residue5 = _mod_small(value, 5)
    if residue5 == 2 or residue5 == 3:
        return False
    var upper = BigUInt(1)
    for _ in range((value.bit_length() + 1) // 2):
        upper.shift_left_one()
    var lower = BigUInt(1)
    var one = BigUInt(1)
    while lower.compare(upper) <= 0:
        var middle = _divide_by_two(lower.add(upper))
        var square = middle.multiply(middle)
        var comparison = square.compare(value)
        if comparison == 0:
            return True
        if comparison < 0:
            lower = middle.add(one)
        else:
            if middle.is_zero():
                return False
            upper = middle.subtract(one)
    return False


def strong_lucas_selfridge(value: BigUInt) raises -> Bool:
    """Strong Lucas probable-prime test with Selfridge's parameter choice."""
    if value.compare(BigUInt(2)) < 0 or value.bit(0) == 0:
        return value.compare(BigUInt(2)) == 0
    if is_perfect_square(value):
        return False
    var d_parameter = 5
    var found = False
    for _ in range(10000):
        var symbol = jacobi_symbol(d_parameter, value)
        if symbol == -1:
            found = True
            break
        if symbol == 0:
            return (
                value.compare(
                    BigUInt(
                        UInt64(
                            d_parameter if d_parameter >= 0 else -d_parameter
                        )
                    )
                )
                == 0
            )
        if d_parameter > 0:
            d_parameter = -(d_parameter + 2)
        else:
            d_parameter = -d_parameter + 2
    if not found:
        return False
    var q_parameter = (1 - d_parameter) // 4
    var decomposition = _decompose_twos(value.add(BigUInt(1)))
    var odd_index = decomposition[0].copy()
    var s = decomposition[1]
    var sequence = _lucas_sequence(value, d_parameter, q_parameter, odd_index)
    var u = sequence[0].copy()
    var v = sequence[1].copy()
    var q_power = sequence[2].copy()
    if u.is_zero() or v.is_zero():
        return True
    for _ in range(1, s):
        v = v.modular_multiply(v, value).modular_subtract(
            q_power.modular_add(q_power, value), value
        )
        q_power = q_power.modular_multiply(q_power, value)
        if v.is_zero():
            return True
    return False


def _passes_small_prime_sieve(value: BigUInt) raises -> Bool:
    """Reject small factors with one limb scan per packed prime product."""
    var primes = materialize[_SMALL_PRIMES]()
    if value.bit_length() <= 8:
        for prime in primes:
            var comparison = value.compare(BigUInt(UInt64(prime)))
            if comparison == 0:
                return True
            if comparison < 0:
                return False
    if value.bit(0) == 0:
        return False
    var start = 1
    while start < len(primes):
        var product = UInt64(1)
        var end = start
        while end < len(primes):
            var prime = UInt64(primes[end])
            if product > UInt64(0xFFFFFFFF) // prime:
                break
            product *= prime
            end += 1
        var remainder = _mod_small(value, UInt32(product))
        for index in range(start, end):
            if remainder % primes[index] == 0:
                return False
        start = end
    return True


def is_baillie_psw_prime(value: BigUInt) raises -> Bool:
    """Baillie-PSW probable-prime test (base-2 MR plus strong Lucas)."""
    if not _passes_small_prime_sieve(value):
        return False
    if not strong_miller_rabin(value, 2):
        return False
    return strong_lucas_selfridge(value)


def is_probable_prime(value: BigUInt, rounds: Int = 16) raises -> Bool:
    """BPSW plus `rounds` fixed strong-MR screens; not a proof."""
    if rounds < 0:
        raise Error("Miller-Rabin rounds cannot be negative")
    if not is_baillie_psw_prime(value):
        return False
    var bases = materialize[_MR_BASES]()
    for i in range(rounds):
        if not strong_miller_rabin(value, bases[(i + 1) % len(bases)]):
            return False
    return True


def _random_bits(mut rng: ChaChaRNG, bits: Int) raises -> BigUInt:
    if bits < 2:
        raise Error("prime size must be at least two bits")
    var byte_count = (bits + 7) // 8
    var bytes = rng.random_bytes(byte_count)
    var excess = byte_count * 8 - bits
    bytes[byte_count - 1] &= UInt8(0xFF >> excess)
    bytes[byte_count - 1] |= UInt8(1 << (7 - excess))
    bytes[0] |= 1
    var limb_count = (byte_count + 3) // 4
    var limbs = List[UInt32](length=limb_count, fill=0)
    for i in range(byte_count):
        limbs[i // 4] |= UInt32(bytes[i]) << UInt32((i % 4) * 8)
    return BigUInt.from_limbs(Span(limbs))


def generate_probable_prime(bits: Int, rounds: Int = 16) raises -> BigUInt:
    """Generate an odd exact-width probable prime from operating-system entropy.
    """
    if bits < 2:
        raise Error("prime size must be at least two bits")
    if rounds < 1:
        raise Error("prime generation requires at least one Miller-Rabin round")
    var rng = _seeded_rng()
    while True:
        var candidate = _random_bits(rng, bits)
        if is_probable_prime(candidate, rounds):
            return candidate^


def _trial_prime_exact(value: BigUInt) raises -> Bool:
    if value.compare(BigUInt(2)) < 0:
        return False
    if value.compare(BigUInt(2)) == 0:
        return True
    if value.bit(0) == 0:
        return False
    var divisor = UInt32(3)
    while True:
        var d = BigUInt(UInt64(divisor))
        if d.multiply(d).compare(value) > 0:
            return True
        if _mod_small(value, divisor) == 0:
            return False
        divisor += 2


def _generate_proved(mut rng: ChaChaRNG, bits: Int) raises -> BigUInt:
    # Exact trial division is the induction base.  For larger values construct
    # n = 2*r*q + 1 with recursively proved q > sqrt(n), then apply Pocklington.
    if bits <= 20:
        while True:
            var candidate = _random_bits(rng, bits)
            if _trial_prime_exact(candidate):
                return candidate^
    var q_bits = bits // 2 + 1
    var q = _generate_proved(rng, q_bits)
    var r_bits = bits - q_bits
    while True:
        var r = _random_bits(rng, max(2, r_bits))
        if r_bits < 2:
            r = BigUInt(1)
        var two_r = r.add(r)
        var candidate = two_r.multiply(q).add(BigUInt(1))
        if candidate.bit_length() != bits:
            continue
        # Pocklington needs the known factor q of n - 1 to exceed sqrt(n).
        if q.multiply(q).compare(candidate) <= 0:
            continue
        if not trial_division(candidate):
            continue
        if not strong_miller_rabin(candidate, 2):
            continue
        var candidate_minus_one = candidate.subtract(BigUInt(1))
        var bases = materialize[_MR_BASES]()
        for witness in bases:
            var a = BigUInt(witness)
            if a.compare(candidate) >= 0:
                continue
            if (
                a.modular_power(candidate_minus_one, candidate).compare(
                    BigUInt(1)
                )
                != 0
            ):
                break
            var pocklington_term = a.modular_power(two_r, candidate)
            if pocklington_term.is_zero():
                continue
            pocklington_term = pocklington_term.subtract(BigUInt(1))
            if _is_one(gcd(pocklington_term, candidate)):
                return candidate^


def generate_provable_prime(bits: Int) raises -> BigUInt:
    """Generate an exact-width prime proved recursively by Pocklington's theorem.
    """
    if bits < 2:
        raise Error("prime size must be at least two bits")
    var rng = _seeded_rng()
    return _generate_proved(rng, bits)
