"""Internal multiprecision and framed-key helpers for legacy public-key schemes."""

from ..math.biguint import BigUInt
from ..random.entropy import system_entropy
from ..hashes.sha1 import sha1


def uint_from_bytes[origin: Origin](data: Span[UInt8, origin]) -> BigUInt:
    var limbs = List[UInt32](length=max(1, (len(data) + 3) // 4), fill=0)
    for i in range(len(data)):
        var source = len(data) - 1 - i
        limbs[i // 4] |= UInt32(data[source]) << UInt32(8 * (i % 4))
    return BigUInt.from_limbs(Span(limbs))


def uint_to_bytes(value: BigUInt, width: Int = 0) raises -> List[UInt8]:
    var needed = max(1, (value.bit_length() + 7) // 8)
    if width != 0 and needed > width:
        raise Error("integer does not fit encoded width")
    var count = max(needed, width)
    var output = List[UInt8](length=count, fill=0)
    for i in range(min(count, len(value.limbs) * 4)):
        output[count - 1 - i] = UInt8(
            value.limbs[i // 4] >> UInt32(8 * (i % 4))
        )
    return output^


def quotient(dividend: BigUInt, divisor: BigUInt) raises -> BigUInt:
    return dividend.divide(divisor)


def gcd(left: BigUInt, right: BigUInt) raises -> BigUInt:
    var a = left.copy()
    var b = right.copy()
    while not b.is_zero():
        var next = a.modulo(b)
        a = b^
        b = next^
    return a^


def inverse(value: BigUInt, modulus: BigUInt) raises -> BigUInt:
    return value.modular_inverse(modulus)


def jacobi(value: BigUInt, odd_modulus: BigUInt) raises -> Int:
    return value.jacobi_symbol(odd_modulus)


@always_inline("nodebug")
def _mod_small(value: BigUInt, divisor: UInt32) -> UInt32:
    var remainder = UInt64(0)
    for i in range(len(value.limbs) - 1, -1, -1):
        remainder = ((remainder << 32) | UInt64(value.limbs[i])) % UInt64(
            divisor
        )
    return UInt32(remainder)


def _miller_rabin_base(
    candidate: BigUInt,
    candidate_minus_one: BigUInt,
    odd_part: BigUInt,
    shifts: Int,
    base: UInt64,
) raises -> Bool:
    var x = BigUInt(base).modular_power(odd_part, candidate)
    if x.compare(BigUInt(1)) == 0 or x.compare(candidate_minus_one) == 0:
        return True
    for _ in range(shifts - 1):
        x = x.modular_multiply(x, candidate)
        if x.compare(candidate_minus_one) == 0:
            return True
        if x.compare(BigUInt(1)) == 0:
            return False
    return False


def is_probable_prime(candidate: BigUInt) raises -> Bool:
    if candidate.compare(BigUInt(2)) < 0:
        return False
    for small in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if candidate.compare(BigUInt(UInt64(small))) == 0:
            return True
        if _mod_small(candidate, UInt32(small)) == 0:
            return False
    var candidate_minus_one = candidate.subtract(BigUInt(1))
    var odd_part = candidate_minus_one.copy()
    var shifts = 0
    while odd_part.bit(0) == 0:
        odd_part.shift_right_one()
        shifts += 1
    for base in [2, 3, 5, 7, 11, 13, 17]:
        if not _miller_rabin_base(
            candidate,
            candidate_minus_one,
            odd_part,
            shifts,
            UInt64(base),
        ):
            return False
    return True


def random_below(limit: BigUInt) raises -> BigUInt:
    if limit.compare(BigUInt(2)) < 0:
        raise Error("random limit too small")
    var width = (limit.bit_length() + 7) // 8
    while True:
        var bytes = system_entropy(width)
        var excess = width * 8 - limit.bit_length()
        if excess != 0:
            bytes[0] &= UInt8(0xFF >> excess)
        var value = uint_from_bytes(Span(bytes))
        if value.compare(limit) < 0:
            return value^


def _random_prime_candidate(bits: Int, residue4: Int) raises -> BigUInt:
    var width = (bits + 7) // 8
    var bytes = system_entropy(width)
    var excess = width * 8 - bits
    bytes[0] &= UInt8(0xFF >> excess)
    bytes[0] |= UInt8(1 << (7 - excess))
    bytes[width - 1] |= 1
    if residue4 >= 0:
        bytes[width - 1] = (bytes[width - 1] & 0xFC) | UInt8(residue4)
    return uint_from_bytes(Span(bytes))


def _passes_prime_sieve(candidate: BigUInt, primes: List[UInt32]) -> Bool:
    """Reject small factors with packed divisors and one limb scan per pack."""
    var start = 0
    while start < len(primes):
        var product = UInt64(1)
        var end = start
        while end < len(primes):
            var prime = UInt64(primes[end])
            if product > UInt64(0xFFFFFFFF) // prime:
                break
            product *= prime
            end += 1
        var remainder = _mod_small(candidate, UInt32(product))
        for index in range(start, end):
            if remainder % primes[index] == 0:
                return False
        start = end
    return True


def _passes_safe_prime_sieve(
    q: BigUInt, p: BigUInt, primes: List[UInt32]
) -> Bool:
    """Reject factors of q and p with two limb scans per divisor pack."""
    var start = 0
    while start < len(primes):
        var product = UInt64(1)
        var end = start
        while end < len(primes):
            var prime = UInt64(primes[end])
            if product > UInt64(0xFFFFFFFF) // prime:
                break
            product *= prime
            end += 1
        var q_remainder = _mod_small(q, UInt32(product))
        var p_remainder = _mod_small(p, UInt32(product))
        for index in range(start, end):
            if (
                q_remainder % primes[index] == 0
                or p_remainder % primes[index] == 0
            ):
                return False
        start = end
    return True


def generate_prime(
    bits: Int, residue4: Int = -1, residue8: Int = -1
) raises -> BigUInt:
    if bits < 16:
        raise Error("prime size must be at least 16 bits")
    if residue8 >= 0 and residue8 % 2 == 0:
        raise Error("prime residue modulo eight must be odd")
    var increment = UInt32(8 if residue8 >= 0 else (4 if residue4 >= 0 else 2))
    var sieve_primes = _sieve_primes(997)
    while True:
        var candidate = _random_prime_candidate(bits, residue4)
        if residue8 >= 0:
            candidate.limbs[0] = (
                candidate.limbs[0] & UInt32(0xFFFFFFF8)
            ) | UInt32(residue8)
        while candidate.bit_length() == bits:
            if _passes_prime_sieve(
                candidate, sieve_primes
            ) and is_probable_prime(candidate):
                return candidate^
            candidate.add_small(increment)


def _sieve_primes(limit: Int) -> List[UInt32]:
    var primes = List[UInt32]()
    for candidate in range(3, limit + 1, 2):
        var prime = True
        for divisor in range(3, candidate, 2):
            if divisor * divisor > candidate:
                break
            if candidate % divisor == 0:
                prime = False
                break
        if prime:
            primes.append(UInt32(candidate))
    return primes^


def generate_safe_prime_pair(
    bits: Int, relation: Int = 1
) raises -> Tuple[BigUInt, BigUInt]:
    """Generate prime `q` and exact-width prime `p = 2*q + relation`."""
    if bits < 128 or (relation != 1 and relation != -1):
        raise Error("invalid safe-prime parameters")
    var sieve_primes = _sieve_primes(997)
    while True:
        var q = _random_prime_candidate(bits - 1, -1)
        while q.bit_length() == bits - 1:
            var doubled = q.add(q)
            var p = doubled.add(
                BigUInt(1)
            ) if relation == 1 else doubled.subtract(BigUInt(1))
            if p.bit_length() != bits:
                q.add_small(2)
                continue
            var passes_sieve = _passes_safe_prime_sieve(q, p, sieve_primes)
            if passes_sieve:
                var q_minus_one = q.subtract(BigUInt(1))
                var q_odd = q_minus_one.copy()
                var q_shifts = 0
                while q_odd.bit(0) == 0:
                    q_odd.shift_right_one()
                    q_shifts += 1
                var p_minus_one = p.subtract(BigUInt(1))
                var p_odd = p_minus_one.copy()
                var p_shifts = 0
                while p_odd.bit(0) == 0:
                    p_odd.shift_right_one()
                    p_shifts += 1
                if _miller_rabin_base(q, q_minus_one, q_odd, q_shifts, 2) and (
                    _miller_rabin_base(p, p_minus_one, p_odd, p_shifts, 2)
                ):
                    var probable = True
                    for base in [3, 5, 7, 11, 13, 17]:
                        if not _miller_rabin_base(
                            q, q_minus_one, q_odd, q_shifts, UInt64(base)
                        ) or not _miller_rabin_base(
                            p, p_minus_one, p_odd, p_shifts, UInt64(base)
                        ):
                            probable = False
                            break
                    if probable:
                        return (p^, q^)
            q.add_small(2)


def append_u32(mut output: List[UInt8], value: Int) raises:
    if value < 0 or value > 0x7FFFFFFF:
        raise Error("invalid framed length")
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


def read_u32[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> Int:
    if offset < 0 or offset + 4 > len(data):
        raise Error("truncated framed length")
    return (
        (Int(data[offset]) << 24)
        | (Int(data[offset + 1]) << 16)
        | (Int(data[offset + 2]) << 8)
        | Int(data[offset + 3])
    )


def encode_key[
    origin: Origin
](magic: Span[UInt8, origin], components: List[BigUInt]) raises -> List[UInt8]:
    if len(magic) != 4 or len(components) > 255:
        raise Error("invalid key frame")
    var output = List[UInt8](capacity=5 + len(components) * 8)
    for byte in magic:
        output.append(byte)
    output.append(UInt8(len(components)))
    for component in components:
        var encoded = uint_to_bytes(component)
        append_u32(output, len(encoded))
        for byte in encoded:
            output.append(byte)
    return output^


def decode_key[
    origin: Origin
](data: Span[UInt8, origin], magic: StaticString, count: Int) raises -> List[
    BigUInt
]:
    if len(data) < 5 or magic.byte_length() != 4:
        raise Error("invalid key frame")
    for i in range(4):
        if data[i] != UInt8(ord(magic[byte=i])):
            raise Error("wrong key type")
    if Int(data[4]) != count:
        raise Error("wrong key component count")
    var values = List[BigUInt](capacity=count)
    var offset = 5
    for _ in range(count):
        var length = read_u32(data, offset)
        offset += 4
        if length <= 0 or offset + length > len(data):
            raise Error("truncated key component")
        values.append(uint_from_bytes(data[offset : offset + length]))
        offset += length
    if offset != len(data):
        raise Error("trailing key data")
    return values^


def mgf1_sha1[
    origin: Origin
](seed: Span[UInt8, origin], length: Int) raises -> List[UInt8]:
    if length < 0:
        raise Error("negative mask length")
    var output = List[UInt8](capacity=length)
    var counter = 0
    while len(output) < length:
        var block = List[UInt8](capacity=len(seed) + 4)
        for byte in seed:
            block.append(byte)
        block.append(UInt8(counter >> 24))
        block.append(UInt8(counter >> 16))
        block.append(UInt8(counter >> 8))
        block.append(UInt8(counter))
        var digest = sha1(Span(block))
        for byte in digest:
            if len(output) == length:
                break
            output.append(byte)
        counter += 1
    return output^


def constant_time_equal[
    a_origin: Origin, b_origin: Origin
](a: Span[UInt8, a_origin], b: Span[UInt8, b_origin]) -> Bool:
    if len(a) != len(b):
        return False
    var difference = UInt8(0)
    for i in range(len(a)):
        difference |= a[i] ^ b[i]
    return difference == 0
