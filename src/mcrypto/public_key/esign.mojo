"""IEEE P1363a ESIGN with EMSA5-MGF1(SHA-1), implemented in pure Mojo.

Public keys are ``ESG1 || 2 || len(n)||n || len(e)||e`` and private keys are
``ESS1 || 4`` followed by ``n,e,p,q``. Lengths are unsigned 32-bit big-endian;
integers and fixed-width signatures are unsigned big-endian. ``n = p^2*q``.
"""

from ..math.biguint import BigUInt
from ..hashes.sha1 import sha1
from ._legacy_math import (
    encode_key,
    decode_key,
    generate_prime,
    random_below,
    uint_to_bytes,
    uint_from_bytes,
    quotient,
    mgf1_sha1,
    constant_time_equal,
)


def _magic(text: StaticString) -> List[UInt8]:
    return [
        UInt8(ord(text[byte=0])),
        UInt8(ord(text[byte=1])),
        UInt8(ord(text[byte=2])),
        UInt8(ord(text[byte=3])),
    ]


def _power2(bits: Int) -> BigUInt:
    var value = BigUInt(1)
    for _ in range(bits):
        value.shift_left_one()
    return value^


def _shift_left(value: BigUInt, bits: Int) -> BigUInt:
    var result = value.copy()
    for _ in range(bits):
        result.shift_left_one()
    return result^


def keypair(
    bits: Int = 384, public_exponent: UInt64 = 32
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate ESIGN primes. The modulus size must be divisible by three."""
    if bits < 192 or bits % 3 != 0 or public_exponent < 8:
        raise Error("invalid ESIGN parameters")
    var prime_bits = bits // 3
    var lower_p = _power2(prime_bits - 2).multiply(BigUInt(3))
    var p = generate_prime(prime_bits)
    while p.compare(lower_p) < 0:
        p = generate_prime(prime_bits)
    var p_squared = p.multiply(p)
    var q: BigUInt
    var n: BigUInt
    while True:
        q = generate_prime(prime_bits)
        if p.compare(q) == 0:
            continue
        n = p_squared.multiply(q)
        if n.bit_length() == bits:
            break
    var e = BigUInt(public_exponent)
    return (
        encode_key(Span(_magic("ESG1")), [n.copy(), e.copy()]),
        encode_key(
            Span(_magic("ESS1")), [n.copy(), e.copy(), p.copy(), q.copy()]
        ),
    )


def representative[
    origin: Origin
](message: Span[UInt8, origin], bits: Int) raises -> BigUInt:
    """EMSA5 representative: MGF1-SHA1(Hash(message)) cropped to ``bits``."""
    if bits <= 0:
        raise Error("invalid ESIGN representative size")
    var digest = sha1(message)
    var mask = mgf1_sha1(Span(digest), (bits + 7) // 8)
    if bits % 8 != 0:
        mask[0] &= UInt8(0xFF >> (8 - bits % 8))
    from ._legacy_math import uint_from_bytes

    return uint_from_bytes(Span(mask))


def _apply_decoded[
    signature_origin: Origin
](
    n: BigUInt,
    e: BigUInt,
    signature: Span[UInt8, signature_origin],
) raises -> BigUInt:
    var value = uint_from_bytes(signature)
    if value.compare(n) >= 0:
        raise Error("ESIGN signature outside modulus")
    var k = max(0, n.bit_length() // 3 - 1)
    var powered = value.modular_power(e, n)
    var image = quotient(powered, _power2(2 * k + 2))
    var maximum = _power2(k).subtract(BigUInt(1))
    if image.compare(maximum) < 0:
        return image^
    return maximum^


def apply[
    key_origin: Origin, signature_origin: Origin
](
    public_key: Span[UInt8, key_origin],
    signature: Span[UInt8, signature_origin],
) raises -> BigUInt:
    var key = decode_key(public_key, "ESG1", 2)
    return _apply_decoded(key[0], key[1], signature)


def _sign_decoded[
    message_origin: Origin
](
    n: BigUInt,
    e: BigUInt,
    p: BigUInt,
    inverse_exponent: BigUInt,
    pq: BigUInt,
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    var k = max(0, n.bit_length() // 3 - 1)
    var x = representative(message, k)
    var z = _shift_left(x, 2 * k + 2)
    var r: BigUInt
    var re: BigUInt
    var w0: BigUInt
    while True:
        r = random_below(pq)
        if r.modulo(p).is_zero():
            continue
        re = r.modular_power(e, n)
        var a = z.modular_subtract(re, n)
        w0 = quotient(a, pq)
        var remainder = a.modulo(pq)
        var distance = BigUInt()
        if not remainder.is_zero():
            w0.add_small(1)
            distance = pq.subtract(remainder)
        if distance.bit_length() <= 2 * k + 1:
            break
    var numerator = w0.modular_multiply(r, p)
    var denominator = e.modular_multiply(re, p)
    var t = numerator.modular_multiply(
        denominator.modular_power(inverse_exponent, p), p
    )
    var signature = r.add(t.multiply(pq))
    if signature.compare(n) >= 0:
        raise Error("ESIGN inverse produced out-of-range value")
    return uint_to_bytes(signature, (n.bit_length() + 7) // 8)


def sign[
    key_origin: Origin, message_origin: Origin
](
    private_key: Span[UInt8, key_origin], message: Span[UInt8, message_origin]
) raises -> List[UInt8]:
    var key = decode_key(private_key, "ESS1", 4)
    if key[2].multiply(key[2]).multiply(key[3]).compare(key[0]) != 0:
        raise Error("inconsistent ESIGN private key")
    return _sign_decoded(
        key[0],
        key[1],
        key[2],
        key[2].subtract(BigUInt(2)),
        key[2].multiply(key[3]),
        message,
    )


def _verify_decoded[
    message_origin: Origin, signature_origin: Origin
](
    n: BigUInt,
    e: BigUInt,
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    var width = (n.bit_length() + 7) // 8
    if len(signature) != width:
        return False
    var value = uint_from_bytes(signature)
    if value.compare(n) >= 0:
        return False
    var got = _apply_decoded(n, e, signature)
    var expected = representative(message, max(0, n.bit_length() // 3 - 1))
    return got.compare(expected) == 0


def verify[
    key_origin: Origin, message_origin: Origin, signature_origin: Origin
](
    public_key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    var key = decode_key(public_key, "ESG1", 2)
    return _verify_decoded(key[0], key[1], message, signature)


struct PreparedESIGNSigner(Movable):
    """Decoded and validated ESIGN private key for repeated signing."""

    var n: BigUInt
    var e: BigUInt
    var p: BigUInt
    var pq: BigUInt
    var inverse_exponent: BigUInt

    def __init__[
        origin: Origin
    ](out self, private_key: Span[UInt8, origin]) raises:
        var key = decode_key(private_key, "ESS1", 4)
        if key[2].multiply(key[2]).multiply(key[3]).compare(key[0]) != 0:
            raise Error("inconsistent ESIGN private key")
        self.n = key[0].copy()
        self.e = key[1].copy()
        self.p = key[2].copy()
        self.pq = key[2].multiply(key[3])
        self.inverse_exponent = self.p.subtract(BigUInt(2))

    def __init__(out self, *, deinit move: Self):
        self.n = move.n^
        self.e = move.e^
        self.p = move.p^
        self.pq = move.pq^
        self.inverse_exponent = move.inverse_exponent^

    def sign[
        origin: Origin
    ](self, message: Span[UInt8, origin]) raises -> List[UInt8]:
        return _sign_decoded(
            self.n,
            self.e,
            self.p,
            self.inverse_exponent,
            self.pq,
            message,
        )

    def sign_repeated[
        origin: Origin
    ](self, message: Span[UInt8, origin], count: Int) raises -> List[
        List[UInt8]
    ]:
        """Create independent randomized signatures with one batch inversion."""
        if count <= 0:
            raise Error("ESIGN signature count must be positive")
        var k = max(0, self.n.bit_length() // 3 - 1)
        var x = representative(message, k)
        var z = _shift_left(x, 2 * k + 2)
        var randoms = List[BigUInt](capacity=count)
        var numerators = List[BigUInt](capacity=count)
        var denominators = List[BigUInt](capacity=count)
        var prefixes = List[BigUInt](capacity=count)
        var product = BigUInt(1)
        for _ in range(count):
            var r: BigUInt
            var re: BigUInt
            var w0: BigUInt
            while True:
                r = random_below(self.pq)
                if r.modulo(self.p).is_zero():
                    continue
                re = r.modular_power(self.e, self.n)
                var a = z.modular_subtract(re, self.n)
                w0 = quotient(a, self.pq)
                var remainder = a.modulo(self.pq)
                var distance = BigUInt()
                if not remainder.is_zero():
                    w0.add_small(1)
                    distance = self.pq.subtract(remainder)
                if distance.bit_length() <= 2 * k + 1:
                    break
            var numerator = w0.modular_multiply(r, self.p)
            var denominator = self.e.modular_multiply(re, self.p)
            prefixes.append(product.copy())
            product = product.modular_multiply(denominator, self.p)
            randoms.append(r^)
            numerators.append(numerator^)
            denominators.append(denominator^)
        var product_inverse = product.modular_power(
            self.inverse_exponent, self.p
        )
        var output = List[List[UInt8]](capacity=count)
        var width = (self.n.bit_length() + 7) // 8
        for i in range(count - 1, -1, -1):
            var denominator_inverse = product_inverse.modular_multiply(
                prefixes[i], self.p
            )
            product_inverse = product_inverse.modular_multiply(
                denominators[i], self.p
            )
            var t = numerators[i].modular_multiply(denominator_inverse, self.p)
            var signature = randoms[i].add(t.multiply(self.pq))
            if signature.compare(self.n) >= 0:
                raise Error("ESIGN inverse produced out-of-range value")
            output.append(uint_to_bytes(signature, width))
        return output^


struct PreparedESIGNVerifier(Movable):
    """Decoded ESIGN public key for repeated verification."""

    var n: BigUInt
    var e: BigUInt
    var k: Int
    var width: Int
    var divisor: BigUInt
    var maximum: BigUInt

    def __init__[
        origin: Origin
    ](out self, public_key: Span[UInt8, origin]) raises:
        var key = decode_key(public_key, "ESG1", 2)
        self.n = key[0].copy()
        self.e = key[1].copy()
        self.k = max(0, self.n.bit_length() // 3 - 1)
        self.width = (self.n.bit_length() + 7) // 8
        self.divisor = _power2(2 * self.k + 2)
        self.maximum = _power2(self.k).subtract(BigUInt(1))

    def __init__(out self, *, deinit move: Self):
        self.n = move.n^
        self.e = move.e^
        self.k = move.k
        self.width = move.width
        self.divisor = move.divisor^
        self.maximum = move.maximum^

    def verify[
        message_origin: Origin, signature_origin: Origin
    ](
        self,
        message: Span[UInt8, message_origin],
        signature: Span[UInt8, signature_origin],
    ) raises -> Bool:
        if len(signature) != self.width:
            return False
        var value = uint_from_bytes(signature)
        if value.compare(self.n) >= 0:
            return False
        var powered = value.modular_power(self.e, self.n)
        var image = quotient(powered, self.divisor)
        var expected = representative(message, self.k)
        if image.compare(self.maximum) >= 0:
            return self.maximum.compare(expected) == 0
        return image.compare(expected) == 0
