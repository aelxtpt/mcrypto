"""LUC trapdoor permutation and LUCELG (LUC-IES) in pure Mojo.

LUC public/private frames are ``LUC1`` with ``n,e`` and ``LUS1`` with
``n,e,p,q,q^-1 mod p``. LUC-IES frames are ``LUE1``/``LUX1`` with
``p,q,g,y|x``. Components are count-prefixed minimal unsigned big-endian
integers (32-bit big-endian lengths). LUC-IES ciphertexts are fixed-width
ephemeral Lucas elements followed by an XOR body and a 20-byte HMAC-SHA1 tag.
"""

from ..math.biguint import (
    BigUInt,
    FixedBaseLucasPower,
    FixedExponentLucasPower,
)
from ..hashes.sha1 import sha1
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import authenticate
from ._legacy_math import (
    encode_key,
    decode_key,
    generate_prime,
    generate_safe_prime_pair,
    inverse,
    is_probable_prime,
    jacobi,
    random_below,
    uint_from_bytes,
    uint_to_bytes,
    quotient,
    constant_time_equal,
    append_u32,
)


def _magic(text: StaticString) -> List[UInt8]:
    return [
        UInt8(ord(text[byte=0])),
        UInt8(ord(text[byte=1])),
        UInt8(ord(text[byte=2])),
        UInt8(ord(text[byte=3])),
    ]


def lucas(
    exponent: BigUInt, parameter: BigUInt, modulus: BigUInt
) raises -> BigUInt:
    return parameter.modular_lucas(exponent, modulus)


def _in_lucas_q_subgroup(value: BigUInt, modulus: BigUInt) -> Bool:
    if value.compare(BigUInt(2)) == 0 or value.compare(modulus) >= 0:
        return False
    try:
        return value.add(BigUInt(2)).jacobi_symbol(modulus) == 1
    except:
        return False


def _inverse_exponent(e: BigUInt, modulus: BigUInt) raises -> BigUInt:
    if len(e.limbs) != 1 or e.limbs[0] < 2:
        raise Error("unsupported LUC exponent")
    for coefficient in range(Int(e.limbs[0])):
        var numerator = modulus.multiply(BigUInt(UInt64(coefficient))).add(
            BigUInt(1)
        )
        if numerator.modulo(e).is_zero():
            return quotient(numerator, e)
    raise Error("LUC exponent is not relatively prime to group order")


def keypair(
    bits: Int = 512, public_exponent: UInt64 = 17
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if bits < 128 or public_exponent < 5 or public_exponent % 2 == 0:
        raise Error("invalid LUC key parameters")
    var e = BigUInt(public_exponent)
    var p: BigUInt
    var q: BigUInt
    while True:
        p = generate_prime(bits // 2)
        try:
            _ = _inverse_exponent(e, p.subtract(BigUInt(1)))
            _ = _inverse_exponent(e, p.add(BigUInt(1)))
            break
        except:
            pass
    while True:
        q = generate_prime(bits - bits // 2)
        if q.compare(p) == 0:
            continue
        try:
            _ = _inverse_exponent(e, q.subtract(BigUInt(1)))
            _ = _inverse_exponent(e, q.add(BigUInt(1)))
            break
        except:
            pass
    var n = p.multiply(q)
    var u = inverse(q, p)
    return (
        encode_key(Span(_magic("LUC1")), [n.copy(), e.copy()]),
        encode_key(
            Span(_magic("LUS1")),
            [n.copy(), e.copy(), p.copy(), q.copy(), u.copy()],
        ),
    )


def apply_decoded[
    input_origin: Origin
](
    modulus: BigUInt,
    exponent: BigUInt,
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    """Apply the LUC public permutation after caller-owned key validation."""
    var value = uint_from_bytes(input)
    if value.compare(modulus) >= 0:
        raise Error("LUC input outside modulus")
    return uint_to_bytes(
        lucas(exponent, value, modulus), (modulus.bit_length() + 7) // 8
    )


def apply[
    key_origin: Origin, input_origin: Origin
](
    public_key: Span[UInt8, key_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    var k = decode_key(public_key, "LUC1", 2)
    return apply_decoded(k[0], k[1], input)


def _crt(
    ap: BigUInt, p: BigUInt, aq: BigUInt, q: BigUInt, u: BigUInt
) raises -> BigUInt:
    return aq.add(
        q.multiply(ap.modular_subtract(aq.modulo(p), p).modular_multiply(u, p))
    )


def invert[
    key_origin: Origin, input_origin: Origin
](
    private_key: Span[UInt8, key_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    var k = decode_key(private_key, "LUS1", 5)
    var n = k[0].copy()
    var e = k[1].copy()
    var p = k[2].copy()
    var q = k[3].copy()
    var u = k[4].copy()
    var m = uint_from_bytes(input)
    if m.compare(n) >= 0:
        raise Error("LUC image outside modulus")
    var four = BigUInt(4)
    var d = m.modular_multiply(m, n).modular_subtract(four, n)
    var jp = jacobi(d, p)
    var jq = jacobi(d, q)
    var orderp = p.subtract(BigUInt(1)) if jp == 1 else p.add(BigUInt(1))
    var orderq = q.subtract(BigUInt(1)) if jq == 1 else q.add(BigUInt(1))
    var ep = _inverse_exponent(e, orderp)
    var eq = _inverse_exponent(e, orderq)
    var xp = lucas(ep, m, p)
    var xq = lucas(eq, m, q)
    var x = _crt(xp, p, xq, q, u)
    return uint_to_bytes(x, (n.bit_length() + 7) // 8)


def lucelg_keypair(bits: Int = 512) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate a LUC-IES safe-prime Lucas subgroup."""
    if bits < 128:
        raise Error("LUCELG modulus must be at least 128 bits")
    var primes = generate_safe_prime_pair(bits, -1)
    var p = primes[0].copy()
    var q = primes[1].copy()
    var g = BigUInt(3)
    while g.compare(p) >= 0 or not _in_lucas_q_subgroup(g, p):
        g.add_small(1)
    var x = random_below(q.subtract(BigUInt(2))).add(BigUInt(1))
    var y = lucas(x, g, p)
    return (
        encode_key(
            Span(_magic("LUE1")), [p.copy(), q.copy(), g.copy(), y.copy()]
        ),
        encode_key(
            Span(_magic("LUX1")), [p.copy(), q.copy(), g.copy(), x.copy()]
        ),
    )


def _kdf[
    origin: Origin
](secret: Span[UInt8, origin], length: Int) raises -> List[UInt8]:
    var output = List[UInt8](capacity=length)
    var counter = 1
    while len(output) < length:
        var block = List[UInt8](capacity=len(secret) + 4)
        for b in secret:
            block.append(b)
        append_u32(block, counter)
        var digest = sha1(Span(block))
        for b in digest:
            if len(output) == length:
                break
            output.append(b)
        counter += 1
    return output^


def _mac_input[
    body_origin: Origin, label_origin: Origin
](body: Span[UInt8, body_origin], label: Span[UInt8, label_origin]) -> List[
    UInt8
]:
    var data = List[UInt8](capacity=len(body) + len(label) + 8)
    for byte in body:
        data.append(byte)
    for byte in label:
        data.append(byte)
    var label_bits = UInt64(len(label)) * 8
    for shift in range(56, -1, -8):
        data.append(UInt8(label_bits >> UInt64(shift)))
    return data^


struct LUCELGEncryptor(Movable):
    """Decoded and validated LUC-IES public key reusable across messages."""

    var p: BigUInt
    var q: BigUInt
    var g: BigUInt
    var y: BigUInt
    var width: Int
    var generator_power: FixedBaseLucasPower
    var public_power: FixedBaseLucasPower

    def __init__[
        origin: Origin
    ](out self, public_key: Span[UInt8, origin]) raises:
        var key = decode_key(public_key, "LUE1", 4)
        self.p = key[0].copy()
        self.q = key[1].copy()
        self.g = key[2].copy()
        self.y = key[3].copy()
        self.width = (self.p.bit_length() + 7) // 8
        if (
            self.p.add(BigUInt(1)).compare(self.q.add(self.q)) != 0
            or not _in_lucas_q_subgroup(self.g, self.p)
            or not _in_lucas_q_subgroup(self.y, self.p)
        ):
            raise Error("invalid LUC-IES public key")
        self.generator_power = FixedBaseLucasPower(
            self.g, self.p, self.q.bit_length()
        )
        self.public_power = FixedBaseLucasPower(
            self.y, self.p, self.q.bit_length()
        )

    def __init__(out self, *, deinit move: Self):
        self.p = move.p^
        self.q = move.q^
        self.g = move.g^
        self.y = move.y^
        self.width = move.width
        self.generator_power = move.generator_power^
        self.public_power = move.public_power^

    def encrypt[
        message_origin: Origin, label_origin: Origin
    ](
        mut self,
        message: Span[UInt8, message_origin],
        label: Span[UInt8, label_origin],
    ) raises -> List[UInt8]:
        var ephemeral = random_below(self.q.subtract(BigUInt(2))).add(
            BigUInt(1)
        )
        var u = self.generator_power.power_reusing(ephemeral)
        var shared = self.public_power.power_reusing(ephemeral)
        var ub = uint_to_bytes(u, self.width)
        var sb = uint_to_bytes(shared, self.width)
        var seed = ub.copy()
        for byte in sb:
            seed.append(byte)
        var derived = _kdf(Span(seed), 16 + len(message))
        var body = List[UInt8](capacity=len(message))
        for i in range(len(message)):
            body.append(message[i] ^ derived[16 + i])
        var authenticated = _mac_input(Span(body), label)
        var tag = authenticate(
            HmacAlgorithm.SHA1, Span(derived)[0:16], Span(authenticated)
        )
        var output = ub^
        for byte in body:
            output.append(byte)
        for byte in tag:
            output.append(byte)
        return output^


struct LUCELGDecryptor(Movable):
    """Decoded LUC-IES private key reusable across ciphertexts."""

    var p: BigUInt
    var q: BigUInt
    var x: BigUInt
    var width: Int
    var shared_power: FixedExponentLucasPower

    def __init__[
        origin: Origin
    ](out self, private_key: Span[UInt8, origin]) raises:
        var key = decode_key(private_key, "LUX1", 4)
        self.p = key[0].copy()
        self.q = key[1].copy()
        self.x = key[3].copy()
        self.width = (self.p.bit_length() + 7) // 8
        if self.p.add(BigUInt(1)).compare(self.q.add(self.q)) != 0:
            raise Error("invalid LUC-IES private key")
        self.shared_power = FixedExponentLucasPower(self.x, self.p)

    def __init__(out self, *, deinit move: Self):
        self.p = move.p^
        self.q = move.q^
        self.x = move.x^
        self.width = move.width
        self.shared_power = move.shared_power^

    def decrypt[
        cipher_origin: Origin, label_origin: Origin
    ](
        mut self,
        ciphertext: Span[UInt8, cipher_origin],
        label: Span[UInt8, label_origin],
    ) raises -> List[UInt8]:
        if len(ciphertext) < self.width + 20:
            raise Error("truncated LUC-IES ciphertext")
        var u = uint_from_bytes(ciphertext[0 : self.width])
        if not _in_lucas_q_subgroup(u, self.p):
            raise Error("invalid LUC-IES ephemeral public key")
        var shared = self.shared_power.power(u)
        var sb = uint_to_bytes(shared, self.width)
        var seed = List[UInt8](capacity=2 * self.width)
        for i in range(self.width):
            seed.append(ciphertext[i])
        for byte in sb:
            seed.append(byte)
        var body_len = len(ciphertext) - self.width - 20
        var derived = _kdf(Span(seed), 16 + body_len)
        var authenticated = _mac_input(
            ciphertext[self.width : self.width + body_len], label
        )
        var expected = authenticate(
            HmacAlgorithm.SHA1, Span(derived)[0:16], Span(authenticated)
        )
        if not constant_time_equal(
            Span(expected), ciphertext[self.width + body_len :]
        ):
            raise Error("LUC-IES authentication failed")
        var output = List[UInt8](capacity=body_len)
        for i in range(body_len):
            output.append(ciphertext[self.width + i] ^ derived[16 + i])
        return output^


def lucelg_encrypt[
    key_origin: Origin, message_origin: Origin, label_origin: Origin
](
    public_key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    label: Span[UInt8, label_origin],
) raises -> List[UInt8]:
    var encryptor = LUCELGEncryptor(public_key)
    return encryptor.encrypt(message, label)


def lucelg_encrypt[
    key_origin: Origin, message_origin: Origin
](
    public_key: Span[UInt8, key_origin], message: Span[UInt8, message_origin]
) raises -> List[UInt8]:
    var label = List[UInt8]()
    return lucelg_encrypt(public_key, message, Span(label))


def lucelg_decrypt[
    key_origin: Origin, cipher_origin: Origin, label_origin: Origin
](
    private_key: Span[UInt8, key_origin],
    ciphertext: Span[UInt8, cipher_origin],
    label: Span[UInt8, label_origin],
) raises -> List[UInt8]:
    var decryptor = LUCELGDecryptor(private_key)
    return decryptor.decrypt(ciphertext, label)


def lucelg_decrypt[
    key_origin: Origin, cipher_origin: Origin
](
    private_key: Span[UInt8, key_origin],
    ciphertext: Span[UInt8, cipher_origin],
) raises -> List[UInt8]:
    var label = List[UInt8]()
    return lucelg_decrypt(private_key, ciphertext, Span(label))
