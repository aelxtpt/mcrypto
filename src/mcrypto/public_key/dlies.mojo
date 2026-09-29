"""Finite-field DLIES (DHAES mode) with SHA-1 KDF2 and HMAC-SHA1.

Public key frames are ``DLI1 || 4 || p || q || g || y``; private frames are
``DLS1 || 4 || p || q || g || x``. Components use 32-bit big-endian lengths and
minimal unsigned big-endian integers. Ciphertexts are fixed-width ephemeral
``g^k`` followed by XOR-encrypted bytes and a 20-byte HMAC tag. DHAES KDF input
is ``ephemeral_public || fixed_width(shared_secret)`` and the MAC covers
``ciphertext_body || label || uint64_be(label_bits)`` as in DLIES.
"""

from ..math.biguint import BigUInt, FixedBaseModularPower
from ..hashes.sha1 import sha1
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import authenticate
from ._legacy_math import (
    encode_key,
    decode_key,
    generate_safe_prime_pair,
    random_below,
    uint_to_bytes,
    uint_from_bytes,
    append_u32,
    constant_time_equal,
)


def _magic(text: StaticString) -> List[UInt8]:
    return [
        UInt8(ord(text[byte=0])),
        UInt8(ord(text[byte=1])),
        UInt8(ord(text[byte=2])),
        UInt8(ord(text[byte=3])),
    ]


def keypair(bits: Int = 512) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate safe-prime DLIES parameters and a private exponent."""
    if bits < 128:
        raise Error("DLIES modulus must be at least 128 bits")
    var primes = generate_safe_prime_pair(bits)
    var p = primes[0].copy()
    var q = primes[1].copy()
    var g = BigUInt(2)
    while g.modular_power(q, p).compare(BigUInt(1)) != 0:
        g.add_small(1)
    var x = random_below(q.subtract(BigUInt(2))).add(BigUInt(1))
    var y = g.modular_power(x, p)
    return (
        encode_key(
            Span(_magic("DLI1")), [p.copy(), q.copy(), g.copy(), y.copy()]
        ),
        encode_key(
            Span(_magic("DLS1")), [p.copy(), q.copy(), g.copy(), x.copy()]
        ),
    )


def _kdf2[
    origin: Origin
](secret: Span[UInt8, origin], length: Int) raises -> List[UInt8]:
    if length < 0:
        raise Error("negative KDF length")
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
    for b in body:
        data.append(b)
    for b in label:
        data.append(b)
    var bits = UInt64(len(label)) * 8
    for shift in range(56, -1, -8):
        data.append(UInt8(bits >> UInt64(shift)))
    return data^


struct PreparedDLIESEncryptor(Movable):
    """Decoded DLIES public key with fixed-base exponentiation tables."""

    var p: BigUInt
    var q: BigUInt
    var width: Int
    var generator_power: FixedBaseModularPower
    var public_power: FixedBaseModularPower

    def __init__[
        origin: Origin
    ](out self, public_key: Span[UInt8, origin]) raises:
        var key = decode_key(public_key, "DLI1", 4)
        self.p = key[0].copy()
        self.q = key[1].copy()
        self.width = (self.p.bit_length() + 7) // 8
        if key[2].compare(self.p) >= 0 or key[3].compare(self.p) >= 0:
            raise Error("invalid DLIES public key")
        self.generator_power = FixedBaseModularPower(
            key[2], self.p, self.q.bit_length()
        )
        self.public_power = FixedBaseModularPower(
            key[3], self.p, self.q.bit_length()
        )

    def __init__(out self, *, deinit move: Self):
        self.p = move.p^
        self.q = move.q^
        self.width = move.width
        self.generator_power = move.generator_power^
        self.public_power = move.public_power^

    def encrypt[
        message_origin: Origin, label_origin: Origin
    ](
        self,
        message: Span[UInt8, message_origin],
        label: Span[UInt8, label_origin],
    ) raises -> List[UInt8]:
        var ephemeral = random_below(self.q.subtract(BigUInt(2))).add(
            BigUInt(1)
        )
        var u = self.generator_power.power(ephemeral)
        var shared = self.public_power.power(ephemeral)
        var ub = uint_to_bytes(u, self.width)
        var sb = uint_to_bytes(shared, self.width)
        var seed = ub.copy()
        for byte in sb:
            seed.append(byte)
        var derived = _kdf2(Span(seed), 16 + len(message))
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


def encrypt[
    key_origin: Origin, message_origin: Origin, label_origin: Origin
](
    public_key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    label: Span[UInt8, label_origin],
) raises -> List[UInt8]:
    var encryptor = PreparedDLIESEncryptor(public_key)
    return encryptor.encrypt(message, label)


def encrypt[
    key_origin: Origin, message_origin: Origin
](
    public_key: Span[UInt8, key_origin], message: Span[UInt8, message_origin]
) raises -> List[UInt8]:
    var label = List[UInt8]()
    return encrypt(public_key, message, Span(label))


struct PreparedDLIESDecryptor(Movable):
    """Decoded DLIES private key reusable across ciphertexts."""

    var p: BigUInt
    var x: BigUInt
    var width: Int

    def __init__[
        origin: Origin
    ](out self, private_key: Span[UInt8, origin]) raises:
        var key = decode_key(private_key, "DLS1", 4)
        self.p = key[0].copy()
        self.x = key[3].copy()
        self.width = (self.p.bit_length() + 7) // 8

    def __init__(out self, *, deinit move: Self):
        self.p = move.p^
        self.x = move.x^
        self.width = move.width

    def decrypt[
        cipher_origin: Origin, label_origin: Origin
    ](
        self,
        ciphertext: Span[UInt8, cipher_origin],
        label: Span[UInt8, label_origin],
    ) raises -> List[UInt8]:
        if len(ciphertext) < self.width + 20:
            raise Error("truncated DLIES ciphertext")
        var u = uint_from_bytes(ciphertext[0 : self.width])
        if (
            u.compare(BigUInt(2)) < 0
            or u.compare(self.p.subtract(BigUInt(1))) >= 0
        ):
            raise Error("invalid DLIES ephemeral public key")
        var shared = u.modular_power(self.x, self.p)
        var sb = uint_to_bytes(shared, self.width)
        var seed = List[UInt8](capacity=2 * self.width)
        for i in range(self.width):
            seed.append(ciphertext[i])
        for byte in sb:
            seed.append(byte)
        var body_len = len(ciphertext) - self.width - 20
        var derived = _kdf2(Span(seed), 16 + body_len)
        var authenticated = _mac_input(
            ciphertext[self.width : self.width + body_len], label
        )
        var expected = authenticate(
            HmacAlgorithm.SHA1, Span(derived)[0:16], Span(authenticated)
        )
        if not constant_time_equal(
            Span(expected), ciphertext[self.width + body_len :]
        ):
            raise Error("DLIES authentication failed")
        var output = List[UInt8](capacity=body_len)
        for i in range(body_len):
            output.append(ciphertext[self.width + i] ^ derived[16 + i])
        return output^


def decrypt[
    key_origin: Origin, cipher_origin: Origin, label_origin: Origin
](
    private_key: Span[UInt8, key_origin],
    ciphertext: Span[UInt8, cipher_origin],
    label: Span[UInt8, label_origin],
) raises -> List[UInt8]:
    var decryptor = PreparedDLIESDecryptor(private_key)
    return decryptor.decrypt(ciphertext, label)


def decrypt[
    key_origin: Origin, cipher_origin: Origin
](
    private_key: Span[UInt8, key_origin], ciphertext: Span[UInt8, cipher_origin]
) raises -> List[UInt8]:
    var label = List[UInt8]()
    return decrypt(private_key, ciphertext, Span(label))
