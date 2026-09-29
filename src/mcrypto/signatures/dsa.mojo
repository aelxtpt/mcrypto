"""DSA over prime-order finite-field groups, including RFC 6979 nonces.

Parameters use ``finite_field``'s length-prefixed ``p,q,g`` block.  A private key is
``q_len``-byte big-endian ``x`` and a public key is ``p_len``-byte big-endian ``g^x``.
Signatures use IEEE P1363 ``r[q_len] || s[q_len]``.  SHA-1, SHA-224 and SHA-256
are supported so that RFC 6979 and legacy DSA vectors retain their exact format.
"""

from ..hashes.algorithm import HashAlgorithm
from ..macs.algorithm import HmacAlgorithm
from ..math.biguint import BigUInt, FixedBaseModularPower
from ..hashes.sha1 import sha1
from ..hashes.sha256 import sha224, sha256
from ..macs.hmac import authenticate
from .finite_field import (
    PrimeGroup,
    decode_parameters,
    decode_private,
    decode_public,
    from_be,
    generate_keypair as _generate_keypair,
    hash_bits_to_int,
    random_scalar,
    to_be_fixed,
)


def _digest[
    origin: Origin
](hash_algorithm: HashAlgorithm, message: Span[UInt8, origin]) raises -> List[
    UInt8
]:
    if hash_algorithm == HashAlgorithm.SHA1:
        return sha1(message)
    if hash_algorithm == HashAlgorithm.SHA224:
        return sha224(message)
    if hash_algorithm == HashAlgorithm.SHA256:
        return sha256(message)
    raise Error("DSA supports SHA-1, SHA-224, and SHA-256")


def _hmac[
    key_origin: Origin, data_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    key: Span[UInt8, key_origin],
    data: Span[UInt8, data_origin],
) raises -> List[UInt8]:
    if hash_algorithm == HashAlgorithm.SHA1:
        return authenticate(HmacAlgorithm.SHA1, key, data)
    if hash_algorithm == HashAlgorithm.SHA256:
        return authenticate(HmacAlgorithm.SHA256, key, data)
    if hash_algorithm != HashAlgorithm.SHA224:
        raise Error("unsupported RFC 6979 hash")
    var normalized = List[UInt8](length=64, fill=0)
    if len(key) > 64:
        var shortened = sha224(key)
        for i in range(28):
            normalized[i] = shortened[i]
    else:
        for i in range(len(key)):
            normalized[i] = key[i]
    var inner = List[UInt8](capacity=64 + len(data))
    var outer = List[UInt8](capacity=92)
    for byte in normalized:
        inner.append(byte ^ 0x36)
        outer.append(byte ^ 0x5C)
    for byte in data:
        inner.append(byte)
    var digest = sha224(Span(inner))
    for byte in digest:
        outer.append(byte)
    return sha224(Span(outer))


def generate_keypair[
    origin: Origin
](parameters: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Return ``(private_x[q_len], public_y[p_len])`` for a parameter block."""
    return _generate_keypair(parameters)


def public_key[
    parameters_origin: Origin, private_origin: Origin
](
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
) raises -> List[UInt8]:
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    return to_be_fixed(group.g.modular_power(x, group.p), group.p_bytes)


def _bits2octets[
    origin: Origin
](digest: Span[UInt8, origin], group: PrimeGroup) raises -> List[UInt8]:
    var value = hash_bits_to_int(digest, group.q.bit_length()).modulo(group.q)
    return to_be_fixed(value, group.q_bytes)


def deterministic_nonce[
    digest_origin: Origin, private_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, digest_origin],
    private_key: Span[UInt8, private_origin],
    group: PrimeGroup,
) raises -> BigUInt:
    """Generate the RFC 6979 nonce for an already-computed message digest."""
    var x = decode_private(private_key, group)
    var x_octets = to_be_fixed(x, group.q_bytes)
    var h_octets = _bits2octets(digest, group)
    var output_len = 20 if hash_algorithm == HashAlgorithm.SHA1 else (
        28 if hash_algorithm == HashAlgorithm.SHA224 else 32
    )
    if (
        hash_algorithm != HashAlgorithm.SHA1
        and hash_algorithm != HashAlgorithm.SHA224
        and hash_algorithm != HashAlgorithm.SHA256
    ):
        raise Error("unsupported RFC 6979 hash")
    var k = List[UInt8](length=output_len, fill=0)
    var v = List[UInt8](length=output_len, fill=1)
    var seed = List[UInt8](capacity=output_len + 1 + 2 * group.q_bytes)
    for byte in v:
        seed.append(byte)
    seed.append(0)
    for byte in x_octets:
        seed.append(byte)
    for byte in h_octets:
        seed.append(byte)
    k = _hmac(hash_algorithm, Span(k), Span(seed))
    v = _hmac(hash_algorithm, Span(k), Span(v))
    seed.clear()
    for byte in v:
        seed.append(byte)
    seed.append(1)
    for byte in x_octets:
        seed.append(byte)
    for byte in h_octets:
        seed.append(byte)
    k = _hmac(hash_algorithm, Span(k), Span(seed))
    v = _hmac(hash_algorithm, Span(k), Span(v))
    while True:
        var t = List[UInt8](capacity=group.q_bytes)
        while len(t) < group.q_bytes:
            v = _hmac(hash_algorithm, Span(k), Span(v))
            for byte in v:
                t.append(byte)
        var candidate = hash_bits_to_int(Span(t), group.q.bit_length())
        if not candidate.is_zero() and candidate.compare(group.q) < 0:
            return candidate^
        seed.clear()
        for byte in v:
            seed.append(byte)
        seed.append(0)
        k = _hmac(hash_algorithm, Span(k), Span(seed))
        v = _hmac(hash_algorithm, Span(k), Span(v))


def _sign_with_nonce(
    group: PrimeGroup, x: BigUInt, z: BigUInt, nonce: BigUInt
) raises -> List[UInt8]:
    if nonce.is_zero() or nonce.compare(group.q) >= 0:
        raise Error("DSA nonce is out of range")
    var r = group.g.modular_power(nonce, group.p).modulo(group.q)
    if r.is_zero():
        raise Error("DSA produced zero r")
    var s = nonce.modular_inverse(group.q).modular_multiply(
        z.modular_add(x.modular_multiply(r, group.q), group.q),
        group.q,
    )
    if s.is_zero():
        raise Error("DSA produced zero s")
    var output = to_be_fixed(r, group.q_bytes)
    var encoded_s = to_be_fixed(s, group.q_bytes)
    for byte in encoded_s:
        output.append(byte)
    return output^


def sign[
    parameters_origin: Origin, private_origin: Origin, message_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    """Create a deterministic RFC 6979 IEEE-P1363 DSA signature."""
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    var digest = _digest(hash_algorithm, message)
    var z = hash_bits_to_int(Span(digest), group.q.bit_length())
    var nonce = deterministic_nonce(
        hash_algorithm, Span(digest), private_key, group
    )
    return _sign_with_nonce(group, x, z, nonce)


def sign_random[
    parameters_origin: Origin, private_origin: Origin, message_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    """Create a randomized IEEE-P1363 DSA signature."""
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    var digest = _digest(hash_algorithm, message)
    return _sign_with_nonce(
        group,
        x,
        hash_bits_to_int(Span(digest), group.q.bit_length()),
        random_scalar(group),
    )


def verify[
    parameters_origin: Origin,
    public_origin: Origin,
    message_origin: Origin,
    signature_origin: Origin,
](
    hash_algorithm: HashAlgorithm,
    parameters: Span[UInt8, parameters_origin],
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    var group = decode_parameters(parameters)
    var y = decode_public(public_key, group)
    if len(signature) != 2 * group.q_bytes:
        return False
    var r_bytes = List[UInt8](capacity=group.q_bytes)
    var s_bytes = List[UInt8](capacity=group.q_bytes)
    for i in range(group.q_bytes):
        r_bytes.append(signature[i])
        s_bytes.append(signature[group.q_bytes + i])
    var r = from_be(Span(r_bytes))
    var s = from_be(Span(s_bytes))
    if (
        r.is_zero()
        or s.is_zero()
        or r.compare(group.q) >= 0
        or s.compare(group.q) >= 0
    ):
        return False
    var digest = _digest(hash_algorithm, message)
    var z = hash_bits_to_int(Span(digest), group.q.bit_length())
    var w = s.modular_inverse(group.q)
    var u1 = z.modular_multiply(w, group.q)
    var u2 = r.modular_multiply(w, group.q)
    var value = (
        group.g.modular_power(u1, group.p)
        .modular_multiply(y.modular_power(u2, group.p), group.p)
        .modulo(group.q)
    )
    return value.compare(r) == 0


struct PreparedDSAVerifier(Movable):
    """Decoded DSA public key with reusable exponentiation tables."""

    var group: PrimeGroup
    var y: BigUInt
    var generator_power: FixedBaseModularPower
    var public_power: FixedBaseModularPower

    def __init__[
        parameters_origin: Origin, public_origin: Origin
    ](
        out self,
        parameters: Span[UInt8, parameters_origin],
        public_key: Span[UInt8, public_origin],
    ) raises:
        self.group = decode_parameters(parameters)
        self.y = decode_public(public_key, self.group)
        self.generator_power = FixedBaseModularPower(
            self.group.g, self.group.p, self.group.q.bit_length()
        )
        self.public_power = FixedBaseModularPower(
            self.y, self.group.p, self.group.q.bit_length()
        )

    def __init__(out self, *, deinit move: Self):
        self.group = move.group^
        self.y = move.y^
        self.generator_power = move.generator_power^
        self.public_power = move.public_power^

    def verify[
        message_origin: Origin, signature_origin: Origin
    ](
        self,
        hash_algorithm: HashAlgorithm,
        message: Span[UInt8, message_origin],
        signature: Span[UInt8, signature_origin],
    ) raises -> Bool:
        if len(signature) != 2 * self.group.q_bytes:
            return False
        var r = from_be(signature[0 : self.group.q_bytes])
        var s = from_be(signature[self.group.q_bytes :])
        if (
            r.is_zero()
            or s.is_zero()
            or r.compare(self.group.q) >= 0
            or s.compare(self.group.q) >= 0
        ):
            return False
        var digest = _digest(hash_algorithm, message)
        var z = hash_bits_to_int(Span(digest), self.group.q.bit_length())
        var w = s.modular_inverse(self.group.q)
        var u1 = z.modular_multiply(w, self.group.q)
        var u2 = r.modular_multiply(w, self.group.q)
        var value = (
            self.generator_power.power(u1)
            .modular_multiply(self.public_power.power(u2), self.group.p)
            .modulo(self.group.q)
        )
        return value.compare(r) == 0
