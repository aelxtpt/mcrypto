"""Nyberg-Rueppel signatures in prime-order finite-field groups.

Parameters use ``finite_field``'s explicit ``p,q,g`` block. Private/public keys are
``x[q_len]`` and ``y[p_len]``. Signatures use IEEE P1363 ``r[q_len] || s[q_len]``.
The representative is the IEEE P1363 ``NR(1363)/EMSA1(SHA-1)`` form.
"""

from ..math.biguint import BigUInt, FixedBaseModularPower
from ..hashes.sha1 import sha1
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


def sign[
    parameters_origin: Origin, private_origin: Origin, message_origin: Origin
](
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    """Create a randomized IEEE-P1363 NR/EMSA1(SHA-1) signature."""
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    var digest = sha1(message)
    var representative = hash_bits_to_int(Span(digest), group.q.bit_length())
    if representative.compare(group.q) >= 0:
        representative = representative.modulo(group.q)
    var k = random_scalar(group)
    var commitment = group.g.modular_power(k, group.p).modulo(group.q)
    var r = representative.modular_add(commitment, group.q)
    if r.is_zero():
        raise Error("NR produced zero r")
    var s = k.modular_subtract(x.modular_multiply(r, group.q), group.q)
    var output = to_be_fixed(r, group.q_bytes)
    var encoded_s = to_be_fixed(s, group.q_bytes)
    for byte in encoded_s:
        output.append(byte)
    return output^


def verify[
    parameters_origin: Origin,
    public_origin: Origin,
    message_origin: Origin,
    signature_origin: Origin,
](
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
    if r.is_zero() or r.compare(group.q) >= 0 or s.compare(group.q) >= 0:
        return False
    var digest = sha1(message)
    var expected = hash_bits_to_int(Span(digest), group.q.bit_length())
    if expected.compare(group.q) >= 0:
        expected = expected.modulo(group.q)
    var commitment = (
        group.g.modular_power(s, group.p)
        .modular_multiply(y.modular_power(r, group.p), group.p)
        .modulo(group.q)
    )
    return r.modular_subtract(commitment, group.q).compare(expected) == 0


struct PreparedNRVerifier(Movable):
    """Decoded NR public key with reusable exponentiation tables."""

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
        message: Span[UInt8, message_origin],
        signature: Span[UInt8, signature_origin],
    ) raises -> Bool:
        if len(signature) != 2 * self.group.q_bytes:
            return False
        var r = from_be(signature[0 : self.group.q_bytes])
        var s = from_be(signature[self.group.q_bytes :])
        if (
            r.is_zero()
            or r.compare(self.group.q) >= 0
            or s.compare(self.group.q) >= 0
        ):
            return False
        var digest = sha1(message)
        var expected = hash_bits_to_int(Span(digest), self.group.q.bit_length())
        if expected.compare(self.group.q) >= 0:
            expected = expected.modulo(self.group.q)
        var commitment = (
            self.generator_power.power(s)
            .modular_multiply(self.public_power.power(r), self.group.p)
            .modulo(self.group.q)
        )
        return (
            r.modular_subtract(commitment, self.group.q).compare(expected) == 0
        )
