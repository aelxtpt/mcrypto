"""Finite-field DH, unified DH2, MQV, HMQV and FHMQV over RFC 3526 group 14."""

from ..math.biguint import BigUInt
from ..hashes.sha512 import sha512
from ._common import (
    from_be,
    to_be,
    parse_hex,
    append_bytes,
)
from .algorithm import AgreementAlgorithm

comptime KEY_BYTES = 256


struct DHGroup(Copyable, Movable):
    """Safe-prime group parameters; p, q and g are mathematical integers."""

    var p: BigUInt
    var q: BigUInt
    var g: BigUInt
    var bytes: Int

    def __init__(
        out self,
        p: BigUInt,
        q: BigUInt,
        g: BigUInt,
        bytes: Int,
        *,
        trusted: Bool = False,
    ) raises:
        if bytes <= 0:
            raise Error("invalid finite-field group")
        if not trusted:
            if p.compare(BigUInt(5)) < 0 or q.compare(BigUInt(2)) < 0:
                raise Error("invalid finite-field group")
            if q.multiply(BigUInt(2)).add(BigUInt(1)).compare(p) != 0:
                raise Error("group must use p = 2q + 1")
            if (
                g.compare(BigUInt(1)) <= 0
                or g.compare(p.subtract(BigUInt(1))) >= 0
            ):
                raise Error("invalid group generator")
            if g.modular_power(q, p).compare(BigUInt(1)) != 0:
                raise Error("generator is not in the prime-order subgroup")
        self.p = p.copy()
        self.q = q.copy()
        self.g = g.copy()
        self.bytes = bytes


def rfc3526_group14() raises -> DHGroup:
    """Return RFC 3526's 2048-bit MODP group with the order-q generator g=2."""
    var p = parse_hex(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
    )
    var q = p.subtract(BigUInt(1))
    q.shift_right_one()
    return DHGroup(p, q, BigUInt(2), KEY_BYTES, trusted=True)


def _private[
    origin: Origin
](group: DHGroup, data: Span[UInt8, origin]) raises -> BigUInt:
    if len(data) != group.bytes:
        raise Error(
            "finite-field private keys must be exactly 256 big-endian bytes"
        )
    var value = from_be(data)
    if value.is_zero() or value.compare(group.q) >= 0:
        raise Error("finite-field private scalar is outside [1,q-1]")
    return value^


def _public[
    origin: Origin
](group: DHGroup, data: Span[UInt8, origin]) raises -> BigUInt:
    if len(data) != group.bytes:
        raise Error(
            "finite-field public keys must be exactly 256 big-endian bytes"
        )
    var value = from_be(data)
    if (
        value.compare(BigUInt(1)) <= 0
        or value.compare(group.p.subtract(BigUInt(1))) >= 0
    ):
        raise Error("finite-field peer key is outside the group")
    if value.jacobi_symbol(group.p) != 1:
        raise Error("finite-field peer key is not in the order-q subgroup")
    return value^


def public_key[
    origin: Origin
](group: DHGroup, private_key: Span[UInt8, origin]) raises -> List[UInt8]:
    """Derive a public key. Private/public encodings are fixed 256-byte big-endian integers.
    """
    return to_be(
        group.g.modular_power(_private(group, private_key), group.p),
        group.bytes,
    )


def dh[
    private_origin: Origin, public_origin: Origin
](
    group: DHGroup,
    private_key: Span[UInt8, private_origin],
    peer_public: Span[UInt8, public_origin],
) raises -> List[UInt8]:
    """DH agreed value as a fixed-width raw field element."""
    var secret = _public(group, peer_public).modular_power(
        _private(group, private_key), group.p
    )
    return to_be(secret, group.bytes)


def dh2[
    sp: Origin, ep: Origin, ss: Origin, es: Origin
](
    group: DHGroup,
    static_private: Span[UInt8, sp],
    ephemeral_private: Span[UInt8, ep],
    peer_static: Span[UInt8, ss],
    peer_ephemeral: Span[UInt8, es],
) raises -> List[UInt8]:
    """DH2 agreed value: raw static DH followed by raw ephemeral DH."""
    var first = _public(group, peer_static).modular_power(
        _private(group, static_private), group.p
    )
    var second = _public(group, peer_ephemeral).modular_power(
        _private(group, ephemeral_private), group.p
    )
    var material = to_be(first, group.bytes)
    append_bytes(material, Span(to_be(second, group.bytes)))
    return material^


def _mqv_bar(value: BigUInt, q: BigUInt) raises -> BigUInt:
    var exponent = (q.bit_length() + 1) // 2
    var limbs = List[UInt32](length=exponent // 32 + 1, fill=0)
    limbs[exponent // 32] = UInt32(1) << UInt32(exponent % 32)
    var power = BigUInt.from_limbs(Span(limbs))
    return value.modulo(power).add(power)


def _transcript[
    ao: Origin, bo: Origin, xo: Origin, yo: Origin
](
    a: Span[UInt8, ao],
    b: Span[UInt8, bo],
    x: Span[UInt8, xo],
    y: Span[UInt8, yo],
    tag: UInt8,
) -> List[UInt8]:
    var data = List[UInt8](capacity=len(a) + len(b) + len(x) + len(y) + 1)
    append_bytes(data, a)
    append_bytes(data, b)
    append_bytes(data, x)
    append_bytes(data, y)
    data.append(tag)
    return data^


def _hash_expand[
    origin: Origin
](data: Span[UInt8, origin], output_bytes: Int) raises -> List[UInt8]:
    var output = List[UInt8](capacity=output_bytes)
    var digest = sha512(data)
    while True:
        for byte in digest:
            if len(output) == output_bytes:
                return output^
            output.append(byte)
        digest = sha512(Span(digest))


def _hash_parts[
    ao: Origin, bo: Origin
](
    first: Span[UInt8, ao], second: Span[UInt8, bo], output_bytes: Int
) raises -> BigUInt:
    var input = List[UInt8](capacity=len(first) + len(second))
    append_bytes(input, first)
    append_bytes(input, second)
    return from_be(Span(_hash_expand(Span(input), output_bytes)))


def authenticated_agree[
    asp: Origin, aep: Origin, lso: Origin, leo: Origin, pso: Origin, peo: Origin
](
    group: DHGroup,
    scheme: AgreementAlgorithm,
    static_private: Span[UInt8, asp],
    ephemeral_private: Span[UInt8, aep],
    local_static: Span[UInt8, lso],
    local_ephemeral: Span[UInt8, leo],
    peer_static: Span[UInt8, pso],
    peer_ephemeral: Span[UInt8, peo],
    initiator: Bool,
) raises -> List[UInt8]:
    """MQV-family agreement. Each private/public input is one 256-byte big-endian scalar/element; initiator fixes A,B,X,Y transcript roles.
    """
    var a_bytes = List[UInt8]()
    var b_bytes = List[UInt8]()
    var x_bytes = List[UInt8]()
    var y_bytes = List[UInt8]()
    append_bytes(a_bytes, local_static if initiator else peer_static)
    append_bytes(b_bytes, peer_static if initiator else local_static)
    append_bytes(x_bytes, local_ephemeral if initiator else peer_ephemeral)
    append_bytes(y_bytes, peer_ephemeral if initiator else local_ephemeral)
    var a = _public(group, Span(a_bytes))
    var b = _public(group, Span(b_bytes))
    var x = _public(group, Span(x_bytes))
    var y = _public(group, Span(y_bytes))
    var own_static = _private(group, static_private)
    var own_eph = _private(group, ephemeral_private)
    var d: BigUInt
    var e: BigUInt
    var coefficient_bytes = (((group.q.bit_length() + 1) // 2) + 7) // 8
    if scheme == AgreementAlgorithm.MQV:
        d = _mqv_bar(x, group.q)
        e = _mqv_bar(y, group.q)
    elif scheme == AgreementAlgorithm.HMQV:
        d = _hash_parts(Span(x_bytes), Span(b_bytes), coefficient_bytes)
        e = _hash_parts(Span(y_bytes), Span(a_bytes), coefficient_bytes)
    elif scheme == AgreementAlgorithm.FHMQV:
        var d_input = List[UInt8](capacity=4 * group.bytes)
        append_bytes(d_input, Span(x_bytes))
        append_bytes(d_input, Span(y_bytes))
        append_bytes(d_input, Span(a_bytes))
        append_bytes(d_input, Span(b_bytes))
        d = from_be(Span(_hash_expand(Span(d_input), coefficient_bytes)))
        var e_input = List[UInt8](capacity=4 * group.bytes)
        append_bytes(e_input, Span(y_bytes))
        append_bytes(e_input, Span(x_bytes))
        append_bytes(e_input, Span(a_bytes))
        append_bytes(e_input, Span(b_bytes))
        e = from_be(Span(_hash_expand(Span(e_input), coefficient_bytes)))
    else:
        raise Error("scheme must be MQV, HMQV or FHMQV")
    var coefficient = (d if initiator else e).copy()
    var peer_coefficient = (e if initiator else d).copy()
    var peer_eph_point = (y if initiator else x).copy()
    var peer_static_point = (b if initiator else a).copy()
    var exponent = own_eph.add(
        own_static.modular_multiply(coefficient, group.q)
    ).modulo(group.q)
    if exponent.is_zero():
        raise Error("authenticated agreement produced a zero exponent")
    var base = peer_eph_point.modular_multiply(
        peer_static_point.modular_power(peer_coefficient, group.p), group.p
    )
    var secret = base.modular_power(exponent, group.p)
    var encoded_secret = to_be(secret, group.bytes)
    if scheme == AgreementAlgorithm.MQV:
        return encoded_secret^
    if scheme == AgreementAlgorithm.HMQV:
        return _hash_expand(Span(encoded_secret), group.bytes)
    var final_input = encoded_secret^
    append_bytes(final_input, Span(x_bytes))
    append_bytes(final_input, Span(y_bytes))
    append_bytes(final_input, Span(a_bytes))
    append_bytes(final_input, Span(b_bytes))
    return _hash_expand(Span(final_input), group.bytes)
