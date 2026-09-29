"""ECDH, ECMQV, ECHMQV and ECFHMQV over the NIST P-256 group."""

from ..math.biguint import BigUInt
from ..hashes.sha512 import sha512
from ..math.ec import ECPoint, PrimeCurve
from ._common import (
    from_be,
    to_be,
    parse_hex,
    append_bytes,
)
from .algorithm import AgreementAlgorithm

comptime PRIVATE_BYTES = 32
comptime PUBLIC_BYTES = 65


struct P256Domain(Copyable, Movable):
    var curve: PrimeCurve
    var generator: ECPoint
    var order: BigUInt

    def __init__(
        out self, curve: PrimeCurve, generator: ECPoint, order: BigUInt
    ) raises:
        if not curve.is_on_curve(generator) or generator.infinity:
            raise Error("invalid elliptic-curve generator")
        # All supported domains are fixed cofactor-one named curves.
        self.curve = curve.copy()
        self.generator = generator.copy()
        self.order = order.copy()


def p256() raises -> P256Domain:
    """Return SEC 2 secp256r1/NIST P-256 domain parameters."""
    var p = parse_hex(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
    )
    var a = parse_hex(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
    )
    var b = parse_hex(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
    )
    var gx = parse_hex(
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    )
    var gy = parse_hex(
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
    )
    var n = parse_hex(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    )
    var curve = PrimeCurve(p, a, b)
    return P256Domain(curve, ECPoint(gx, gy), n)


def _private[
    origin: Origin
](domain: P256Domain, data: Span[UInt8, origin]) raises -> BigUInt:
    if len(data) != PRIVATE_BYTES:
        raise Error("P-256 private keys must be exactly 32 big-endian bytes")
    var scalar = from_be(data)
    if scalar.is_zero() or scalar.compare(domain.order) >= 0:
        raise Error("P-256 private scalar is outside [1,n-1]")
    return scalar^


def encode_point(domain: P256Domain, point: ECPoint) raises -> List[UInt8]:
    """Encode a finite P-256 point as SEC 1 uncompressed 0x04 || X || Y (65 bytes).
    """
    if point.infinity or not domain.curve.is_on_curve(point):
        raise Error("cannot encode an invalid or infinite P-256 point")
    var output = List[UInt8](capacity=PUBLIC_BYTES)
    output.append(4)
    append_bytes(output, Span(to_be(point.x, 32)))
    append_bytes(output, Span(to_be(point.y, 32)))
    return output^


def decode_point[
    origin: Origin
](domain: P256Domain, data: Span[UInt8, origin]) raises -> ECPoint:
    if len(data) != PUBLIC_BYTES or data[0] != 4:
        raise Error(
            "P-256 public keys must be 65-byte uncompressed SEC 1 points"
        )
    var x_bytes = List[UInt8](capacity=32)
    var y_bytes = List[UInt8](capacity=32)
    for i in range(32):
        x_bytes.append(data[i + 1])
        y_bytes.append(data[i + 33])
    var point = ECPoint(from_be(Span(x_bytes)), from_be(Span(y_bytes)))
    if (
        point.x.compare(domain.curve.p) >= 0
        or point.y.compare(domain.curve.p) >= 0
        or not domain.curve.is_on_curve(point)
    ):
        raise Error("P-256 peer public key is not on the curve")
    # P-256 has cofactor one, so every finite on-curve point is in the subgroup.
    return point^


def public_key[
    origin: Origin
](domain: P256Domain, private_key: Span[UInt8, origin]) raises -> List[UInt8]:
    """Derive the 65-byte uncompressed SEC 1 public key from a 32-byte big-endian scalar.
    """
    return encode_point(
        domain,
        domain.curve.scalar_multiply(
            _private(domain, private_key), domain.generator
        ),
    )


def ecdh[
    so: Origin, po: Origin
](
    domain: P256Domain,
    private_key: Span[UInt8, so],
    peer_public: Span[UInt8, po],
) raises -> List[UInt8]:
    """ECDH agreed value: the fixed-width shared x-coordinate."""
    var shared = domain.curve.scalar_multiply(
        _private(domain, private_key), decode_point(domain, peer_public)
    )
    if shared.infinity:
        raise Error("ECDH produced the point at infinity")
    return to_be(shared.x, 32)


def _bar(value: BigUInt, order: BigUInt) raises -> BigUInt:
    var exponent = (order.bit_length() + 1) // 2
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


def _hash_bytes[
    origin: Origin
](data: Span[UInt8, origin], output_bytes: Int) raises -> List[UInt8]:
    var digest = sha512(data)
    var output = List[UInt8](capacity=output_bytes)
    for i in range(output_bytes):
        output.append(digest[i])
    return output^


def _hash_two[
    ao: Origin, bo: Origin
](
    first: Span[UInt8, ao], second: Span[UInt8, bo], output_bytes: Int
) raises -> BigUInt:
    var input = List[UInt8](capacity=len(first) + len(second))
    append_bytes(input, first)
    append_bytes(input, second)
    return from_be(Span(_hash_bytes(Span(input), output_bytes)))


def authenticated_agree[
    asp: Origin, aep: Origin, lso: Origin, leo: Origin, pso: Origin, peo: Origin
](
    domain: P256Domain,
    scheme: AgreementAlgorithm,
    static_private: Span[UInt8, asp],
    ephemeral_private: Span[UInt8, aep],
    local_static: Span[UInt8, lso],
    local_ephemeral: Span[UInt8, leo],
    peer_static: Span[UInt8, pso],
    peer_ephemeral: Span[UInt8, peo],
    initiator: Bool,
) raises -> List[UInt8]:
    """P-256 MQV-family agreement; private keys are 32-byte BE and public keys are 65-byte SEC 1. initiator fixes A,B,X,Y roles.
    """
    var a_bytes = List[UInt8]()
    var b_bytes = List[UInt8]()
    var x_bytes = List[UInt8]()
    var y_bytes = List[UInt8]()
    append_bytes(a_bytes, local_static if initiator else peer_static)
    append_bytes(b_bytes, peer_static if initiator else local_static)
    append_bytes(x_bytes, local_ephemeral if initiator else peer_ephemeral)
    append_bytes(y_bytes, peer_ephemeral if initiator else local_ephemeral)
    var a = decode_point(domain, Span(a_bytes))
    var b = decode_point(domain, Span(b_bytes))
    var x = decode_point(domain, Span(x_bytes))
    var y = decode_point(domain, Span(y_bytes))
    var d: BigUInt
    var e: BigUInt
    var coefficient_bytes = (((domain.order.bit_length() + 1) // 2) + 7) // 8
    if scheme == AgreementAlgorithm.ECMQV_P256:
        d = _bar(x.x, domain.order)
        e = _bar(y.x, domain.order)
    elif scheme == AgreementAlgorithm.ECHMQV_P256:
        d = _hash_two(Span(x_bytes), Span(b_bytes), coefficient_bytes)
        e = _hash_two(Span(y_bytes), Span(a_bytes), coefficient_bytes)
    elif scheme == AgreementAlgorithm.ECFHMQV_P256:
        var d_input = List[UInt8](capacity=4 * PUBLIC_BYTES)
        append_bytes(d_input, Span(x_bytes))
        append_bytes(d_input, Span(y_bytes))
        append_bytes(d_input, Span(a_bytes))
        append_bytes(d_input, Span(b_bytes))
        d = from_be(Span(_hash_bytes(Span(d_input), coefficient_bytes)))
        var e_input = List[UInt8](capacity=4 * PUBLIC_BYTES)
        append_bytes(e_input, Span(y_bytes))
        append_bytes(e_input, Span(x_bytes))
        append_bytes(e_input, Span(a_bytes))
        append_bytes(e_input, Span(b_bytes))
        e = from_be(Span(_hash_bytes(Span(e_input), coefficient_bytes)))
    else:
        raise Error("scheme must be ECMQV, ECHMQV or ECFHMQV")
    var coefficient = (d if initiator else e).copy()
    var peer_coefficient = (e if initiator else d).copy()
    var own_static = _private(domain, static_private)
    var own_ephemeral = _private(domain, ephemeral_private)
    var exponent = own_ephemeral.add(
        own_static.modular_multiply(coefficient, domain.order)
    ).modulo(domain.order)
    var base = domain.curve.add(
        (y if initiator else x).copy(),
        domain.curve.scalar_multiply(
            peer_coefficient, (b if initiator else a).copy()
        ),
    )
    if exponent.is_zero() or base.infinity:
        raise Error("authenticated P-256 agreement rejected degenerate input")
    var shared = domain.curve.scalar_multiply(exponent, base)
    if shared.infinity:
        raise Error("authenticated P-256 agreement produced infinity")
    var encoded_secret = to_be(shared.x, 32)
    if scheme == AgreementAlgorithm.ECMQV_P256:
        return encoded_secret^
    if scheme == AgreementAlgorithm.ECHMQV_P256:
        return _hash_bytes(Span(encoded_secret), 32)
    var final_input = encoded_secret^
    append_bytes(final_input, Span(x_bytes))
    append_bytes(final_input, Span(y_bytes))
    append_bytes(final_input, Span(a_bytes))
    append_bytes(final_input, Span(b_bytes))
    return _hash_bytes(Span(final_input), 32)
