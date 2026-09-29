"""Pure-Mojo ECDSA, RFC 6979, ECNR, and ECGDSA over prime curves.

Private keys and raw signatures are fixed-width big-endian octets. Public keys
are validated SEC1 points; key generation emits uncompressed SEC1, while
verification accepts compressed or uncompressed SEC1.
"""

from .algorithm import ECSignatureScheme
from ..hashes.algorithm import HashAlgorithm
from ..math.curve import CurveAlgorithm
from ..math.biguint import BigUInt
from ..math.ec import (
    ECPoint,
    NamedPrimeCurve,
    FixedBaseMultiplier,
    biguint_from_be,
    biguint_to_be,
    named_curve,
    _shift_right,
)
from ..hashes.sha256 import sha256
from ..hashes.sha512 import sha384, sha512
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import authenticate
from ..random.entropy import system_entropy


def _append[origin: Origin](mut output: List[UInt8], data: Span[UInt8, origin]):
    for byte in data:
        output.append(byte)


def _hmac_sha384[
    ko: Origin, do: Origin
](key: Span[UInt8, ko], data: Span[UInt8, do]) raises -> List[UInt8]:
    var normalized = List[UInt8](length=128, fill=0)
    if len(key) > 128:
        var hashed = sha384(key)
        for i in range(48):
            normalized[i] = hashed[i]
    else:
        for i in range(len(key)):
            normalized[i] = key[i]
    var inner = List[UInt8](capacity=128 + len(data))
    var outer = List[UInt8](capacity=128 + 48)
    for byte in normalized:
        inner.append(byte ^ 0x36)
        outer.append(byte ^ 0x5C)
    _append(inner, data)
    var digest = sha384(Span(inner))
    _append(outer, Span(digest))
    return sha384(Span(outer))


def _hash[
    origin: Origin
](algorithm: HashAlgorithm, data: Span[UInt8, origin]) raises -> List[UInt8]:
    if algorithm == HashAlgorithm.SHA256:
        return sha256(data)
    if algorithm == HashAlgorithm.SHA384:
        return sha384(data)
    if algorithm == HashAlgorithm.SHA512:
        return sha512(data)
    raise Error("ECDSA supports SHA-256, SHA-384, and SHA-512")


def _hmac[
    ko: Origin, do: Origin
](
    algorithm: HashAlgorithm,
    key: Span[UInt8, ko],
    data: Span[UInt8, do],
) raises -> List[UInt8]:
    if algorithm == HashAlgorithm.SHA384:
        return _hmac_sha384(key, data)
    if algorithm == HashAlgorithm.SHA256:
        return authenticate(HmacAlgorithm.SHA256, key, data)
    if algorithm == HashAlgorithm.SHA512:
        return authenticate(HmacAlgorithm.SHA512, key, data)
    raise Error("unsupported RFC 6979 hash")


def _bits2int[origin: Origin](data: Span[UInt8, origin], qlen: Int) -> BigUInt:
    var value = biguint_from_be(data)
    var excess = len(data) * 8 - qlen
    if excess > 0:
        return _shift_right(value, excess)
    return value^


def _message_scalar[
    origin: Origin
](digest: Span[UInt8, origin], order: BigUInt) raises -> BigUInt:
    return _bits2int(digest, order.bit_length()).modulo(order)


def _private_scalar[
    origin: Origin
](domain: NamedPrimeCurve, encoded: Span[UInt8, origin]) raises -> BigUInt:
    if len(encoded) != domain.field_bytes:
        raise Error("private key has the wrong fixed-width encoding")
    var scalar = biguint_from_be(encoded)
    if scalar.is_zero() or scalar.compare(domain.order) >= 0:
        raise Error("private scalar is outside 1..n-1")
    return scalar^


def _encode_signature(
    domain: NamedPrimeCurve, r: BigUInt, s: BigUInt
) raises -> List[UInt8]:
    var output = List[UInt8](capacity=2 * domain.field_bytes)
    var rb = biguint_to_be(r, domain.field_bytes)
    var sb = biguint_to_be(s, domain.field_bytes)
    _append(output, Span(rb))
    _append(output, Span(sb))
    return output^


def _decode_signature[
    origin: Origin
](domain: NamedPrimeCurve, signature: Span[UInt8, origin]) raises -> Tuple[
    BigUInt, BigUInt
]:
    if len(signature) != 2 * domain.field_bytes:
        raise Error("signature has the wrong IEEE P1363 length")
    var r = biguint_from_be(signature[0 : domain.field_bytes])
    var s = biguint_from_be(signature[domain.field_bytes : len(signature)])
    if (
        r.is_zero()
        or s.is_zero()
        or r.compare(domain.order) >= 0
        or s.compare(domain.order) >= 0
    ):
        raise Error("signature scalar is outside 1..n-1")
    return (r^, s^)


def _rfc6979_nonce[
    do: Origin, xo: Origin
](
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, xo],
    order: BigUInt,
) raises -> BigUInt:
    """Generate k exactly as RFC 6979 section 3.2."""
    var qlen = order.bit_length()
    var rolen = (qlen + 7) // 8
    var holen = 32 if hash_algorithm == HashAlgorithm.SHA256 else (
        48 if hash_algorithm == HashAlgorithm.SHA384 else 64
    )
    var x = biguint_from_be(private_key)
    var bx = biguint_to_be(x, rolen)
    var h1 = _bits2int(digest, qlen)
    if h1.compare(order) >= 0:
        h1 = h1.subtract(order)
    var bh = biguint_to_be(h1, rolen)
    var v = List[UInt8](length=holen, fill=1)
    var k = List[UInt8](length=holen, fill=0)
    var input = List[UInt8](capacity=holen + 1 + 2 * rolen)
    _append(input, Span(v))
    input.append(0)
    _append(input, Span(bx))
    _append(input, Span(bh))
    k = _hmac(hash_algorithm, Span(k), Span(input))
    v = _hmac(hash_algorithm, Span(k), Span(v))
    input.clear()
    _append(input, Span(v))
    input.append(1)
    _append(input, Span(bx))
    _append(input, Span(bh))
    k = _hmac(hash_algorithm, Span(k), Span(input))
    v = _hmac(hash_algorithm, Span(k), Span(v))
    while True:
        var t = List[UInt8](capacity=rolen)
        while len(t) < rolen:
            v = _hmac(hash_algorithm, Span(k), Span(v))
            for byte in v:
                if len(t) < rolen:
                    t.append(byte)
        var candidate = _bits2int(Span(t), qlen)
        if not candidate.is_zero() and candidate.compare(order) < 0:
            return candidate^
        input.clear()
        _append(input, Span(v))
        input.append(0)
        k = _hmac(hash_algorithm, Span(k), Span(input))
        v = _hmac(hash_algorithm, Span(k), Span(v))


def public_key[
    origin: Origin
](
    curve: CurveAlgorithm,
    private_key: Span[UInt8, origin],
    compressed: Bool = False,
) raises -> List[UInt8]:
    var domain = named_curve(curve)
    var scalar = _private_scalar(domain, private_key)
    return domain.encode_point(
        domain.curve.scalar_multiply(scalar, domain.generator), compressed
    )


def _generate_private_key(
    curve: CurveAlgorithm = CurveAlgorithm.P256,
) raises -> List[UInt8]:
    """Generate a canonical private scalar without deriving a public point."""
    var domain = named_curve(curve)
    while True:
        var secret = system_entropy(domain.field_bytes)
        var scalar = biguint_from_be(Span(secret)).modulo(domain.order)
        if not scalar.is_zero():
            return biguint_to_be(scalar, domain.field_bytes)


def keypair(
    curve: CurveAlgorithm = CurveAlgorithm.P256,
    compressed: Bool = False,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    var domain = named_curve(curve)
    while True:
        var secret = system_entropy(domain.field_bytes)
        var scalar = biguint_from_be(Span(secret)).modulo(domain.order)
        if not scalar.is_zero():
            var private_key = biguint_to_be(scalar, domain.field_bytes)
            var pub = domain.encode_point(
                domain.curve.scalar_multiply(scalar, domain.generator),
                compressed,
            )
            return (pub^, private_key^)


def _ecdsa_sign_prepared[
    do: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
    x: BigUInt,
) raises -> List[UInt8]:
    var e = _message_scalar(digest, domain.order)
    var k = _rfc6979_nonce(hash_algorithm, digest, private_key, domain.order)
    while True:
        var point = domain.curve.scalar_multiply(k, domain.generator)
        var r = point.x.modulo(domain.order)
        if not r.is_zero():
            var s = k.modular_inverse(domain.order).modular_multiply(
                e.modular_add(
                    x.modular_multiply(r, domain.order), domain.order
                ),
                domain.order,
            )
            if not s.is_zero():
                return _encode_signature(domain, r, s)
        k = k.modular_add(BigUInt(1), domain.order)
        if k.is_zero():
            k = BigUInt(1)


def sign_digest[
    do: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
) raises -> List[UInt8]:
    """Create a deterministic raw r||s ECDSA signature using RFC 6979."""
    var domain = named_curve(curve)
    var x = _private_scalar(domain, private_key)
    return _ecdsa_sign_prepared(
        domain,
        hash_algorithm,
        digest,
        private_key,
        x,
    )


def sign[
    mo: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, mo],
    private_key: Span[UInt8, ko],
) raises -> List[UInt8]:
    var digest = _hash(hash_algorithm, message)
    return sign_digest(curve, hash_algorithm, Span(digest), private_key)


def verify_digest[
    so: Origin, do: Origin, po: Origin
](
    curve: CurveAlgorithm,
    digest: Span[UInt8, do],
    signature: Span[UInt8, so],
    encoded_public_key: Span[UInt8, po],
) raises -> Bool:
    var domain = named_curve(curve)
    var public = domain.decode_point(encoded_public_key)
    try:
        var pair = _decode_signature(domain, signature)
        var r = pair[0].copy()
        var s = pair[1].copy()
        var w = s.modular_inverse(domain.order)
        var e = _message_scalar(digest, domain.order)
        var u1 = e.modular_multiply(w, domain.order)
        var u2 = r.modular_multiply(w, domain.order)
        var point = domain.curve.double_scalar_multiply(
            u1, domain.generator, u2, public
        )
        return (
            not point.infinity and point.x.modulo(domain.order).compare(r) == 0
        )
    except:
        return False


def verify[
    so: Origin, mo: Origin, po: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, mo],
    signature: Span[UInt8, so],
    encoded_public_key: Span[UInt8, po],
) raises -> Bool:
    var digest = _hash(hash_algorithm, message)
    return verify_digest(curve, Span(digest), signature, encoded_public_key)


def _ecnr_sign_prepared[
    do: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
    x: BigUInt,
) raises -> List[UInt8]:
    var e = _message_scalar(digest, domain.order)
    var k = _rfc6979_nonce(hash_algorithm, digest, private_key, domain.order)
    var r = (
        domain.curve.scalar_multiply(k, domain.generator)
        .x.modulo(domain.order)
        .modular_add(e, domain.order)
    )
    if r.is_zero():
        raise Error("ECNR produced zero r")
    var s = k.modular_subtract(
        x.modular_multiply(r, domain.order), domain.order
    )
    return _encode_signature(domain, r, s)


def ecnr_sign_digest[
    do: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
) raises -> List[UInt8]:
    """ECNR: r=(x(kG)+e) mod n, s=(k-x*r) mod n."""
    var domain = named_curve(curve)
    var x = _private_scalar(domain, private_key)
    return _ecnr_sign_prepared(
        domain,
        hash_algorithm,
        digest,
        private_key,
        x,
    )


def ecnr_sign[
    mo: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, mo],
    private_key: Span[UInt8, ko],
) raises -> List[UInt8]:
    var digest = _hash(hash_algorithm, message)
    return ecnr_sign_digest(curve, hash_algorithm, Span(digest), private_key)


def ecnr_verify_digest[
    so: Origin, do: Origin, po: Origin
](
    curve: CurveAlgorithm,
    digest: Span[UInt8, do],
    signature: Span[UInt8, so],
    encoded_public_key: Span[UInt8, po],
) raises -> Bool:
    var domain = named_curve(curve)
    var public = domain.decode_point(encoded_public_key)
    try:
        var pair = _decode_signature(domain, signature)
        var r = pair[0].copy()
        var s = pair[1].copy()
        var point = domain.curve.double_scalar_multiply(
            s, domain.generator, r, public
        )
        var e = _message_scalar(digest, domain.order)
        return (
            not point.infinity
            and point.x.modulo(domain.order)
            .modular_add(e, domain.order)
            .compare(r)
            == 0
        )
    except:
        return False


def ecnr_verify[
    so: Origin, mo: Origin, po: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, mo],
    signature: Span[UInt8, so],
    encoded_public_key: Span[UInt8, po],
) raises -> Bool:
    var digest = _hash(hash_algorithm, message)
    return ecnr_verify_digest(
        curve, Span(digest), signature, encoded_public_key
    )


def ecgdsa_public_key[
    origin: Origin
](
    curve: CurveAlgorithm,
    private_key: Span[UInt8, origin],
    compressed: Bool = False,
) raises -> List[UInt8]:
    """Return the ECGDSA public Q=d^-1*G as SEC1."""
    var domain = named_curve(curve)
    var d = _private_scalar(domain, private_key)
    return domain.encode_point(
        domain.curve.scalar_multiply(
            d.modular_inverse(domain.order), domain.generator
        ),
        compressed,
    )


def _ecgdsa_sign_prepared[
    do: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
    d: BigUInt,
) raises -> List[UInt8]:
    var e = _message_scalar(digest, domain.order)
    var k = _rfc6979_nonce(hash_algorithm, digest, private_key, domain.order)
    var r = domain.curve.scalar_multiply(k, domain.generator).x.modulo(
        domain.order
    )
    var s = (
        k.modular_multiply(r, domain.order)
        .modular_subtract(e, domain.order)
        .modular_multiply(d, domain.order)
    )
    if r.is_zero() or s.is_zero():
        raise Error("ECGDSA produced a zero scalar")
    return _encode_signature(domain, r, s)


def ecgdsa_sign_digest[
    do: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
) raises -> List[UInt8]:
    """ECGDSA/ISO15946: r=x(kG), s=(k*r-e)*d mod n."""
    var domain = named_curve(curve)
    var d = _private_scalar(domain, private_key)
    return _ecgdsa_sign_prepared(
        domain,
        hash_algorithm,
        digest,
        private_key,
        d,
    )


def ecgdsa_sign[
    mo: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, mo],
    private_key: Span[UInt8, ko],
) raises -> List[UInt8]:
    var digest = _hash(hash_algorithm, message)
    return ecgdsa_sign_digest(curve, hash_algorithm, Span(digest), private_key)


def ecgdsa_verify_digest[
    so: Origin, do: Origin, po: Origin
](
    curve: CurveAlgorithm,
    digest: Span[UInt8, do],
    signature: Span[UInt8, so],
    encoded_public_key: Span[UInt8, po],
) raises -> Bool:
    var domain = named_curve(curve)
    var public = domain.decode_point(encoded_public_key)
    try:
        var pair = _decode_signature(domain, signature)
        var r = pair[0].copy()
        var s = pair[1].copy()
        var rinv = r.modular_inverse(domain.order)
        var e = _message_scalar(digest, domain.order)
        var point = domain.curve.double_scalar_multiply(
            e.modular_multiply(rinv, domain.order),
            domain.generator,
            s.modular_multiply(rinv, domain.order),
            public,
        )
        return (
            not point.infinity and point.x.modulo(domain.order).compare(r) == 0
        )
    except:
        return False


def ecgdsa_verify[
    so: Origin, mo: Origin, po: Origin
](
    curve: CurveAlgorithm,
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, mo],
    signature: Span[UInt8, so],
    encoded_public_key: Span[UInt8, po],
) raises -> Bool:
    var digest = _hash(hash_algorithm, message)
    return ecgdsa_verify_digest(
        curve, Span(digest), signature, encoded_public_key
    )


def _ecdsa_sign_fixed[
    do: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    base: FixedBaseMultiplier,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
    x: BigUInt,
) raises -> List[UInt8]:
    var e = _message_scalar(digest, domain.order)
    var k = _rfc6979_nonce(hash_algorithm, digest, private_key, domain.order)
    while True:
        var r = base.multiply(k).x.modulo(domain.order)
        if not r.is_zero():
            var s = k.modular_inverse(domain.order).modular_multiply(
                e.modular_add(
                    x.modular_multiply(r, domain.order), domain.order
                ),
                domain.order,
            )
            if not s.is_zero():
                return _encode_signature(domain, r, s)
        k = k.modular_add(BigUInt(1), domain.order)
        if k.is_zero():
            k = BigUInt(1)


def _ecnr_sign_fixed[
    do: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    base: FixedBaseMultiplier,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
    x: BigUInt,
) raises -> List[UInt8]:
    var e = _message_scalar(digest, domain.order)
    var k = _rfc6979_nonce(hash_algorithm, digest, private_key, domain.order)
    var r = base.multiply(k).x.modulo(domain.order).modular_add(e, domain.order)
    if r.is_zero():
        raise Error("ECNR produced zero r")
    var s = k.modular_subtract(
        x.modular_multiply(r, domain.order), domain.order
    )
    return _encode_signature(domain, r, s)


def _ecgdsa_sign_fixed[
    do: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    base: FixedBaseMultiplier,
    hash_algorithm: HashAlgorithm,
    digest: Span[UInt8, do],
    private_key: Span[UInt8, ko],
    scalar: BigUInt,
) raises -> List[UInt8]:
    var e = _message_scalar(digest, domain.order)
    var k = _rfc6979_nonce(hash_algorithm, digest, private_key, domain.order)
    var r = base.multiply(k).x.modulo(domain.order)
    var s = (
        k.modular_multiply(r, domain.order)
        .modular_subtract(e, domain.order)
        .modular_multiply(scalar, domain.order)
    )
    if r.is_zero() or s.is_zero():
        raise Error("ECGDSA produced a zero scalar")
    return _encode_signature(domain, r, s)


def _is_ecdsa_scheme(scheme: ECSignatureScheme) -> Bool:
    return scheme == ECSignatureScheme.ECDSA


def _is_ecnr_scheme(scheme: ECSignatureScheme) -> Bool:
    return scheme == ECSignatureScheme.ECNR


struct PreparedECSigner(Movable):
    """Validated named-curve private key for repeated EC signatures."""

    var scheme: ECSignatureScheme
    var hash_algorithm: HashAlgorithm
    var private_key: List[UInt8]
    var domain: NamedPrimeCurve
    var scalar: BigUInt
    var fixed_base: FixedBaseMultiplier

    def __init__[
        origin: Origin
    ](
        out self,
        scheme: ECSignatureScheme,
        curve: CurveAlgorithm,
        hash_algorithm: HashAlgorithm,
        private_key: Span[UInt8, origin],
    ) raises:
        if (
            scheme != ECSignatureScheme.ECDSA
            and scheme != ECSignatureScheme.ECGDSA
            and scheme != ECSignatureScheme.ECNR
        ):
            raise Error("invalid EC signature scheme selector")
        self.scheme = scheme
        self.hash_algorithm = hash_algorithm
        self.private_key = List[UInt8](capacity=len(private_key))
        for byte in private_key:
            self.private_key.append(byte)
        self.domain = named_curve(curve)
        self.scalar = _private_scalar(self.domain, private_key)
        self.fixed_base = FixedBaseMultiplier(
            self.domain.curve,
            self.domain.generator,
            self.domain.order.bit_length(),
        )

    def __init__(out self, *, deinit move: Self):
        self.scheme = move.scheme
        self.hash_algorithm = move.hash_algorithm
        self.private_key = move.private_key^
        self.domain = move.domain^
        self.scalar = move.scalar^
        self.fixed_base = move.fixed_base^

    def sign[
        origin: Origin
    ](self, message: Span[UInt8, origin]) raises -> List[UInt8]:
        var digest = _hash(self.hash_algorithm, message)
        if _is_ecdsa_scheme(self.scheme):
            return _ecdsa_sign_fixed(
                self.domain,
                self.fixed_base,
                self.hash_algorithm,
                Span(digest),
                Span(self.private_key),
                self.scalar,
            )
        if _is_ecnr_scheme(self.scheme):
            return _ecnr_sign_fixed(
                self.domain,
                self.fixed_base,
                self.hash_algorithm,
                Span(digest),
                Span(self.private_key),
                self.scalar,
            )
        if self.scheme == ECSignatureScheme.ECGDSA:
            return _ecgdsa_sign_fixed(
                self.domain,
                self.fixed_base,
                self.hash_algorithm,
                Span(digest),
                Span(self.private_key),
                self.scalar,
            )
        raise Error("invalid EC signature scheme selector")
