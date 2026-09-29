"""XTR-DH using traces in an optimal-normal-basis GF(p²)."""

from ..math.biguint import BigUInt
from ._common import from_be, to_be, parse_hex


struct GFp2(Copyable, Movable):
    """An XTR trace represented by its two ONB coordinates."""

    var real: BigUInt
    var imag: BigUInt

    def __init__(out self, real: BigUInt, imag: BigUInt):
        self.real = real.copy()
        self.imag = imag.copy()

    def __init__(out self, real: UInt64, imag: UInt64):
        self.real = BigUInt(real)
        self.imag = BigUInt(imag)

    def __init__(out self, *, copy: Self):
        self.real = copy.real.copy()
        self.imag = copy.imag.copy()

    def __init__(out self, *, deinit move: Self):
        self.real = move.real^
        self.imag = move.imag^


struct XTRDomain(Copyable, Movable):
    """XTR parameters p, q and Tr(g), with fixed-width encodings."""

    var p: BigUInt
    var q: BigUInt
    var trace: GFp2
    var field_bytes: Int
    var private_bytes: Int

    def __init__(out self, p: BigUInt, q: BigUInt, trace: GFp2):
        self.p = p.copy()
        self.q = q.copy()
        self.trace = trace.copy()
        self.field_bytes = (p.bit_length() + 7) // 8
        self.private_bytes = (q.bit_length() + 7) // 8

    def __init__(out self, *, copy: Self):
        self.p = copy.p.copy()
        self.q = copy.q.copy()
        self.trace = copy.trace.copy()
        self.field_bytes = copy.field_bytes
        self.private_bytes = copy.private_bytes

    def __init__(out self, *, deinit move: Self):
        self.p = move.p^
        self.q = move.q^
        self.trace = move.trace^
        self.field_bytes = move.field_bytes
        self.private_bytes = move.private_bytes


def xtr171_domain() raises -> XTRDomain:
    """Return the canonical 171-bit XTR-DH domain."""
    var p = parse_hex("559dcd66a95a57249a15bad6b431bf2cd58615b901d")
    var q = parse_hex("3365cfa0d3b1b6577b2db243dde45edb91c18b0f5f")
    var g1 = parse_hex("32f4eba0911b3d0b14f6f1292a74dffd4a8fcf22c18")
    var g2 = parse_hex("211cb3eda809fa0ff8c3a8ae691ec4c95a06a3395cf")
    return XTRDomain(p, q, GFp2(g1, g2))


def _equal(a: GFp2, b: GFp2) -> Bool:
    return a.real.compare(b.real) == 0 and a.imag.compare(b.imag) == 0


def _constant(domain: XTRDomain, value: UInt64) raises -> GFp2:
    # In the optimal normal basis, a base-field constant a is (-a, -a).
    var encoded = domain.p.subtract(BigUInt(value).modulo(domain.p))
    if encoded.compare(domain.p) == 0:
        encoded = BigUInt()
    return GFp2(encoded, encoded)


@always_inline("nodebug")
def _add_value(a: BigUInt, b: BigUInt, modulus: BigUInt) raises -> BigUInt:
    var sum = a.add(b)
    if sum.compare(modulus) >= 0:
        return sum.subtract(modulus)
    return sum^


def _add(domain: XTRDomain, a: GFp2, b: GFp2) raises -> GFp2:
    return GFp2(
        _add_value(a.real, b.real, domain.p),
        _add_value(a.imag, b.imag, domain.p),
    )


def _sub_value(a: BigUInt, b: BigUInt, modulus: BigUInt) raises -> BigUInt:
    if a.compare(b) >= 0:
        return a.subtract(b)
    return a.add(modulus).subtract(b)


def _sub(domain: XTRDomain, a: GFp2, b: GFp2) raises -> GFp2:
    return GFp2(
        _sub_value(a.real, b.real, domain.p),
        _sub_value(a.imag, b.imag, domain.p),
    )


def _mul(domain: XTRDomain, a: GFp2, b: GFp2) raises -> GFp2:
    # ONB multiplication. The coordinates are not polynomial-basis
    # real/imaginary parts despite their historical public names here.
    var sum_product = _add_value(a.real, a.imag, domain.p).modular_multiply(
        _add_value(b.real, b.imag, domain.p), domain.p
    )
    var same_real = a.real.modular_multiply(b.real, domain.p)
    var same_imag = a.imag.modular_multiply(b.imag, domain.p)
    var cross = _sub_value(sum_product, same_real, domain.p)
    cross = _sub_value(cross, same_imag, domain.p)
    return GFp2(
        _sub_value(same_imag, cross, domain.p),
        _sub_value(same_real, cross, domain.p),
    )


def _square(domain: XTRDomain, a: GFp2) raises -> GFp2:
    var twice_real = _add_value(a.real, a.real, domain.p)
    var twice_imag = _add_value(a.imag, a.imag, domain.p)
    return GFp2(
        _sub_value(a.imag, twice_real, domain.p).modular_multiply(
            a.imag, domain.p
        ),
        _sub_value(a.real, twice_imag, domain.p).modular_multiply(
            a.real, domain.p
        ),
    )


def _pth_power(a: GFp2) -> GFp2:
    return GFp2(a.imag, a.real)


def _special1(domain: XTRDomain, a: GFp2) raises -> GFp2:
    # a² - 2a^p
    var squared = _square(domain, a)
    return _sub(
        domain,
        squared,
        GFp2(
            _add_value(a.imag, a.imag, domain.p),
            _add_value(a.real, a.real, domain.p),
        ),
    )


def _special2(domain: XTRDomain, x: GFp2, y: GFp2, z: GFp2) raises -> GFp2:
    # x*z - y*z^p, in the optimal normal basis.
    var t = _add_value(x.imag, y.imag, domain.p)
    var first = z.real.modular_multiply(
        _sub_value(y.real, t, domain.p), domain.p
    )
    first = _add_value(
        first,
        z.imag.modular_multiply(_sub_value(t, x.real, domain.p), domain.p),
        domain.p,
    )
    t = _add_value(x.real, y.real, domain.p)
    var second = z.imag.modular_multiply(
        _sub_value(y.imag, t, domain.p), domain.p
    )
    second = _add_value(
        second,
        z.real.modular_multiply(_sub_value(t, x.imag, domain.p), domain.p),
        domain.p,
    )
    return GFp2(first, second)


comptime _XTR_P0 = UInt64(0x1BF2CD58615B901D)
comptime _XTR_P1 = UInt64(0xA57249A15BAD6B43)
comptime _XTR_P2 = UInt64(0x00000559DCD66A95)
comptime _XTR_N0 = UInt64(0x68165CA8047C4DCB)
comptime _XTR_R2_0 = UInt64(0xBE162F793C401464)
comptime _XTR_R2_1 = UInt64(0x24F2E8CC5570AACA)
comptime _XTR_R2_2 = UInt64(0x0000032E3050C9DF)


struct _Fp(Copyable, Movable):
    var words: InlineArray[UInt64, 3]

    @always_inline("nodebug")
    def __init__(
        out self, low: UInt64 = 0, middle: UInt64 = 0, high: UInt64 = 0
    ):
        self.words = InlineArray[UInt64, 3](uninitialized=True)
        self.words[0] = low
        self.words[1] = middle
        self.words[2] = high

    @always_inline("nodebug")
    def __init__(out self, *, copy: Self):
        self.words = copy.words.copy()

    @always_inline("nodebug")
    def __init__(out self, *, deinit move: Self):
        self.words = move.words^


struct _GFp2(Copyable, Movable):
    var real: _Fp
    var imag: _Fp

    @always_inline("nodebug")
    def __init__(out self, real: _Fp, imag: _Fp):
        self.real = real.copy()
        self.imag = imag.copy()

    @always_inline("nodebug")
    def __init__(out self, *, copy: Self):
        self.real = copy.real.copy()
        self.imag = copy.imag.copy()

    @always_inline("nodebug")
    def __init__(out self, *, deinit move: Self):
        self.real = move.real^
        self.imag = move.imag^


@always_inline("nodebug")
def _fp_modulus() -> _Fp:
    return _Fp(_XTR_P0, _XTR_P1, _XTR_P2)


@always_inline("nodebug")
def _fp_geq(left: _Fp, right: _Fp) -> Bool:
    comptime for offset in range(3):
        comptime index = 2 - offset
        if left.words[index] > right.words[index]:
            return True
        if left.words[index] < right.words[index]:
            return False
    return True


@always_inline("nodebug")
def _fp_sub_ordered(left: _Fp, right: _Fp) -> _Fp:
    var output = _Fp()
    var borrow = UInt64(0)
    comptime for i in range(3):
        var lhs = UInt128(left.words[i])
        var rhs = UInt128(right.words[i]) + UInt128(borrow)
        if lhs < rhs:
            output.words[i] = UInt64((UInt128(1) << 64) + lhs - rhs)
            borrow = 1
        else:
            output.words[i] = UInt64(lhs - rhs)
            borrow = 0
    return output^


@always_inline("nodebug")
def _fp_add(left: _Fp, right: _Fp) -> _Fp:
    var output = _Fp()
    var carry = UInt64(0)
    comptime for i in range(3):
        var total = (
            UInt128(left.words[i]) + UInt128(right.words[i]) + UInt128(carry)
        )
        output.words[i] = UInt64(total)
        carry = UInt64(total >> 64)
    var modulus = _fp_modulus()
    if carry != 0 or _fp_geq(output, modulus):
        output = _fp_sub_ordered(output, modulus)
    return output^


@always_inline("nodebug")
def _fp_sub(left: _Fp, right: _Fp) -> _Fp:
    if _fp_geq(left, right):
        return _fp_sub_ordered(left, right)
    var modulus = _fp_modulus()
    return _fp_add(left, _fp_sub_ordered(modulus, right))


@always_inline("nodebug")
def _fp_multiply(left: _Fp, right: _Fp) -> _Fp:
    var work = InlineArray[UInt64, 8](fill=0)
    comptime for i in range(3):
        var carry = UInt64(0)
        comptime for j in range(3):
            comptime index = i + j
            var total = (
                UInt128(work[index])
                + UInt128(left.words[i]) * UInt128(right.words[j])
                + UInt128(carry)
            )
            work[index] = UInt64(total)
            carry = UInt64(total >> 64)
        var index = i + 3
        while carry != 0:
            var total = UInt128(work[index]) + UInt128(carry)
            work[index] = UInt64(total)
            carry = UInt64(total >> 64)
            index += 1
    var modulus = _fp_modulus()
    comptime for i in range(3):
        var multiplier = work[i] * _XTR_N0
        var carry = UInt64(0)
        comptime for j in range(3):
            comptime index = i + j
            var total = (
                UInt128(work[index])
                + UInt128(multiplier) * UInt128(modulus.words[j])
                + UInt128(carry)
            )
            work[index] = UInt64(total)
            carry = UInt64(total >> 64)
        var index = i + 3
        while carry != 0:
            var total = UInt128(work[index]) + UInt128(carry)
            work[index] = UInt64(total)
            carry = UInt64(total >> 64)
            index += 1
    var output = _Fp(work[3], work[4], work[5])
    if work[6] != 0 or _fp_geq(output, modulus):
        output = _fp_sub_ordered(output, modulus)
    return output^


@always_inline("nodebug")
def _fp_from_big(value: BigUInt) raises -> _Fp:
    var normal = _Fp()
    if value.bit_length() > 192:
        raise Error("XTR field element is too large")
    for i in range(min(len(value.limbs), 6)):
        normal.words[i // 2] |= UInt64(value.limbs[i]) << UInt64(32 * (i & 1))
    var modulus = _fp_modulus()
    if _fp_geq(normal, modulus):
        raise Error("XTR field element is outside the canonical field")
    var r2 = _Fp(_XTR_R2_0, _XTR_R2_1, _XTR_R2_2)
    return _fp_multiply(normal, r2)


@always_inline("nodebug")
def _fp_to_big(value: _Fp) -> BigUInt:
    var normal = _fp_multiply(value, _Fp(1))
    var limbs = List[UInt32](unsafe_uninit_length=6)
    comptime for i in range(3):
        limbs[2 * i] = UInt32(normal.words[i])
        limbs[2 * i + 1] = UInt32(normal.words[i] >> 32)
    return BigUInt.from_limbs(Span(limbs))


@always_inline("nodebug")
def _fp2_from(value: GFp2) raises -> _GFp2:
    return _GFp2(_fp_from_big(value.real), _fp_from_big(value.imag))


@always_inline("nodebug")
def _fp2_to(value: _GFp2) -> GFp2:
    return GFp2(_fp_to_big(value.real), _fp_to_big(value.imag))


@always_inline("nodebug")
def _fp2_constant(value: UInt64) -> _GFp2:
    var modulus = _fp_modulus()
    var encoded = _fp_sub_ordered(modulus, _Fp(value))
    var r2 = _Fp(_XTR_R2_0, _XTR_R2_1, _XTR_R2_2)
    var montgomery = _fp_multiply(encoded, r2)
    return _GFp2(montgomery, montgomery)


@always_inline("nodebug")
def _fp2_add(left: _GFp2, right: _GFp2) -> _GFp2:
    return _GFp2(_fp_add(left.real, right.real), _fp_add(left.imag, right.imag))


@always_inline("nodebug")
def _fp2_sub(left: _GFp2, right: _GFp2) -> _GFp2:
    return _GFp2(_fp_sub(left.real, right.real), _fp_sub(left.imag, right.imag))


@always_inline("nodebug")
def _fp2_mul(left: _GFp2, right: _GFp2) -> _GFp2:
    var sum_product = _fp_multiply(
        _fp_add(left.real, left.imag), _fp_add(right.real, right.imag)
    )
    var same_real = _fp_multiply(left.real, right.real)
    var same_imag = _fp_multiply(left.imag, right.imag)
    var cross = _fp_sub(_fp_sub(sum_product, same_real), same_imag)
    return _GFp2(_fp_sub(same_imag, cross), _fp_sub(same_real, cross))


@always_inline("nodebug")
def _fp2_square(value: _GFp2) -> _GFp2:
    var twice_real = _fp_add(value.real, value.real)
    var twice_imag = _fp_add(value.imag, value.imag)
    return _GFp2(
        _fp_multiply(_fp_sub(value.imag, twice_real), value.imag),
        _fp_multiply(_fp_sub(value.real, twice_imag), value.real),
    )


@always_inline("nodebug")
def _fp2_pth(value: _GFp2) -> _GFp2:
    return _GFp2(value.imag, value.real)


@always_inline("nodebug")
def _fp2_special1(value: _GFp2) -> _GFp2:
    var squared = _fp2_square(value)
    return _fp2_sub(
        squared,
        _GFp2(
            _fp_add(value.imag, value.imag),
            _fp_add(value.real, value.real),
        ),
    )


@always_inline("nodebug")
def _fp2_special2(x: _GFp2, y: _GFp2, z: _GFp2) -> _GFp2:
    var t = _fp_add(x.imag, y.imag)
    var first = _fp_multiply(z.real, _fp_sub(y.real, t))
    first = _fp_add(first, _fp_multiply(z.imag, _fp_sub(t, x.real)))
    t = _fp_add(x.real, y.real)
    var second = _fp_multiply(z.imag, _fp_sub(y.imag, t))
    second = _fp_add(second, _fp_multiply(z.real, _fp_sub(t, x.imag)))
    return _GFp2(first, second)


def _is_canonical_xtr(domain: XTRDomain) -> Bool:
    return (
        len(domain.p.limbs) == 6
        and domain.p.limbs[0] == UInt32(_XTR_P0)
        and domain.p.limbs[1] == UInt32(_XTR_P0 >> 32)
        and domain.p.limbs[2] == UInt32(_XTR_P1)
        and domain.p.limbs[3] == UInt32(_XTR_P1 >> 32)
        and domain.p.limbs[4] == UInt32(_XTR_P2)
        and domain.p.limbs[5] == UInt32(_XTR_P2 >> 32)
    )


def _trace_power_canonical(exponent: BigUInt, base: GFp2) raises -> GFp2:
    if exponent.is_zero():
        return _fp2_to(_fp2_constant(3))
    var lowest_one = 0
    while exponent.bit(lowest_one) == 0:
        lowest_one += 1
    var c = _fp2_from(base)
    var cp = _fp2_pth(c)
    var s0 = _fp2_constant(3)
    var s1 = c.copy()
    var s2 = _fp2_special1(c)
    for i in range(exponent.bit_length() - 1, lowest_one, -1):
        if exponent.bit(i) != 0:
            s0 = _fp2_pth(s0)
            s0 = _fp2_add(s0, _fp2_special2(s2, c, s1))
            s1 = _fp2_special1(s1)
            s2 = _fp2_special1(s2)
            var swap = s0^
            s0 = s1^
            s1 = swap^
        else:
            s2 = _fp2_pth(s2)
            s2 = _fp2_add(s2, _fp2_special2(s0, cp, s1))
            s1 = _fp2_special1(s1)
            s0 = _fp2_special1(s0)
            var swap = s2^
            s2 = s1^
            s1 = swap^
    for _ in range(lowest_one):
        s1 = _fp2_special1(s1)
    return _fp2_to(s1)


def _trace_power(
    domain: XTRDomain, exponent: BigUInt, base: GFp2
) raises -> GFp2:
    """Trace exponentiation in O(log exponent) using trace arithmetic."""
    if _is_canonical_xtr(domain):
        return _trace_power_canonical(exponent, base)
    if exponent.is_zero():
        return _constant(domain, 3)
    var lowest_one = 0
    while exponent.bit(lowest_one) == 0:
        lowest_one += 1
    var c = base.copy()
    var cp = _pth_power(c)
    var s0 = _constant(domain, 3)
    var s1 = c.copy()
    var s2 = _special1(domain, c)
    for i in range(exponent.bit_length() - 1, lowest_one, -1):
        if exponent.bit(i) != 0:
            s0 = _pth_power(s0)
            s0 = _add(domain, s0, _special2(domain, s2, c, s1))
            s1 = _special1(domain, s1)
            s2 = _special1(domain, s2)
            var swap = s0^
            s0 = s1^
            s1 = swap^
        else:
            s2 = _pth_power(s2)
            s2 = _add(domain, s2, _special2(domain, s0, cp, s1))
            s1 = _special1(domain, s1)
            s0 = _special1(domain, s0)
            var swap = s2^
            s2 = s1^
            s1 = swap^
    for _ in range(lowest_one):
        s1 = _special1(domain, s1)
    return s1^


def _decode_private[
    origin: Origin
](domain: XTRDomain, data: Span[UInt8, origin]) raises -> BigUInt:
    if len(data) != domain.private_bytes:
        raise Error("XTR private key has the wrong fixed width")
    var value = from_be(data)
    if value.is_zero() or value.compare(domain.q) >= 0:
        raise Error("XTR private exponent is outside [1,q-1]")
    return value^


def _encode(domain: XTRDomain, value: GFp2) raises -> List[UInt8]:
    var output = to_be(value.real, domain.field_bytes)
    var second = to_be(value.imag, domain.field_bytes)
    for byte in second:
        output.append(byte)
    return output^


def _decode[
    origin: Origin
](domain: XTRDomain, data: Span[UInt8, origin]) raises -> GFp2:
    if len(data) != 2 * domain.field_bytes:
        raise Error("XTR public key has the wrong fixed width")
    var first = from_be(data[0 : domain.field_bytes])
    var second = from_be(data[domain.field_bytes :])
    if first.compare(domain.p) >= 0 or second.compare(domain.p) >= 0:
        raise Error("XTR peer trace is outside GF(p²)")
    var point = GFp2(first, second)
    var three = _constant(domain, 3)
    if _equal(point, three) or not _equal(
        _trace_power(domain, domain.q, point), three
    ):
        raise Error("XTR peer trace is not in the order-q trace subgroup")
    return point^


def public_key[
    origin: Origin
](domain: XTRDomain, private_key: Span[UInt8, origin]) raises -> List[UInt8]:
    return _encode(
        domain,
        _trace_power(
            domain, _decode_private(domain, private_key), domain.trace
        ),
    )


def agree[
    so: Origin, po: Origin
](
    domain: XTRDomain,
    private_key: Span[UInt8, so],
    peer_public: Span[UInt8, po],
) raises -> List[UInt8]:
    """Return the fixed-width raw ``Tr(g^(ab))`` agreed value."""
    var scalar = _decode_private(domain, private_key)
    var peer = _decode(domain, peer_public)
    return _encode(domain, _trace_power(domain, scalar, peer))
