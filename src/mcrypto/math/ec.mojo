"""Affine short-Weierstrass groups over odd prime fields."""

from .curve import CurveAlgorithm
from .biguint import BigUInt


def biguint_from_be[origin: Origin](data: Span[UInt8, origin]) -> BigUInt:
    """Decode an unsigned integer from big-endian octets."""
    var limbs = List[UInt32](length=max(1, (len(data) + 3) // 4), fill=0)
    for i in range(len(data)):
        var source = len(data) - 1 - i
        limbs[i // 4] |= UInt32(data[source]) << UInt32(8 * (i % 4))
    return BigUInt.from_limbs(Span(limbs))


def biguint_to_be(value: BigUInt, size: Int) raises -> List[UInt8]:
    """Encode an unsigned integer as exactly `size` big-endian octets."""
    if size < 0 or value.bit_length() > size * 8:
        raise Error("integer does not fit the requested byte encoding")
    var output = List[UInt8](length=size, fill=0)
    for i in range(min(size, len(value.limbs) * 4)):
        output[size - 1 - i] = UInt8(value.limbs[i // 4] >> UInt32(8 * (i % 4)))
    return output^


def biguint_from_hex(text: String) raises -> BigUInt:
    """Decode an unsigned hexadecimal integer, ignoring ASCII whitespace."""
    var result = BigUInt()
    for cp in text.codepoints():
        var code = Int(cp)
        var digit: UInt32
        if code >= 48 and code <= 57:
            digit = UInt32(code - 48)
        elif code >= 65 and code <= 70:
            digit = UInt32(code - 55)
        elif code >= 97 and code <= 102:
            digit = UInt32(code - 87)
        elif code == 32 or code == 9 or code == 10 or code == 13:
            continue
        else:
            raise Error("invalid hexadecimal integer")
        result.shift_left_one()
        result.shift_left_one()
        result.shift_left_one()
        result.shift_left_one()
        result.add_small(digit)
    return result^


def _shift_right(value: BigUInt, amount: Int) -> BigUInt:
    var limb_shift = amount // 32
    var bit_shift = amount % 32
    if limb_shift >= len(value.limbs):
        return BigUInt()
    var output = BigUInt()
    output.limbs = List[UInt32](length=len(value.limbs) - limb_shift, fill=0)
    for i in range(len(output.limbs)):
        var source = i + limb_shift
        output.limbs[i] = value.limbs[source] >> UInt32(bit_shift)
        if bit_shift != 0 and source + 1 < len(value.limbs):
            output.limbs[i] |= value.limbs[source + 1] << UInt32(32 - bit_shift)
    output._normalize()
    return output^


@always_inline("nodebug")
def _fixed_product[
    words: Int
](left: BigUInt, right: BigUInt) -> InlineArray[UInt32, 2 * words]:
    var product = InlineArray[UInt32, 2 * words](fill=0)
    comptime for i in range(words):
        var left_word = UInt64(left.limbs[i]) if i < len(
            left.limbs
        ) else UInt64(0)
        var carry = UInt64(0)
        comptime for j in range(words):
            comptime index = i + j
            var right_word = UInt64(right.limbs[j]) if j < len(
                right.limbs
            ) else UInt64(0)
            var total = UInt64(product[index]) + left_word * right_word + carry
            product[index] = UInt32(total)
            carry = total >> 32
        product[i + words] = UInt32(carry)
    return product^


@always_inline("nodebug")
def _normalize_p256(mut coefficients: InlineArray[Int64, 16]):
    comptime for i in range(8):
        var carry = coefficients[i] >> 32
        coefficients[i] -= carry << 32
        coefficients[i + 1] += carry


def _p256_multiply(
    left: BigUInt, right: BigUInt, modulus: BigUInt
) raises -> BigUInt:
    var product = _fixed_product[8](left, right)
    var coefficients = InlineArray[Int64, 16](uninitialized=True)
    comptime for i in range(16):
        coefficients[i] = Int64(UInt64(product[i]))
    for i in range(15, 7, -1):
        var value = coefficients[i]
        coefficients[i] = 0
        coefficients[i - 8] += value
        coefficients[i - 5] -= value
        coefficients[i - 2] -= value
        coefficients[i - 1] += value
    _normalize_p256(coefficients)
    var overflow = coefficients[8]
    coefficients[8] = 0
    coefficients[0] += overflow
    coefficients[3] -= overflow
    coefficients[6] -= overflow
    coefficients[7] += overflow
    _normalize_p256(coefficients)
    var limbs = List[UInt32](length=8, fill=0)
    comptime for i in range(8):
        limbs[i] = UInt32(coefficients[i])
    var result = BigUInt.from_limbs(Span(limbs))
    if result.compare(modulus) >= 0:
        result = result.subtract(modulus)
    return result^


@always_inline("nodebug")
def _normalize_p384(mut coefficients: InlineArray[Int64, 24]):
    comptime for i in range(12):
        var carry = coefficients[i] >> 32
        coefficients[i] -= carry << 32
        coefficients[i + 1] += carry


def _p384_multiply(
    left: BigUInt, right: BigUInt, modulus: BigUInt
) raises -> BigUInt:
    var product = _fixed_product[12](left, right)
    var coefficients = InlineArray[Int64, 24](uninitialized=True)
    comptime for i in range(24):
        coefficients[i] = Int64(UInt64(product[i]))
    for i in range(23, 11, -1):
        var value = coefficients[i]
        coefficients[i] = 0
        coefficients[i - 12] += value
        coefficients[i - 11] -= value
        coefficients[i - 9] += value
        coefficients[i - 8] += value
    _normalize_p384(coefficients)
    var overflow = coefficients[12]
    coefficients[12] = 0
    coefficients[0] += overflow
    coefficients[1] -= overflow
    coefficients[3] += overflow
    coefficients[4] += overflow
    _normalize_p384(coefficients)
    var limbs = List[UInt32](length=12, fill=0)
    comptime for i in range(12):
        limbs[i] = UInt32(coefficients[i])
    var result = BigUInt.from_limbs(Span(limbs))
    if result.compare(modulus) >= 0:
        result = result.subtract(modulus)
    return result^


@always_inline("nodebug")
def _p521_low(value: BigUInt) -> BigUInt:
    var limbs = List[UInt32](length=min(17, len(value.limbs)), fill=0)
    for i in range(len(limbs)):
        limbs[i] = value.limbs[i]
    if len(limbs) == 17:
        limbs[16] &= 0x1FF
    return BigUInt.from_limbs(Span(limbs))


def _p521_multiply(
    left: BigUInt, right: BigUInt, modulus: BigUInt
) raises -> BigUInt:
    var product = left.multiply(right)
    var result = _p521_low(product).add(_shift_right(product, 521))
    result = _p521_low(result).add(_shift_right(result, 521))
    if result.compare(modulus) >= 0:
        result = result.subtract(modulus)
    return result^


struct ECPoint(Copyable, Movable):
    var x: BigUInt
    var y: BigUInt
    var infinity: Bool

    def __init__(out self):
        self.x = BigUInt()
        self.y = BigUInt()
        self.infinity = True

    def __init__(out self, x: BigUInt, y: BigUInt):
        self.x = x.copy()
        self.y = y.copy()
        self.infinity = False

    def __init__(out self, *, copy: Self):
        self.x = copy.x.copy()
        self.y = copy.y.copy()
        self.infinity = copy.infinity

    def __init__(out self, *, deinit move: Self):
        self.x = move.x^
        self.y = move.y^
        self.infinity = move.infinity


struct JacobianPoint(Copyable, Movable):
    var x: BigUInt
    var y: BigUInt
    var z: BigUInt

    def __init__(out self):
        self.x = BigUInt()
        self.y = BigUInt(1)
        self.z = BigUInt()

    def __init__(out self, x: BigUInt, y: BigUInt, z: BigUInt):
        self.x = x.copy()
        self.y = y.copy()
        self.z = z.copy()

    def __init__(out self, *, copy: Self):
        self.x = copy.x.copy()
        self.y = copy.y.copy()
        self.z = copy.z.copy()

    def __init__(out self, *, deinit move: Self):
        self.x = move.x^
        self.y = move.y^
        self.z = move.z^


struct PrimeCurve(Copyable, Movable):
    var p: BigUInt
    var a: BigUInt
    var b: BigUInt
    var reduction_kind: UInt8
    var minus_three: Bool

    def __init__(out self, p: BigUInt, a: BigUInt, b: BigUInt) raises:
        if p.compare(BigUInt(3)) <= 0 or p.bit(0) == 0:
            raise Error(
                "curve modulus must be an odd integer greater than three"
            )
        self.p = p.copy()
        self.reduction_kind = 0
        if (
            len(self.p.limbs) == 8
            and self.p.limbs[0] == 0xFFFFFFFF
            and self.p.limbs[1] == 0xFFFFFFFF
            and self.p.limbs[2] == 0xFFFFFFFF
            and self.p.limbs[3] == 0
            and self.p.limbs[4] == 0
            and self.p.limbs[5] == 0
            and self.p.limbs[6] == 1
            and self.p.limbs[7] == 0xFFFFFFFF
        ):
            self.reduction_kind = 1
        elif (
            len(self.p.limbs) == 12
            and self.p.limbs[0] == 0xFFFFFFFF
            and self.p.limbs[1] == 0
            and self.p.limbs[2] == 0
            and self.p.limbs[3] == 0xFFFFFFFF
            and self.p.limbs[4] == 0xFFFFFFFE
            and self.p.limbs[5] == 0xFFFFFFFF
            and self.p.limbs[6] == 0xFFFFFFFF
            and self.p.limbs[7] == 0xFFFFFFFF
            and self.p.limbs[8] == 0xFFFFFFFF
            and self.p.limbs[9] == 0xFFFFFFFF
            and self.p.limbs[10] == 0xFFFFFFFF
            and self.p.limbs[11] == 0xFFFFFFFF
        ):
            self.reduction_kind = 2
        elif len(self.p.limbs) == 17 and self.p.limbs[16] == 0x1FF:
            var p521 = True
            for i in range(16):
                p521 = p521 and self.p.limbs[i] == 0xFFFFFFFF
            if p521:
                self.reduction_kind = 3
        self.a = a.modulo(self.p)
        self.minus_three = self.a.compare(self.p.subtract(BigUInt(3))) == 0
        self.b = b.modulo(self.p)

    def __init__(out self, *, copy: Self):
        self.p = copy.p.copy()
        self.a = copy.a.copy()
        self.b = copy.b.copy()
        self.reduction_kind = copy.reduction_kind
        self.minus_three = copy.minus_three

    def __init__(out self, *, deinit move: Self):
        self.p = move.p^
        self.a = move.a^
        self.b = move.b^
        self.reduction_kind = move.reduction_kind
        self.minus_three = move.minus_three

    @always_inline("nodebug")
    def _mul(self, left: BigUInt, right: BigUInt) raises -> BigUInt:
        if self.reduction_kind == 1:
            return _p256_multiply(left, right, self.p)
        if self.reduction_kind == 2:
            return _p384_multiply(left, right, self.p)
        if self.reduction_kind == 3:
            return _p521_multiply(left, right, self.p)
        return left.modular_multiply(right, self.p)

    def is_on_curve(self, point: ECPoint) raises -> Bool:
        if point.infinity:
            return True
        var left = self._mul(point.y, point.y)
        var x_squared = self._mul(point.x, point.x)
        var x_cubed = self._mul(x_squared, point.x)
        var right = x_cubed.modular_add(self._mul(self.a, point.x), self.p)
        right = right.modular_add(self.b, self.p)
        return left.compare(right) == 0

    def negate(self, point: ECPoint) raises -> ECPoint:
        if point.infinity:
            return ECPoint()
        if point.y.is_zero():
            return point.copy()
        return ECPoint(point.x.copy(), self.p.subtract(point.y.modulo(self.p)))

    def add(self, left: ECPoint, right: ECPoint) raises -> ECPoint:
        if not self.is_on_curve(left) or not self.is_on_curve(right):
            raise Error("point is not on the curve")
        if left.infinity:
            return right.copy()
        if right.infinity:
            return left.copy()
        if left.x.compare(right.x) == 0:
            if left.y.compare(right.y) != 0 or left.y.is_zero():
                return ECPoint()
            return self.double(left)
        var numerator = right.y.modular_subtract(left.y, self.p)
        var denominator = right.x.modular_subtract(
            left.x, self.p
        ).modular_inverse(self.p)
        var slope = self._mul(numerator, denominator)
        var x3 = self._mul(slope, slope)
        x3 = x3.modular_subtract(left.x, self.p).modular_subtract(
            right.x, self.p
        )
        var y3 = self._mul(left.x.modular_subtract(x3, self.p), slope)
        y3 = y3.modular_subtract(left.y, self.p)
        return ECPoint(x3^, y3^)

    def double(self, point: ECPoint) raises -> ECPoint:
        if not self.is_on_curve(point):
            raise Error("point is not on the curve")
        if point.infinity or point.y.is_zero():
            return ECPoint()
        var x_squared = self._mul(point.x, point.x)
        var numerator = self._mul(x_squared, BigUInt(3))
        numerator = numerator.modular_add(self.a, self.p)
        var denominator = point.y.modular_add(point.y, self.p).modular_inverse(
            self.p
        )
        var slope = self._mul(numerator, denominator)
        var x3 = self._mul(slope, slope)
        x3 = x3.modular_subtract(point.x, self.p).modular_subtract(
            point.x, self.p
        )
        var y3 = self._mul(point.x.modular_subtract(x3, self.p), slope)
        y3 = y3.modular_subtract(point.y, self.p)
        return ECPoint(x3^, y3^)

    def _add_mod(self, left: BigUInt, right: BigUInt) raises -> BigUInt:
        var result = left.add(right)
        if result.compare(self.p) >= 0:
            result = result.subtract(self.p)
        return result^

    def _sub_mod(self, left: BigUInt, right: BigUInt) raises -> BigUInt:
        if left.compare(right) >= 0:
            return left.subtract(right)
        return self.p.subtract(right.subtract(left))

    def _double_mod(self, value: BigUInt) raises -> BigUInt:
        return self._add_mod(value, value)

    def _jacobian_double(self, point: JacobianPoint) raises -> JacobianPoint:
        if point.z.is_zero() or point.y.is_zero():
            return JacobianPoint()
        var a = self._mul(point.x, point.x)
        var b = self._mul(point.y, point.y)
        var c = self._mul(b, b)
        var x_plus_b = self._add_mod(point.x, b)
        var d = self._mul(x_plus_b, x_plus_b)
        d = self._sub_mod(self._sub_mod(d, a), c)
        d = self._double_mod(d)
        var z_squared = self._mul(point.z, point.z)
        var e: BigUInt
        if self.minus_three:
            var difference = self._sub_mod(point.x, z_squared)
            var sum = self._add_mod(point.x, z_squared)
            var product = self._mul(difference, sum)
            e = self._add_mod(product, self._double_mod(product))
        else:
            var z_fourth = self._mul(z_squared, z_squared)
            e = self._add_mod(a, self._double_mod(a))
            e = self._add_mod(e, self._mul(self.a, z_fourth))
        var f = self._mul(e, e)
        var x3 = self._sub_mod(f, self._double_mod(d))
        var eight_c = self._double_mod(c)
        eight_c = self._double_mod(eight_c)
        eight_c = self._double_mod(eight_c)
        var y3 = self._mul(e, self._sub_mod(d, x3))
        y3 = self._sub_mod(y3, eight_c)
        var z3 = self._mul(point.y, point.z)
        z3 = self._double_mod(z3)
        return JacobianPoint(x3^, y3^, z3^)

    def _jacobian_add(
        self, left: JacobianPoint, right: JacobianPoint
    ) raises -> JacobianPoint:
        if left.z.is_zero():
            return right.copy()
        if right.z.is_zero():
            return left.copy()
        var z1_squared = self._mul(left.z, left.z)
        var z2_squared = self._mul(right.z, right.z)
        var u1 = self._mul(left.x, z2_squared)
        var u2 = self._mul(right.x, z1_squared)
        var z1_cubed = self._mul(z1_squared, left.z)
        var z2_cubed = self._mul(z2_squared, right.z)
        var s1 = self._mul(left.y, z2_cubed)
        var s2 = self._mul(right.y, z1_cubed)
        if u1.compare(u2) == 0:
            if s1.compare(s2) != 0:
                return JacobianPoint()
            return self._jacobian_double(left)
        var h = self._sub_mod(u2, u1)
        var two_h = self._double_mod(h)
        var i = self._mul(two_h, two_h)
        var j = self._mul(h, i)
        var r = self._double_mod(self._sub_mod(s2, s1))
        var v = self._mul(u1, i)
        var x3 = self._mul(r, r)
        x3 = self._sub_mod(self._sub_mod(x3, j), self._double_mod(v))
        var y3 = self._mul(r, self._sub_mod(v, x3))
        y3 = self._sub_mod(y3, self._double_mod(self._mul(s1, j)))
        var z_sum = self._add_mod(left.z, right.z)
        var z3 = self._mul(z_sum, z_sum)
        z3 = self._sub_mod(self._sub_mod(z3, z1_squared), z2_squared)
        z3 = self._mul(z3, h)
        return JacobianPoint(x3^, y3^, z3^)

    def _jacobian_add_mixed(
        self, left: JacobianPoint, right: JacobianPoint
    ) raises -> JacobianPoint:
        """Add a Jacobian point to a table point whose z coordinate is one."""
        if left.z.is_zero():
            return right.copy()
        if right.z.is_zero():
            return left.copy()
        var z_squared = self._mul(left.z, left.z)
        var u2 = self._mul(right.x, z_squared)
        var s2 = self._mul(right.y, self._mul(left.z, z_squared))
        if left.x.compare(u2) == 0:
            if left.y.compare(s2) != 0:
                return JacobianPoint()
            return self._jacobian_double(left)
        var h = self._sub_mod(u2, left.x)
        var hh = self._mul(h, h)
        var i = self._double_mod(self._double_mod(hh))
        var j = self._mul(h, i)
        var r = self._double_mod(self._sub_mod(s2, left.y))
        var v = self._mul(left.x, i)
        var x3 = self._sub_mod(
            self._sub_mod(self._mul(r, r), j), self._double_mod(v)
        )
        var y3 = self._sub_mod(
            self._mul(r, self._sub_mod(v, x3)),
            self._double_mod(self._mul(left.y, j)),
        )
        var z_plus_h = self._add_mod(left.z, h)
        var z3 = self._sub_mod(
            self._sub_mod(self._mul(z_plus_h, z_plus_h), z_squared), hh
        )
        return JacobianPoint(x3^, y3^, z3^)

    def _normalize_batch(self, mut points: List[JacobianPoint]) raises:
        """Convert non-infinity Jacobian points to z=1 with one inversion."""
        var prefixes = List[BigUInt](capacity=len(points))
        var product = BigUInt(1)
        for i in range(len(points)):
            prefixes.append(product.copy())
            if not points[i].z.is_zero():
                product = self._mul(product, points[i].z)
        var inverse = product.modular_inverse(self.p)
        for i in range(len(points) - 1, -1, -1):
            if points[i].z.is_zero():
                continue
            var z = points[i].z.copy()
            var z_inverse = self._mul(inverse, prefixes[i])
            inverse = self._mul(inverse, z)
            var z_squared = self._mul(z_inverse, z_inverse)
            points[i].x = self._mul(points[i].x, z_squared)
            points[i].y = self._mul(
                points[i].y, self._mul(z_squared, z_inverse)
            )
            points[i].z = BigUInt(1)

    def _from_jacobian(self, point: JacobianPoint) raises -> ECPoint:
        if point.z.is_zero():
            return ECPoint()
        var inverse = point.z.modular_inverse(self.p)
        var inverse_squared = self._mul(inverse, inverse)
        var x = self._mul(point.x, inverse_squared)
        var inverse_cubed = self._mul(inverse_squared, inverse)
        var y = self._mul(point.y, inverse_cubed)
        return ECPoint(x^, y^)

    def scalar_multiply(
        self, scalar: BigUInt, point: ECPoint
    ) raises -> ECPoint:
        if not self.is_on_curve(point):
            raise Error("point is not on the curve")
        if scalar.is_zero() or point.infinity:
            return ECPoint()
        var result = JacobianPoint()
        var addend = JacobianPoint(point.x.copy(), point.y.copy(), BigUInt(1))
        if scalar.bit_length() < 32:
            for i in range(scalar.bit_length()):
                if scalar.bit(i) != 0:
                    result = self._jacobian_add(result, addend)
                addend = self._jacobian_double(addend)
        else:
            var table = List[JacobianPoint](capacity=16)
            table.append(JacobianPoint())
            table.append(addend.copy())
            for i in range(2, 16):
                table.append(self._jacobian_add(table[i - 1], addend))
            var windows = (scalar.bit_length() + 3) // 4
            for window in range(windows - 1, -1, -1):
                for _ in range(4):
                    result = self._jacobian_double(result)
                var digit = 0
                for bit in range(4):
                    digit |= Int(scalar.bit(window * 4 + bit)) << bit
                if digit != 0:
                    result = self._jacobian_add(result, table[digit])
        return self._from_jacobian(result)

    def double_scalar_multiply(
        self,
        left_scalar: BigUInt,
        left_point: ECPoint,
        right_scalar: BigUInt,
        right_point: ECPoint,
    ) raises -> ECPoint:
        """Compute aP + bQ with one shared doubling chain."""
        if not self.is_on_curve(left_point) or not self.is_on_curve(
            right_point
        ):
            raise Error("point is not on the curve")
        if left_point.infinity or right_point.infinity:
            return self.add(
                self.scalar_multiply(left_scalar, left_point),
                self.scalar_multiply(right_scalar, right_point),
            )
        var left_base = JacobianPoint(
            left_point.x.copy(), left_point.y.copy(), BigUInt(1)
        )
        var right_base = JacobianPoint(
            right_point.x.copy(), right_point.y.copy(), BigUInt(1)
        )
        var left_multiples = List[JacobianPoint](capacity=4)
        var right_multiples = List[JacobianPoint](capacity=4)
        left_multiples.append(JacobianPoint())
        right_multiples.append(JacobianPoint())
        left_multiples.append(left_base.copy())
        right_multiples.append(right_base.copy())
        for i in range(2, 4):
            left_multiples.append(
                self._jacobian_add(left_multiples[i - 1], left_base)
            )
            right_multiples.append(
                self._jacobian_add(right_multiples[i - 1], right_base)
            )
        var table = List[JacobianPoint](capacity=16)
        for right_digit in range(4):
            for left_digit in range(4):
                if left_digit == 0:
                    table.append(right_multiples[right_digit].copy())
                elif right_digit == 0:
                    table.append(left_multiples[left_digit].copy())
                else:
                    table.append(
                        self._jacobian_add(
                            left_multiples[left_digit],
                            right_multiples[right_digit],
                        )
                    )
        var result = JacobianPoint()
        var bit_length = max(
            left_scalar.bit_length(), right_scalar.bit_length()
        )
        var windows = (bit_length + 1) // 2
        for window in range(windows - 1, -1, -1):
            result = self._jacobian_double(result)
            result = self._jacobian_double(result)
            var left_digit = Int(left_scalar.bit(window * 2)) | (
                Int(left_scalar.bit(window * 2 + 1)) << 1
            )
            var right_digit = Int(right_scalar.bit(window * 2)) | (
                Int(right_scalar.bit(window * 2 + 1)) << 1
            )
            var digit = right_digit * 4 + left_digit
            if digit != 0:
                result = self._jacobian_add(result, table[digit])
        return self._from_jacobian(result)


struct FixedBaseMultiplier(Movable):
    """Precomputed radix-32 table for repeated multiplication of one point."""

    var curve: PrimeCurve
    var table: List[JacobianPoint]
    var window_count: Int

    def __init__(
        out self, curve: PrimeCurve, point: ECPoint, scalar_bits: Int
    ) raises:
        if scalar_bits <= 0:
            raise Error("fixed-base scalar width must be positive")
        if point.infinity or not curve.is_on_curve(point):
            raise Error("fixed base is not on the curve")
        self.curve = curve.copy()
        self.window_count = (scalar_bits + 4) // 5
        self.table = List[JacobianPoint](capacity=self.window_count * 32)
        var bases = List[JacobianPoint](capacity=self.window_count)
        var base = JacobianPoint(point.x.copy(), point.y.copy(), BigUInt(1))
        for _ in range(self.window_count):
            bases.append(base.copy())
            for _ in range(5):
                base = self.curve._jacobian_double(base)
        self.curve._normalize_batch(bases)
        for window in range(self.window_count):
            var normalized_base = bases[window].copy()
            self.table.append(JacobianPoint())
            self.table.append(normalized_base.copy())
            for _ in range(2, 32):
                self.table.append(
                    self.curve._jacobian_add_mixed(
                        self.table[len(self.table) - 1],
                        normalized_base,
                    )
                )
        self.curve._normalize_batch(self.table)

    def __init__(out self, *, deinit move: Self):
        self.curve = move.curve^
        self.table = move.table^
        self.window_count = move.window_count

    def multiply(self, scalar: BigUInt) raises -> ECPoint:
        if scalar.bit_length() > self.window_count * 5:
            raise Error("scalar exceeds fixed-base table width")
        if scalar.is_zero():
            return ECPoint()
        var result = JacobianPoint()
        for window in range(self.window_count):
            var digit = 0
            for bit in range(5):
                digit |= Int(scalar.bit(window * 5 + bit)) << bit
            if digit != 0:
                result = self.curve._jacobian_add_mixed(
                    result, self.table[window * 32 + digit]
                )
        return self.curve._from_jacobian(result)


struct NamedPrimeCurve(Copyable, Movable):
    """A validated cofactor-one short-Weierstrass prime-order domain."""

    var name: String
    var curve: PrimeCurve
    var generator: ECPoint
    var order: BigUInt
    var field_bytes: Int

    def __init__(
        out self,
        name: String,
        p: BigUInt,
        a: BigUInt,
        b: BigUInt,
        gx: BigUInt,
        gy: BigUInt,
        order: BigUInt,
        field_bytes: Int,
        validate_generator: Bool = True,
    ) raises:
        self.name = name
        self.curve = PrimeCurve(p, a, b)
        self.generator = ECPoint(gx, gy)
        self.order = order.copy()
        self.field_bytes = field_bytes
        if self.order.compare(BigUInt(2)) < 0:
            raise Error("invalid subgroup order")
        if not self.curve.is_on_curve(self.generator):
            raise Error("generator is not on the curve")
        if (
            validate_generator
            and not self.curve.scalar_multiply(
                self.order, self.generator
            ).infinity
        ):
            raise Error("generator has the wrong subgroup order")

    def __init__(out self, *, copy: Self):
        self.name = copy.name
        self.curve = copy.curve.copy()
        self.generator = copy.generator.copy()
        self.order = copy.order.copy()
        self.field_bytes = copy.field_bytes

    def __init__(out self, *, deinit move: Self):
        self.name = move.name^
        self.curve = move.curve^
        self.generator = move.generator^
        self.order = move.order^
        self.field_bytes = move.field_bytes

    def validate_public_point(self, point: ECPoint) raises:
        if (
            point.infinity
            or point.x.compare(self.curve.p) >= 0
            or point.y.compare(self.curve.p) >= 0
        ):
            raise Error("invalid public point")
        if not self.curve.is_on_curve(point):
            raise Error("public point is not on the curve")

    def encode_point(
        self, point: ECPoint, compressed: Bool = False
    ) raises -> List[UInt8]:
        """Encode a finite point as SEC1 compressed (02/03||X) or uncompressed (04||X||Y).
        """
        self.validate_public_point(point)
        var x = biguint_to_be(point.x, self.field_bytes)
        var output = List[UInt8](
            capacity=1 + self.field_bytes * (1 if compressed else 2)
        )
        output.append(
            (
                UInt8(3) if point.y.bit(0) != 0 else UInt8(2)
            ) if compressed else UInt8(4)
        )
        for byte in x:
            output.append(byte)
        if not compressed:
            var y = biguint_to_be(point.y, self.field_bytes)
            for byte in y:
                output.append(byte)
        return output^

    def decode_point[
        origin: Origin
    ](self, encoded: Span[UInt8, origin]) raises -> ECPoint:
        """Decode and validate a SEC1 compressed or uncompressed public point.
        """
        var point: ECPoint
        if len(encoded) == 1 + 2 * self.field_bytes and encoded[0] == 4:
            point = ECPoint(
                biguint_from_be(encoded[1 : 1 + self.field_bytes]),
                biguint_from_be(encoded[1 + self.field_bytes : len(encoded)]),
            )
        elif len(encoded) == 1 + self.field_bytes and (
            encoded[0] == 2 or encoded[0] == 3
        ):
            var x = biguint_from_be(encoded[1 : len(encoded)])
            if x.compare(self.curve.p) >= 0:
                raise Error("SEC1 x-coordinate is out of range")
            var x_squared = self.curve._mul(x, x)
            var rhs = self.curve._mul(x_squared, x)
            rhs = rhs.modular_add(
                self.curve._mul(self.curve.a, x), self.curve.p
            )
            rhs = rhs.modular_add(self.curve.b, self.curve.p)
            var exponent = self.curve.p.add(BigUInt(1))
            exponent = _shift_right(exponent, 2)
            var y = rhs.modular_power(exponent, self.curve.p)
            if self.curve._mul(y, y).compare(rhs) != 0:
                raise Error("SEC1 compressed point has no square root")
            if y.bit(0) != UInt32(encoded[0] & 1):
                y = self.curve.p.subtract(y)
            point = ECPoint(x^, y^)
        else:
            raise Error("invalid SEC1 point encoding")
        self.validate_public_point(point)
        return point^


def named_curve(curve: CurveAlgorithm) raises -> NamedPrimeCurve:
    """Return a supported NIST or Brainpool prime-field domain."""
    if curve == CurveAlgorithm.BRAINPOOL_P256R1:
        # RFC 5639 section 3.4.  This is the random (r1), cofactor-one
        # Brainpool curve, not the -3-isomorphic twisted (t1) domain.
        return NamedPrimeCurve(
            "brainpoolP256r1",
            biguint_from_hex(
                "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"
            ),
            biguint_from_hex(
                "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"
            ),
            biguint_from_hex(
                "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"
            ),
            biguint_from_hex(
                "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"
            ),
            biguint_from_hex(
                "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
            ),
            biguint_from_hex(
                "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"
            ),
            32,
            False,
        )
    if curve == CurveAlgorithm.P256:
        return NamedPrimeCurve(
            "P-256",
            biguint_from_hex(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
            ),
            biguint_from_hex(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
            ),
            biguint_from_hex(
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
            ),
            biguint_from_hex(
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
            ),
            biguint_from_hex(
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
            ),
            biguint_from_hex(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
            ),
            32,
            False,
        )
    if curve == CurveAlgorithm.P384:
        return NamedPrimeCurve(
            "P-384",
            biguint_from_hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
            ),
            biguint_from_hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"
            ),
            biguint_from_hex(
                "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
            ),
            biguint_from_hex(
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
            ),
            biguint_from_hex(
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
            ),
            biguint_from_hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
            ),
            48,
            False,
        )
    if curve == CurveAlgorithm.P521:
        return NamedPrimeCurve(
            "P-521",
            biguint_from_hex(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            ),
            biguint_from_hex(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"
            ),
            biguint_from_hex(
                "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"
            ),
            biguint_from_hex(
                "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
            ),
            biguint_from_hex(
                "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
            ),
            biguint_from_hex(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
            ),
            66,
            False,
        )
    raise Error("unknown elliptic curve")
