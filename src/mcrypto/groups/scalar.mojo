"""Pure-Mojo scalar and group operations for X25519, Ed25519, and Ristretto255."""

from .algorithm import (
    BatchedCoreAlgorithm,
    CoreAlgorithm,
    EdwardsGroupAlgorithm,
    GroupFamily,
    GroupOperation,
)
from ..key_exchange.x25519 import public_key, agree
from ..math.biguint import BigUInt
from std.collections import InlineArray
from std.memory import bitcast
from ..ciphers.stream import (
    _qr_eight,
    _hchacha,
    _hsalsa,
    _load_le32_unchecked,
    _salsa_block_chunks,
    _salsa_rounds_eight,
)
from ..hashes.keccak import keccak_f1600
from ..internal.bytes import load_le64, store_le32, store_le64
from ..internal.ed25519_base import BASE_COMB
from ..internal.field25519 import (
    add as _field_add,
    equal as _field_equal,
    inverse as _field_inverse,
    is_negative as _field_is_negative,
    is_zero as _field_is_zero,
    multiply_inplace as _field_multiply_inplace,
    multiply_small_inplace as _field_multiply_small_inplace,
    multiply as _field_multiply,
    negate as _field_negate,
    pack_fixed as _field_pack_fixed,
    pack as _field_pack,
    pow2523 as _field_pow2523,
    square as _field_square,
    subtract as _field_subtract,
    subtract_inplace as _field_subtract_inplace,
    unpack as _field_unpack,
)


@always_inline("nodebug")
def _load_le64_unchecked[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> UInt64:
    return bitcast[DType.uint64, 1](
        data.unsafe_ptr().unsafe_load[width=8](offset)
    )[0]


@always_inline("nodebug")
def _store_le64_unchecked[
    origin: MutOrigin
](value: UInt64, output: Span[mut=True, UInt8, origin], offset: Int):
    output.unsafe_ptr().unsafe_store[width=8](
        offset, bitcast[DType.uint8, 8](SIMD[DType.uint64, 1](value))
    )


comptime _D: InlineArray[UInt64, 5] = [
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]
comptime _TWO_D: InlineArray[UInt64, 5] = [
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]
comptime _SQRT_M1: InlineArray[UInt64, 5] = [
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]
comptime _INVSQRT_A_MINUS_D: InlineArray[UInt64, 5] = [
    278908739862762,
    821645201101625,
    8113234426968,
    1777959178193151,
    2118520810568447,
]
comptime _SQRT_AD_MINUS_ONE: InlineArray[UInt64, 5] = [
    2241493124984347,
    425987919032274,
    2207028919301688,
    1220490630685848,
    974799131293748,
]

comptime _SCALAR_L: InlineArray[UInt8, 32] = [
    0xED,
    0xD3,
    0xF5,
    0x5C,
    0x1A,
    0x63,
    0x12,
    0x58,
    0xD6,
    0x9C,
    0xF7,
    0xA2,
    0xDE,
    0xF9,
    0xDE,
    0x14,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x10,
]
comptime _ORDER_LIMBS: InlineArray[UInt32, 8] = [
    0x5CF5D3ED,
    0x5812631A,
    0xA2F79CD6,
    0x14DEF9DE,
    0,
    0,
    0,
    0x10000000,
]


struct _EdPoint(Copyable, Movable):
    var x: InlineArray[UInt64, 5]
    var y: InlineArray[UInt64, 5]
    var z: InlineArray[UInt64, 5]
    var t: InlineArray[UInt64, 5]

    def __init__(
        out self,
        var x: InlineArray[UInt64, 5],
        var y: InlineArray[UInt64, 5],
        var z: InlineArray[UInt64, 5],
        var t: InlineArray[UInt64, 5],
    ):
        self.x = x^
        self.y = y^
        self.z = z^
        self.t = t^


def _from_le[origin: Origin](data: Span[UInt8, origin]) -> BigUInt:
    var limbs = InlineArray[UInt32, 8](fill=0)
    for i in range(len(data)):
        limbs[i // 4] |= UInt32(data[i]) << UInt32(8 * (i % 4))
    return BigUInt.from_limbs(Span(limbs))


def _to_le(value: BigUInt, count: Int = 32) -> List[UInt8]:
    var output = List[UInt8](length=count, fill=0)
    for i in range(min((count + 3) // 4, len(value.limbs))):
        for j in range(4):
            if i * 4 + j < count:
                output[i * 4 + j] = UInt8(value.limbs[i] >> UInt32(8 * j))
    return output^


def _order() -> BigUInt:
    var limbs = materialize[_ORDER_LIMBS]()
    return BigUInt.from_limbs(Span(limbs))


@always_inline("nodebug")
def _scalar_is_zero[origin: Origin](scalar: Span[UInt8, origin]) raises -> Bool:
    if len(scalar) != 32:
        return False
    return (
        load_le64(scalar, 0)
        | load_le64(scalar, 8)
        | load_le64(scalar, 16)
        | load_le64(scalar, 24)
    ) == 0


@always_inline("nodebug")
def _scalar_is_canonical[
    origin: Origin
](scalar: Span[UInt8, origin]) raises -> Bool:
    if len(scalar) != 32:
        return False
    var value = load_le64(scalar, 0)
    var subtrahend = UInt64(0x5812631A5CF5D3ED)
    var borrow = UInt64(value < subtrahend)
    value = load_le64(scalar, 8)
    subtrahend = UInt64(0x14DEF9DEA2F79CD6) + borrow
    borrow = UInt64(value < subtrahend)
    value = load_le64(scalar, 16)
    subtrahend = borrow
    borrow = UInt64(value < subtrahend)
    value = load_le64(scalar, 24)
    subtrahend = UInt64(0x1000000000000000) + borrow
    borrow = UInt64(value < subtrahend)
    return borrow == 1


def _scalar_mod_l(mut value: InlineArray[Int64, 64]) -> List[UInt8]:
    var order = materialize[_SCALAR_L]()
    for offset in range(32):
        var i = 63 - offset
        var carry = Int64(0)
        var start = i - 32
        for j in range(start, i - 12):
            value[j] += carry - 16 * value[i] * Int64(order[j - start])
            carry = (value[j] + 128) >> 8
            value[j] -= carry << 8
        value[i - 12] += carry
        value[i] = 0
    var carry = Int64(0)
    for j in range(32):
        value[j] += carry - (value[31] >> 4) * Int64(order[j])
        carry = value[j] >> 8
        value[j] &= 255
    for j in range(32):
        value[j] -= carry * Int64(order[j])
    var output = List[UInt8](length=32, fill=0)
    for i in range(32):
        value[i + 1] += value[i] >> 8
        output[i] = UInt8(value[i] & 255)
    return output^


@always_inline("nodebug")
def _scalar_limb21[
    index: Int, origin: Origin
](value: Span[UInt8, origin]) -> Int64:
    comptime byte_offset = (index * 21) // 8
    comptime shift = (index * 21) % 8
    var word = _load_le32_unchecked(value, byte_offset)
    return Int64((word >> UInt32(shift)) & 0x1FFFFF)


@always_inline("nodebug")
def _scalar_carry21(mut limbs: InlineArray[Int64, 24], index: Int):
    var carry = (limbs[index] + (Int64(1) << 20)) >> 21
    limbs[index + 1] += carry
    limbs[index] -= carry << 21


@always_inline("nodebug")
def _scalar_fold21(mut limbs: InlineArray[Int64, 24], index: Int):
    var high = limbs[index]
    limbs[index - 12] += high * 666643
    limbs[index - 11] += high * 470296
    limbs[index - 10] += high * 654183
    limbs[index - 9] -= high * 997805
    limbs[index - 8] += high * 136657
    limbs[index - 7] -= high * 683901
    limbs[index] = 0


def _scalar_multiply_mod_l[
    left_origin: Origin, right_origin: Origin
](
    left: Span[UInt8, left_origin],
    right: Span[UInt8, right_origin],
) raises -> List[UInt8]:
    var left_limbs = InlineArray[Int64, 12](uninitialized=True)
    var right_limbs = InlineArray[Int64, 12](uninitialized=True)
    comptime for i in range(12):
        left_limbs[i] = _scalar_limb21[i](left)
        right_limbs[i] = _scalar_limb21[i](right)
    var limbs = InlineArray[Int64, 24](fill=0)
    comptime for diagonal in range(23):
        var product = Int64(0)
        comptime for left_index in range(
            max(0, diagonal - 11), min(11, diagonal) + 1
        ):
            product += (
                left_limbs[left_index] * right_limbs[diagonal - left_index]
            )
        limbs[diagonal] = product

    comptime for i in range(0, 23, 2):
        _scalar_carry21(limbs, i)
    comptime for i in range(1, 22, 2):
        _scalar_carry21(limbs, i)
    comptime for i in range(23, 17, -1):
        _scalar_fold21(limbs, i)

    comptime for i in range(6, 17, 2):
        _scalar_carry21(limbs, i)
    comptime for i in range(7, 16, 2):
        _scalar_carry21(limbs, i)
    comptime for i in range(17, 11, -1):
        _scalar_fold21(limbs, i)

    comptime for i in range(0, 12, 2):
        _scalar_carry21(limbs, i)
    comptime for i in range(1, 12, 2):
        _scalar_carry21(limbs, i)
    _scalar_fold21(limbs, 12)

    comptime for i in range(12):
        var carry = limbs[i] >> 21
        limbs[i + 1] += carry
        limbs[i] -= carry << 21
    _scalar_fold21(limbs, 12)
    comptime for i in range(11):
        var carry = limbs[i] >> 21
        limbs[i + 1] += carry
        limbs[i] -= carry << 21

    var packed = InlineArray[UInt64, 4](fill=0)
    comptime for i in range(12):
        comptime bit_offset = i * 21
        comptime word = bit_offset // 64
        comptime shift = bit_offset % 64
        packed[word] |= UInt64(limbs[i]) << UInt64(shift)
        comptime if shift > 43:
            packed[word + 1] |= UInt64(limbs[i]) >> UInt64(64 - shift)
    var output = List[UInt8](length=32, fill=0)
    Span(output).unsafe_ptr().unsafe_store[width=32](
        0,
        bitcast[DType.uint8, 32](
            Span(packed).unsafe_ptr().unsafe_load[width=4](0)
        ),
    )
    return output^


@always_inline("nodebug")
def _zero() -> InlineArray[UInt64, 5]:
    return InlineArray[UInt64, 5](fill=0)


@always_inline("nodebug")
def _one() -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](fill=0)
    output[0] = 1
    return output^


@always_inline("nodebug")
def _d() -> InlineArray[UInt64, 5]:
    return materialize[_D]()


@always_inline("nodebug")
def _sqrt_m1() -> InlineArray[UInt64, 5]:
    return materialize[_SQRT_M1]()


@always_inline("nodebug")
def _fadd(
    a: InlineArray[UInt64, 5], b: InlineArray[UInt64, 5]
) -> InlineArray[UInt64, 5]:
    # field25519 writes all five limbs; zero-fill would be dead work.
    var output = InlineArray[UInt64, 5](uninitialized=True)
    _field_add(output, a, b)
    return output^


@always_inline("nodebug")
def _fsub(
    a: InlineArray[UInt64, 5], b: InlineArray[UInt64, 5]
) -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](uninitialized=True)
    _field_subtract(output, a, b)
    return output^


@always_inline("nodebug")
def _fmul(
    a: InlineArray[UInt64, 5], b: InlineArray[UInt64, 5]
) -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](uninitialized=True)
    _field_multiply(output, a, b)
    return output^


@always_inline("nodebug")
def _fneg(a: InlineArray[UInt64, 5]) -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](uninitialized=True)
    _field_negate(output, a)
    return output^


@always_inline("nodebug")
def _fsquare(a: InlineArray[UInt64, 5]) -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](uninitialized=True)
    _field_square(output, a)
    return output^


@always_inline("nodebug")
def _finvert(a: InlineArray[UInt64, 5]) -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](uninitialized=True)
    _field_inverse(output, a)
    return output^


@always_inline("nodebug")
def _is_negative(a: InlineArray[UInt64, 5]) -> Bool:
    return _field_is_negative(a)


@always_inline("nodebug")
def _fabs(a: InlineArray[UInt64, 5]) -> InlineArray[UInt64, 5]:
    if _is_negative(a):
        return _fneg(a)
    return a.copy()


@always_inline("nodebug")
def _sqrt_ratio_m1(
    u: InlineArray[UInt64, 5], v: InlineArray[UInt64, 5]
) -> Tuple[Bool, InlineArray[UInt64, 5]]:
    if _field_is_zero(v):
        return (False, _zero())
    var v3 = _fmul(_fsquare(v), v)
    var v7 = _fmul(_fsquare(v3), v)
    var uv7 = _fmul(u, v7)
    var root = InlineArray[UInt64, 5](uninitialized=True)
    _field_pow2523(root, uv7)
    _field_multiply_inplace(root, _fmul(u, v3))
    var check = _fmul(v, _fsquare(root))
    var negative_u = _fneg(_fmul(u, _one()))
    var correct = _field_equal(check, u)
    var flipped = _field_equal(check, negative_u)
    var sqrt_m1 = _sqrt_m1()
    var flipped_i = _field_equal(_fmul(check, sqrt_m1), u)
    if flipped or flipped_i:
        root = _fmul(root, sqrt_m1)
    root = _fabs(root)
    return (correct or flipped, root^)


def _field_decode_canonical[
    origin: Origin
](data: Span[UInt8, origin]) raises -> InlineArray[UInt64, 5]:
    if len(data) != 32:
        raise Error("field element must be 32 bytes")
    var value = _field_unpack(data)
    var encoded = _field_pack_fixed(value)
    var difference = UInt8(0)
    comptime for i in range(32):
        difference |= encoded[i] ^ data[i]
    if difference != 0:
        raise Error("non-canonical field element")
    return value^


def _identity() -> _EdPoint:
    return _EdPoint(_zero(), _one(), _one(), _zero())


@always_inline("nodebug")
def _point_add(p: _EdPoint, q: _EdPoint) -> _EdPoint:
    # Every scratch is defined by its first field operation.
    var a = InlineArray[UInt64, 5](uninitialized=True)
    var b = InlineArray[UInt64, 5](uninitialized=True)
    var c = InlineArray[UInt64, 5](uninitialized=True)
    var d2 = InlineArray[UInt64, 5](uninitialized=True)
    var e = InlineArray[UInt64, 5](uninitialized=True)
    var f = InlineArray[UInt64, 5](uninitialized=True)
    var g = InlineArray[UInt64, 5](uninitialized=True)
    var h = InlineArray[UInt64, 5](uninitialized=True)
    var temporary_left = InlineArray[UInt64, 5](uninitialized=True)
    var temporary_right = InlineArray[UInt64, 5](uninitialized=True)
    _field_subtract(temporary_left, p.y, p.x)
    _field_subtract(temporary_right, q.y, q.x)
    _field_multiply(a, temporary_left, temporary_right)
    _field_add(temporary_left, p.y, p.x)
    _field_add(temporary_right, q.y, q.x)
    _field_multiply(b, temporary_left, temporary_right)
    _field_multiply(c, p.t, q.t)
    _field_multiply_inplace(c, materialize[_TWO_D]())
    _field_multiply(d2, p.z, q.z)
    _field_multiply_small_inplace(d2, 2)
    _field_subtract(e, b, a)
    _field_subtract(f, d2, c)
    _field_add(g, d2, c)
    _field_add(h, b, a)
    var x = InlineArray[UInt64, 5](uninitialized=True)
    var y = InlineArray[UInt64, 5](uninitialized=True)
    var z = InlineArray[UInt64, 5](uninitialized=True)
    var t = InlineArray[UInt64, 5](uninitialized=True)
    _field_multiply(x, e, f)
    _field_multiply(y, g, h)
    _field_multiply(z, f, g)
    _field_multiply(t, e, h)
    return _EdPoint(x^, y^, z^, t^)


@always_inline("nodebug")
def _point_double(p: _EdPoint) -> _EdPoint:
    # Every scratch is defined by its first field operation.
    var a = InlineArray[UInt64, 5](uninitialized=True)
    var b = InlineArray[UInt64, 5](uninitialized=True)
    var c = InlineArray[UInt64, 5](uninitialized=True)
    var d = InlineArray[UInt64, 5](uninitialized=True)
    var e = InlineArray[UInt64, 5](uninitialized=True)
    var f = InlineArray[UInt64, 5](uninitialized=True)
    var g = InlineArray[UInt64, 5](uninitialized=True)
    var h = InlineArray[UInt64, 5](uninitialized=True)
    var temporary = InlineArray[UInt64, 5](uninitialized=True)
    _field_square(a, p.x)
    _field_square(b, p.y)
    _field_square(c, p.z)
    _field_multiply_small_inplace(c, 2)
    _field_negate(d, a)
    _field_add(temporary, p.x, p.y)
    _field_square(e, temporary)
    _field_subtract_inplace(e, a)
    _field_subtract_inplace(e, b)
    _field_add(g, d, b)
    _field_subtract(f, g, c)
    _field_subtract(h, d, b)
    var x = InlineArray[UInt64, 5](uninitialized=True)
    var y = InlineArray[UInt64, 5](uninitialized=True)
    var z = InlineArray[UInt64, 5](uninitialized=True)
    var t = InlineArray[UInt64, 5](uninitialized=True)
    _field_multiply(x, e, f)
    _field_multiply(y, g, h)
    _field_multiply(z, f, g)
    _field_multiply(t, e, h)
    return _EdPoint(x^, y^, z^, t^)


@always_inline("nodebug")
def _point_negate(p: _EdPoint) -> _EdPoint:
    return _EdPoint(
        _fneg(_fmul(p.x, _one())),
        p.y.copy(),
        p.z.copy(),
        _fneg(_fmul(p.t, _one())),
    )


def _multiples(point: _EdPoint) -> InlineArray[_EdPoint, 16]:
    var table = InlineArray[_EdPoint, 16](fill=_identity())
    table[1] = point.copy()
    for i in range(2, 16):
        table[i] = _point_add(table[i - 1], point)
    return table^


@always_inline("nodebug")
def _select_multiple(
    table: InlineArray[_EdPoint, 16], index: UInt8
) -> _EdPoint:
    var selected_x = SIMD[DType.uint64, 4](0)
    var selected_y = SIMD[DType.uint64, 4](0)
    var selected_z = SIMD[DType.uint64, 4](0)
    var selected_t = SIMD[DType.uint64, 4](0)
    var selected_x4 = UInt64(0)
    var selected_y4 = UInt64(0)
    var selected_z4 = UInt64(0)
    var selected_t4 = UInt64(0)
    comptime for i in range(16):
        var mask = UInt64(0) - UInt64(index == UInt8(i))
        var mask_vector = SIMD[DType.uint64, 4](mask)
        selected_x |= (
            Span(table[i].x).unsafe_ptr().unsafe_load[width=4](0) & mask_vector
        )
        selected_y |= (
            Span(table[i].y).unsafe_ptr().unsafe_load[width=4](0) & mask_vector
        )
        selected_z |= (
            Span(table[i].z).unsafe_ptr().unsafe_load[width=4](0) & mask_vector
        )
        selected_t |= (
            Span(table[i].t).unsafe_ptr().unsafe_load[width=4](0) & mask_vector
        )
        selected_x4 |= table[i].x[4] & mask
        selected_y4 |= table[i].y[4] & mask
        selected_z4 |= table[i].z[4] & mask
        selected_t4 |= table[i].t[4] & mask
    # SIMD stores define limbs 0..3 and the scalar stores below define limb 4.
    var x = InlineArray[UInt64, 5](uninitialized=True)
    var y = InlineArray[UInt64, 5](uninitialized=True)
    var z = InlineArray[UInt64, 5](uninitialized=True)
    var t = InlineArray[UInt64, 5](uninitialized=True)
    Span(x).unsafe_ptr().unsafe_store[width=4](0, selected_x)
    Span(y).unsafe_ptr().unsafe_store[width=4](0, selected_y)
    Span(z).unsafe_ptr().unsafe_store[width=4](0, selected_z)
    Span(t).unsafe_ptr().unsafe_store[width=4](0, selected_t)
    x[4] = selected_x4
    y[4] = selected_y4
    z[4] = selected_z4
    t[4] = selected_t4
    return _EdPoint(x^, y^, z^, t^)


def _point_multiply[
    origin: Origin
](scalar: Span[UInt8, origin], point: _EdPoint) -> _EdPoint:
    var table = _multiples(point)
    var scalar_pointer = scalar.unsafe_ptr()
    var result = _identity()
    for offset in range(64):
        comptime for _ in range(4):
            result = _point_double(result)
        var nibble_index = 63 - offset
        var nibble = (
            scalar_pointer.unsafe_load(nibble_index >> 1)
            >> UInt8(4 * (nibble_index & 1))
        ) & 15
        result = _point_add(result, _select_multiple(table, nibble))
    return result^


@always_inline("nodebug")
def _select_base_comb(
    table: InlineArray[UInt64, 300], index: UInt8
) -> _EdPoint:
    var selected = _identity()
    var selected_x = Span(selected.x).unsafe_ptr().unsafe_load[width=4](0)
    var selected_y = Span(selected.y).unsafe_ptr().unsafe_load[width=4](0)
    var selected_z = Span(selected.z).unsafe_ptr().unsafe_load[width=4](0)
    var selected_t = Span(selected.t).unsafe_ptr().unsafe_load[width=4](0)
    var selected_x4 = selected.x[4]
    var selected_y4 = selected.y[4]
    var selected_z4 = selected.z[4]
    var selected_t4 = selected.t[4]
    var table_pointer = Span(table).unsafe_ptr()
    comptime for candidate_index in range(1, 16):
        comptime start = (candidate_index - 1) * 20
        var mask = UInt64(0) - UInt64(index == UInt8(candidate_index))
        var mask_vector = SIMD[DType.uint64, 4](mask)
        var candidate_x = table_pointer.unsafe_load[width=4](start)
        var candidate_y = table_pointer.unsafe_load[width=4](start + 5)
        var candidate_z = table_pointer.unsafe_load[width=4](start + 10)
        var candidate_t = table_pointer.unsafe_load[width=4](start + 15)
        selected_x ^= mask_vector & (selected_x ^ candidate_x)
        selected_y ^= mask_vector & (selected_y ^ candidate_y)
        selected_z ^= mask_vector & (selected_z ^ candidate_z)
        selected_t ^= mask_vector & (selected_t ^ candidate_t)
        selected_x4 ^= mask & (selected_x4 ^ table[start + 4])
        selected_y4 ^= mask & (selected_y4 ^ table[start + 9])
        selected_z4 ^= mask & (selected_z4 ^ table[start + 14])
        selected_t4 ^= mask & (selected_t4 ^ table[start + 19])
    Span(selected.x).unsafe_ptr().unsafe_store[width=4](0, selected_x)
    Span(selected.y).unsafe_ptr().unsafe_store[width=4](0, selected_y)
    Span(selected.z).unsafe_ptr().unsafe_store[width=4](0, selected_z)
    Span(selected.t).unsafe_ptr().unsafe_store[width=4](0, selected_t)
    selected.x[4] = selected_x4
    selected.y[4] = selected_y4
    selected.z[4] = selected_z4
    selected.t[4] = selected_t4
    return selected^


def _point_multiply_base[
    origin: Origin
](scalar: Span[UInt8, origin]) -> _EdPoint:
    var table = materialize[BASE_COMB]()
    var result = _identity()
    for offset in range(64):
        result = _point_double(result)
        var bit_index = 63 - offset
        var byte_index = bit_index >> 3
        var shift = UInt8(bit_index & 7)
        var index = UInt8(
            ((scalar[byte_index] >> shift) & 1)
            | (((scalar[byte_index + 8] >> shift) & 1) << 1)
            | (((scalar[byte_index + 16] >> shift) & 1) << 2)
            | (((scalar[byte_index + 24] >> shift) & 1) << 3)
        )
        result = _point_add(result, _select_base_comb(table, index))
    return result^


def _ed_decode[origin: Origin](encoded: Span[UInt8, origin]) raises -> _EdPoint:
    if len(encoded) != 32:
        raise Error("Ed25519 point must be 32 bytes")
    # The copy defines all bytes before canonical decoding.
    var bytes = InlineArray[UInt8, 32](uninitialized=True)
    var bytes_pointer = Span(bytes).unsafe_ptr()
    var encoded_pointer = encoded.unsafe_ptr()
    bytes_pointer.unsafe_store[width=16](
        0, encoded_pointer.unsafe_load[width=16](0)
    )
    bytes_pointer.unsafe_store[width=16](
        16, encoded_pointer.unsafe_load[width=16](16)
    )
    var sign = (bytes[31] >> 7) != 0
    bytes[31] &= 0x7F
    var y = _field_decode_canonical(Span(bytes))
    var y2 = _fsquare(y)
    var numerator = _fsub(y2, _one())
    var denominator = _fadd(_fmul(_d(), y2), _one())
    var roots = _sqrt_ratio_m1(numerator, denominator)
    var square = roots[0]
    var x = roots[1].copy()
    if not square:
        raise Error("invalid Ed25519 point")
    if _field_is_zero(x) and sign:
        raise Error("non-canonical Ed25519 sign bit")
    if _is_negative(x) != sign:
        x = _fneg(x)
    var t = _fmul(x, y)
    return _EdPoint(x^, y^, _one(), t^)


def _ed_encode(point: _EdPoint) raises -> List[UInt8]:
    if _field_is_zero(point.z):
        raise Error("invalid projective point")
    var inverse_z = _finvert(point.z)
    var x = _fmul(point.x, inverse_z)
    var y = _fmul(point.y, inverse_z)
    var output = _field_pack(y)
    if _is_negative(x):
        output[31] |= 0x80
    return output^


def _ristretto_decode[
    origin: Origin
](encoded: Span[UInt8, origin]) raises -> _EdPoint:
    if len(encoded) != 32:
        raise Error("Ristretto255 point must be 32 bytes")
    var s = _field_decode_canonical(encoded)
    if _is_negative(s):
        raise Error("non-canonical Ristretto255 point")
    var ss = _fsquare(s)
    var u1 = _fsub(_one(), ss)
    var u2 = _fadd(_one(), ss)
    var u1_sq = _fsquare(u1)
    var u2_sq = _fsquare(u2)
    var v = _fsub(_fneg(_fmul(_d(), u1_sq)), u2_sq)
    var roots = _sqrt_ratio_m1(_one(), _fmul(v, u2_sq))
    var square = roots[0]
    var inverse_sqrt = roots[1].copy()
    var dx = _fmul(inverse_sqrt, u2)
    var dy = _fmul(_fmul(inverse_sqrt, dx), v)
    var x = _fabs(_fmul(_fadd(s, s), dx))
    var y = _fmul(u1, dy)
    var t = _fmul(x, y)
    if not square or _is_negative(t) or _field_is_zero(y):
        raise Error("invalid Ristretto255 point")
    return _EdPoint(x^, y^, _one(), t^)


@always_inline("nodebug")
def _invsqrt_a_minus_d() -> InlineArray[UInt64, 5]:
    return materialize[_INVSQRT_A_MINUS_D]()


@always_inline("nodebug")
def _sqrt_ad_minus_one() -> InlineArray[UInt64, 5]:
    return materialize[_SQRT_AD_MINUS_ONE]()


def _ristretto_encode(point: _EdPoint) raises -> List[UInt8]:
    var u1 = _fmul(_fadd(point.z, point.y), _fsub(point.z, point.y))
    var u2 = _fmul(point.x, point.y)
    var roots = _sqrt_ratio_m1(_one(), _fmul(u1, _fsquare(u2)))
    var square = roots[0]
    var inverse_sqrt = roots[1].copy()
    if not square:
        raise Error("point is not in the Ristretto255 group")
    var den1 = _fmul(inverse_sqrt, u1)
    var den2 = _fmul(inverse_sqrt, u2)
    var z_inverse = _fmul(_fmul(den1, den2), point.t)
    var ix = _fmul(point.x, _sqrt_m1())
    var iy = _fmul(point.y, _sqrt_m1())
    var enchanted_denominator = _fmul(den1, _invsqrt_a_minus_d())
    var x = point.x.copy()
    var y = point.y.copy()
    var denominator = den2.copy()
    if _is_negative(_fmul(point.t, z_inverse)):
        x = iy^
        y = ix^
        denominator = enchanted_denominator^
    if _is_negative(_fmul(x, z_inverse)):
        y = _fneg(y)
    return _field_pack(_fabs(_fmul(denominator, _fsub(point.z, y))))


def _ristretto_map(r0: InlineArray[UInt64, 5]) raises -> _EdPoint:
    var r = _fmul(_sqrt_m1(), _fsquare(r0))
    var ns = _fmul(_fadd(r, _one()), _fsub(_one(), _fsquare(_d())))
    var c = _fneg(_one())
    var denominator = _fmul(_fsub(c, _fmul(_d(), r)), _fadd(r, _d()))
    var roots = _sqrt_ratio_m1(ns, denominator)
    var square = roots[0]
    var s = roots[1].copy()
    if not square:
        s = _fneg(_fabs(_fmul(s, r0)))
        c = r.copy()
    var nt = _fsub(
        _fmul(_fmul(c, _fsub(r, _one())), _fsquare(_fsub(_d(), _one()))),
        denominator,
    )
    var s_sq = _fsquare(s)
    var w0 = _fmul(_fadd(s, s), denominator)
    var w1 = _fmul(nt, _sqrt_ad_minus_one())
    var w2 = _fsub(_one(), s_sq)
    var w3 = _fadd(_one(), s_sq)
    return _EdPoint(_fmul(w0, w3), _fmul(w2, w1), _fmul(w1, w3), _fmul(w0, w2))


def _ristretto_from_hash[
    origin: Origin
](uniform: Span[UInt8, origin]) raises -> List[UInt8]:
    if len(uniform) != 64:
        raise Error("Ristretto255 hash input must be 64 bytes")
    # Both halves are fully copied before their high bits are masked.
    var first_bytes = InlineArray[UInt8, 32](uninitialized=True)
    var second_bytes = InlineArray[UInt8, 32](uninitialized=True)
    var first_pointer = Span(first_bytes).unsafe_ptr()
    var second_pointer = Span(second_bytes).unsafe_ptr()
    var uniform_pointer = uniform.unsafe_ptr()
    first_pointer.unsafe_store[width=16](
        0, uniform_pointer.unsafe_load[width=16](0)
    )
    first_pointer.unsafe_store[width=16](
        16, uniform_pointer.unsafe_load[width=16](16)
    )
    second_pointer.unsafe_store[width=16](
        0, uniform_pointer.unsafe_load[width=16](32)
    )
    second_pointer.unsafe_store[width=16](
        16, uniform_pointer.unsafe_load[width=16](48)
    )
    first_bytes[31] &= 0x7F
    second_bytes[31] &= 0x7F
    var first = _ristretto_map(_field_unpack(Span(first_bytes)))
    var second = _ristretto_map(_field_unpack(Span(second_bytes)))
    return _ristretto_encode(_point_add(first, second))


def _clamped_ed_scalar_bytes[
    origin: Origin
](scalar: Span[UInt8, origin]) -> InlineArray[UInt8, 32]:
    var bytes = InlineArray[UInt8, 32](uninitialized=True)
    var bytes_pointer = Span(bytes).unsafe_ptr()
    var scalar_pointer = scalar.unsafe_ptr()
    bytes_pointer.unsafe_store[width=16](
        0, scalar_pointer.unsafe_load[width=16](0)
    )
    bytes_pointer.unsafe_store[width=16](
        16, scalar_pointer.unsafe_load[width=16](16)
    )
    bytes[0] &= 248
    bytes[31] &= 127
    bytes[31] |= 64
    return bytes^


@always_inline("nodebug")
def _is_identity(point: _EdPoint) -> Bool:
    return _field_is_zero(point.x) and _field_equal(point.y, point.z)


def _point_multiply_order(point: _EdPoint) -> _EdPoint:
    var order = materialize[_SCALAR_L]()
    return _point_multiply(Span(order), point)


def _is_main_subgroup(point: _EdPoint) -> Bool:
    # Exact multiplication by L is retained; no cofactor-only shortcut is valid.
    return _is_identity(_point_multiply_order(point))


def _is_valid_ed_point(point: _EdPoint) -> Bool:
    if _is_identity(point) or not _is_main_subgroup(point):
        return False
    return True


@always_inline("nodebug")
def _require_canonical_scalar[
    origin: Origin
](scalar: Span[UInt8, origin]) raises -> BigUInt:
    if len(scalar) != 32:
        raise Error("scalar must be 32 bytes")
    if not _scalar_is_canonical(scalar):
        raise Error("scalar must be canonical")
    return _from_le(scalar)


def scalar_reduce[
    origin: Origin
](scalar: Span[UInt8, origin]) raises -> List[UInt8]:
    if len(scalar) != 64:
        raise Error("scalar reduction input must be 64 bytes")
    # The public contract fixes 64 input bytes, all copied before reduction.
    var expanded = InlineArray[Int64, 64](uninitialized=True)
    var expanded_pointer = Span(expanded).unsafe_ptr()
    var scalar_pointer = scalar.unsafe_ptr()
    comptime for i in range(0, 64, 4):
        expanded_pointer.unsafe_store[width=4](
            i, scalar_pointer.unsafe_load[width=4](i).cast[DType.int64]()
        )
    return _scalar_mod_l(expanded)


def scalar_invert[
    origin: Origin
](scalar: Span[UInt8, origin]) raises -> List[UInt8]:
    var value = _require_canonical_scalar(scalar)
    if value.is_zero():
        raise Error("zero scalar has no inverse")
    return _to_le(value.modular_inverse(_order()))


def scalar_base[
    origin: Origin
](family: GroupFamily, scalar: Span[UInt8, origin]) raises -> List[UInt8]:
    if len(scalar) != 32:
        raise Error("scalar must be 32 bytes")
    if family == GroupFamily.X25519:
        return public_key(scalar)
    if family == GroupFamily.ED25519:
        if _scalar_is_zero(scalar):
            raise Error("Ed25519 scalar must be nonzero")
        var clamped = _clamped_ed_scalar_bytes(scalar)
        return _ed_encode(_point_multiply_base(Span(clamped)))
    if family == GroupFamily.RISTRETTO255:
        if _scalar_is_zero(scalar) or not _scalar_is_canonical(scalar):
            raise Error("Ristretto255 scalar must be canonical and nonzero")
        return _ristretto_encode(_point_multiply_base(scalar))
    raise Error("unknown scalar family")


def scalar_mult[
    scalar_origin: Origin, point_origin: Origin
](
    family: GroupFamily,
    scalar: Span[UInt8, scalar_origin],
    point: Span[UInt8, point_origin],
) raises -> List[UInt8]:
    if len(scalar) != 32 or len(point) != 32:
        raise Error("scalar and point must be 32 bytes")
    if family == GroupFamily.X25519:
        return agree(scalar, point)
    if family == GroupFamily.ED25519:
        var decoded = _ed_decode(point)
        if _scalar_is_zero(scalar):
            raise Error("Ed25519 scalar must be nonzero")
        if not _is_valid_ed_point(decoded):
            raise Error("Ed25519 point must be in the main subgroup")
        var clamped = _clamped_ed_scalar_bytes(scalar)
        var result = _point_multiply(Span(clamped), decoded)
        if _is_identity(result):
            raise Error("Ed25519 multiplication produced identity")
        return _ed_encode(result)
    if family == GroupFamily.RISTRETTO255:
        if _scalar_is_zero(scalar) or not _scalar_is_canonical(scalar):
            raise Error("Ristretto255 scalar must be canonical and nonzero")
        var decoded = _ristretto_decode(point)
        var result = _point_multiply(scalar, decoded)
        if _is_identity(result):
            raise Error("Ristretto255 multiplication produced identity")
        return _ristretto_encode(result)
    raise Error("unknown scalar family")


@always_inline("nodebug")
def _salsa_core[
    round_count: Int,
    key_origin: Origin,
    input_origin: Origin,
](
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    """The interop Salsa20 core with its standard 32-byte-key constant."""
    if len(key) != 32 or len(input) != 16:
        raise Error("Salsa20 core requires a 32-byte key and 16-byte input")
    var state = InlineArray[UInt32, 16](fill=0)
    var key_words = bitcast[DType.uint32, 8](
        key.unsafe_ptr().unsafe_load[width=32](0)
    )
    var input_words = bitcast[DType.uint32, 4](
        input.unsafe_ptr().unsafe_load[width=16](0)
    )
    state[0] = 0x61707865
    comptime for i in range(4):
        state[1 + i] = key_words[i]
    state[5] = 0x3320646E
    comptime for i in range(4):
        state[6 + i] = input_words[i]
    state[10] = 0x79622D32
    comptime for i in range(4):
        state[11 + i] = key_words[4 + i]
    state[15] = 0x6B206574
    var chunks = _salsa_block_chunks[round_count](state)
    var output = List[UInt8](length=64, fill=0)
    var output_pointer = Span(output).unsafe_ptr()
    comptime for chunk in range(4):
        output_pointer.unsafe_store[width=16](
            chunk * 16, bitcast[DType.uint8, 16](chunks[chunk])
        )
    return output^


def _keccak_f1600_bytes[
    origin: Origin
](encoded_state: Span[UInt8, origin]) raises -> List[UInt8]:
    """Apply Keccak-f[1600] to its canonical 25-lane little-endian state."""
    if len(encoded_state) != 200:
        raise Error("Keccak-f1600 core requires a 200-byte state")
    var state = InlineArray[UInt64, 25](fill=0)
    comptime for lane in range(25):
        state[lane] = _load_le64_unchecked(encoded_state, lane * 8)
    keccak_f1600(state)
    var output = List[UInt8](length=200, fill=0)
    var output_span = Span(output)
    comptime for lane in range(25):
        _store_le64_unchecked(state[lane], output_span, lane * 8)
    return output^


@always_inline("nodebug")
def hchacha20_core[
    key_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    """Apply the HChaCha20 core to one key and input block."""
    if len(key) != 32 or len(input) != 16:
        raise Error("HChaCha20 core requires a 32-byte key and 16-byte input")
    return _hchacha(key, input)


@always_inline("nodebug")
def hsalsa20_core[
    key_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    """Apply the HSalsa20 core to one key and input block."""
    if len(key) != 32 or len(input) != 16:
        raise Error("HSalsa20 core requires a 32-byte key and 16-byte input")
    return _hsalsa(key, input)


@always_inline("nodebug")
def salsa20_core[
    round_count: Int,
    key_origin: Origin,
    input_origin: Origin,
](
    key: Span[UInt8, key_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    """Apply the Salsa20 core with a compile-time round count."""
    return _salsa_core[round_count](key, input)


def core_operation_eight_into[
    key_origin: Origin,
    input_origin: Origin,
    output_origin: MutOrigin,
](
    family: BatchedCoreAlgorithm,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    """Apply eight identical ChaCha/Salsa core operations in SIMD lanes."""
    if (
        len(key) != 32
        or len(input) != 16
        or len(output)
        != (
            32 if family == BatchedCoreAlgorithm.HCHACHA20
            or family == BatchedCoreAlgorithm.HSALSA20 else 64
        )
    ):
        raise Error("invalid batched core spans")
    var state = InlineArray[UInt32, 16](fill=0)
    var key_words = bitcast[DType.uint32, 8](
        key.unsafe_ptr().unsafe_load[width=32](0)
    )
    var input_words = bitcast[DType.uint32, 4](
        input.unsafe_ptr().unsafe_load[width=16](0)
    )
    if family == BatchedCoreAlgorithm.HCHACHA20:
        state[0] = 0x61707865
        state[1] = 0x3320646E
        state[2] = 0x79622D32
        state[3] = 0x6B206574
        comptime for i in range(8):
            state[4 + i] = key_words[i]
        comptime for i in range(4):
            state[12 + i] = input_words[i]
        var lanes = InlineArray[SIMD[DType.uint32, 8], 16](uninitialized=True)
        comptime for word in range(16):
            lanes[word] = SIMD[DType.uint32, 8](state[word])
        comptime for _ in range(10):
            _qr_eight[0, 4, 8, 12](lanes)
            _qr_eight[1, 5, 9, 13](lanes)
            _qr_eight[2, 6, 10, 14](lanes)
            _qr_eight[3, 7, 11, 15](lanes)
            _qr_eight[0, 5, 10, 15](lanes)
            _qr_eight[1, 6, 11, 12](lanes)
            _qr_eight[2, 7, 8, 13](lanes)
            _qr_eight[3, 4, 9, 14](lanes)
        var output_words = SIMD[DType.uint32, 8](
            lanes[0][0],
            lanes[1][0],
            lanes[2][0],
            lanes[3][0],
            lanes[12][0],
            lanes[13][0],
            lanes[14][0],
            lanes[15][0],
        )
        output.unsafe_ptr().unsafe_store[width=32](
            0, bitcast[DType.uint8, 32](output_words)
        )
        return
    state[0] = 0x61707865
    comptime for i in range(4):
        state[1 + i] = key_words[i]
    state[5] = 0x3320646E
    comptime for i in range(4):
        state[6 + i] = input_words[i]
    state[10] = 0x79622D32
    comptime for i in range(4):
        state[11 + i] = key_words[4 + i]
    state[15] = 0x6B206574
    var lanes = InlineArray[SIMD[DType.uint32, 8], 16](uninitialized=True)
    comptime for word in range(16):
        lanes[word] = SIMD[DType.uint32, 8](state[word])
    if family == BatchedCoreAlgorithm.HSALSA20:
        _salsa_rounds_eight[20](lanes)
        var output_words = SIMD[DType.uint32, 8](
            lanes[0][0],
            lanes[5][0],
            lanes[10][0],
            lanes[15][0],
            lanes[6][0],
            lanes[7][0],
            lanes[8][0],
            lanes[9][0],
        )
        output.unsafe_ptr().unsafe_store[width=32](
            0, bitcast[DType.uint8, 32](output_words)
        )
        return
    if family == BatchedCoreAlgorithm.SALSA20:
        _salsa_rounds_eight[20](lanes)
    elif family == BatchedCoreAlgorithm.SALSA20_12:
        _salsa_rounds_eight[12](lanes)
    elif family == BatchedCoreAlgorithm.SALSA20_8:
        _salsa_rounds_eight[8](lanes)
    else:
        raise Error("unsupported batched core")
    comptime for word in range(16):
        store_le32(lanes[word][0] + state[word], output, 4 * word)


def core_operation_eight[
    key_origin: Origin, input_origin: Origin
](
    family: BatchedCoreAlgorithm,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    """Apply eight identical ChaCha/Salsa core operations in SIMD lanes."""
    var output = List[UInt8](
        length=(
            32 if family == BatchedCoreAlgorithm.HCHACHA20
            or family == BatchedCoreAlgorithm.HSALSA20 else 64
        ),
        fill=0,
    )
    core_operation_eight_into(family, key, input, Span(output))
    return output^


def keccak_f1600_core[
    origin: Origin
](encoded_state: Span[UInt8, origin]) raises -> List[UInt8]:
    """Apply Keccak-f[1600] to a canonical encoded state."""
    return _keccak_f1600_bytes(encoded_state)


def keccak_f1600_core_into[
    input_origin: Origin, output_origin: MutOrigin
](
    encoded_state: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    """Apply Keccak-f[1600] into caller-owned 200-byte storage."""
    if len(encoded_state) != 200 or len(output) != 200:
        raise Error("Keccak-f1600 core requires 200-byte spans")
    var state = InlineArray[UInt64, 25](fill=0)
    comptime for lane in range(25):
        state[lane] = _load_le64_unchecked(encoded_state, lane * 8)
    keccak_f1600(state)
    comptime for lane in range(25):
        _store_le64_unchecked(state[lane], output, lane * 8)


def scalar_multiply_mod_l[
    left_origin: Origin, right_origin: Origin
](
    left: Span[UInt8, left_origin], right: Span[UInt8, right_origin]
) raises -> List[UInt8]:
    """Multiply two canonical Ed25519-group scalars modulo L."""
    if len(left) != 32 or len(right) != 32:
        raise Error("scalar must be 32 bytes")
    if not _scalar_is_canonical(left) or not _scalar_is_canonical(right):
        raise Error("scalar must be canonical")
    return _scalar_multiply_mod_l(left, right)


def core_operation[
    left_origin: Origin, right_origin: Origin
](
    algorithm: CoreAlgorithm,
    left: Span[UInt8, left_origin],
    right: Span[UInt8, right_origin],
) raises -> List[UInt8]:
    if algorithm == CoreAlgorithm.HCHACHA20:
        return hchacha20_core(left, right)
    if algorithm == CoreAlgorithm.HSALSA20:
        return hsalsa20_core(left, right)
    if algorithm == CoreAlgorithm.SALSA20:
        return salsa20_core[20](left, right)
    if algorithm == CoreAlgorithm.SALSA20_12:
        return salsa20_core[12](left, right)
    if algorithm == CoreAlgorithm.SALSA20_8:
        return salsa20_core[8](left, right)
    if algorithm == CoreAlgorithm.KECCAK_F1600:
        if len(right) != 0:
            raise Error("Keccak-f1600 core does not accept a second operand")
        return keccak_f1600_core(left)
    raise Error("invalid core algorithm selector")


def group_operation[
    left_origin: Origin, right_origin: Origin
](
    algorithm: EdwardsGroupAlgorithm,
    operation: GroupOperation,
    left: Span[UInt8, left_origin],
    right: Span[UInt8, right_origin],
) raises -> List[UInt8]:
    if (
        algorithm != EdwardsGroupAlgorithm.ED25519
        and algorithm != EdwardsGroupAlgorithm.RISTRETTO255
    ):
        raise Error("invalid Edwards-group selector")
    if operation == GroupOperation.SCALAR_MUL:
        return scalar_multiply_mod_l(left, right)
    if operation == GroupOperation.SCALAR_REDUCE or (
        operation == GroupOperation.FROM_HASH
        and algorithm == EdwardsGroupAlgorithm.RISTRETTO255
    ):
        var wide = InlineArray[UInt8, 64](fill=0)
        if len(left) == 64:
            comptime for i in range(64):
                wide[i] = left[i]
        elif len(left) == 32 and len(right) == 32:
            comptime for i in range(32):
                wide[i] = left[i]
                wide[32 + i] = right[i]
        else:
            raise Error("operation requires 64 bytes")
        if operation == GroupOperation.SCALAR_REDUCE:
            return scalar_reduce(Span(wide))
        return _ristretto_from_hash(Span(wide))
    if operation == GroupOperation.SCALAR_INVERT:
        return scalar_invert(left)
    if operation == GroupOperation.IS_VALID:
        try:
            if algorithm == EdwardsGroupAlgorithm.ED25519:
                if not _is_valid_ed_point(_ed_decode(left)):
                    raise Error("invalid Ed25519 subgroup point")
            else:
                _ = _ristretto_decode(left)
            return [UInt8(1)]
        except:
            return [UInt8(0)]
    if operation == GroupOperation.ADD or operation == GroupOperation.SUB:
        var lpoint = _ed_decode(
            left
        ) if algorithm == EdwardsGroupAlgorithm.ED25519 else _ristretto_decode(
            left
        )
        var rpoint = _ed_decode(
            right
        ) if algorithm == EdwardsGroupAlgorithm.ED25519 else _ristretto_decode(
            right
        )
        if operation == GroupOperation.SUB:
            rpoint = _point_negate(rpoint)
        var result = _point_add(lpoint, rpoint)
        return _ed_encode(
            result
        ) if algorithm == EdwardsGroupAlgorithm.ED25519 else _ristretto_encode(
            result
        )
    if (
        operation != GroupOperation.SCALAR_ADD
        and operation != GroupOperation.SCALAR_SUB
        and operation != GroupOperation.SCALAR_NEGATE
        and operation != GroupOperation.SCALAR_COMPLEMENT
    ):
        raise Error("unknown core group operation")
    var modulus = _order()
    var l = _require_canonical_scalar(left)
    if operation == GroupOperation.SCALAR_NEGATE:
        return _to_le(BigUInt(0).modular_subtract(l, modulus))
    if operation == GroupOperation.SCALAR_COMPLEMENT:
        return _to_le(BigUInt(1).modular_subtract(l, modulus))
    var r = _require_canonical_scalar(right)
    if operation == GroupOperation.SCALAR_ADD:
        return _to_le(l.modular_add(r, modulus))
    return _to_le(l.modular_subtract(r, modulus))
