"""Pure-Mojo RFC 8032 Ed25519 and Ed25519ph.

Key formats match interop: public keys are compressed Edwards points and
secret keys are ``seed || public_key``. Field arithmetic uses fixed radix-2^51
limbs; scalar reduction uses the fixed-order ref10 reduction.
"""

from ..hashes.sha512 import SHA512, sha512
from ..internal.ed25519_base import BASE_COMB
from ..internal.field25519 import (
    add_inplace as _field_add_inplace,
    add as _field_add,
    equal as _field_equal,
    inverse as _field_inverse,
    is_negative as _field_is_negative,
    is_zero as _field_is_zero,
    multiply_inplace as _field_multiply_inplace,
    multiply as _field_multiply,
    pack_fixed as _field_pack_fixed,
    multiply_small_inplace as _field_multiply_small_inplace,
    negate as _field_negate,
    pack as _field_pack,
    pow2523_inplace as _field_pow2523_inplace,
    square as _field_square,
    subtract as _field_subtract,
    subtract_inplace as _field_subtract_inplace,
    unpack as _field_unpack,
)
from ..random.entropy import system_entropy

comptime PUBLIC_KEY_BYTES = 32
comptime SEED_BYTES = 32
comptime SECRET_KEY_BYTES = 64
comptime SIGNATURE_BYTES = 64


@always_inline("nodebug")
def _join32[
    left_origin: Origin, right_origin: Origin
](
    left: Span[UInt8, left_origin],
    right: Span[UInt8, right_origin],
) -> List[
    UInt8
]:
    # Internal callers guarantee two 32-byte inputs; four stores define the result.
    var joined = List[UInt8](length=64, fill=0)
    var joined_pointer = Span(joined).unsafe_ptr()
    var left_pointer = left.unsafe_ptr()
    var right_pointer = right.unsafe_ptr()
    joined_pointer.unsafe_store[width=16](
        0, left_pointer.unsafe_load[width=16](0)
    )
    joined_pointer.unsafe_store[width=16](
        16, left_pointer.unsafe_load[width=16](16)
    )
    joined_pointer.unsafe_store[width=16](
        32, right_pointer.unsafe_load[width=16](0)
    )
    joined_pointer.unsafe_store[width=16](
        48, right_pointer.unsafe_load[width=16](16)
    )
    return joined^


comptime _D: InlineArray[UInt64, 5] = [
    0x34DCA135978A3,
    0x1A8283B156EBD,
    0x5E7A26001C029,
    0x739C663A03CBB,
    0x52036CEE2B6FF,
]
comptime _TWO_D: InlineArray[UInt64, 5] = [
    0x69B9426B2F159,
    0x35050762ADD7A,
    0x3CF44C0038052,
    0x6738CC7407977,
    0x2406D9DC56DFF,
]
comptime _SQRT_M1: InlineArray[UInt64, 5] = [
    0x61B274A0EA0B0,
    0x0D5A5FC8F189D,
    0x7EF5E9CBD0C60,
    0x78595A6804C9E,
    0x2B8324804FC1D,
]
comptime _L: InlineArray[UInt8, 32] = [
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

comptime _DOM2: InlineArray[UInt8, 34] = [
    83,
    105,
    103,
    69,
    100,
    50,
    53,
    53,
    49,
    57,
    32,
    110,
    111,
    32,
    69,
    100,
    50,
    53,
    53,
    49,
    57,
    32,
    99,
    111,
    108,
    108,
    105,
    115,
    105,
    111,
    110,
    115,
    1,
    0,
]


struct _Point(Copyable, Movable):
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
        # Coordinates are uniquely owned temporaries at every construction site.
        self.x = x^
        self.y = y^
        self.z = z^
        self.t = t^


@always_inline("nodebug")
def _one() -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](fill=0)
    output[0] = 1
    return output^


def _identity() -> _Point:
    return _Point(
        InlineArray[UInt64, 5](fill=0),
        _one(),
        _one(),
        InlineArray[UInt64, 5](fill=0),
    )


@always_inline("nodebug")
def _add(left: _Point, right: _Point) -> _Point:
    # field25519 output parameters overwrite every limb before any scratch read.
    var a = InlineArray[UInt64, 5](uninitialized=True)
    var b = InlineArray[UInt64, 5](uninitialized=True)
    var c = InlineArray[UInt64, 5](uninitialized=True)
    var d = InlineArray[UInt64, 5](uninitialized=True)
    var e = InlineArray[UInt64, 5](uninitialized=True)
    var f = InlineArray[UInt64, 5](uninitialized=True)
    var g = InlineArray[UInt64, 5](uninitialized=True)
    var h = InlineArray[UInt64, 5](uninitialized=True)
    var temporary_left = InlineArray[UInt64, 5](uninitialized=True)
    var temporary_right = InlineArray[UInt64, 5](uninitialized=True)
    _field_subtract(temporary_left, left.y, left.x)
    _field_subtract(temporary_right, right.y, right.x)
    _field_multiply(a, temporary_left, temporary_right)
    _field_add(temporary_left, left.y, left.x)
    _field_add(temporary_right, right.y, right.x)
    _field_multiply(b, temporary_left, temporary_right)
    _field_multiply(c, left.t, right.t)
    _field_multiply_inplace(c, materialize[_TWO_D]())
    _field_multiply(d, left.z, right.z)
    _field_multiply_small_inplace(d, 2)
    _field_subtract(e, b, a)
    _field_subtract(f, d, c)
    _field_add(g, d, c)
    _field_add(h, b, a)
    var x = InlineArray[UInt64, 5](uninitialized=True)
    var y = InlineArray[UInt64, 5](uninitialized=True)
    var z = InlineArray[UInt64, 5](uninitialized=True)
    var t = InlineArray[UInt64, 5](uninitialized=True)
    _field_multiply(x, e, f)
    _field_multiply(y, g, h)
    _field_multiply(z, f, g)
    _field_multiply(t, e, h)
    return _Point(x^, y^, z^, t^)


@always_inline("nodebug")
def _double(point: _Point) -> _Point:
    # Each scratch is defined by its first field operation.
    var a = InlineArray[UInt64, 5](uninitialized=True)
    var b = InlineArray[UInt64, 5](uninitialized=True)
    var c = InlineArray[UInt64, 5](uninitialized=True)
    var d = InlineArray[UInt64, 5](uninitialized=True)
    var e = InlineArray[UInt64, 5](uninitialized=True)
    var f = InlineArray[UInt64, 5](uninitialized=True)
    var g = InlineArray[UInt64, 5](uninitialized=True)
    var h = InlineArray[UInt64, 5](uninitialized=True)
    var temporary = InlineArray[UInt64, 5](uninitialized=True)
    _field_square(a, point.x)
    _field_square(b, point.y)
    _field_square(c, point.z)
    _field_multiply_small_inplace(c, 2)
    _field_negate(d, a)
    _field_add(temporary, point.x, point.y)
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
    return _Point(x^, y^, z^, t^)


def _multiples(point: _Point) -> InlineArray[_Point, 16]:
    var table = InlineArray[_Point, 16](fill=_identity())
    table[1] = point.copy()
    for i in range(2, 16):
        table[i] = _add(table[i - 1], point)
    return table^


@always_inline("nodebug")
def _select_multiple(table: InlineArray[_Point, 16], index: UInt8) -> _Point:
    # Full-table masked selection is constant-time; four limbs travel per SIMD load.
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
    return _Point(x^, y^, z^, t^)


def _scalar_multiply[
    scalar_origin: Origin
](scalar: Span[UInt8, scalar_origin], point: _Point) -> _Point:
    var table = _multiples(point)
    var scalar_pointer = scalar.unsafe_ptr()
    var result = _identity()
    for offset in range(64):
        comptime for _ in range(4):
            result = _double(result)
        var nibble_index = 63 - offset
        var nibble = (
            scalar_pointer.unsafe_load(nibble_index >> 1)
            >> UInt8(4 * (nibble_index & 1))
        ) & 15
        result = _add(result, table[Int(nibble)])
    return result^


@always_inline("nodebug")
def _select_base_comb(table: InlineArray[UInt64, 300], index: UInt8) -> _Point:
    # Candidate zero is the identity; every other candidate is scanned masked.
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


@always_inline("nodebug")
def _select_base_comb_public(
    table: InlineArray[UInt64, 300], index: UInt8
) -> _Point:
    if index == 0:
        return _identity()
    var start = (Int(index) - 1) * 20
    var pointer = Span(table).unsafe_ptr()
    var selected = _identity()
    Span(selected.x).unsafe_ptr().unsafe_store[width=4](
        0, pointer.unsafe_load[width=4](start)
    )
    Span(selected.y).unsafe_ptr().unsafe_store[width=4](
        0, pointer.unsafe_load[width=4](start + 5)
    )
    Span(selected.z).unsafe_ptr().unsafe_store[width=4](
        0, pointer.unsafe_load[width=4](start + 10)
    )
    Span(selected.t).unsafe_ptr().unsafe_store[width=4](
        0, pointer.unsafe_load[width=4](start + 15)
    )
    selected.x[4] = table[start + 4]
    selected.y[4] = table[start + 9]
    selected.z[4] = table[start + 14]
    selected.t[4] = table[start + 19]
    return selected^


def _scalar_multiply_base[
    origin: Origin
](scalar: Span[UInt8, origin]) -> _Point:
    var table = materialize[BASE_COMB]()
    var result = _identity()
    for offset in range(64):
        result = _double(result)
        var bit_index = 63 - offset
        var byte_index = bit_index >> 3
        var shift = UInt8(bit_index & 7)
        var index = UInt8(
            ((scalar[byte_index] >> shift) & 1)
            | (((scalar[byte_index + 8] >> shift) & 1) << 1)
            | (((scalar[byte_index + 16] >> shift) & 1) << 2)
            | (((scalar[byte_index + 24] >> shift) & 1) << 3)
        )
        result = _add(result, _select_base_comb(table, index))
    return result^


def _scalar_multiply_base_public[
    origin: Origin
](scalar: Span[UInt8, origin]) -> _Point:
    var table = materialize[BASE_COMB]()
    var result = _identity()
    for offset in range(64):
        result = _double(result)
        var bit_index = 63 - offset
        var byte_index = bit_index >> 3
        var shift = UInt8(bit_index & 7)
        var index = UInt8(
            ((scalar[byte_index] >> shift) & 1)
            | (((scalar[byte_index + 8] >> shift) & 1) << 1)
            | (((scalar[byte_index + 16] >> shift) & 1) << 2)
            | (((scalar[byte_index + 24] >> shift) & 1) << 3)
        )
        result = _add(result, _select_base_comb_public(table, index))
    return result^


@always_inline("nodebug")
def _equal(left: _Point, right: _Point) -> Bool:
    var left_x = InlineArray[UInt64, 5](uninitialized=True)
    var right_x = InlineArray[UInt64, 5](uninitialized=True)
    var left_y = InlineArray[UInt64, 5](uninitialized=True)
    var right_y = InlineArray[UInt64, 5](uninitialized=True)
    _field_multiply(left_x, left.x, right.z)
    _field_multiply(right_x, right.x, left.z)
    _field_multiply(left_y, left.y, right.z)
    _field_multiply(right_y, right.y, left.z)
    return _field_equal(left_x, right_x) and _field_equal(left_y, right_y)


@always_inline("nodebug")
def _is_identity(point: _Point) -> Bool:
    return _field_is_zero(point.x) and _field_equal(point.y, point.z)


def _is_small_order(point: _Point) -> Bool:
    var multiplied = point.copy()
    comptime for _ in range(3):
        multiplied = _double(multiplied)
    return _is_identity(multiplied)


def _encode(point: _Point) raises -> List[UInt8]:
    var inverse_z = InlineArray[UInt64, 5](uninitialized=True)
    var x = InlineArray[UInt64, 5](uninitialized=True)
    var y = InlineArray[UInt64, 5](uninitialized=True)
    _field_inverse(inverse_z, point.z)
    _field_multiply(x, point.x, inverse_z)
    _field_multiply(y, point.y, inverse_z)
    var output = _field_pack(y)
    if _field_is_negative(x):
        output[31] |= 0x80
    return output^


def _decode[origin: Origin](encoded: Span[UInt8, origin]) raises -> _Point:
    if len(encoded) != 32:
        raise Error("Ed25519 point encoding must be 32 bytes")
    # The fixed-size copy defines all bytes before the sign bit is inspected.
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
    var y = _field_unpack(Span(bytes))
    var canonical = _field_pack_fixed(y)
    var difference = UInt8(0)
    comptime for i in range(32):
        difference |= canonical[i] ^ bytes[i]
    if difference != 0:
        raise Error("non-canonical Ed25519 point encoding")
    var one = _one()
    var y_squared = InlineArray[UInt64, 5](uninitialized=True)
    var numerator = InlineArray[UInt64, 5](uninitialized=True)
    var denominator = InlineArray[UInt64, 5](uninitialized=True)
    _field_square(y_squared, y)
    _field_subtract(numerator, y_squared, one)
    _field_multiply(denominator, materialize[_D](), y_squared)
    _field_add_inplace(denominator, one)
    var denominator2 = InlineArray[UInt64, 5](uninitialized=True)
    var denominator4 = InlineArray[UInt64, 5](uninitialized=True)
    var denominator6 = InlineArray[UInt64, 5](uninitialized=True)
    var x = InlineArray[UInt64, 5](uninitialized=True)
    _field_square(denominator2, denominator)
    _field_square(denominator4, denominator2)
    _field_multiply(denominator6, denominator4, denominator2)
    _field_multiply(x, denominator6, numerator)
    _field_multiply_inplace(x, denominator)
    _field_pow2523_inplace(x)
    _field_multiply_inplace(x, numerator)
    _field_multiply_inplace(x, denominator)
    _field_multiply_inplace(x, denominator)
    _field_multiply_inplace(x, denominator)
    var check = InlineArray[UInt64, 5](uninitialized=True)
    _field_square(check, x)
    _field_multiply_inplace(check, denominator)
    if not _field_equal(check, numerator):
        _field_multiply_inplace(x, materialize[_SQRT_M1]())
        _field_square(check, x)
        _field_multiply_inplace(check, denominator)
        if not _field_equal(check, numerator):
            raise Error("invalid Ed25519 point encoding")
    if _field_is_zero(x) and sign:
        raise Error("non-canonical Ed25519 point sign")
    if _field_is_negative(x) != sign:
        _field_negate(x, x.copy())
    var t = InlineArray[UInt64, 5](uninitialized=True)
    _field_multiply(t, x, y)
    return _Point(x^, y^, one^, t^)


def _mod_l(mut value: InlineArray[Int64, 64]) -> InlineArray[UInt8, 32]:
    var order = materialize[_L]()
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
    var output = InlineArray[UInt8, 32](uninitialized=True)
    for i in range(32):
        value[i + 1] += value[i] >> 8
        output[i] = UInt8(value[i] & 255)
    return output^


def _reduce_scalar[
    origin: Origin
](value: Span[UInt8, origin]) -> InlineArray[UInt8, 32]:
    # All callers pass a SHA-512 digest, so all 64 coefficients are defined.
    var expanded = InlineArray[Int64, 64](uninitialized=True)
    var expanded_pointer = Span(expanded).unsafe_ptr()
    var value_pointer = value.unsafe_ptr()
    comptime for i in range(0, 64, 4):
        expanded_pointer.unsafe_store[width=4](
            i, value_pointer.unsafe_load[width=4](i).cast[DType.int64]()
        )
    return _mod_l(expanded)


def _multiply_add_scalar[
    r_origin: Origin, k_origin: Origin, a_origin: Origin
](
    r: Span[UInt8, r_origin],
    k: Span[UInt8, k_origin],
    a: Span[UInt8, a_origin],
) -> InlineArray[UInt8, 32]:
    var expanded = InlineArray[Int64, 64](fill=0)
    var expanded_pointer = Span(expanded).unsafe_ptr()
    var r_pointer = r.unsafe_ptr()
    var a_pointer = a.unsafe_ptr()
    comptime for j in range(0, 32, 4):
        expanded_pointer.unsafe_store[width=4](
            j, r_pointer.unsafe_load[width=4](j).cast[DType.int64]()
        )
    comptime for i in range(32):
        var k_value = Int64(k[i])
        comptime for j in range(0, 32, 4):
            comptime width = 4
            var products = a_pointer.unsafe_load[width=width](j).cast[
                DType.int64
            ]() * SIMD[DType.int64, width](k_value)
            expanded_pointer.unsafe_store[width=width](
                i + j,
                expanded_pointer.unsafe_load[width=width](i + j) + products,
            )
    return _mod_l(expanded)


@always_inline("nodebug")
def _is_canonical_scalar[origin: Origin](scalar: Span[UInt8, origin]) -> Bool:
    var order = materialize[_L]()
    comptime for offset in range(32):
        comptime i = 31 - offset
        if scalar[i] < order[i]:
            return True
        if scalar[i] > order[i]:
            return False
    return False


def keypair_from_seed[
    origin: Origin
](seed: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Derive a interop-compatible ``(public_key, seed || public_key)`` pair.
    """
    if len(seed) != SEED_BYTES:
        raise Error("Ed25519 seed must be 32 bytes")
    var digest = sha512(seed)
    digest[0] &= 248
    digest[31] &= 63
    digest[31] |= 64
    var public_key = _encode(_scalar_multiply_base(Span(digest)[0:32]))
    var secret_key = _join32(seed, Span(public_key))
    return (public_key^, secret_key^)


def keypair() raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate a keypair from a fresh 32-byte operating-system seed."""
    var seed = system_entropy(SEED_BYTES)
    return keypair_from_seed(Span(seed))


def _sign_impl[
    message_origin: Origin, key_origin: Origin
](
    message: Span[UInt8, message_origin],
    secret_key: Span[UInt8, key_origin],
    prehashed: Bool,
) raises -> List[UInt8]:
    if len(secret_key) != SECRET_KEY_BYTES:
        raise Error("Ed25519 secret key must be 64 bytes")
    var seed = secret_key[0:32]
    var public_key = secret_key[32:64]
    var digest = sha512(seed)
    digest[0] &= 248
    digest[31] &= 63
    digest[31] |= 64
    # DOM2 is read only on the prehashed branch, which first assigns all 34 bytes.
    var domain = InlineArray[UInt8, 34](uninitialized=True)
    if prehashed:
        domain = materialize[_DOM2]()
    var r_state = SHA512()
    if prehashed:
        r_state.update(Span(domain))
    r_state.update(Span(digest)[32:64])
    r_state.update(message)
    var r_digest = r_state.finalize()
    var r = _reduce_scalar(Span(r_digest))
    var encoded_r = _encode(_scalar_multiply_base(Span(r)))
    var k_state = SHA512()
    if prehashed:
        k_state.update(Span(domain))
    k_state.update(Span(encoded_r))
    k_state.update(public_key)
    k_state.update(message)
    var k_digest = k_state.finalize()
    var k = _reduce_scalar(Span(k_digest))
    var s = _multiply_add_scalar(Span(r), Span(k), Span(digest)[0:32])
    return _join32(Span(encoded_r), Span(s))


def sign[
    message_origin: Origin, key_origin: Origin
](
    message: Span[UInt8, message_origin],
    secret_key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    """Create an RFC 8032 Ed25519 detached signature."""
    return _sign_impl(message, secret_key, False)


def sign_ph[
    message_origin: Origin, key_origin: Origin
](
    message: Span[UInt8, message_origin],
    secret_key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    """Create an RFC 8032 Ed25519ph signature with an empty context."""
    if len(secret_key) != SECRET_KEY_BYTES:
        raise Error("Ed25519 secret key must be 64 bytes")
    var digest = sha512(message)
    return _sign_impl(Span(digest), secret_key, True)


def _verify_impl[
    signature_origin: Origin,
    message_origin: Origin,
    key_origin: Origin,
](
    signature: Span[UInt8, signature_origin],
    message: Span[UInt8, message_origin],
    public_key: Span[UInt8, key_origin],
    prehashed: Bool,
) -> Bool:
    if len(signature) != SIGNATURE_BYTES or len(public_key) != PUBLIC_KEY_BYTES:
        return False
    if not _is_canonical_scalar(signature[32:64]):
        return False
    try:
        var public_point = _decode(public_key)
        var r_point = _decode(signature[0:32])
        # Strict decoding plus small-order rejection preserves subgroup validation.
        if _is_small_order(public_point) or _is_small_order(r_point):
            return False
        # DOM2 is read only on the prehashed branch, which first assigns all bytes.
        var domain = InlineArray[UInt8, 34](uninitialized=True)
        if prehashed:
            domain = materialize[_DOM2]()
        var hash_state = SHA512()
        if prehashed:
            hash_state.update(Span(domain))
        hash_state.update(signature[0:32])
        hash_state.update(public_key)
        hash_state.update(message)
        var hash_digest = hash_state.finalize()
        var k = _reduce_scalar(Span(hash_digest))
        var left = _scalar_multiply_base_public(signature[32:64])
        var right = _add(r_point, _scalar_multiply(Span(k), public_point))
        return _equal(left, right)
    except:
        return False


def verify[
    signature_origin: Origin,
    message_origin: Origin,
    key_origin: Origin,
](
    signature: Span[UInt8, signature_origin],
    message: Span[UInt8, message_origin],
    public_key: Span[UInt8, key_origin],
) -> Bool:
    """Strictly verify an RFC 8032 Ed25519 detached signature."""
    return _verify_impl(signature, message, public_key, False)


def verify_ph[
    signature_origin: Origin,
    message_origin: Origin,
    key_origin: Origin,
](
    signature: Span[UInt8, signature_origin],
    message: Span[UInt8, message_origin],
    public_key: Span[UInt8, key_origin],
) -> Bool:
    """Strictly verify Ed25519ph with an empty context."""
    try:
        var digest = sha512(message)
        return _verify_impl(signature, Span(digest), public_key, True)
    except:
        return False
