"""RFC 7748 X25519 using fixed radix-2^51 field limbs."""

from ..internal.field25519 import (
    add as _add,
    add_inplace as _add_inplace,
    multiply as _multiply,
    inverse_inplace as _inverse_inplace,
    multiply_small as _multiply_small,
    multiply_inplace as _multiply_inplace,
    pack as _pack,
    select as _select,
    square as _square,
    subtract as _subtract,
    subtract_inplace as _subtract_inplace,
    unpack as _unpack,
)

comptime SCALAR_BYTES = 32
comptime POINT_BYTES = 32

comptime _BASE_POINT: InlineArray[UInt8, 32] = [
    9,
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
    0,
]


def _multiply_scalar[
    scalar_origin: Origin, point_origin: Origin
](
    scalar: Span[UInt8, scalar_origin],
    point: Span[UInt8, point_origin],
) raises -> List[UInt8]:
    if len(scalar) != 32 or len(point) != 32:
        raise Error("X25519 inputs must be 32 bytes")
    # Every byte is copied before clamping; no secret-dependent byte is left unread.
    var clamped = InlineArray[UInt8, 32](uninitialized=True)
    var clamped_pointer = Span(clamped).unsafe_ptr()
    var scalar_pointer = scalar.unsafe_ptr()
    clamped_pointer.unsafe_store[width=16](
        0, scalar_pointer.unsafe_load[width=16](0)
    )
    clamped_pointer.unsafe_store[width=16](
        16, scalar_pointer.unsafe_load[width=16](16)
    )
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    var x = _unpack(point)
    var a = InlineArray[UInt64, 5](fill=0)
    var b = x.copy()
    var c = InlineArray[UInt64, 5](fill=0)
    var d = InlineArray[UInt64, 5](fill=0)
    # Field operations below overwrite all five limbs before either scratch is read.
    var e = InlineArray[UInt64, 5](uninitialized=True)
    var f = InlineArray[UInt64, 5](uninitialized=True)
    a[0] = 1
    d[0] = 1
    var swap = UInt64(0)
    for offset in range(255):
        var position = 254 - offset
        var bit = UInt64((clamped[position >> 3] >> UInt8(position & 7)) & 1)
        swap ^= bit
        _select(a, b, swap)
        _select(c, d, swap)
        swap = bit
        _add(e, a, c)
        _subtract_inplace(a, c)
        _add(c, b, d)
        _subtract_inplace(b, d)
        _square(d, e)
        _square(f, a)
        _multiply_inplace(a, c)
        _multiply(c, b, e)
        _add(e, a, c)
        _subtract_inplace(a, c)
        _square(b, a)
        _subtract(c, d, f)
        _multiply_small(a, c, 121665)
        _add_inplace(a, d)
        _multiply_inplace(c, a)
        _multiply(a, d, f)
        _multiply(d, b, x)
        _square(b, e)
    _select(a, b, swap)
    _select(c, d, swap)
    _inverse_inplace(c)
    _multiply_inplace(a, c)
    var output = _pack(a)
    # Scan the complete shared value: low-order rejection has no early exit.
    var nonzero = UInt8(0)
    for byte in output:
        nonzero |= byte
    if nonzero == 0:
        raise Error("X25519 rejected the low-order peer point")
    return output^


def public_key[
    origin: Origin
](secret_key: Span[UInt8, origin]) raises -> List[UInt8]:
    return _multiply_scalar(secret_key, Span(materialize[_BASE_POINT]()))


def agree[
    secret_origin: Origin, public_origin: Origin
](
    secret_key: Span[UInt8, secret_origin],
    public_key: Span[UInt8, public_origin],
) raises -> List[UInt8]:
    return _multiply_scalar(secret_key, public_key)
