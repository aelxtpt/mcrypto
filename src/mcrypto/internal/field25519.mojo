"""Fixed radix-2^51 arithmetic modulo 2^255 - 19."""

from .bytes import load_le64, store_le64

comptime MASK51 = UInt64(0x7FFFFFFFFFFFF)


@always_inline("nodebug")
def reduce(mut value: InlineArray[UInt64, 5]):
    var carry = value[0] >> 51
    value[0] &= MASK51
    value[1] += carry
    carry = value[1] >> 51
    value[1] &= MASK51
    value[2] += carry
    carry = value[2] >> 51
    value[2] &= MASK51
    value[3] += carry
    carry = value[3] >> 51
    value[3] &= MASK51
    value[4] += carry
    carry = value[4] >> 51
    value[4] &= MASK51
    value[0] += 19 * carry
    carry = value[0] >> 51
    value[0] &= MASK51
    value[1] += carry


@always_inline("nodebug")
def select(
    mut left: InlineArray[UInt64, 5],
    mut right: InlineArray[UInt64, 5],
    bit: UInt64,
):
    var mask = UInt64(0) - bit
    comptime for i in range(5):
        var swapped = mask & (left[i] ^ right[i])
        left[i] ^= swapped
        right[i] ^= swapped


@always_inline("nodebug")
def add(
    mut output: InlineArray[UInt64, 5],
    left: InlineArray[UInt64, 5],
    right: InlineArray[UInt64, 5],
):
    comptime for i in range(5):
        output[i] = left[i] + right[i]


@always_inline("nodebug")
def add_inplace(
    mut left: InlineArray[UInt64, 5],
    right: InlineArray[UInt64, 5],
):
    comptime for i in range(5):
        left[i] += right[i]


@always_inline("nodebug")
def subtract(
    mut output: InlineArray[UInt64, 5],
    left: InlineArray[UInt64, 5],
    right: InlineArray[UInt64, 5],
):
    output[0] = left[0] + 2 * (MASK51 - 18) - right[0]
    comptime for i in range(1, 5):
        output[i] = left[i] + 2 * MASK51 - right[i]


@always_inline("nodebug")
def subtract_inplace(
    mut left: InlineArray[UInt64, 5],
    right: InlineArray[UInt64, 5],
):
    left[0] = left[0] + 2 * (MASK51 - 18) - right[0]
    comptime for i in range(1, 5):
        left[i] = left[i] + 2 * MASK51 - right[i]


@always_inline("nodebug")
def negate(
    mut output: InlineArray[UInt64, 5],
    value: InlineArray[UInt64, 5],
):
    output[0] = 2 * (MASK51 - 18) - value[0]
    comptime for i in range(1, 5):
        output[i] = 2 * MASK51 - value[i]


@always_inline("nodebug")
def _store_product(
    mut output: InlineArray[UInt64, 5],
    c0: UInt128,
    c1: UInt128,
    c2: UInt128,
    c3: UInt128,
    c4: UInt128,
):
    var r1 = c1 + (c0 >> 51)
    var r2 = c2 + (r1 >> 51)
    var r3 = c3 + (r2 >> 51)
    var r4 = c4 + (r3 >> 51)
    output[0] = UInt64(c0 & UInt128(MASK51))
    output[1] = UInt64(r1 & UInt128(MASK51))
    output[2] = UInt64(r2 & UInt128(MASK51))
    output[3] = UInt64(r3 & UInt128(MASK51))
    output[4] = UInt64(r4 & UInt128(MASK51))
    output[0] += UInt64(r4 >> 51) * 19
    reduce(output)


@always_inline("nodebug")
def multiply(
    mut output: InlineArray[UInt64, 5],
    left: InlineArray[UInt64, 5],
    right: InlineArray[UInt64, 5],
):
    var a0 = UInt128(left[0])
    var a1 = UInt128(left[1])
    var a2 = UInt128(left[2])
    var a3 = UInt128(left[3])
    var a4 = UInt128(left[4])
    var b0 = UInt128(right[0])
    var b1 = UInt128(right[1])
    var b2 = UInt128(right[2])
    var b3 = UInt128(right[3])
    var b4 = UInt128(right[4])
    var c0 = a0 * b0 + UInt128(19) * (a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1)
    var c1 = a0 * b1 + a1 * b0 + UInt128(19) * (a2 * b4 + a3 * b3 + a4 * b2)
    var c2 = a0 * b2 + a1 * b1 + a2 * b0 + UInt128(19) * (a3 * b4 + a4 * b3)
    var c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + UInt128(19) * a4 * b4
    var c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
    _store_product(output, c0, c1, c2, c3, c4)


@always_inline("nodebug")
def multiply_inplace(
    mut left: InlineArray[UInt64, 5],
    right: InlineArray[UInt64, 5],
):
    var a0 = UInt128(left[0])
    var a1 = UInt128(left[1])
    var a2 = UInt128(left[2])
    var a3 = UInt128(left[3])
    var a4 = UInt128(left[4])
    var b0 = UInt128(right[0])
    var b1 = UInt128(right[1])
    var b2 = UInt128(right[2])
    var b3 = UInt128(right[3])
    var b4 = UInt128(right[4])
    var c0 = a0 * b0 + UInt128(19) * (a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1)
    var c1 = a0 * b1 + a1 * b0 + UInt128(19) * (a2 * b4 + a3 * b3 + a4 * b2)
    var c2 = a0 * b2 + a1 * b1 + a2 * b0 + UInt128(19) * (a3 * b4 + a4 * b3)
    var c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + UInt128(19) * a4 * b4
    var c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
    _store_product(left, c0, c1, c2, c3, c4)


@always_inline("nodebug")
def square(
    mut output: InlineArray[UInt64, 5],
    value: InlineArray[UInt64, 5],
):
    var a0 = UInt128(value[0])
    var a1 = UInt128(value[1])
    var a2 = UInt128(value[2])
    var a3 = UInt128(value[3])
    var a4 = UInt128(value[4])
    var c0 = a0 * a0 + UInt128(38) * (a1 * a4 + a2 * a3)
    var c1 = (
        UInt128(2) * a0 * a1 + UInt128(38) * a2 * a4 + UInt128(19) * a3 * a3
    )
    var c2 = UInt128(2) * a0 * a2 + a1 * a1 + UInt128(38) * a3 * a4
    var c3 = UInt128(2) * (a0 * a3 + a1 * a2) + UInt128(19) * a4 * a4
    var c4 = UInt128(2) * (a0 * a4 + a1 * a3) + a2 * a2
    _store_product(output, c0, c1, c2, c3, c4)


@always_inline("nodebug")
def square_inplace(mut value: InlineArray[UInt64, 5]):
    var a0 = UInt128(value[0])
    var a1 = UInt128(value[1])
    var a2 = UInt128(value[2])
    var a3 = UInt128(value[3])
    var a4 = UInt128(value[4])
    var c0 = a0 * a0 + UInt128(38) * (a1 * a4 + a2 * a3)
    var c1 = (
        UInt128(2) * a0 * a1 + UInt128(38) * a2 * a4 + UInt128(19) * a3 * a3
    )
    var c2 = UInt128(2) * a0 * a2 + a1 * a1 + UInt128(38) * a3 * a4
    var c3 = UInt128(2) * (a0 * a3 + a1 * a2) + UInt128(19) * a4 * a4
    var c4 = UInt128(2) * (a0 * a4 + a1 * a3) + a2 * a2
    _store_product(value, c0, c1, c2, c3, c4)


@always_inline("nodebug")
def multiply_small(
    mut output: InlineArray[UInt64, 5],
    value: InlineArray[UInt64, 5],
    scalar: UInt64,
):
    var c0 = UInt128(value[0]) * UInt128(scalar)
    var c1 = UInt128(value[1]) * UInt128(scalar) + (c0 >> 51)
    var c2 = UInt128(value[2]) * UInt128(scalar) + (c1 >> 51)
    var c3 = UInt128(value[3]) * UInt128(scalar) + (c2 >> 51)
    var c4 = UInt128(value[4]) * UInt128(scalar) + (c3 >> 51)
    output[0] = UInt64(c0 & UInt128(MASK51))
    output[1] = UInt64(c1 & UInt128(MASK51))
    output[2] = UInt64(c2 & UInt128(MASK51))
    output[3] = UInt64(c3 & UInt128(MASK51))
    output[4] = UInt64(c4 & UInt128(MASK51))
    output[0] += UInt64(c4 >> 51) * 19
    reduce(output)


@always_inline("nodebug")
def multiply_small_inplace(mut value: InlineArray[UInt64, 5], scalar: UInt64):
    var c0 = UInt128(value[0]) * UInt128(scalar)
    var c1 = UInt128(value[1]) * UInt128(scalar) + (c0 >> 51)
    var c2 = UInt128(value[2]) * UInt128(scalar) + (c1 >> 51)
    var c3 = UInt128(value[3]) * UInt128(scalar) + (c2 >> 51)
    var c4 = UInt128(value[4]) * UInt128(scalar) + (c3 >> 51)
    value[0] = UInt64(c0 & UInt128(MASK51))
    value[1] = UInt64(c1 & UInt128(MASK51))
    value[2] = UInt64(c2 & UInt128(MASK51))
    value[3] = UInt64(c3 & UInt128(MASK51))
    value[4] = UInt64(c4 & UInt128(MASK51))
    value[0] += UInt64(c4 >> 51) * 19
    reduce(value)


@always_inline("nodebug")
def square_n(
    mut output: InlineArray[UInt64, 5],
    value: InlineArray[UInt64, 5],
    count: Int,
):
    comptime for i in range(5):
        output[i] = value[i]
    for _ in range(count):
        square_inplace(output)


@always_inline("nodebug")
def square_n_inplace(mut value: InlineArray[UInt64, 5], count: Int):
    for _ in range(count):
        square_inplace(value)


def inverse(
    mut output: InlineArray[UInt64, 5],
    value: InlineArray[UInt64, 5],
):
    var z2 = InlineArray[UInt64, 5](fill=0)
    var z9 = InlineArray[UInt64, 5](fill=0)
    var z11 = InlineArray[UInt64, 5](fill=0)
    var z2_5_0 = InlineArray[UInt64, 5](fill=0)
    var z2_10_0 = InlineArray[UInt64, 5](fill=0)
    var z2_20_0 = InlineArray[UInt64, 5](fill=0)
    var z2_50_0 = InlineArray[UInt64, 5](fill=0)
    var z2_100_0 = InlineArray[UInt64, 5](fill=0)
    var temporary = InlineArray[UInt64, 5](fill=0)
    square(z2, value)
    square(temporary, z2)
    square_inplace(temporary)
    multiply(z9, temporary, value)
    multiply(z11, z9, z2)
    square(temporary, z11)
    multiply(z2_5_0, temporary, z9)
    square_n(temporary, z2_5_0, 5)
    multiply(z2_10_0, temporary, z2_5_0)
    square_n(temporary, z2_10_0, 10)
    multiply(z2_20_0, temporary, z2_10_0)
    square_n(temporary, z2_20_0, 20)
    multiply_inplace(temporary, z2_20_0)
    square_n_inplace(temporary, 10)
    multiply(z2_50_0, temporary, z2_10_0)
    square_n(temporary, z2_50_0, 50)
    multiply(z2_100_0, temporary, z2_50_0)
    square_n(temporary, z2_100_0, 100)
    multiply_inplace(temporary, z2_100_0)
    square_n_inplace(temporary, 50)
    multiply_inplace(temporary, z2_50_0)
    square_n_inplace(temporary, 5)
    multiply(output, temporary, z11)


def inverse_inplace(mut value: InlineArray[UInt64, 5]):
    var output = InlineArray[UInt64, 5](fill=0)
    inverse(output, value)
    value = output^


def pow2523(
    mut output: InlineArray[UInt64, 5],
    value: InlineArray[UInt64, 5],
):
    var z2 = InlineArray[UInt64, 5](fill=0)
    var z9 = InlineArray[UInt64, 5](fill=0)
    var z11 = InlineArray[UInt64, 5](fill=0)
    var z2_5_0 = InlineArray[UInt64, 5](fill=0)
    var z2_10_0 = InlineArray[UInt64, 5](fill=0)
    var z2_20_0 = InlineArray[UInt64, 5](fill=0)
    var z2_50_0 = InlineArray[UInt64, 5](fill=0)
    var z2_100_0 = InlineArray[UInt64, 5](fill=0)
    var temporary = InlineArray[UInt64, 5](fill=0)
    square(z2, value)
    square(temporary, z2)
    square_inplace(temporary)
    multiply(z9, temporary, value)
    multiply(z11, z9, z2)
    square(temporary, z11)
    multiply(z2_5_0, temporary, z9)
    square_n(temporary, z2_5_0, 5)
    multiply(z2_10_0, temporary, z2_5_0)
    square_n(temporary, z2_10_0, 10)
    multiply(z2_20_0, temporary, z2_10_0)
    square_n(temporary, z2_20_0, 20)
    multiply_inplace(temporary, z2_20_0)
    square_n_inplace(temporary, 10)
    multiply(z2_50_0, temporary, z2_10_0)
    square_n(temporary, z2_50_0, 50)
    multiply(z2_100_0, temporary, z2_50_0)
    square_n(temporary, z2_100_0, 100)
    multiply_inplace(temporary, z2_100_0)
    square_n_inplace(temporary, 50)
    multiply_inplace(temporary, z2_50_0)
    square_inplace(temporary)
    square_inplace(temporary)
    multiply(output, temporary, value)


def pow2523_inplace(mut value: InlineArray[UInt64, 5]):
    var output = InlineArray[UInt64, 5](fill=0)
    pow2523(output, value)
    value = output^


@always_inline("nodebug")
def unpack[
    origin: Origin
](input: Span[UInt8, origin]) raises -> InlineArray[UInt64, 5]:
    var output = InlineArray[UInt64, 5](fill=0)
    output[0] = load_le64(input, 0) & MASK51
    output[1] = (load_le64(input, 6) >> 3) & MASK51
    output[2] = (load_le64(input, 12) >> 6) & MASK51
    output[3] = (load_le64(input, 19) >> 1) & MASK51
    output[4] = (load_le64(input, 24) >> 12) & MASK51
    return output^


@always_inline("nodebug")
def _canonicalize(mut value: InlineArray[UInt64, 5]):
    reduce(value)
    reduce(value)
    var candidate = InlineArray[UInt64, 5](fill=0)
    candidate[0] = value[0] + 19
    var carry = candidate[0] >> 51
    candidate[0] &= MASK51
    comptime for i in range(1, 5):
        candidate[i] = value[i] + carry
        carry = candidate[i] >> 51
        candidate[i] &= MASK51
    var mask = UInt64(0) - carry
    comptime for i in range(5):
        value[i] = (value[i] & ~mask) | (candidate[i] & mask)


def pack_fixed(value: InlineArray[UInt64, 5]) raises -> InlineArray[UInt8, 32]:
    var reduced = value.copy()
    _canonicalize(reduced)
    var output = InlineArray[UInt8, 32](fill=0)
    var output_span = Span(output)
    store_le64(reduced[0] | (reduced[1] << 51), output_span, 0)
    store_le64((reduced[1] >> 13) | (reduced[2] << 38), output_span, 8)
    store_le64((reduced[2] >> 26) | (reduced[3] << 25), output_span, 16)
    store_le64((reduced[3] >> 39) | (reduced[4] << 12), output_span, 24)
    return output^


def pack(value: InlineArray[UInt64, 5]) raises -> List[UInt8]:
    var reduced = value.copy()
    _canonicalize(reduced)
    var output = List[UInt8](length=32, fill=0)
    var output_span = Span(output)
    store_le64(reduced[0] | (reduced[1] << 51), output_span, 0)
    store_le64((reduced[1] >> 13) | (reduced[2] << 38), output_span, 8)
    store_le64((reduced[2] >> 26) | (reduced[3] << 25), output_span, 16)
    store_le64((reduced[3] >> 39) | (reduced[4] << 12), output_span, 24)
    return output^


@always_inline("nodebug")
def equal(left: InlineArray[UInt64, 5], right: InlineArray[UInt64, 5]) -> Bool:
    var a = left.copy()
    var b = right.copy()
    _canonicalize(a)
    _canonicalize(b)
    var difference = UInt64(0)
    comptime for i in range(5):
        difference |= a[i] ^ b[i]
    return difference == 0


@always_inline("nodebug")
def is_zero(value: InlineArray[UInt64, 5]) -> Bool:
    var canonical = value.copy()
    _canonicalize(canonical)
    var combined = UInt64(0)
    comptime for i in range(5):
        combined |= canonical[i]
    return combined == 0


@always_inline("nodebug")
def is_negative(value: InlineArray[UInt64, 5]) -> Bool:
    var canonical = value.copy()
    _canonicalize(canonical)
    return (canonical[0] & 1) != 0
