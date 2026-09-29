"""Allocation-free Poly1305 framing for secretstream records."""

from std.memory import bitcast

from ..internal.bytes import load_le64, store_le64


@always_inline("nodebug")
def _field_multiply(
    left: InlineArray[UInt64, 3],
    right: InlineArray[UInt64, 3],
) -> InlineArray[UInt64, 3]:
    var right1_20 = right[1] * 20
    var right2_20 = right[2] * 20
    var d0 = (
        UInt128(left[0]) * UInt128(right[0])
        + UInt128(left[1]) * UInt128(right2_20)
        + UInt128(left[2]) * UInt128(right1_20)
    )
    var d1 = (
        UInt128(left[0]) * UInt128(right[1])
        + UInt128(left[1]) * UInt128(right[0])
        + UInt128(left[2]) * UInt128(right2_20)
    )
    var d2 = (
        UInt128(left[0]) * UInt128(right[2])
        + UInt128(left[1]) * UInt128(right[1])
        + UInt128(left[2]) * UInt128(right[0])
    )
    var carry = UInt64(d0 >> 44)
    var h0 = UInt64(d0) & UInt64(0xFFFFFFFFFFF)
    d1 += UInt128(carry)
    carry = UInt64(d1 >> 44)
    var h1 = UInt64(d1) & UInt64(0xFFFFFFFFFFF)
    d2 += UInt128(carry)
    carry = UInt64(d2 >> 42)
    var h2 = UInt64(d2) & UInt64(0x3FFFFFFFFFF)
    h0 += carry * 5
    carry = h0 >> 44
    h0 &= UInt64(0xFFFFFFFFFFF)
    h1 += carry
    var output: InlineArray[UInt64, 3] = [h0, h1, h2]
    return output^


def _field_power(
    base0: UInt64, base1: UInt64, base2: UInt64, exponent: Int
) -> InlineArray[UInt64, 3]:
    var result: InlineArray[UInt64, 3] = [1, 0, 0]
    var base: InlineArray[UInt64, 3] = [base0, base1, base2]
    var remaining = exponent
    while remaining != 0:
        if remaining & 1 != 0:
            result = _field_multiply(result, base)
        remaining >>= 1
        if remaining != 0:
            base = _field_multiply(base, base)
    return result^


struct _Poly1305:
    var r0: UInt64
    var r1: UInt64
    var r2: UInt64
    var s1: UInt64
    var s2: UInt64
    var rr0: UInt64
    var rr1: UInt64
    var rr2: UInt64
    var ss1: UInt64
    var ss2: UInt64
    var tr0: UInt64
    var tr1: UInt64
    var tr2: UInt64
    var ts1: UInt64
    var ts2: UInt64
    var fr0: UInt64
    var fr1: UInt64
    var fr2: UInt64
    var fs1: UInt64
    var fs2: UInt64
    var h0: UInt64
    var h1: UInt64
    var h2: UInt64
    var pad0: UInt64
    var pad1: UInt64

    @always_inline("nodebug")
    def __init__[origin: Origin](out self, key: Span[UInt8, origin]) raises:
        if len(key) != 32:
            raise Error("Poly1305 key must be 32 bytes")
        var key_low = load_le64(key, 0)
        var key_high = load_le64(key, 8)
        self.r0 = key_low & UInt64(0x0FFC0FFFFFFF)
        self.r1 = ((key_low >> 44) | (key_high << 20)) & UInt64(0x0FFFFFC0FFFF)
        self.r2 = (key_high >> 24) & UInt64(0x00000FFFFFFC0F)
        self.s1 = self.r1 * 20
        self.s2 = self.r2 * 20
        var rd0 = (
            UInt128(self.r0) * UInt128(self.r0)
            + UInt128(self.r1) * UInt128(self.s2)
            + UInt128(self.r2) * UInt128(self.s1)
        )
        var rd1 = (
            UInt128(self.r0) * UInt128(self.r1)
            + UInt128(self.r1) * UInt128(self.r0)
            + UInt128(self.r2) * UInt128(self.s2)
        )
        var rd2 = (
            UInt128(self.r0) * UInt128(self.r2)
            + UInt128(self.r1) * UInt128(self.r1)
            + UInt128(self.r2) * UInt128(self.r0)
        )
        var carry = UInt64(rd0 >> 44)
        self.rr0 = UInt64(rd0) & UInt64(0xFFFFFFFFFFF)
        rd1 += UInt128(carry)
        carry = UInt64(rd1 >> 44)
        self.rr1 = UInt64(rd1) & UInt64(0xFFFFFFFFFFF)
        rd2 += UInt128(carry)
        carry = UInt64(rd2 >> 42)
        self.rr2 = UInt64(rd2) & UInt64(0x3FFFFFFFFFF)
        self.rr0 += carry * 5
        carry = self.rr0 >> 44
        self.rr0 &= UInt64(0xFFFFFFFFFFF)
        self.rr1 += carry
        self.ss1 = self.rr1 * 20
        self.ss2 = self.rr2 * 20
        var td0 = (
            UInt128(self.rr0) * UInt128(self.r0)
            + UInt128(self.rr1) * UInt128(self.s2)
            + UInt128(self.rr2) * UInt128(self.s1)
        )
        var td1 = (
            UInt128(self.rr0) * UInt128(self.r1)
            + UInt128(self.rr1) * UInt128(self.r0)
            + UInt128(self.rr2) * UInt128(self.s2)
        )
        var td2 = (
            UInt128(self.rr0) * UInt128(self.r2)
            + UInt128(self.rr1) * UInt128(self.r1)
            + UInt128(self.rr2) * UInt128(self.r0)
        )
        carry = UInt64(td0 >> 44)
        self.tr0 = UInt64(td0) & UInt64(0xFFFFFFFFFFF)
        td1 += UInt128(carry)
        carry = UInt64(td1 >> 44)
        self.tr1 = UInt64(td1) & UInt64(0xFFFFFFFFFFF)
        td2 += UInt128(carry)
        carry = UInt64(td2 >> 42)
        self.tr2 = UInt64(td2) & UInt64(0x3FFFFFFFFFF)
        self.tr0 += carry * 5
        carry = self.tr0 >> 44
        self.tr0 &= UInt64(0xFFFFFFFFFFF)
        self.tr1 += carry
        self.ts1 = self.tr1 * 20
        self.ts2 = self.tr2 * 20
        var fd0 = (
            UInt128(self.rr0) * UInt128(self.rr0)
            + UInt128(self.rr1) * UInt128(self.ss2)
            + UInt128(self.rr2) * UInt128(self.ss1)
        )
        var fd1 = (
            UInt128(self.rr0) * UInt128(self.rr1)
            + UInt128(self.rr1) * UInt128(self.rr0)
            + UInt128(self.rr2) * UInt128(self.ss2)
        )
        var fd2 = (
            UInt128(self.rr0) * UInt128(self.rr2)
            + UInt128(self.rr1) * UInt128(self.rr1)
            + UInt128(self.rr2) * UInt128(self.rr0)
        )
        carry = UInt64(fd0 >> 44)
        self.fr0 = UInt64(fd0) & UInt64(0xFFFFFFFFFFF)
        fd1 += UInt128(carry)
        carry = UInt64(fd1 >> 44)
        self.fr1 = UInt64(fd1) & UInt64(0xFFFFFFFFFFF)
        fd2 += UInt128(carry)
        carry = UInt64(fd2 >> 42)
        self.fr2 = UInt64(fd2) & UInt64(0x3FFFFFFFFFF)
        self.fr0 += carry * 5
        carry = self.fr0 >> 44
        self.fr0 &= UInt64(0xFFFFFFFFFFF)
        self.fr1 += carry
        self.fs1 = self.fr1 * 20
        self.fs2 = self.fr2 * 20
        self.h0 = 0
        self.h1 = 0
        self.h2 = 0
        self.pad0 = load_le64(key, 16)
        self.pad1 = load_le64(key, 24)

    def combine(mut self, other: Self, blocks: Int):
        """Append an independently accumulated full-block segment."""
        var power = _field_power(self.r0, self.r1, self.r2, blocks)
        var current: InlineArray[UInt64, 3] = [
            self.h0,
            self.h1,
            self.h2,
        ]
        var shifted = _field_multiply(current, power)
        self.h0 = shifted[0] + other.h0
        self.h1 = shifted[1] + other.h1
        self.h2 = shifted[2] + other.h2
        var carry = self.h0 >> 44
        self.h0 &= UInt64(0xFFFFFFFFFFF)
        self.h1 += carry
        carry = self.h1 >> 44
        self.h1 &= UInt64(0xFFFFFFFFFFF)
        self.h2 += carry
        carry = self.h2 >> 42
        self.h2 &= UInt64(0x3FFFFFFFFFF)
        self.h0 += carry * 5
        carry = self.h0 >> 44
        self.h0 &= UInt64(0xFFFFFFFFFFF)
        self.h1 += carry

    @always_inline("nodebug")
    def update_block[origin: Origin](mut self, block: Span[UInt8, origin]):
        var size = len(block)
        var bytes = SIMD[DType.uint8, 16](0)
        var high_bit = UInt64(0)
        if size == 16:
            bytes = block.unsafe_ptr().unsafe_load[width=16](0)
            high_bit = UInt64(1) << 40
        else:
            for i in range(size):
                bytes[i] = block[i]
            bytes[size] = 1
        var words = bitcast[DType.uint64, 2](bytes)
        var low = UInt64(words[0])
        var high = UInt64(words[1])
        self.h0 += low & UInt64(0xFFFFFFFFFFF)
        self.h1 += ((low >> 44) | (high << 20)) & UInt64(0xFFFFFFFFFFF)
        self.h2 += ((high >> 24) & UInt64(0x3FFFFFFFFFF)) | high_bit
        var d0 = (
            UInt128(self.h0) * UInt128(self.r0)
            + UInt128(self.h1) * UInt128(self.s2)
            + UInt128(self.h2) * UInt128(self.s1)
        )
        var d1 = (
            UInt128(self.h0) * UInt128(self.r1)
            + UInt128(self.h1) * UInt128(self.r0)
            + UInt128(self.h2) * UInt128(self.s2)
        )
        var d2 = (
            UInt128(self.h0) * UInt128(self.r2)
            + UInt128(self.h1) * UInt128(self.r1)
            + UInt128(self.h2) * UInt128(self.r0)
        )
        var carry = UInt64(d0 >> 44)
        self.h0 = UInt64(d0) & UInt64(0xFFFFFFFFFFF)
        d1 += UInt128(carry)
        carry = UInt64(d1 >> 44)
        self.h1 = UInt64(d1) & UInt64(0xFFFFFFFFFFF)
        d2 += UInt128(carry)
        carry = UInt64(d2 >> 42)
        self.h2 = UInt64(d2) & UInt64(0x3FFFFFFFFFF)
        self.h0 += carry * 5
        carry = self.h0 >> 44
        self.h0 &= UInt64(0xFFFFFFFFFFF)
        self.h1 += carry

    @always_inline("nodebug")
    def update_pair[origin: Origin](mut self, blocks: Span[UInt8, origin]):
        var pointer = blocks.unsafe_ptr()
        var first_words = bitcast[DType.uint64, 2](
            pointer.unsafe_load[width=16](0)
        )
        var second_words = bitcast[DType.uint64, 2](
            pointer.unsafe_load[width=16](16)
        )
        var first_low = UInt64(first_words[0])
        var first_high = UInt64(first_words[1])
        var second_low = UInt64(second_words[0])
        var second_high = UInt64(second_words[1])
        var x0 = self.h0 + (first_low & UInt64(0xFFFFFFFFFFF))
        var x1 = self.h1 + (
            ((first_low >> 44) | (first_high << 20)) & UInt64(0xFFFFFFFFFFF)
        )
        var x2 = self.h2 + (
            ((first_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (UInt64(1) << 40)
        )
        var m0 = second_low & UInt64(0xFFFFFFFFFFF)
        var m1 = ((second_low >> 44) | (second_high << 20)) & UInt64(
            0xFFFFFFFFFFF
        )
        var m2 = ((second_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (
            UInt64(1) << 40
        )
        var d0 = (
            UInt128(x0) * UInt128(self.rr0)
            + UInt128(x1) * UInt128(self.ss2)
            + UInt128(x2) * UInt128(self.ss1)
            + UInt128(m0) * UInt128(self.r0)
            + UInt128(m1) * UInt128(self.s2)
            + UInt128(m2) * UInt128(self.s1)
        )
        var d1 = (
            UInt128(x0) * UInt128(self.rr1)
            + UInt128(x1) * UInt128(self.rr0)
            + UInt128(x2) * UInt128(self.ss2)
            + UInt128(m0) * UInt128(self.r1)
            + UInt128(m1) * UInt128(self.r0)
            + UInt128(m2) * UInt128(self.s2)
        )
        var d2 = (
            UInt128(x0) * UInt128(self.rr2)
            + UInt128(x1) * UInt128(self.rr1)
            + UInt128(x2) * UInt128(self.rr0)
            + UInt128(m0) * UInt128(self.r2)
            + UInt128(m1) * UInt128(self.r1)
            + UInt128(m2) * UInt128(self.r0)
        )
        var carry = UInt64(d0 >> 44)
        self.h0 = UInt64(d0) & UInt64(0xFFFFFFFFFFF)
        d1 += UInt128(carry)
        carry = UInt64(d1 >> 44)
        self.h1 = UInt64(d1) & UInt64(0xFFFFFFFFFFF)
        d2 += UInt128(carry)
        carry = UInt64(d2 >> 42)
        self.h2 = UInt64(d2) & UInt64(0x3FFFFFFFFFF)
        self.h0 += carry * 5
        carry = self.h0 >> 44
        self.h0 &= UInt64(0xFFFFFFFFFFF)
        self.h1 += carry

    @always_inline("nodebug")
    def update_four[origin: Origin](mut self, blocks: Span[UInt8, origin]):
        """Fold four full blocks with independent powers r^4 through r."""
        var pointer = blocks.unsafe_ptr()
        var first = bitcast[DType.uint64, 2](pointer.unsafe_load[width=16](0))
        var second = bitcast[DType.uint64, 2](pointer.unsafe_load[width=16](16))
        var third = bitcast[DType.uint64, 2](pointer.unsafe_load[width=16](32))
        var fourth = bitcast[DType.uint64, 2](pointer.unsafe_load[width=16](48))
        var first_low = UInt64(first[0])
        var first_high = UInt64(first[1])
        var second_low = UInt64(second[0])
        var second_high = UInt64(second[1])
        var third_low = UInt64(third[0])
        var third_high = UInt64(third[1])
        var fourth_low = UInt64(fourth[0])
        var fourth_high = UInt64(fourth[1])
        var x0 = self.h0 + (first_low & UInt64(0xFFFFFFFFFFF))
        var x1 = self.h1 + (
            ((first_low >> 44) | (first_high << 20)) & UInt64(0xFFFFFFFFFFF)
        )
        var x2 = self.h2 + (
            ((first_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (UInt64(1) << 40)
        )
        var m0 = second_low & UInt64(0xFFFFFFFFFFF)
        var m1 = ((second_low >> 44) | (second_high << 20)) & UInt64(
            0xFFFFFFFFFFF
        )
        var m2 = ((second_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (
            UInt64(1) << 40
        )
        var n0 = third_low & UInt64(0xFFFFFFFFFFF)
        var n1 = ((third_low >> 44) | (third_high << 20)) & UInt64(
            0xFFFFFFFFFFF
        )
        var n2 = ((third_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (
            UInt64(1) << 40
        )
        var o0 = fourth_low & UInt64(0xFFFFFFFFFFF)
        var o1 = ((fourth_low >> 44) | (fourth_high << 20)) & UInt64(
            0xFFFFFFFFFFF
        )
        var o2 = ((fourth_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (
            UInt64(1) << 40
        )
        var d0 = (
            UInt128(x0) * UInt128(self.fr0)
            + UInt128(x1) * UInt128(self.fs2)
            + UInt128(x2) * UInt128(self.fs1)
            + UInt128(m0) * UInt128(self.tr0)
            + UInt128(m1) * UInt128(self.ts2)
            + UInt128(m2) * UInt128(self.ts1)
            + UInt128(n0) * UInt128(self.rr0)
            + UInt128(n1) * UInt128(self.ss2)
            + UInt128(n2) * UInt128(self.ss1)
            + UInt128(o0) * UInt128(self.r0)
            + UInt128(o1) * UInt128(self.s2)
            + UInt128(o2) * UInt128(self.s1)
        )
        var d1 = (
            UInt128(x0) * UInt128(self.fr1)
            + UInt128(x1) * UInt128(self.fr0)
            + UInt128(x2) * UInt128(self.fs2)
            + UInt128(m0) * UInt128(self.tr1)
            + UInt128(m1) * UInt128(self.tr0)
            + UInt128(m2) * UInt128(self.ts2)
            + UInt128(n0) * UInt128(self.rr1)
            + UInt128(n1) * UInt128(self.rr0)
            + UInt128(n2) * UInt128(self.ss2)
            + UInt128(o0) * UInt128(self.r1)
            + UInt128(o1) * UInt128(self.r0)
            + UInt128(o2) * UInt128(self.s2)
        )
        var d2 = (
            UInt128(x0) * UInt128(self.fr2)
            + UInt128(x1) * UInt128(self.fr1)
            + UInt128(x2) * UInt128(self.fr0)
            + UInt128(m0) * UInt128(self.tr2)
            + UInt128(m1) * UInt128(self.tr1)
            + UInt128(m2) * UInt128(self.tr0)
            + UInt128(n0) * UInt128(self.rr2)
            + UInt128(n1) * UInt128(self.rr1)
            + UInt128(n2) * UInt128(self.rr0)
            + UInt128(o0) * UInt128(self.r2)
            + UInt128(o1) * UInt128(self.r1)
            + UInt128(o2) * UInt128(self.r0)
        )
        var carry = UInt64(d0 >> 44)
        self.h0 = UInt64(d0) & UInt64(0xFFFFFFFFFFF)
        d1 += UInt128(carry)
        carry = UInt64(d1 >> 44)
        self.h1 = UInt64(d1) & UInt64(0xFFFFFFFFFFF)
        d2 += UInt128(carry)
        carry = UInt64(d2 >> 42)
        self.h2 = UInt64(d2) & UInt64(0x3FFFFFFFFFF)
        self.h0 += carry * 5
        carry = self.h0 >> 44
        self.h0 &= UInt64(0xFFFFFFFFFFF)
        self.h1 += carry

    @always_inline("nodebug")
    def finish_into[
        origin: MutOrigin
    ](
        mut self,
        output: Span[mut=True, UInt8, origin],
        output_offset: Int,
    ) raises:
        var carry = self.h1 >> 44
        self.h1 &= UInt64(0xFFFFFFFFFFF)
        self.h2 += carry
        carry = self.h2 >> 42
        self.h2 &= UInt64(0x3FFFFFFFFFF)
        self.h0 += carry * 5
        carry = self.h0 >> 44
        self.h0 &= UInt64(0xFFFFFFFFFFF)
        self.h1 += carry
        var g0 = self.h0 + 5
        carry = g0 >> 44
        g0 &= UInt64(0xFFFFFFFFFFF)
        var g1 = self.h1 + carry
        carry = g1 >> 44
        g1 &= UInt64(0xFFFFFFFFFFF)
        var g2 = self.h2 + carry - (UInt64(1) << 42)
        var mask = (g2 >> 63) - 1
        var inverse_mask = ~mask
        self.h0 = (self.h0 & inverse_mask) | (g0 & mask)
        self.h1 = (self.h1 & inverse_mask) | (g1 & mask)
        self.h2 = (self.h2 & inverse_mask) | (g2 & mask)
        var low = self.h0 | (self.h1 << 44)
        var high = (self.h1 >> 20) | (self.h2 << 24)
        var first = UInt128(low) + UInt128(self.pad0)
        var second = UInt128(high) + UInt128(self.pad1) + (first >> 64)
        if output_offset < 0 or output_offset + 16 > len(output):
            raise Error("Poly1305 output span is too short")
        store_le64(UInt64(first), output, output_offset)
        store_le64(UInt64(second), output, output_offset + 8)


@always_inline("nodebug")
def _authenticate_record_prefix[
    aad_origin: Origin,
    block_origin: Origin,
](
    mut poly: _Poly1305,
    aad: Span[UInt8, aad_origin],
    tag_block: Span[UInt8, block_origin],
) raises:
    var offset = 0
    while offset + 64 <= len(aad):
        poly.update_four(aad[offset : offset + 64])
        offset += 64
    if offset + 32 <= len(aad):
        poly.update_pair(aad[offset : offset + 32])
        offset += 32
    if offset + 16 <= len(aad):
        poly.update_block(aad[offset : offset + 16])
        offset += 16
    if offset < len(aad):
        var padded_aad = InlineArray[UInt8, 16](fill=0)
        for i in range(len(aad) - offset):
            padded_aad[i] = aad[offset + i]
        poly.update_block(Span(padded_aad))
    if len(tag_block) != 64:
        raise Error("secretstream tag block must be 64 bytes")
    poly.update_four(tag_block)


@always_inline("nodebug")
def _authenticate_record_suffix[
    tail_origin: Origin,
    output_origin: MutOrigin,
](
    mut poly: _Poly1305,
    ciphertext_tail: Span[UInt8, tail_origin],
    ciphertext_bytes: Int,
    aad_bytes: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int = 0,
) raises:
    var offset = 0
    if len(ciphertext_tail) >= 16:
        poly.update_block(ciphertext_tail[0:16])
        offset = 16
    var remainder = len(ciphertext_tail) - offset
    # interop's wire format intentionally preserves its historical padding
    # expression: it appends `mlen % 16` zero bytes, not conventional
    # pad-to-16 bytes.
    var tail = InlineArray[UInt8, 48](fill=0)
    for i in range(remainder):
        tail[i] = ciphertext_tail[offset + i]
    var trailer_offset = 2 * remainder
    store_le64(UInt64(aad_bytes), Span(tail), trailer_offset)
    store_le64(UInt64(64 + ciphertext_bytes), Span(tail), trailer_offset + 8)
    var tail_size = trailer_offset + 16
    var tail_offset = 0
    while tail_offset + 16 <= tail_size:
        poly.update_block(Span(tail)[tail_offset : tail_offset + 16])
        tail_offset += 16
    if tail_offset < tail_size:
        poly.update_block(Span(tail)[tail_offset:tail_size])
    poly.finish_into(output, output_offset)


@always_inline("nodebug")
def authenticate_record_into[
    key_origin: Origin,
    aad_origin: Origin,
    block_origin: Origin,
    cipher_origin: Origin,
    output_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    aad: Span[UInt8, aad_origin],
    tag_block: Span[UInt8, block_origin],
    ciphertext: Span[UInt8, cipher_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int = 0,
) raises:
    var poly = _Poly1305(key)
    _authenticate_record_prefix(poly, aad, tag_block)
    var offset = 0
    while offset + 64 <= len(ciphertext):
        poly.update_four(ciphertext[offset : offset + 64])
        offset += 64
    if offset + 32 <= len(ciphertext):
        poly.update_pair(ciphertext[offset : offset + 32])
        offset += 32
    _authenticate_record_suffix(
        poly,
        ciphertext[offset:],
        len(ciphertext),
        len(aad),
        output,
        output_offset,
    )
