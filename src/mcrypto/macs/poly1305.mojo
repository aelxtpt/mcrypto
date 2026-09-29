"""Poly1305 one-time authenticator in pure Mojo."""

from std.memory import bitcast
from ..internal.bytes import load_le64, store_le64


@always_inline("nodebug")
def _load_padded_aead_block[
    aad_origin: Origin, cipher_origin: Origin
](
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    offset: Int,
) -> SIMD[DType.uint8, 16]:
    var aad_bytes = (len(aad) + 15) & ~15
    var cipher_bytes = (len(ciphertext) + 15) & ~15
    var bytes = SIMD[DType.uint8, 16](0)
    if offset < aad_bytes:
        var remaining = len(aad) - offset
        if remaining >= 16:
            return aad.unsafe_ptr().unsafe_load[width=16](offset)
        for i in range(remaining):
            bytes[i] = aad[offset + i]
        return bytes
    var cipher_offset = offset - aad_bytes
    if cipher_offset < cipher_bytes:
        var remaining = len(ciphertext) - cipher_offset
        if remaining >= 16:
            return ciphertext.unsafe_ptr().unsafe_load[width=16](cipher_offset)
        for i in range(remaining):
            bytes[i] = ciphertext[cipher_offset + i]
        return bytes
    var lengths = SIMD[DType.uint64, 2](0)
    lengths[0] = UInt64(len(aad))
    lengths[1] = UInt64(len(ciphertext))
    return bitcast[DType.uint8, 16](lengths)


@always_inline("nodebug")
def _load_legacy_aead_block[
    aad_origin: Origin, cipher_origin: Origin
](
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    offset: Int,
) -> SIMD[DType.uint8, 16]:
    var aad_length_offset = len(aad)
    var cipher_offset = aad_length_offset + 8
    var cipher_length_offset = cipher_offset + len(ciphertext)
    if offset + 16 <= aad_length_offset:
        return aad.unsafe_ptr().unsafe_load[width=16](offset)
    if offset >= cipher_offset and offset + 16 <= cipher_length_offset:
        return ciphertext.unsafe_ptr().unsafe_load[width=16](
            offset - cipher_offset
        )
    var bytes = SIMD[DType.uint8, 16](0)
    var total = cipher_length_offset + 8
    for i in range(16):
        var position = offset + i
        if position >= total:
            break
        if position < aad_length_offset:
            bytes[i] = aad[position]
        elif position < cipher_offset:
            bytes[i] = UInt8(
                UInt64(len(aad)) >> UInt64((position - aad_length_offset) * 8)
            )
        elif position < cipher_length_offset:
            bytes[i] = ciphertext[position - cipher_offset]
        else:
            bytes[i] = UInt8(
                UInt64(len(ciphertext))
                >> UInt64((position - cipher_length_offset) * 8)
            )
    return bytes


def _authenticate[
    mode: Int,
    key_origin: Origin,
    message_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    output_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(key) != 32:
        raise Error("Poly1305 key must be 32 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("Poly1305 output span is too short")
    var key_low = load_le64(key, 0)
    var key_high = load_le64(key, 8)
    var r0 = key_low & UInt64(0x0FFC0FFFFFFF)
    var r1 = ((key_low >> 44) | (key_high << 20)) & UInt64(0x0FFFFFC0FFFF)
    var r2 = (key_high >> 24) & UInt64(0x00000FFFFFFC0F)
    var s1 = r1 * 20
    var s2 = r2 * 20
    # Two full blocks are folded at once as
    # ((h + m0) * r + m1) * r = (h + m0) * r^2 + m1 * r.
    # This preserves the field arithmetic while halving the carry chain.
    var rd0 = (
        UInt128(r0) * UInt128(r0)
        + UInt128(r1) * UInt128(s2)
        + UInt128(r2) * UInt128(s1)
    )
    var rd1 = (
        UInt128(r0) * UInt128(r1)
        + UInt128(r1) * UInt128(r0)
        + UInt128(r2) * UInt128(s2)
    )
    var rd2 = (
        UInt128(r0) * UInt128(r2)
        + UInt128(r1) * UInt128(r1)
        + UInt128(r2) * UInt128(r0)
    )
    var rcarry = UInt64(rd0 >> 44)
    var rr0 = UInt64(rd0) & UInt64(0xFFFFFFFFFFF)
    rd1 += UInt128(rcarry)
    rcarry = UInt64(rd1 >> 44)
    var rr1 = UInt64(rd1) & UInt64(0xFFFFFFFFFFF)
    rd2 += UInt128(rcarry)
    rcarry = UInt64(rd2 >> 42)
    var rr2 = UInt64(rd2) & UInt64(0x3FFFFFFFFFF)
    rr0 += rcarry * 5
    rcarry = rr0 >> 44
    rr0 &= UInt64(0xFFFFFFFFFFF)
    rr1 += rcarry
    var ss1 = rr1 * 20
    var ss2 = rr2 * 20
    var h0 = UInt64(0)
    var h1 = UInt64(0)
    var h2 = UInt64(0)
    var offset = 0
    var input_bytes = len(message)
    comptime if mode == 1:
        input_bytes = (
            ((len(aad) + 15) & ~15) + ((len(ciphertext) + 15) & ~15) + 16
        )
    else:
        comptime if mode == 2:
            input_bytes = len(aad) + len(ciphertext) + 16
    var message_pointer = message.unsafe_ptr()
    while offset + 32 <= input_bytes:
        var first_bytes: SIMD[DType.uint8, 16]
        var second_bytes: SIMD[DType.uint8, 16]
        comptime if mode == 1:
            first_bytes = _load_padded_aead_block(aad, ciphertext, offset)
            second_bytes = _load_padded_aead_block(aad, ciphertext, offset + 16)
        else:
            comptime if mode == 2:
                first_bytes = _load_legacy_aead_block(aad, ciphertext, offset)
                second_bytes = _load_legacy_aead_block(
                    aad, ciphertext, offset + 16
                )
            else:
                first_bytes = message_pointer.unsafe_load[width=16](offset)
                second_bytes = message_pointer.unsafe_load[width=16](
                    offset + 16
                )
        var first_words = bitcast[DType.uint64, 2](first_bytes)
        var second_words = bitcast[DType.uint64, 2](second_bytes)
        var first_low = UInt64(first_words[0])
        var first_high = UInt64(first_words[1])
        var second_low = UInt64(second_words[0])
        var second_high = UInt64(second_words[1])
        var x0 = h0 + (first_low & UInt64(0xFFFFFFFFFFF))
        var x1 = h1 + (
            ((first_low >> 44) | (first_high << 20)) & UInt64(0xFFFFFFFFFFF)
        )
        var x2 = h2 + (
            ((first_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (UInt64(1) << 40)
        )
        var m0 = second_low & UInt64(0xFFFFFFFFFFF)
        var m1 = ((second_low >> 44) | (second_high << 20)) & UInt64(
            0xFFFFFFFFFFF
        )
        var m2 = ((second_high >> 24) & UInt64(0x3FFFFFFFFFF)) | (
            UInt64(1) << 40
        )
        var bd0 = (
            UInt128(x0) * UInt128(rr0)
            + UInt128(x1) * UInt128(ss2)
            + UInt128(x2) * UInt128(ss1)
            + UInt128(m0) * UInt128(r0)
            + UInt128(m1) * UInt128(s2)
            + UInt128(m2) * UInt128(s1)
        )
        var bd1 = (
            UInt128(x0) * UInt128(rr1)
            + UInt128(x1) * UInt128(rr0)
            + UInt128(x2) * UInt128(ss2)
            + UInt128(m0) * UInt128(r1)
            + UInt128(m1) * UInt128(r0)
            + UInt128(m2) * UInt128(s2)
        )
        var bd2 = (
            UInt128(x0) * UInt128(rr2)
            + UInt128(x1) * UInt128(rr1)
            + UInt128(x2) * UInt128(rr0)
            + UInt128(m0) * UInt128(r2)
            + UInt128(m1) * UInt128(r1)
            + UInt128(m2) * UInt128(r0)
        )
        var batch_carry = UInt64(bd0 >> 44)
        h0 = UInt64(bd0) & UInt64(0xFFFFFFFFFFF)
        bd1 += UInt128(batch_carry)
        batch_carry = UInt64(bd1 >> 44)
        h1 = UInt64(bd1) & UInt64(0xFFFFFFFFFFF)
        bd2 += UInt128(batch_carry)
        batch_carry = UInt64(bd2 >> 42)
        h2 = UInt64(bd2) & UInt64(0x3FFFFFFFFFF)
        h0 += batch_carry * 5
        batch_carry = h0 >> 44
        h0 &= UInt64(0xFFFFFFFFFFF)
        h1 += batch_carry
        offset += 32
    while offset < input_bytes:
        var size = min(16, input_bytes - offset)
        var bytes = SIMD[DType.uint8, 16](0)
        var high_bit = UInt64(0)
        comptime if mode == 1:
            bytes = _load_padded_aead_block(aad, ciphertext, offset)
            high_bit = UInt64(1) << 40
        else:
            comptime if mode == 2:
                bytes = _load_legacy_aead_block(aad, ciphertext, offset)
                if size == 16:
                    high_bit = UInt64(1) << 40
                else:
                    bytes[size] = 1
            else:
                if size == 16:
                    bytes = message_pointer.unsafe_load[width=16](offset)
                    high_bit = UInt64(1) << 40
                else:
                    for i in range(size):
                        bytes[i] = message_pointer.unsafe_load(offset + i)
                    bytes[size] = 1
        var words = bitcast[DType.uint64, 2](bytes)
        var low = UInt64(words[0])
        var high = UInt64(words[1])
        h0 += low & UInt64(0xFFFFFFFFFFF)
        h1 += ((low >> 44) | (high << 20)) & UInt64(0xFFFFFFFFFFF)
        h2 += ((high >> 24) & UInt64(0x3FFFFFFFFFF)) | high_bit
        var d0 = (
            UInt128(h0) * UInt128(r0)
            + UInt128(h1) * UInt128(s2)
            + UInt128(h2) * UInt128(s1)
        )
        var d1 = (
            UInt128(h0) * UInt128(r1)
            + UInt128(h1) * UInt128(r0)
            + UInt128(h2) * UInt128(s2)
        )
        var d2 = (
            UInt128(h0) * UInt128(r2)
            + UInt128(h1) * UInt128(r1)
            + UInt128(h2) * UInt128(r0)
        )
        var carry = UInt64(d0 >> 44)
        h0 = UInt64(d0) & UInt64(0xFFFFFFFFFFF)
        d1 += UInt128(carry)
        carry = UInt64(d1 >> 44)
        h1 = UInt64(d1) & UInt64(0xFFFFFFFFFFF)
        d2 += UInt128(carry)
        carry = UInt64(d2 >> 42)
        h2 = UInt64(d2) & UInt64(0x3FFFFFFFFFF)
        h0 += carry * 5
        carry = h0 >> 44
        h0 &= UInt64(0xFFFFFFFFFFF)
        h1 += carry
        offset += size
    var carry = h1 >> 44
    h1 &= UInt64(0xFFFFFFFFFFF)
    h2 += carry
    carry = h2 >> 42
    h2 &= UInt64(0x3FFFFFFFFFF)
    h0 += carry * 5
    carry = h0 >> 44
    h0 &= UInt64(0xFFFFFFFFFFF)
    h1 += carry
    var g0 = h0 + 5
    carry = g0 >> 44
    g0 &= UInt64(0xFFFFFFFFFFF)
    var g1 = h1 + carry
    carry = g1 >> 44
    g1 &= UInt64(0xFFFFFFFFFFF)
    var g2 = h2 + carry - (UInt64(1) << 42)
    var mask = (g2 >> 63) - 1
    var inverse_mask = ~mask
    h0 = (h0 & inverse_mask) | (g0 & mask)
    h1 = (h1 & inverse_mask) | (g1 & mask)
    h2 = (h2 & inverse_mask) | (g2 & mask)
    var low = h0 | (h1 << 44)
    var high = (h1 >> 20) | (h2 << 24)
    var first = UInt128(low) + UInt128(load_le64(key, 16))
    var second = UInt128(high) + UInt128(load_le64(key, 24)) + (first >> 64)
    store_le64(UInt64(first), output, output_offset)
    store_le64(UInt64(second), output, output_offset + 8)


def authenticate_into[
    key_origin: Origin,
    message_origin: Origin,
    output_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int = 0,
) raises:
    var unused_aad = InlineArray[UInt8, 1](uninitialized=True)
    var unused_ciphertext = InlineArray[UInt8, 1](uninitialized=True)
    _authenticate[0](
        key,
        message,
        Span(unused_aad)[0:0],
        Span(unused_ciphertext)[0:0],
        output,
        output_offset,
    )


def authenticate[
    key_origin: Origin, message_origin: Origin
](
    key: Span[UInt8, key_origin], message: Span[UInt8, message_origin]
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    authenticate_into(key, message, Span(output))
    return output^


def authenticate_padded_parts[
    key_origin: Origin, aad_origin: Origin, cipher_origin: Origin
](
    key: Span[UInt8, key_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
) raises -> List[UInt8]:
    """Authenticate RFC 8439 AEAD input without materializing its padding."""
    var unused = InlineArray[UInt8, 1](fill=0)
    var output = List[UInt8](length=16, fill=0)
    _authenticate[1](key, Span(unused), aad, ciphertext, Span(output), 0)
    return output^


def authenticate_legacy_parts[
    key_origin: Origin, aad_origin: Origin, cipher_origin: Origin
](
    key: Span[UInt8, key_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
) raises -> List[UInt8]:
    """Authenticate original ChaCha20-Poly1305 input without concatenating."""
    var unused = InlineArray[UInt8, 1](fill=0)
    var output = List[UInt8](length=16, fill=0)
    _authenticate[2](key, Span(unused), aad, ciphertext, Span(output), 0)
    return output^
