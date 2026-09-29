"""Hex, Base32, Base64, and Base64URL transforms in pure Mojo."""
from .algorithm import EncodingTransform
from std.builtin.globals import global_constant
from std.memory import bitcast


def _hex_pairs() -> InlineArray[UInt16, 256]:
    var pairs = InlineArray[UInt16, 256](uninitialized=True)
    comptime for value in range(256):
        comptime high = value >> 4
        comptime low = value & 15
        comptime high_ascii = high + 48 + (39 if high >= 10 else 0)
        comptime low_ascii = low + 48 + (39 if low >= 10 else 0)
        pairs[value] = UInt16(high_ascii) | (UInt16(low_ascii) << 8)
    return pairs^


comptime _HEX_PAIRS = _hex_pairs()


def _hex[origin: Origin](input: Span[UInt8, origin]) -> List[UInt8]:
    var output = List[UInt8](unsafe_uninit_length=len(input) * 2)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    ref pairs = global_constant[_HEX_PAIRS]()
    var offset = 0
    while offset + 4 <= len(input):
        var packed = (
            UInt64(pairs[Int(input_pointer.unsafe_load(offset))])
            | (UInt64(pairs[Int(input_pointer.unsafe_load(offset + 1))]) << 16)
            | (UInt64(pairs[Int(input_pointer.unsafe_load(offset + 2))]) << 32)
            | (UInt64(pairs[Int(input_pointer.unsafe_load(offset + 3))]) << 48)
        )
        output_pointer.unsafe_store[width=8](
            offset * 2,
            bitcast[DType.uint8, 8](SIMD[DType.uint64, 1](packed)),
        )
        offset += 4
    comptime digits: StaticString = "0123456789abcdef"
    while offset < len(input):
        var byte = input_pointer.unsafe_load(offset)
        output_pointer.unsafe_store(
            offset * 2, UInt8(ord(digits[byte=Int(byte >> 4)]))
        )
        output_pointer.unsafe_store(
            offset * 2 + 1, UInt8(ord(digits[byte=Int(byte & 15)]))
        )
        offset += 1
    return output^


def _hex_value(c: UInt8) raises -> Int:
    if c >= 48 and c <= 57:
        return Int(c) - 48
    if c >= 65 and c <= 70:
        return Int(c) - 55
    if c >= 97 and c <= 102:
        return Int(c) - 87
    raise Error("invalid hex digit")


def _hex_decode[
    origin: Origin
](input: Span[UInt8, origin]) raises -> List[UInt8]:
    if len(input) % 2 != 0:
        raise Error("hex input length must be even")
    var output = List[UInt8](unsafe_uninit_length=len(input) // 2)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    for i in range(len(output)):
        var h = _hex_value(input_pointer.unsafe_load(i * 2))
        var l = _hex_value(input_pointer.unsafe_load(i * 2 + 1))
        output_pointer.unsafe_store(i, UInt8(h * 16 + l))
    return output^


def _base64[
    origin: Origin
](input: Span[UInt8, origin], url: Bool) -> List[UInt8]:
    var table = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" if url else "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    ).as_bytes()
    var output = List[UInt8](unsafe_uninit_length=(len(input) + 2) // 3 * 4)
    var output_pointer = Span(output).unsafe_ptr()
    for offset in range(0, len(input), 3):
        var count = min(3, len(input) - offset)
        var value = UInt32(input[offset]) << 16
        if count > 1:
            value |= UInt32(input[offset + 1]) << 8
        if count > 2:
            value |= UInt32(input[offset + 2])
        var output_offset = (offset // 3) * 4
        output_pointer.unsafe_store(
            output_offset, table[Int((value >> 18) & 63)]
        )
        output_pointer.unsafe_store(
            output_offset + 1, table[Int((value >> 12) & 63)]
        )
        output_pointer.unsafe_store(
            output_offset + 2,
            table[Int((value >> 6) & 63)] if count > 1 else UInt8(61),
        )
        output_pointer.unsafe_store(
            output_offset + 3,
            table[Int(value & 63)] if count > 2 else UInt8(61),
        )
    return output^


def _base64_decode[
    origin: Origin
](input: Span[UInt8, origin], url: Bool) raises -> List[UInt8]:
    if len(input) % 4 != 0:
        raise Error("base64 length must be divisible by four")

    var output = List[UInt8](capacity=len(input) // 4 * 3)
    for offset in range(0, len(input), 4):
        var value = UInt32(0)
        var padding = 0
        for j in range(4):
            var c = input[offset + j]
            if c == 61:
                if offset + 4 != len(input) or j < 2:
                    raise Error("invalid base64 padding")
                padding += 1
                value <<= 6
                continue
            if padding != 0:
                raise Error("invalid base64 padding")

            var v: Int
            if c >= 65 and c <= 90:
                v = Int(c) - 65
            elif c >= 97 and c <= 122:
                v = Int(c) - 71
            elif c >= 48 and c <= 57:
                v = Int(c) + 4
            elif c == UInt8(45 if url else 43):
                v = 62
            elif c == UInt8(95 if url else 47):
                v = 63
            else:
                raise Error("invalid base64 digit")
            value = (value << 6) | UInt32(v)

        if padding == 1 and (value & UInt32(255)) != 0:
            raise Error("non-zero base64 trailing bits")
        if padding == 2 and (value & UInt32(65535)) != 0:
            raise Error("non-zero base64 trailing bits")

        output.append(UInt8(value >> 16))
        if padding < 2:
            output.append(UInt8(value >> 8))
        if padding < 1:
            output.append(UInt8(value))
    return output^


def _base32[origin: Origin](input: Span[UInt8, origin]) -> List[UInt8]:
    var table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".as_bytes()
    var output = List[UInt8]()
    var accumulator = UInt32(0)
    var bits = 0
    for byte in input:
        accumulator = (accumulator << 8) | UInt32(byte)
        bits += 8
        while bits >= 5:
            bits -= 5
            output.append(table[Int((accumulator >> UInt32(bits)) & 31)])
    if bits != 0:
        output.append(table[Int((accumulator << UInt32(5 - bits)) & 31)])
    while len(output) % 8 != 0:
        output.append(61)
    return output^


def _base32_decode[
    origin: Origin
](input: Span[UInt8, origin]) raises -> List[UInt8]:
    var output = List[UInt8](capacity=(len(input) * 5 + 7) // 8)
    var accumulator = UInt32(0)
    var bits = 0
    var data_length = 0
    var padding = 0
    for c in input:
        if c == 61:
            padding += 1
            continue
        if padding != 0:
            raise Error("invalid base32 padding")

        var v: Int
        if c >= 65 and c <= 90:
            v = Int(c) - 65
        elif c >= 50 and c <= 55:
            v = Int(c) - 24
        else:
            raise Error("invalid base32 digit")
        data_length += 1
        accumulator = (accumulator << 5) | UInt32(v)
        bits += 5
        if bits >= 8:
            bits -= 8
            output.append(UInt8((accumulator >> UInt32(bits)) & UInt32(255)))

    var remainder = data_length % 8
    var expected_padding: Int
    if remainder == 0:
        expected_padding = 0
    elif remainder == 2:
        expected_padding = 6
    elif remainder == 4:
        expected_padding = 4
    elif remainder == 5:
        expected_padding = 3
    elif remainder == 7:
        expected_padding = 1
    else:
        raise Error("impossible base32 length")

    if padding != 0:
        if len(input) % 8 != 0 or padding != expected_padding:
            raise Error("invalid base32 padding")
    if bits != 0:
        var trailing_mask = (UInt32(1) << UInt32(bits)) - UInt32(1)
        if (accumulator & trailing_mask) != 0:
            raise Error("non-zero base32 trailing bits")
    return output^


def transform[
    origin: Origin
](algorithm: EncodingTransform, input: Span[UInt8, origin]) raises -> List[
    UInt8
]:
    if algorithm == EncodingTransform.HEX_ENCODE:
        return _hex(input)
    if algorithm == EncodingTransform.HEX_DECODE:
        return _hex_decode(input)
    if algorithm == EncodingTransform.BASE32_ENCODE:
        return _base32(input)
    if algorithm == EncodingTransform.BASE32_DECODE:
        return _base32_decode(input)
    if algorithm == EncodingTransform.BASE64_ENCODE:
        return _base64(input, False)
    if algorithm == EncodingTransform.BASE64_DECODE:
        return _base64_decode(input, False)
    if algorithm == EncodingTransform.BASE64URL_ENCODE:
        return _base64(input, True)
    if algorithm == EncodingTransform.BASE64URL_DECODE:
        return _base64_decode(input, True)
    raise Error("invalid encoding selector")
