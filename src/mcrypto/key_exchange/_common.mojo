"""Internal pure-Mojo integer and byte codecs for key agreements."""

from ..math.biguint import BigUInt


def from_be[origin: Origin](data: Span[UInt8, origin]) -> BigUInt:
    var limbs = List[UInt32](length=max(1, (len(data) + 3) // 4), fill=0)
    for i in range(len(data)):
        var source = len(data) - 1 - i
        limbs[i // 4] |= UInt32(data[source]) << UInt32(8 * (i % 4))
    return BigUInt.from_limbs(Span(limbs))


def to_be(value: BigUInt, size: Int) raises -> List[UInt8]:
    if size <= 0 or value.bit_length() > size * 8:
        raise Error("integer does not fit the requested byte encoding")
    var output = List[UInt8](length=size, fill=0)
    for i in range(min(size, len(value.limbs) * 4)):
        output[size - 1 - i] = UInt8(value.limbs[i // 4] >> UInt32(8 * (i % 4)))
    return output^


@always_inline("nodebug")
def _hex_digit(code: Int) raises -> Int:
    if code >= 48 and code <= 57:
        return code - 48
    if code >= 65 and code <= 70:
        return code - 55
    if code >= 97 and code <= 102:
        return code - 87
    if code == 32 or code == 10 or code == 13 or code == 9:
        return -1
    raise Error("invalid hexadecimal group parameter")


def parse_hex(text: String) raises -> BigUInt:
    var digit_count = 0
    for cp in text.codepoints():
        if _hex_digit(Int(cp)) >= 0:
            digit_count += 1
    var limbs = List[UInt32](length=max(1, (digit_count + 7) // 8), fill=0)
    var position = 0
    for cp in text.codepoints():
        var digit = _hex_digit(Int(cp))
        if digit < 0:
            continue
        var reverse_position = digit_count - 1 - position
        limbs[reverse_position // 8] |= UInt32(digit) << UInt32(
            4 * (reverse_position % 8)
        )
        position += 1
    return BigUInt.from_limbs(Span(limbs))


def append_bytes[
    origin: Origin
](mut output: List[UInt8], data: Span[UInt8, origin]):
    for byte in data:
        output.append(byte)
