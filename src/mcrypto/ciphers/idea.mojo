"""IDEA 64-bit block cipher in pure Mojo."""


@always_inline("nodebug")
def _mul(left: UInt16, right: UInt16) -> UInt16:
    var a = UInt32(left) if left != 0 else UInt32(65536)
    var b = UInt32(right) if right != 0 else UInt32(65536)
    var product = (a * b) % UInt32(65537)
    return UInt16(0 if product == 65536 else product)


def _inverse(value: UInt16) -> UInt16:
    if value <= 1:
        return value
    var t0 = Int64(0)
    var t1 = Int64(1)
    var r0 = Int64(65537)
    var r1 = Int64(value)
    while r1 != 0:
        var quotient = r0 // r1
        var next_r = r0 - quotient * r1
        r0 = r1
        r1 = next_r
        var next_t = t0 - quotient * t1
        t0 = t1
        t1 = next_t
    if t0 < 0:
        t0 += 65537
    return UInt16(0 if t0 == 65536 else t0)


def _encrypt_keys[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt16]:
    if len(key) != 16:
        raise Error("IDEA key must be 16 bytes")
    var output = List[UInt16](length=52, fill=0)
    for i in range(8):
        output[i] = (UInt16(key[2 * i]) << 8) | UInt16(key[2 * i + 1])
    for i in range(8, 52):
        var base = (i // 8) * 8 - 8
        output[i] = (output[base + (i + 1) % 8] << 9) | (
            output[base + (i + 2) % 8] >> 7
        )
    return output^


def _decrypt_keys(encryption: List[UInt16]) -> List[UInt16]:
    var output = List[UInt16](length=52, fill=0)
    for i in range(8):
        output[6 * i] = _inverse(encryption[(8 - i) * 6])
        output[6 * i + 1] = (
            UInt16(0) - encryption[(8 - i) * 6 + 1 + (1 if i > 0 else 0)]
        )
        output[6 * i + 2] = (
            UInt16(0) - encryption[(8 - i) * 6 + 2 - (1 if i > 0 else 0)]
        )
        output[6 * i + 3] = _inverse(encryption[(8 - i) * 6 + 3])
        output[6 * i + 4] = encryption[(7 - i) * 6 + 4]
        output[6 * i + 5] = encryption[(7 - i) * 6 + 5]
    output[48] = _inverse(encryption[0])
    output[49] = UInt16(0) - encryption[1]
    output[50] = UInt16(0) - encryption[2]
    output[51] = _inverse(encryption[3])
    return output^


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> List[UInt16]:
    var round_keys = _encrypt_keys(key)
    if decrypt:
        return _decrypt_keys(round_keys)
    return round_keys^


def process_prepared_into[
    block_origin: Origin, output_origin: MutOrigin
](
    round_keys: List[UInt16],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 8:
        raise Error("IDEA block must be 8 bytes")
    if len(round_keys) != 52:
        raise Error("IDEA schedule must contain 52 words")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("IDEA output span is too short")
    var key_pointer = Span(round_keys).unsafe_ptr()
    var x0 = (UInt16(block[0]) << 8) | UInt16(block[1])
    var x1 = (UInt16(block[2]) << 8) | UInt16(block[3])
    var x2 = (UInt16(block[4]) << 8) | UInt16(block[5])
    var x3 = (UInt16(block[6]) << 8) | UInt16(block[7])
    comptime for round in range(8):
        x0 = _mul(x0, key_pointer.unsafe_load(6 * round))
        x1 += key_pointer.unsafe_load(6 * round + 1)
        x2 += key_pointer.unsafe_load(6 * round + 2)
        x3 = _mul(x3, key_pointer.unsafe_load(6 * round + 3))
        var t0 = _mul(x0 ^ x2, key_pointer.unsafe_load(6 * round + 4))
        var t1 = _mul(
            t0 + (x1 ^ x3),
            key_pointer.unsafe_load(6 * round + 5),
        )
        t0 += t1
        x0 ^= t1
        x3 ^= t0
        t0 ^= x1
        x1 = x2 ^ t1
        x2 = t0
    x0 = _mul(x0, key_pointer.unsafe_load(48))
    x2 += key_pointer.unsafe_load(49)
    x1 += key_pointer.unsafe_load(50)
    x3 = _mul(x3, key_pointer.unsafe_load(51))
    var values: InlineArray[UInt16, 4] = [x0, x2, x1, x3]
    comptime for i in range(4):
        output[output_offset + 2 * i] = UInt8(values[i] >> 8)
        output[output_offset + 2 * i + 1] = UInt8(values[i])


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var round_keys = prepare(key, decrypt)
    var output = List[UInt8](length=8, fill=0)
    process_prepared_into(round_keys, block, Span(output), 0)
    return output^
