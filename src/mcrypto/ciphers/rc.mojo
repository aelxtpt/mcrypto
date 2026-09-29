"""RC5-32 with a 16-round default and RC6-32/20 block ciphers."""

from std.memory import bitcast
from ..internal.bytes import load_le32, store_le32


@always_inline("nodebug")
def _rol(x: UInt32, n: UInt32) -> UInt32:
    var amount = n & 31
    if amount == 0:
        return x
    return (x << amount) | (x >> (32 - amount))


@always_inline("nodebug")
def _ror(x: UInt32, n: UInt32) -> UInt32:
    return _rol(x, 32 - (n & 31))


@always_inline("nodebug")
def _rol_eight(
    x: SIMD[DType.uint32, 8], n: SIMD[DType.uint32, 8]
) -> SIMD[DType.uint32, 8]:
    var amount = n & SIMD[DType.uint32, 8](31)
    return (x << amount) | (x >> ((SIMD[DType.uint32, 8](0) - amount) & 31))


def _schedule[
    key_origin: Origin
](key: Span[UInt8, key_origin], words: Int) -> List[UInt32]:
    var count = max(1, (len(key) + 3) // 4)
    var l = List[UInt32](length=count, fill=0)
    for i in range(len(key)):
        l[i // 4] |= UInt32(key[i]) << UInt32(8 * (i % 4))
    var s = List[UInt32](length=words, fill=0)
    s[0] = 0xB7E15163
    for i in range(1, words):
        s[i] = s[i - 1] + 0x9E3779B9
    var a = UInt32(0)
    var b = UInt32(0)
    for h in range(3 * max(words, count)):
        var si = h % words
        var li = h % count
        a = _rol(s[si] + a + b, 3)
        s[si] = a
        b = _rol(l[li] + a + b, a + b)
        l[li] = b
    return s^


def prepare5[
    key_origin: Origin
](key: Span[UInt8, key_origin], rounds: Int = 16) raises -> List[UInt32]:
    if len(key) > 255 or rounds < 1:
        raise Error("RC5 requires a 0..255-byte key and at least one round")
    return _schedule(key, 2 * (rounds + 1))


def process_prepared5_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    schedule: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    rounds: Int = 16,
) raises:
    if len(block) != 8:
        raise Error("RC5 block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("RC5 output span is too short")
    var a = load_le32(block, 0)
    var b = load_le32(block, 4)
    comptime if decrypting:
        for offset in range(rounds):
            var i = rounds - 1 - offset
            b = _ror(b - schedule[2 * i + 3], a) ^ a
            a = _ror(a - schedule[2 * i + 2], b) ^ b
        b -= schedule[1]
        a -= schedule[0]
    else:
        a += schedule[0]
        b += schedule[1]
        for i in range(rounds):
            a = _rol(a ^ b, b) + schedule[2 * i + 2]
            b = _rol(a ^ b, a) + schedule[2 * i + 3]
    store_le32(a, output, output_offset)
    store_le32(b, output, output_offset + 4)


def process_eight5_into[
    block_origin: Origin, output_origin: MutOrigin
](
    schedule: List[UInt32],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 64:
        raise Error("eight RC5 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("RC5 output span is too short")
    var words = bitcast[DType.uint32, 16](
        blocks.unsafe_ptr().unsafe_load[width=64](0)
    )
    var a = SIMD[DType.uint32, 8](0)
    var b = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        a[lane] = words[2 * lane]
        b[lane] = words[2 * lane + 1]
    var key_pointer = Span(schedule).unsafe_ptr()
    a += key_pointer.unsafe_load(0)
    b += key_pointer.unsafe_load(1)
    comptime for i in range(16):
        a = _rol_eight(a ^ b, b) + key_pointer.unsafe_load(2 * i + 2)
        b = _rol_eight(a ^ b, a) + key_pointer.unsafe_load(2 * i + 3)
    comptime for lane in range(8):
        words[2 * lane] = a[lane]
        words[2 * lane + 1] = b[lane]
    output.unsafe_ptr().unsafe_store[width=64](
        output_offset, bitcast[DType.uint8, 64](words)
    )


def process_prepared5[
    block_origin: Origin
](
    decrypt: Bool,
    schedule: List[UInt32],
    block: Span[UInt8, block_origin],
    rounds: Int = 16,
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    if decrypt:
        process_prepared5_into[True](schedule, block, Span(output), 0, rounds)
    else:
        process_prepared5_into[False](schedule, block, Span(output), 0, rounds)
    return output^


def prepare6[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("RC6 key must be 16, 24, or 32 bytes")
    return _schedule(key, 44)


def process_prepared6_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    schedule: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("RC6 block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("RC6 output span is too short")
    var a = load_le32(block, 0)
    var b = load_le32(block, 4)
    var c = load_le32(block, 8)
    var d = load_le32(block, 12)
    comptime if decrypting:
        c -= schedule[43]
        a -= schedule[42]
        comptime for offset in range(20):
            comptime i = 19 - offset
            var temporary = a
            a = d
            d = c
            c = b
            b = temporary
            var u = _rol(d * (2 * d + 1), 5)
            temporary = _rol(b * (2 * b + 1), 5)
            c = _ror(c - schedule[2 * i + 3], temporary) ^ u
            a = _ror(a - schedule[2 * i + 2], u) ^ temporary
        d -= schedule[1]
        b -= schedule[0]
    else:
        b += schedule[0]
        d += schedule[1]
        comptime for i in range(20):
            var temporary = _rol(b * (2 * b + 1), 5)
            var u = _rol(d * (2 * d + 1), 5)
            a = _rol(a ^ temporary, u) + schedule[2 * i + 2]
            c = _rol(c ^ u, temporary) + schedule[2 * i + 3]
            temporary = a
            a = b
            b = c
            c = d
            d = temporary
        a += schedule[42]
        c += schedule[43]
    store_le32(a, output, output_offset)
    store_le32(b, output, output_offset + 4)
    store_le32(c, output, output_offset + 8)
    store_le32(d, output, output_offset + 12)


def process_eight6_into[
    block_origin: Origin, output_origin: MutOrigin
](
    schedule: List[UInt32],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 128:
        raise Error("eight RC6 blocks must total 128 bytes")
    if output_offset < 0 or output_offset + 128 > len(output):
        raise Error("RC6 output span is too short")
    var words = bitcast[DType.uint32, 32](
        blocks.unsafe_ptr().unsafe_load[width=128](0)
    )
    var a = SIMD[DType.uint32, 8](0)
    var b = SIMD[DType.uint32, 8](0)
    var c = SIMD[DType.uint32, 8](0)
    var d = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        a[lane] = words[4 * lane]
        b[lane] = words[4 * lane + 1]
        c[lane] = words[4 * lane + 2]
        d[lane] = words[4 * lane + 3]
    var key_pointer = Span(schedule).unsafe_ptr()
    b += key_pointer.unsafe_load(0)
    d += key_pointer.unsafe_load(1)
    comptime for i in range(20):
        var t = _rol_eight(b * (2 * b + 1), SIMD[DType.uint32, 8](5))
        var u = _rol_eight(d * (2 * d + 1), SIMD[DType.uint32, 8](5))
        a = _rol_eight(a ^ t, u) + key_pointer.unsafe_load(2 * i + 2)
        c = _rol_eight(c ^ u, t) + key_pointer.unsafe_load(2 * i + 3)
        var temporary = a
        a = b
        b = c
        c = d
        d = temporary
    a += key_pointer.unsafe_load(42)
    c += key_pointer.unsafe_load(43)
    comptime for lane in range(8):
        words[4 * lane] = a[lane]
        words[4 * lane + 1] = b[lane]
        words[4 * lane + 2] = c[lane]
        words[4 * lane + 3] = d[lane]
    output.unsafe_ptr().unsafe_store[width=128](
        output_offset, bitcast[DType.uint8, 128](words)
    )


def process_prepared6[
    block_origin: Origin
](
    decrypt: Bool,
    schedule: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    if decrypt:
        process_prepared6_into[True](schedule, block, Span(output), 0)
    else:
        process_prepared6_into[False](schedule, block, Span(output), 0)
    return output^


def rc5[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    rounds: Int = 16,
) raises -> List[UInt8]:
    return process_prepared5(decrypt, prepare5(key, rounds), block, rounds)


def rc6[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    return process_prepared6(decrypt, prepare6(key), block)
