"""SHACAL-2 block cipher in pure Mojo."""

from ..internal.bytes import load_be32, store_be32


comptime _K: InlineArray[UInt32, 64] = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


@always_inline("nodebug")
def _ror(value: UInt32, amount: Int) -> UInt32:
    return (value >> UInt32(amount)) | (value << UInt32(32 - amount))


@always_inline("nodebug")
def _s0(value: UInt32) -> UInt32:
    return _ror(value, 7) ^ _ror(value, 18) ^ (value >> 3)


@always_inline("nodebug")
def _s1(value: UInt32) -> UInt32:
    return _ror(value, 17) ^ _ror(value, 19) ^ (value >> 10)


@always_inline("nodebug")
def _big0(value: UInt32) -> UInt32:
    return _ror(value, 2) ^ _ror(value, 13) ^ _ror(value, 22)


@always_inline("nodebug")
def _big1(value: UInt32) -> UInt32:
    return _ror(value, 6) ^ _ror(value, 11) ^ _ror(value, 25)


@always_inline("nodebug")
def _ch(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return z ^ (x & (y ^ z))


@always_inline("nodebug")
def _maj(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) | (z & (x | y))


def _schedule[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) < 16 or len(key) > 64:
        raise Error("SHACAL-2 key must contain 16 through 64 bytes")
    var words = InlineArray[UInt32, 64](fill=0)
    var complete_words = len(key) // 4
    for i in range(complete_words):
        words[i] = load_be32(key, 4 * i)
    var remaining = len(key) - 4 * complete_words
    if remaining != 0:
        var final_word = UInt32(0)
        for i in range(remaining):
            final_word |= UInt32(key[4 * complete_words + i]) << UInt32(
                24 - 8 * i
            )
        words[complete_words] = final_word
    comptime for i in range(16, 64):
        words[i] = (
            words[i - 16]
            + _s0(words[i - 15])
            + words[i - 7]
            + _s1(words[i - 2])
        )
    var output = List[UInt32](length=64, fill=0)
    var output_pointer = Span(output).unsafe_ptr()
    comptime for offset in range(0, 64, 4):
        var packed = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            comptime index = offset + lane
            packed[lane] = words[index] + materialize[_K[index]]()
        output_pointer.unsafe_store[width=4](offset, packed)
    return output^


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    return _schedule(key)


def process_prepared_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    round_keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 32:
        raise Error("SHACAL-2 block must be 32 bytes")
    if len(round_keys) != 64:
        raise Error("SHACAL-2 schedule must contain 64 words")
    if output_offset < 0 or output_offset + 32 > len(output):
        raise Error("SHACAL-2 output span is too short")
    var a = load_be32(block, 0)
    var b = load_be32(block, 4)
    var c = load_be32(block, 8)
    var d = load_be32(block, 12)
    var e = load_be32(block, 16)
    var f = load_be32(block, 20)
    var g = load_be32(block, 24)
    var h = load_be32(block, 28)
    var round_key_pointer = Span(round_keys).unsafe_ptr()
    comptime if decrypting:
        comptime for offset in range(64):
            comptime i = 63 - offset
            var old_a = b
            var old_b = c
            var old_c = d
            var old_e = f
            var old_f = g
            var old_g = h
            var old_h = a - _big0(old_a) - _maj(old_a, old_b, old_c)
            var old_d = e - old_h
            old_h -= (
                _big1(old_e)
                + _ch(old_e, old_f, old_g)
                + round_key_pointer[unsafe_offset=i]
            )
            a = old_a
            b = old_b
            c = old_c
            d = old_d
            e = old_e
            f = old_f
            g = old_g
            h = old_h
    else:
        comptime for i in range(64):
            var t1 = (
                h + _big1(e) + _ch(e, f, g) + round_key_pointer[unsafe_offset=i]
            )
            var t2 = _big0(a) + _maj(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
    store_be32(a, output, output_offset)
    store_be32(b, output, output_offset + 4)
    store_be32(c, output, output_offset + 8)
    store_be32(d, output, output_offset + 12)
    store_be32(e, output, output_offset + 16)
    store_be32(f, output, output_offset + 20)
    store_be32(g, output, output_offset + 24)
    store_be32(h, output, output_offset + 28)


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    round_keys: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=32, fill=0)
    if decrypt:
        process_prepared_into[True](round_keys, block, Span(output), 0)
    else:
        process_prepared_into[False](round_keys, block, Span(output), 0)
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var round_keys = _schedule(key)
    return process_prepared(decrypt, round_keys, block)
