"""Pure-Mojo DEFLATE (RFC 1951), zlib (RFC 1950), and gzip (RFC 1952)."""
from .algorithm import CompressionTransform

from ..hashes.checksums import (
    adler32 as _adler32_digest,
    crc32 as _crc32_digest,
)


def _length_base() -> List[Int]:
    return [
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        13,
        15,
        17,
        19,
        23,
        27,
        31,
        35,
        43,
        51,
        59,
        67,
        83,
        99,
        115,
        131,
        163,
        195,
        227,
        258,
    ]


def _length_extra() -> List[Int]:
    return [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
        1,
        1,
        2,
        2,
        2,
        2,
        3,
        3,
        3,
        3,
        4,
        4,
        4,
        4,
        5,
        5,
        5,
        5,
        0,
    ]


def _dist_base() -> List[Int]:
    return [
        1,
        2,
        3,
        4,
        5,
        7,
        9,
        13,
        17,
        25,
        33,
        49,
        65,
        97,
        129,
        193,
        257,
        385,
        513,
        769,
        1025,
        1537,
        2049,
        3073,
        4097,
        6145,
        8193,
        12289,
        16385,
        24577,
    ]


def _dist_extra() -> List[Int]:
    return [
        0,
        0,
        0,
        0,
        1,
        1,
        2,
        2,
        3,
        3,
        4,
        4,
        5,
        5,
        6,
        6,
        7,
        7,
        8,
        8,
        9,
        9,
        10,
        10,
        11,
        11,
        12,
        12,
        13,
        13,
    ]


def _code_length_order() -> List[Int]:
    return [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


@always_inline("nodebug")
def _reverse_bits(value: Int, count: Int) -> Int:
    var result = 0
    var current = value
    for _ in range(count):
        result = (result << 1) | (current & 1)
        current >>= 1
    return result


@always_inline("nodebug")
def _read_bits[
    origin: Origin
](
    input: Span[UInt8, origin],
    mut position: Int,
    mut bits: UInt64,
    mut bit_count: Int,
    count: Int,
) raises -> Int:
    while bit_count < count:
        if position >= len(input):
            raise Error("truncated DEFLATE stream")
        bits |= UInt64(input[position]) << UInt64(bit_count)
        position += 1
        bit_count += 8
    var mask = (UInt64(1) << UInt64(count)) - 1 if count != 0 else UInt64(0)
    var result = Int(bits & mask)
    bits >>= UInt64(count)
    bit_count -= count
    return result


@always_inline("nodebug")
def _write_bits(
    mut output: List[UInt8],
    mut bits: UInt64,
    mut bit_count: Int,
    value: Int,
    count: Int,
):
    bits |= UInt64(value) << UInt64(bit_count)
    bit_count += count
    while bit_count >= 8:
        output.append(UInt8(bits))
        bits >>= 8
        bit_count -= 8


def _make_codes(lengths: List[Int], max_allowed: Int) raises -> List[Int]:
    var counts = List[Int](length=max_allowed + 1, fill=0)
    var nonzero = 0
    for length in lengths:
        if length < 0 or length > max_allowed:
            raise Error("invalid Huffman code length")
        if length != 0:
            counts[length] += 1
            nonzero += 1
    if nonzero == 0:
        return List[Int](length=len(lengths), fill=0)
    var left = 1
    for length in range(1, max_allowed + 1):
        left = left * 2 - counts[length]
        if left < 0:
            raise Error("oversubscribed Huffman tree")
    var next_code = List[Int](length=max_allowed + 1, fill=0)
    var code = 0
    for length in range(1, max_allowed + 1):
        code = (code + counts[length - 1]) << 1
        next_code[length] = code
    var result = List[Int](length=len(lengths), fill=0)
    for symbol in range(len(lengths)):
        var length = lengths[symbol]
        if length != 0:
            result[symbol] = _reverse_bits(next_code[length], length)
            next_code[length] += 1
    return result^


def _validate_huffman_tree(
    lengths: List[Int], max_allowed: Int, allow_empty: Bool, allow_single: Bool
) raises:
    var counts = List[Int](length=max_allowed + 1, fill=0)
    var nonzero = 0
    var max_used = 0
    for length in lengths:
        if length < 0 or length > max_allowed:
            raise Error("invalid Huffman code length")
        if length != 0:
            counts[length] += 1
            nonzero += 1
            max_used = max(max_used, length)
    if nonzero == 0:
        if allow_empty:
            return
        raise Error("empty Huffman tree")
    var left = 1
    for length in range(1, max_allowed + 1):
        left = left * 2 - counts[length]
        if left < 0:
            raise Error("oversubscribed Huffman tree")
    if left != 0 and not (allow_single and nonzero == 1 and max_used == 1):
        raise Error("incomplete Huffman tree")


def _decode_symbol[
    origin: Origin
](
    input: Span[UInt8, origin],
    mut position: Int,
    mut bits: UInt64,
    mut bit_count: Int,
    lengths: List[Int],
    codes: List[Int],
    max_bits: Int,
) raises -> Int:
    var code = 0
    for length in range(1, max_bits + 1):
        code |= _read_bits(input, position, bits, bit_count, 1) << (length - 1)
        for symbol in range(len(lengths)):
            if lengths[symbol] == length and codes[symbol] == code:
                return symbol
    raise Error("invalid Huffman code")


def _decode_table(
    lengths: List[Int], codes: List[Int], max_bits: Int
) -> List[Int]:
    var root_bits = min(max_bits, 9)
    var root_size = 1 << root_bits
    var root_mask = root_size - 1
    var sub_widths = List[Int](length=root_size, fill=0)
    for symbol in range(len(lengths)):
        var length = lengths[symbol]
        if length > root_bits:
            var prefix = codes[symbol] & root_mask
            sub_widths[prefix] = max(sub_widths[prefix], length - root_bits)
    var table = List[Int](length=root_size, fill=-1)
    for prefix in range(root_size):
        var sub_bits = sub_widths[prefix]
        if sub_bits != 0:
            var offset = len(table)
            table.resize(offset + (1 << sub_bits), -1)
            table[prefix] = -((offset << 5) | sub_bits) - 2
    for symbol in range(len(lengths)):
        var length = lengths[symbol]
        if length == 0:
            continue
        var entry = (length << 16) | symbol
        if length <= root_bits:
            var combinations = 1 << (root_bits - length)
            for suffix in range(combinations):
                table[codes[symbol] | (suffix << length)] = entry
            continue
        var prefix = codes[symbol] & root_mask
        var descriptor = -table[prefix] - 2
        var sub_bits = descriptor & 31
        var sub_offset = descriptor >> 5
        var suffix_code = codes[symbol] >> root_bits
        var suffix_length = length - root_bits
        var combinations = 1 << (sub_bits - suffix_length)
        for suffix in range(combinations):
            table[sub_offset + suffix_code + (suffix << suffix_length)] = entry
    return table^


@always_inline("nodebug")
def _decode_table_symbol[
    origin: Origin
](
    input: Span[UInt8, origin],
    mut position: Int,
    mut bits: UInt64,
    mut bit_count: Int,
    table: List[Int],
    max_bits: Int,
) raises -> Int:
    var root_bits = min(max_bits, 9)
    while bit_count < root_bits and position < len(input):
        bits |= UInt64(input[position]) << UInt64(bit_count)
        position += 1
        bit_count += 8
    var entry = table[Int(bits & UInt64((1 << root_bits) - 1))]
    if entry < -1:
        var descriptor = -entry - 2
        var sub_bits = descriptor & 31
        var sub_offset = descriptor >> 5
        while bit_count < root_bits + sub_bits and position < len(input):
            bits |= UInt64(input[position]) << UInt64(bit_count)
            position += 1
            bit_count += 8
        var suffix = Int(
            (bits >> UInt64(root_bits)) & UInt64((1 << sub_bits) - 1)
        )
        entry = table[sub_offset + suffix]
    if entry < 0:
        raise Error("invalid Huffman code")
    var length = entry >> 16
    if length > bit_count:
        raise Error("truncated DEFLATE stream")
    bits >>= UInt64(length)
    bit_count -= length
    return entry & 0xFFFF


def _fixed_lengths() -> List[Int]:
    var lengths = List[Int](length=288, fill=0)
    for i in range(0, 144):
        lengths[i] = 8
    for i in range(144, 256):
        lengths[i] = 9
    for i in range(256, 280):
        lengths[i] = 7
    for i in range(280, 288):
        lengths[i] = 8
    return lengths^


def _inflate_codes[
    origin: Origin
](
    input: Span[UInt8, origin],
    mut position: Int,
    mut bits: UInt64,
    mut bit_count: Int,
    mut output: List[UInt8],
    lit_lengths: List[Int],
    dist_lengths: List[Int],
    max_distance: Int,
) raises:
    if len(lit_lengths) <= 256 or lit_lengths[256] == 0:
        raise Error("DEFLATE tree has no end-of-block code")
    _validate_huffman_tree(lit_lengths, 15, False, True)
    _validate_huffman_tree(dist_lengths, 15, True, True)
    var lit_codes = _make_codes(lit_lengths, 15)
    var dist_codes = _make_codes(dist_lengths, 15)
    var lit_table_bits = 1
    for length in lit_lengths:
        lit_table_bits = max(lit_table_bits, length)
    var dist_table_bits = 1
    for length in dist_lengths:
        dist_table_bits = max(dist_table_bits, length)
    var lit_table = _decode_table(lit_lengths, lit_codes, lit_table_bits)
    var dist_table = _decode_table(dist_lengths, dist_codes, dist_table_bits)
    var length_base = _length_base()
    var length_extra_table = _length_extra()
    var dist_base = _dist_base()
    var dist_extra_table = _dist_extra()
    while True:
        var symbol = _decode_table_symbol(
            input, position, bits, bit_count, lit_table, lit_table_bits
        )
        if symbol < 256:
            output.append(UInt8(symbol))
        elif symbol == 256:
            return
        elif symbol <= 285:
            var length_index = symbol - 257
            var match_length = length_base[length_index]
            var length_extra = length_extra_table[length_index]
            if length_extra != 0:
                match_length += _read_bits(
                    input, position, bits, bit_count, length_extra
                )
            var dist_symbol = _decode_table_symbol(
                input, position, bits, bit_count, dist_table, dist_table_bits
            )
            if dist_symbol >= 30:
                raise Error("reserved DEFLATE distance code")
            var distance = dist_base[dist_symbol]
            var dist_extra = dist_extra_table[dist_symbol]
            if dist_extra != 0:
                distance += _read_bits(
                    input, position, bits, bit_count, dist_extra
                )
            if (
                distance <= 0
                or distance > len(output)
                or distance > max_distance
            ):
                raise Error("invalid DEFLATE back-reference")
            var output_offset = len(output)
            output.resize(output_offset + match_length, 0)
            var output_pointer = Span(output).unsafe_ptr()
            if distance == 1:
                var byte = output_pointer.unsafe_load(output_offset - 1)
                var repeated = SIMD[DType.uint8, 32](byte)
                var copied = 0
                while copied + 32 <= match_length:
                    output_pointer.unsafe_store[width=32](
                        output_offset + copied, repeated
                    )
                    copied += 32
                while copied < match_length:
                    output_pointer.unsafe_store(output_offset + copied, byte)
                    copied += 1
            elif distance >= 32:
                var copied = 0
                while copied + 32 <= match_length:
                    output_pointer.unsafe_store[width=32](
                        output_offset + copied,
                        output_pointer.unsafe_load[width=32](
                            output_offset - distance + copied
                        ),
                    )
                    copied += 32
                while copied < match_length:
                    output_pointer.unsafe_store(
                        output_offset + copied,
                        output_pointer.unsafe_load(
                            output_offset - distance + copied
                        ),
                    )
                    copied += 1
            else:
                for copied in range(match_length):
                    output_pointer.unsafe_store(
                        output_offset + copied,
                        output_pointer.unsafe_load(
                            output_offset - distance + copied
                        ),
                    )
        else:
            raise Error("reserved DEFLATE length code")


def _dynamic_lengths[
    origin: Origin
](
    input: Span[UInt8, origin],
    mut position: Int,
    mut bits: UInt64,
    mut bit_count: Int,
) raises -> List[List[Int]]:
    var hlit = _read_bits(input, position, bits, bit_count, 5) + 257
    var hdist = _read_bits(input, position, bits, bit_count, 5) + 1
    var hclen = _read_bits(input, position, bits, bit_count, 4) + 4
    if hlit > 286 or hdist > 32:
        raise Error("invalid dynamic Huffman counts")
    var order = _code_length_order()
    var code_lengths = List[Int](length=19, fill=0)
    for i in range(hclen):
        code_lengths[order[i]] = _read_bits(input, position, bits, bit_count, 3)
    var code_codes = _make_codes(code_lengths, 7)
    _validate_huffman_tree(code_lengths, 7, False, False)
    var combined = List[Int](capacity=hlit + hdist)
    while len(combined) < hlit + hdist:
        var symbol = _decode_symbol(
            input, position, bits, bit_count, code_lengths, code_codes, 7
        )
        if symbol <= 15:
            combined.append(symbol)
        elif symbol == 16:
            if len(combined) == 0:
                raise Error("repeat code has no previous length")
            var repeat = _read_bits(input, position, bits, bit_count, 2) + 3
            if len(combined) + repeat > hlit + hdist:
                raise Error("Huffman length repeat exceeds tree")
            var previous = combined[len(combined) - 1]
            for _ in range(repeat):
                combined.append(previous)
        elif symbol == 17:
            var repeat = _read_bits(input, position, bits, bit_count, 3) + 3
            if len(combined) + repeat > hlit + hdist:
                raise Error("Huffman zero repeat exceeds tree")
            for _ in range(repeat):
                combined.append(0)
        elif symbol == 18:
            var repeat = _read_bits(input, position, bits, bit_count, 7) + 11
            if len(combined) + repeat > hlit + hdist:
                raise Error("Huffman zero repeat exceeds tree")
            for _ in range(repeat):
                combined.append(0)
        else:
            raise Error("invalid code-length symbol")
    var literal = List[Int](capacity=hlit)
    var distance = List[Int](capacity=hdist)
    for i in range(hlit):
        literal.append(combined[i])
    for i in range(hdist):
        distance.append(combined[hlit + i])
    return [literal^, distance^]


struct _InflateResult(Movable):
    var output: List[UInt8]
    var consumed: Int

    def __init__(out self, var output: List[UInt8], consumed: Int):
        self.output = output^
        self.consumed = consumed

    def into_output(deinit self) -> List[UInt8]:
        return self.output^


def _inflate_raw[
    origin: Origin
](
    input: Span[UInt8, origin], start: Int = 0, max_distance: Int = 32768
) raises -> _InflateResult:
    var position = start
    var bits = UInt64(0)
    var bit_count = 0
    var output = List[UInt8]()
    var final_block = False
    while not final_block:
        final_block = _read_bits(input, position, bits, bit_count, 1) != 0
        var block_type = _read_bits(input, position, bits, bit_count, 2)
        if block_type == 0:
            bits = 0
            bit_count = 0
            if position + 4 > len(input):
                raise Error("truncated stored DEFLATE block")
            var block_len = Int(input[position]) | (
                Int(input[position + 1]) << 8
            )
            var complement = Int(input[position + 2]) | (
                Int(input[position + 3]) << 8
            )
            position += 4
            if (block_len ^ 0xFFFF) != complement:
                raise Error("invalid stored DEFLATE block length")
            if position + block_len > len(input):
                raise Error("truncated stored DEFLATE payload")
            var output_offset = len(output)
            output.resize(output_offset + block_len, 0)
            var input_pointer = input.unsafe_ptr()
            var output_pointer = Span(output).unsafe_ptr()
            var copied = 0
            while copied + 32 <= block_len:
                output_pointer.unsafe_store[width=32](
                    output_offset + copied,
                    input_pointer.unsafe_load[width=32](position + copied),
                )
                copied += 32
            while copied < block_len:
                output_pointer.unsafe_store(
                    output_offset + copied,
                    input_pointer.unsafe_load(position + copied),
                )
                copied += 1
            position += block_len
        elif block_type == 1:
            var literal = _fixed_lengths()
            var distance = List[Int](length=32, fill=5)
            _inflate_codes(
                input,
                position,
                bits,
                bit_count,
                output,
                literal,
                distance,
                max_distance,
            )
        elif block_type == 2:
            var trees = _dynamic_lengths(input, position, bits, bit_count)
            _inflate_codes(
                input,
                position,
                bits,
                bit_count,
                output,
                trees[0],
                trees[1],
                max_distance,
            )
        else:
            raise Error("reserved DEFLATE block type")
    position -= bit_count // 8
    return _InflateResult(output^, position)


@always_inline("nodebug")
def _emit_symbol(
    mut output: List[UInt8],
    mut bits: UInt64,
    mut bit_count: Int,
    symbol: Int,
    lengths: List[Int],
    codes: List[Int],
):
    _write_bits(output, bits, bit_count, codes[symbol], lengths[symbol])


def _length_symbol(length: Int, base: List[Int], extra: List[Int]) -> Int:
    for i in range(29):
        if length <= base[i] + ((1 << extra[i]) - 1):
            return 257 + i
    return 285


def _distance_symbol(distance: Int, base: List[Int], extra: List[Int]) -> Int:
    for i in range(30):
        if distance <= base[i] + ((1 << extra[i]) - 1):
            return i
    return 29


def deflate[origin: Origin](input: Span[UInt8, origin]) raises -> List[UInt8]:
    """Compress one byte span as a final fixed-Huffman DEFLATE block."""
    var output = List[UInt8]()
    var bits = UInt64(0)
    var bit_count = 0
    _write_bits(output, bits, bit_count, 1, 1)
    _write_bits(output, bits, bit_count, 1, 2)
    var lit_lengths = _fixed_lengths()
    var lit_codes = _make_codes(lit_lengths, 15)
    var dist_lengths = List[Int](length=32, fill=5)
    var dist_codes = _make_codes(dist_lengths, 15)
    var length_base = _length_base()
    var length_extra_table = _length_extra()
    var dist_base = _dist_base()
    var dist_extra_table = _dist_extra()
    var heads = List[Int](length=65536, fill=-1)
    var previous = List[Int](length=len(input), fill=-1)
    var position = 0
    while position < len(input):
        var best_length = 0
        var best_distance = 0
        if position + 2 < len(input):
            var hash = (
                (Int(input[position]) * 251 + Int(input[position + 1])) * 251
                + Int(input[position + 2])
            ) & 0xFFFF
            var candidate = heads[hash]
            previous[position] = candidate
            heads[hash] = position
            var chain = 0
            while (
                candidate >= 0 and position - candidate <= 32768 and chain < 128
            ):
                var available = min(258, len(input) - position)
                var match_length = 0
                while (
                    match_length < available
                    and input[candidate + match_length]
                    == input[position + match_length]
                ):
                    match_length += 1
                if match_length >= 3 and match_length > best_length:
                    best_length = match_length
                    best_distance = position - candidate
                    if match_length == 258:
                        break
                candidate = previous[candidate]
                chain += 1
        if best_length >= 3:
            var length_symbol = _length_symbol(
                best_length, length_base, length_extra_table
            )
            _emit_symbol(
                output, bits, bit_count, length_symbol, lit_lengths, lit_codes
            )
            var length_index = length_symbol - 257
            var length_extra = length_extra_table[length_index]
            if length_extra != 0:
                _write_bits(
                    output,
                    bits,
                    bit_count,
                    best_length - length_base[length_index],
                    length_extra,
                )
            var distance_symbol = _distance_symbol(
                best_distance, dist_base, dist_extra_table
            )
            _emit_symbol(
                output,
                bits,
                bit_count,
                distance_symbol,
                dist_lengths,
                dist_codes,
            )
            var distance_extra = dist_extra_table[distance_symbol]
            if distance_extra != 0:
                _write_bits(
                    output,
                    bits,
                    bit_count,
                    best_distance - dist_base[distance_symbol],
                    distance_extra,
                )
            for skipped in range(1, best_length):
                var inserted = position + skipped
                if inserted + 2 < len(input):
                    var hash = (
                        (Int(input[inserted]) * 251 + Int(input[inserted + 1]))
                        * 251
                        + Int(input[inserted + 2])
                    ) & 0xFFFF
                    previous[inserted] = heads[hash]
                    heads[hash] = inserted
            position += best_length
        else:
            _emit_symbol(
                output,
                bits,
                bit_count,
                Int(input[position]),
                lit_lengths,
                lit_codes,
            )
            position += 1
    _emit_symbol(output, bits, bit_count, 256, lit_lengths, lit_codes)
    if bit_count != 0:
        output.append(UInt8(bits))
    return output^


def inflate[origin: Origin](input: Span[UInt8, origin]) raises -> List[UInt8]:
    var result = _inflate_raw(input)
    if result.consumed != len(input):
        raise Error("trailing data after DEFLATE stream")
    return result^.into_output()


@always_inline("nodebug")
def _adler32[origin: Origin](input: Span[UInt8, origin]) -> UInt32:
    var digest = _adler32_digest(input)
    return (
        (UInt32(digest[0]) << 24)
        | (UInt32(digest[1]) << 16)
        | (UInt32(digest[2]) << 8)
        | UInt32(digest[3])
    )


@always_inline("nodebug")
def _crc32[origin: Origin](input: Span[UInt8, origin]) -> UInt32:
    var digest = _crc32_digest(input)
    return (
        (UInt32(digest[0]) << 24)
        | (UInt32(digest[1]) << 16)
        | (UInt32(digest[2]) << 8)
        | UInt32(digest[3])
    )


@always_inline("nodebug")
def _append_be32(mut output: List[UInt8], value: UInt32):
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


@always_inline("nodebug")
def _append_le32(mut output: List[UInt8], value: UInt32):
    output.append(UInt8(value))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 24))


@always_inline("nodebug")
def _load_be32[origin: Origin](input: Span[UInt8, origin], at: Int) -> UInt32:
    return (
        (UInt32(input[at]) << 24)
        | (UInt32(input[at + 1]) << 16)
        | (UInt32(input[at + 2]) << 8)
        | UInt32(input[at + 3])
    )


@always_inline("nodebug")
def _load_le32[origin: Origin](input: Span[UInt8, origin], at: Int) -> UInt32:
    return (
        UInt32(input[at])
        | (UInt32(input[at + 1]) << 8)
        | (UInt32(input[at + 2]) << 16)
        | (UInt32(input[at + 3]) << 24)
    )


def zlib_compress[
    origin: Origin
](input: Span[UInt8, origin]) raises -> List[UInt8]:
    var output: List[UInt8] = [0x78, 0x9C]
    var compressed = deflate(input)
    for byte in compressed:
        output.append(byte)
    _append_be32(output, _adler32(input))
    return output^


def zlib_decompress[
    origin: Origin
](input: Span[UInt8, origin]) raises -> List[UInt8]:
    if len(input) < 6:
        raise Error("truncated zlib stream")
    var cmf = Int(input[0])
    var flg = Int(input[1])
    if (cmf & 15) != 8 or (cmf >> 4) > 7 or ((cmf << 8) + flg) % 31 != 0:
        raise Error("invalid zlib header")
    if (flg & 0x20) != 0:
        raise Error("zlib preset dictionaries are unsupported")
    var result = _inflate_raw(input, 2, 1 << ((cmf >> 4) + 8))
    var trailer = result.consumed
    if trailer + 4 != len(input):
        raise Error("truncated or trailing zlib data")
    if _load_be32(input, trailer) != _adler32(Span(result.output)):
        raise Error("zlib Adler-32 mismatch")
    return result^.into_output()


def gzip_compress[
    origin: Origin
](input: Span[UInt8, origin]) raises -> List[UInt8]:
    var output: List[UInt8] = [0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255]
    var compressed = deflate(input)
    for byte in compressed:
        output.append(byte)
    _append_le32(output, _crc32(input))
    _append_le32(output, UInt32(len(input)))
    return output^


def gzip_decompress[
    origin: Origin
](input: Span[UInt8, origin]) raises -> List[UInt8]:
    var member_start = 0
    var output = List[UInt8]()
    while member_start < len(input):
        if (
            member_start + 18 > len(input)
            or input[member_start] != 0x1F
            or input[member_start + 1] != 0x8B
            or input[member_start + 2] != 8
        ):
            raise Error("invalid or truncated gzip header")
        var flags = Int(input[member_start + 3])
        if (flags & 0xE0) != 0:
            raise Error("reserved gzip flags are set")
        var position = member_start + 10
        if (flags & 4) != 0:
            if position + 2 > len(input):
                raise Error("truncated gzip extra field")
            var extra_length = Int(input[position]) | (
                Int(input[position + 1]) << 8
            )
            position += 2
            if position + extra_length > len(input):
                raise Error("truncated gzip extra field")
            position += extra_length
        if (flags & 8) != 0:
            while position < len(input) and input[position] != 0:
                position += 1
            if position >= len(input):
                raise Error("unterminated gzip filename")
            position += 1
        if (flags & 16) != 0:
            while position < len(input) and input[position] != 0:
                position += 1
            if position >= len(input):
                raise Error("unterminated gzip comment")
            position += 1
        if (flags & 2) != 0:
            if position + 2 > len(input):
                raise Error("truncated gzip header checksum")
            var header = List[UInt8](capacity=position - member_start)
            for i in range(member_start, position):
                header.append(input[i])
            var expected = UInt16(_crc32(Span(header)))
            var actual = UInt16(input[position]) | (
                UInt16(input[position + 1]) << 8
            )
            if expected != actual:
                raise Error("gzip header checksum mismatch")
            position += 2
        var result = _inflate_raw(input, position)
        var trailer = result.consumed
        if trailer + 8 > len(input):
            raise Error("truncated gzip data")
        if _load_le32(input, trailer) != _crc32(Span(result.output)):
            raise Error("gzip CRC-32 mismatch")
        if _load_le32(input, trailer + 4) != UInt32(len(result.output)):
            raise Error("gzip uncompressed length mismatch")
        for byte in result.output:
            output.append(byte)
        member_start = trailer + 8
    if member_start == 0:
        raise Error("invalid or truncated gzip header")
    return output^


def transform[
    origin: Origin
](algorithm: CompressionTransform, input: Span[UInt8, origin]) raises -> List[
    UInt8
]:
    if algorithm == CompressionTransform.DEFLATE:
        return deflate(input)
    if algorithm == CompressionTransform.INFLATE:
        return inflate(input)
    if algorithm == CompressionTransform.ZLIB_COMPRESS:
        return zlib_compress(input)
    if algorithm == CompressionTransform.ZLIB_DECOMPRESS:
        return zlib_decompress(input)
    if algorithm == CompressionTransform.GZIP:
        return gzip_compress(input)
    if algorithm == CompressionTransform.GUNZIP:
        return gzip_decompress(input)
    raise Error("invalid compression selector")
