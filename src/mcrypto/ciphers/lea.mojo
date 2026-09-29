"""LEA-128 block cipher with 128-, 192-, and 256-bit keys."""

from std.bit import rotate_bits_left

from ..internal.bytes import load_le32, store_le32

comptime _DELTA: InlineArray[UInt32, 8] = [
    0xC3EFE9DB,
    0x44626B02,
    0x79E27C8A,
    0x78DF30EC,
    0x715EA49E,
    0xC785DA0A,
    0xE04EF22A,
    0xE5C40957,
]


@always_inline("nodebug")
def _rol(value: UInt32, amount: Int) -> UInt32:
    var shift = amount % 32
    if shift == 0:
        return value
    return (value << UInt32(shift)) | (value >> UInt32(32 - shift))


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> Tuple[List[UInt32], Int]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("LEA key must be 16, 24, or 32 bytes")
    var delta = materialize[_DELTA]()
    var words = len(key) // 4
    var state = InlineArray[UInt32, 8](fill=0)
    for i in range(words):
        state[i] = load_le32(key, i * 4)
    if words == 4:
        var output = List[UInt32](length=24 * 6, fill=0)
        var output_pointer = Span(output).unsafe_ptr()
        for round in range(24):
            var constant = delta[round & 3]
            var base = round * 6
            state[0] = _rol(state[0] + _rol(constant, round), 1)
            state[1] = _rol(state[1] + _rol(constant, round + 1), 3)
            state[2] = _rol(state[2] + _rol(constant, round + 2), 6)
            state[3] = _rol(state[3] + _rol(constant, round + 3), 11)
            output_pointer.unsafe_store(base, state[0])
            output_pointer.unsafe_store(base + 1, state[1])
            output_pointer.unsafe_store(base + 2, state[2])
            output_pointer.unsafe_store(base + 3, state[1])
            output_pointer.unsafe_store(base + 4, state[3])
            output_pointer.unsafe_store(base + 5, state[1])
        return (output^, 24)
    if words == 6:
        var output = List[UInt32](length=28 * 6, fill=0)
        var output_pointer = Span(output).unsafe_ptr()
        for round in range(28):
            var constant = delta[round % 6]
            var base = round * 6
            state[0] = _rol(state[0] + _rol(constant, round), 1)
            state[1] = _rol(state[1] + _rol(constant, round + 1), 3)
            state[2] = _rol(state[2] + _rol(constant, round + 2), 6)
            state[3] = _rol(state[3] + _rol(constant, round + 3), 11)
            state[4] = _rol(state[4] + _rol(constant, round + 4), 13)
            state[5] = _rol(state[5] + _rol(constant, round + 5), 17)
            comptime for j in range(6):
                output_pointer.unsafe_store(base + j, state[j])
        return (output^, 28)
    var output = List[UInt32](length=32 * 6, fill=0)
    var output_pointer = Span(output).unsafe_ptr()
    for round in range(32):
        var constant = delta[round & 7]
        var base = round * 6
        var index0 = base & 7
        var index1 = (base + 1) & 7
        var index2 = (base + 2) & 7
        var index3 = (base + 3) & 7
        var index4 = (base + 4) & 7
        var index5 = (base + 5) & 7
        state[index0] = _rol(state[index0] + _rol(constant, round), 1)
        state[index1] = _rol(state[index1] + _rol(constant, round + 1), 3)
        state[index2] = _rol(state[index2] + _rol(constant, round + 2), 6)
        state[index3] = _rol(state[index3] + _rol(constant, round + 3), 11)
        state[index4] = _rol(state[index4] + _rol(constant, round + 4), 13)
        state[index5] = _rol(state[index5] + _rol(constant, round + 5), 17)
        output_pointer.unsafe_store(base, state[index0])
        output_pointer.unsafe_store(base + 1, state[index1])
        output_pointer.unsafe_store(base + 2, state[index2])
        output_pointer.unsafe_store(base + 3, state[index3])
        output_pointer.unsafe_store(base + 4, state[index4])
        output_pointer.unsafe_store(base + 5, state[index5])
    return (output^, 32)


def process_prepared_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    rounds: Int,
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("LEA block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("LEA output span is too short")
    var key_pointer = Span(keys).unsafe_ptr()
    var x0 = load_le32(block, 0)
    var x1 = load_le32(block, 4)
    var x2 = load_le32(block, 8)
    var x3 = load_le32(block, 12)
    comptime if decrypting:
        for offset in range(rounds):
            var base = (rounds - 1 - offset) * 6
            var old0 = x3
            var old1 = (
                rotate_bits_left[23](x0)
                - (old0 ^ key_pointer.unsafe_load(base))
            ) ^ key_pointer.unsafe_load(base + 1)
            var old2 = (
                rotate_bits_left[5](x1)
                - (old1 ^ key_pointer.unsafe_load(base + 2))
            ) ^ key_pointer.unsafe_load(base + 3)
            var old3 = (
                rotate_bits_left[3](x2)
                - (old2 ^ key_pointer.unsafe_load(base + 4))
            ) ^ key_pointer.unsafe_load(base + 5)
            x0 = old0
            x1 = old1
            x2 = old2
            x3 = old3
    else:
        for round in range(rounds):
            var base = round * 6
            var old0 = x0
            var old1 = x1
            var old2 = x2
            var old3 = x3
            x0 = rotate_bits_left[9](
                (old0 ^ key_pointer.unsafe_load(base))
                + (old1 ^ key_pointer.unsafe_load(base + 1))
            )
            x1 = rotate_bits_left[27](
                (old1 ^ key_pointer.unsafe_load(base + 2))
                + (old2 ^ key_pointer.unsafe_load(base + 3))
            )
            x2 = rotate_bits_left[29](
                (old2 ^ key_pointer.unsafe_load(base + 4))
                + (old3 ^ key_pointer.unsafe_load(base + 5))
            )
            x3 = old0
    store_le32(x0, output, output_offset)
    store_le32(x1, output, output_offset + 4)
    store_le32(x2, output, output_offset + 8)
    store_le32(x3, output, output_offset + 12)


def encrypt_prepared[
    block_origin: Origin
](
    keys: List[UInt32],
    rounds: Int,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared_into[False](keys, rounds, block, Span(output), 0)
    return output^


def decrypt_prepared[
    block_origin: Origin
](
    keys: List[UInt32],
    rounds: Int,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared_into[True](keys, rounds, block, Span(output), 0)
    return output^


def process_eight[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    keys: List[UInt32],
    rounds: Int,
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 128:
        raise Error("eight LEA blocks must total 128 bytes")
    if output_offset < 0 or output_offset + 128 > len(output):
        raise Error("LEA output span is too short")
    var key_pointer = Span(keys).unsafe_ptr()
    var x0 = SIMD[DType.uint32, 8](0)
    var x1 = SIMD[DType.uint32, 8](0)
    var x2 = SIMD[DType.uint32, 8](0)
    var x3 = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        x0[lane] = load_le32(blocks, lane * 16)
        x1[lane] = load_le32(blocks, lane * 16 + 4)
        x2[lane] = load_le32(blocks, lane * 16 + 8)
        x3[lane] = load_le32(blocks, lane * 16 + 12)
    if decrypt:
        for offset in range(rounds):
            var base = (rounds - 1 - offset) * 6
            var old0 = x3
            var old1 = (
                rotate_bits_left[23](x0)
                - (old0 ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base)))
            ) ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 1))
            var old2 = (
                rotate_bits_left[5](x1)
                - (
                    old1
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 2))
                )
            ) ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 3))
            var old3 = (
                rotate_bits_left[3](x2)
                - (
                    old2
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 4))
                )
            ) ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 5))
            x0 = old0
            x1 = old1
            x2 = old2
            x3 = old3
    else:
        for round in range(rounds):
            var base = round * 6
            var old0 = x0
            var old1 = x1
            var old2 = x2
            var old3 = x3
            x0 = rotate_bits_left[9](
                (old0 ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base)))
                + (
                    old1
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 1))
                )
            )
            x1 = rotate_bits_left[27](
                (
                    old1
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 2))
                )
                + (
                    old2
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 3))
                )
            )
            x2 = rotate_bits_left[29](
                (
                    old2
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 4))
                )
                + (
                    old3
                    ^ SIMD[DType.uint32, 8](key_pointer.unsafe_load(base + 5))
                )
            )
            x3 = old0
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        var value0 = UInt32(x0[lane])
        var value1 = UInt32(x1[lane])
        var value2 = UInt32(x2[lane])
        var value3 = UInt32(x3[lane])
        comptime for byte in range(4):
            output_pointer.unsafe_store(
                output_offset + lane * 16 + byte,
                UInt8(value0 >> UInt32(byte * 8)),
            )
            output_pointer.unsafe_store(
                output_offset + lane * 16 + 4 + byte,
                UInt8(value1 >> UInt32(byte * 8)),
            )
            output_pointer.unsafe_store(
                output_offset + lane * 16 + 8 + byte,
                UInt8(value2 >> UInt32(byte * 8)),
            )
            output_pointer.unsafe_store(
                output_offset + lane * 16 + 12 + byte,
                UInt8(value3 >> UInt32(byte * 8)),
            )


def encrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    var schedule = prepare(key)
    return encrypt_prepared(schedule[0], schedule[1], block)


def decrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    var schedule = prepare(key)
    return decrypt_prepared(schedule[0], schedule[1], block)
