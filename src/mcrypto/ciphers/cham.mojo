"""CHAM-64/128 and CHAM-128/128/256 block ciphers."""

from std.bit import rotate_bits_left

from ..internal.bytes import load_be32, store_be32
from .algorithm import BlockCipherAlgorithm


@always_inline("nodebug")
def _rol16(x: UInt16, n: Int) -> UInt16:
    return (x << UInt16(n)) | (x >> UInt16(16 - n))


@always_inline("nodebug")
def _ror16(x: UInt16, n: Int) -> UInt16:
    return (x >> UInt16(n)) | (x << UInt16(16 - n))


@always_inline("nodebug")
def _rol32(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


@always_inline("nodebug")
def _ror32(x: UInt32, n: Int) -> UInt32:
    return (x >> UInt32(n)) | (x << UInt32(32 - n))


def prepare16[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> InlineArray[UInt16, 16]:
    if len(key) != 16:
        raise Error("CHAM-64 requires a 16-byte key")
    var round_keys = InlineArray[UInt16, 16](fill=0)
    comptime for i in range(8):
        var word = (UInt16(key[2 * i]) << 8) | UInt16(key[2 * i + 1])
        round_keys[i] = word ^ _rol16(word, 1) ^ _rol16(word, 8)
        round_keys[(i + 8) ^ 1] = word ^ _rol16(word, 1) ^ _rol16(word, 11)
    return round_keys.copy()


@always_inline("nodebug")
def _prepare32[
    words: Int, key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> InlineArray[UInt32, 16]:
    var round_keys = InlineArray[UInt32, 16](fill=0)
    comptime for i in range(words):
        var word = load_be32(key, i * 4)
        round_keys[i] = word ^ _rol32(word, 1) ^ _rol32(word, 8)
        round_keys[(i + words) ^ 1] = word ^ _rol32(word, 1) ^ _rol32(word, 11)
    return round_keys.copy()


def prepare32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> Tuple[InlineArray[UInt32, 16], Int]:
    if len(key) == 16:
        return (_prepare32[4](key), 80)
    if len(key) == 32:
        return (_prepare32[8](key), 96)
    raise Error("CHAM-128 requires a 16- or 32-byte key")


@always_inline("nodebug")
def process_prepared16_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    round_keys: InlineArray[UInt16, 16],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 8:
        raise Error("CHAM-64 block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("CHAM-64 output span is too short")
    var a = (UInt16(block[0]) << 8) | UInt16(block[1])
    var b = (UInt16(block[2]) << 8) | UInt16(block[3])
    var c = (UInt16(block[4]) << 8) | UInt16(block[5])
    var d = (UInt16(block[6]) << 8) | UInt16(block[7])
    comptime if decrypt:
        comptime for group in range(20):
            comptime base = 76 - 4 * group
            d = (
                _ror16(d, 1) - (_rol16(a, 8) ^ round_keys[(base + 3) & 15])
            ) ^ UInt16(base + 3)
            c = (
                _ror16(c, 8) - (_rol16(d, 1) ^ round_keys[(base + 2) & 15])
            ) ^ UInt16(base + 2)
            b = (
                _ror16(b, 1) - (_rol16(c, 8) ^ round_keys[(base + 1) & 15])
            ) ^ UInt16(base + 1)
            a = (
                _ror16(a, 8) - (_rol16(b, 1) ^ round_keys[base & 15])
            ) ^ UInt16(base)
    else:
        comptime for base in range(0, 80, 4):
            a = _rol16(
                (a ^ UInt16(base)) + (_rol16(b, 1) ^ round_keys[base & 15]), 8
            )
            b = _rol16(
                (b ^ UInt16(base + 1))
                + (_rol16(c, 8) ^ round_keys[(base + 1) & 15]),
                1,
            )
            c = _rol16(
                (c ^ UInt16(base + 2))
                + (_rol16(d, 1) ^ round_keys[(base + 2) & 15]),
                8,
            )
            d = _rol16(
                (d ^ UInt16(base + 3))
                + (_rol16(a, 8) ^ round_keys[(base + 3) & 15]),
                1,
            )
    output[output_offset] = UInt8(a >> 8)
    output[output_offset + 1] = UInt8(a)
    output[output_offset + 2] = UInt8(b >> 8)
    output[output_offset + 3] = UInt8(b)
    output[output_offset + 4] = UInt8(c >> 8)
    output[output_offset + 5] = UInt8(c)
    output[output_offset + 6] = UInt8(d >> 8)
    output[output_offset + 7] = UInt8(d)


@always_inline("nodebug")
def process_prepared32_into[
    decrypt: Bool,
    rounds: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    round_keys: InlineArray[UInt32, 16],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("CHAM-128 block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("CHAM-128 output span is too short")
    comptime key_mask = 7 if rounds == 80 else 15
    var a = load_be32(block, 0)
    var b = load_be32(block, 4)
    var c = load_be32(block, 8)
    var d = load_be32(block, 12)
    comptime if decrypt:
        comptime for group in range(rounds // 4):
            comptime base = rounds - 4 - 4 * group
            d = (
                _ror32(d, 1)
                - (_rol32(a, 8) ^ round_keys[(base + 3) & key_mask])
            ) ^ UInt32(base + 3)
            c = (
                _ror32(c, 8)
                - (_rol32(d, 1) ^ round_keys[(base + 2) & key_mask])
            ) ^ UInt32(base + 2)
            b = (
                _ror32(b, 1)
                - (_rol32(c, 8) ^ round_keys[(base + 1) & key_mask])
            ) ^ UInt32(base + 1)
            a = (
                _ror32(a, 8) - (_rol32(b, 1) ^ round_keys[base & key_mask])
            ) ^ UInt32(base)
    else:
        comptime for base in range(0, rounds, 4):
            a = _rol32(
                (a ^ UInt32(base))
                + (_rol32(b, 1) ^ round_keys[base & key_mask]),
                8,
            )
            b = _rol32(
                (b ^ UInt32(base + 1))
                + (_rol32(c, 8) ^ round_keys[(base + 1) & key_mask]),
                1,
            )
            c = _rol32(
                (c ^ UInt32(base + 2))
                + (_rol32(d, 1) ^ round_keys[(base + 2) & key_mask]),
                8,
            )
            d = _rol32(
                (d ^ UInt32(base + 3))
                + (_rol32(a, 8) ^ round_keys[(base + 3) & key_mask]),
                1,
            )
    store_be32(a, output, output_offset)
    store_be32(b, output, output_offset + 4)
    store_be32(c, output, output_offset + 8)
    store_be32(d, output, output_offset + 12)


def encrypt_prepared16[
    block_origin: Origin
](
    round_keys: InlineArray[UInt16, 16],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared16_into[False](round_keys, block, Span(output), 0)
    return output^


def decrypt_prepared16[
    block_origin: Origin
](
    round_keys: InlineArray[UInt16, 16],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared16_into[True](round_keys, block, Span(output), 0)
    return output^


def encrypt_prepared32[
    rounds: Int, block_origin: Origin
](
    round_keys: InlineArray[UInt32, 16],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared32_into[False, rounds](round_keys, block, Span(output), 0)
    return output^


def decrypt_prepared32[
    rounds: Int, block_origin: Origin
](
    round_keys: InlineArray[UInt32, 16],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared32_into[True, rounds](round_keys, block, Span(output), 0)
    return output^


def process_sixteen16[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    round_keys: InlineArray[UInt16, 16],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 128:
        raise Error("sixteen CHAM-64 blocks must total 128 bytes")
    if output_offset < 0 or output_offset + 128 > len(output):
        raise Error("CHAM-64 output span is too short")
    var state = InlineArray[SIMD[DType.uint16, 16], 4](
        fill=SIMD[DType.uint16, 16](0)
    )
    comptime for lane in range(16):
        comptime for word in range(4):
            state[word][lane] = (
                UInt16(blocks[lane * 8 + word * 2]) << 8
            ) | UInt16(blocks[lane * 8 + word * 2 + 1])
    if decrypt:
        comptime for offset in range(80):
            comptime round = 79 - offset
            comptime lane = round % 4
            comptime next_lane = (round + 1) % 4
            comptime even = round % 2 == 0
            var right = (
                rotate_bits_left[1](
                    state[next_lane]
                ) if even else rotate_bits_left[8](state[next_lane])
            ) ^ SIMD[DType.uint16, 16](round_keys[round % 16])
            state[lane] = (
                (
                    rotate_bits_left[8](
                        state[lane]
                    ) if even else rotate_bits_left[15](state[lane])
                )
                - right
            ) ^ SIMD[DType.uint16, 16](UInt16(round))
    else:
        comptime for round in range(80):
            comptime lane = round % 4
            comptime next_lane = (round + 1) % 4
            comptime even = round % 2 == 0
            var left = state[lane] ^ SIMD[DType.uint16, 16](UInt16(round))
            var right = (
                rotate_bits_left[1](
                    state[next_lane]
                ) if even else rotate_bits_left[8](state[next_lane])
            ) ^ SIMD[DType.uint16, 16](round_keys[round % 16])
            state[lane] = rotate_bits_left[8](
                left + right
            ) if even else rotate_bits_left[1](left + right)
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(16):
        comptime for word in range(4):
            var value = UInt16(state[word][lane])
            output_pointer.unsafe_store(
                output_offset + lane * 8 + word * 2,
                UInt8(value >> 8),
            )
            output_pointer.unsafe_store(
                output_offset + lane * 8 + word * 2 + 1,
                UInt8(value),
            )


def process_eight32[
    rounds: Int, block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    round_keys: InlineArray[UInt32, 16],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 128:
        raise Error("eight CHAM-128 blocks must total 128 bytes")
    if output_offset < 0 or output_offset + 128 > len(output):
        raise Error("CHAM-128 output span is too short")
    var state = InlineArray[SIMD[DType.uint32, 8], 4](
        fill=SIMD[DType.uint32, 8](0)
    )
    comptime for lane in range(8):
        comptime for word in range(4):
            state[word][lane] = load_be32(blocks, lane * 16 + word * 4)
    comptime key_count = 8 if rounds == 80 else 16
    if decrypt:
        comptime for offset in range(rounds):
            comptime round = rounds - 1 - offset
            comptime lane = round % 4
            comptime next_lane = (round + 1) % 4
            comptime even = round % 2 == 0
            var right = (
                rotate_bits_left[1](
                    state[next_lane]
                ) if even else rotate_bits_left[8](state[next_lane])
            ) ^ SIMD[DType.uint32, 8](round_keys[round % key_count])
            state[lane] = (
                (
                    rotate_bits_left[24](
                        state[lane]
                    ) if even else rotate_bits_left[31](state[lane])
                )
                - right
            ) ^ SIMD[DType.uint32, 8](UInt32(round))
    else:
        comptime for round in range(rounds):
            comptime lane = round % 4
            comptime next_lane = (round + 1) % 4
            comptime even = round % 2 == 0
            var left = state[lane] ^ SIMD[DType.uint32, 8](UInt32(round))
            var right = (
                rotate_bits_left[1](
                    state[next_lane]
                ) if even else rotate_bits_left[8](state[next_lane])
            ) ^ SIMD[DType.uint32, 8](round_keys[round % key_count])
            state[lane] = rotate_bits_left[8](
                left + right
            ) if even else rotate_bits_left[1](left + right)
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        comptime for word in range(4):
            var value = UInt32(state[word][lane])
            comptime for byte in range(4):
                output_pointer.unsafe_store(
                    output_offset + lane * 16 + word * 4 + byte,
                    UInt8(value >> UInt32(24 - byte * 8)),
                )


def encrypt[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.CHAM64:
        return encrypt_prepared16(prepare16(key), block)
    if algorithm == BlockCipherAlgorithm.CHAM128:
        var prepared = prepare32(key)
        if prepared[1] == 80:
            return encrypt_prepared32[80](prepared[0], block)
        return encrypt_prepared32[96](prepared[0], block)
    raise Error("unknown CHAM variant")


def decrypt[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.CHAM64:
        return decrypt_prepared16(prepare16(key), block)
    if algorithm == BlockCipherAlgorithm.CHAM128:
        var prepared = prepare32(key)
        if prepared[1] == 80:
            return decrypt_prepared32[80](prepared[0], block)
        return decrypt_prepared32[96](prepared[0], block)
    raise Error("unknown CHAM variant")
