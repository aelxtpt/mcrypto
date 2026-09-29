"""SIMECK-32 and SIMECK-64 block ciphers in pure Mojo."""

from std.bit import rotate_bits_left

from ..internal.bytes import load_be32, store_be32
from .algorithm import BlockCipherAlgorithm


@always_inline("nodebug")
def _rol16(value: UInt16, amount: Int) -> UInt16:
    return (value << UInt16(amount)) | (value >> UInt16(16 - amount))


@always_inline("nodebug")
def _rol32(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _round16(key: UInt16, left: UInt16, right: UInt16) -> Tuple[UInt16, UInt16]:
    return ((left & _rol16(left, 5)) ^ _rol16(left, 1) ^ right ^ key, left)


@always_inline("nodebug")
def _round32(key: UInt32, left: UInt32, right: UInt32) -> Tuple[UInt32, UInt32]:
    return ((left & _rol32(left, 5)) ^ _rol32(left, 1) ^ right ^ key, left)


def _keys16[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt16]:
    if len(key) != 8:
        raise Error("SIMECK-32 key must be 8 bytes")
    var words = List[UInt16](length=5, fill=0)
    words[3] = (UInt16(key[0]) << 8) | UInt16(key[1])
    words[2] = (UInt16(key[2]) << 8) | UInt16(key[3])
    words[1] = (UInt16(key[4]) << 8) | UInt16(key[5])
    words[0] = (UInt16(key[6]) << 8) | UInt16(key[7])
    var output = List[UInt16](capacity=32)
    var sequence = UInt32(0x9A42BB1F)
    for _ in range(32):
        output.append(words[0])
        var constant = UInt16(0xFFFC | (sequence & 1))
        sequence >>= 1
        var old0 = words[0]
        var old1 = words[1]
        var generated = (
            (old1 & _rol16(old1, 5)) ^ _rol16(old1, 1) ^ old0 ^ constant
        )
        words[0] = words[1]
        words[1] = words[2]
        words[2] = words[3]
        words[3] = generated
    return output^


def _keys32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 16:
        raise Error("SIMECK-64 key must be 16 bytes")
    var words = List[UInt32](length=5, fill=0)
    words[3] = load_be32(key, 0)
    words[2] = load_be32(key, 4)
    words[1] = load_be32(key, 8)
    words[0] = load_be32(key, 12)
    var output = List[UInt32](capacity=44)
    var sequence = UInt64(0x938BCA3083F)
    for _ in range(44):
        output.append(words[0])
        var constant = UInt32(0xFFFFFFFC | (sequence & 1))
        sequence >>= 1
        var old0 = words[0]
        var old1 = words[1]
        var generated = (
            (old1 & _rol32(old1, 5)) ^ _rol32(old1, 1) ^ old0 ^ constant
        )
        words[0] = words[1]
        words[1] = words[2]
        words[2] = words[3]
        words[3] = generated
    return output^


def prepare16[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt16]:
    return _keys16(key)


def prepare32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    return _keys32(key)


def process_prepared16_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt16],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 4:
        raise Error("SIMECK-32 block must be 4 bytes")
    if output_offset < 0 or output_offset + 4 > len(output):
        raise Error("SIMECK-32 output span is too short")
    var left = (UInt16(block[0]) << 8) | UInt16(block[1])
    var right = (UInt16(block[2]) << 8) | UInt16(block[3])
    comptime if decrypt:
        left, right = right, left
        for offset in range(len(keys)):
            left, right = _round16(keys[len(keys) - 1 - offset], left, right)
        left, right = right, left
    else:
        for key in keys:
            left, right = _round16(key, left, right)
    output[output_offset] = UInt8(left >> 8)
    output[output_offset + 1] = UInt8(left)
    output[output_offset + 2] = UInt8(right >> 8)
    output[output_offset + 3] = UInt8(right)


def process_prepared32_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 8:
        raise Error("SIMECK-64 block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("SIMECK-64 output span is too short")
    var left = load_be32(block, 0)
    var right = load_be32(block, 4)
    comptime if decrypt:
        left, right = right, left
        for offset in range(len(keys)):
            left, right = _round32(keys[len(keys) - 1 - offset], left, right)
        left, right = right, left
    else:
        for key in keys:
            left, right = _round32(key, left, right)
    store_be32(left, output, output_offset)
    store_be32(right, output, output_offset + 4)


def process_prepared16[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt16],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != 4:
        raise Error("SIMECK-32 block must be 4 bytes")
    var left = (UInt16(block[0]) << 8) | UInt16(block[1])
    var right = (UInt16(block[2]) << 8) | UInt16(block[3])
    if decrypt:
        var swap = left
        left = right
        right = swap
    for offset in range(len(keys)):
        var round_key = keys[len(keys) - 1 - offset] if decrypt else keys[
            offset
        ]
        var step = _round16(round_key, left, right)
        left = step[0]
        right = step[1]
    if decrypt:
        var swap = left
        left = right
        right = swap
    var output = List[UInt8](length=4, fill=0)
    output[0] = UInt8(left >> 8)
    output[1] = UInt8(left)
    output[2] = UInt8(right >> 8)
    output[3] = UInt8(right)
    return output^


def process_prepared32[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("SIMECK-64 block must be 8 bytes")
    var left = load_be32(block, 0)
    var right = load_be32(block, 4)
    if decrypt:
        var swap = left
        left = right
        right = swap
    for offset in range(len(keys)):
        var round_key = keys[len(keys) - 1 - offset] if decrypt else keys[
            offset
        ]
        var step = _round32(round_key, left, right)
        left = step[0]
        right = step[1]
    if decrypt:
        var swap = left
        left = right
        right = swap
    var output = List[UInt8](length=8, fill=0)
    var span = Span(output)
    store_be32(left, span, 0)
    store_be32(right, span, 4)
    return output^


def process_sixteen16[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    keys: List[UInt16],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 64:
        raise Error("sixteen SIMECK-32 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SIMECK-32 output span is too short")
    var left = SIMD[DType.uint16, 16](0)
    var right = SIMD[DType.uint16, 16](0)
    comptime for lane in range(16):
        left[lane] = (UInt16(blocks[lane * 4]) << 8) | UInt16(
            blocks[lane * 4 + 1]
        )
        right[lane] = (UInt16(blocks[lane * 4 + 2]) << 8) | UInt16(
            blocks[lane * 4 + 3]
        )
    if decrypt:
        var swap = left
        left = right
        right = swap
    for offset in range(len(keys)):
        var round_key = keys[len(keys) - 1 - offset] if decrypt else keys[
            offset
        ]
        var next = (
            (left & rotate_bits_left[5](left))
            ^ rotate_bits_left[1](left)
            ^ right
            ^ SIMD[DType.uint16, 16](round_key)
        )
        right = left
        left = next
    if decrypt:
        var swap = left
        left = right
        right = swap
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(16):
        var first = UInt16(left[lane])
        var second = UInt16(right[lane])
        output_pointer.unsafe_store(output_offset + lane * 4, UInt8(first >> 8))
        output_pointer.unsafe_store(output_offset + lane * 4 + 1, UInt8(first))
        output_pointer.unsafe_store(
            output_offset + lane * 4 + 2, UInt8(second >> 8)
        )
        output_pointer.unsafe_store(output_offset + lane * 4 + 3, UInt8(second))


def process_eight32[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    keys: List[UInt32],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 64:
        raise Error("eight SIMECK-64 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SIMECK-64 output span is too short")
    var left = SIMD[DType.uint32, 8](0)
    var right = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        left[lane] = load_be32(blocks, lane * 8)
        right[lane] = load_be32(blocks, lane * 8 + 4)
    if decrypt:
        var swap = left
        left = right
        right = swap
    for offset in range(len(keys)):
        var round_key = keys[len(keys) - 1 - offset] if decrypt else keys[
            offset
        ]
        var next = (
            (left & rotate_bits_left[5](left))
            ^ rotate_bits_left[1](left)
            ^ right
            ^ SIMD[DType.uint32, 8](round_key)
        )
        right = left
        left = next
    if decrypt:
        var swap = left
        left = right
        right = swap
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        comptime for word in range(2):
            var value = UInt32(left[lane] if word == 0 else right[lane])
            comptime for byte in range(4):
                output_pointer.unsafe_store(
                    output_offset + lane * 8 + word * 4 + byte,
                    UInt8(value >> UInt32(24 - byte * 8)),
                )


def process[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.SIMECK32:
        return process_prepared16(decrypt, _keys16(key), block)
    if algorithm == BlockCipherAlgorithm.SIMECK64:
        return process_prepared32(decrypt, _keys32(key), block)
    raise Error("unknown SIMECK variant")
