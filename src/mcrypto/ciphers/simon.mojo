"""SIMON-64 and SIMON-128 block ciphers."""

from std.bit import rotate_bits_left

from ..internal.bytes import load_le32, load_le64, store_le32, store_le64
from .algorithm import BlockCipherAlgorithm


@always_inline("nodebug")
def _f32(x: UInt32) -> UInt32:
    return (((x << 1) | (x >> 31)) & ((x << 8) | (x >> 24))) ^ (
        (x << 2) | (x >> 30)
    )


@always_inline("nodebug")
def _f64(x: UInt64) -> UInt64:
    return (((x << 1) | (x >> 63)) & ((x << 8) | (x >> 56))) ^ (
        (x << 2) | (x >> 62)
    )


@always_inline("nodebug")
def _r32(x: UInt32, n: Int) -> UInt32:
    return (x >> UInt32(n)) | (x << UInt32(32 - n))


@always_inline("nodebug")
def _r64(x: UInt64, n: Int) -> UInt64:
    return (x >> UInt64(n)) | (x << UInt64(64 - n))


def _keys32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 12 and len(key) != 16:
        raise Error("SIMON-64 key must be 12 or 16 bytes")
    var words = List[UInt32](capacity=len(key) // 4)
    for offset in range(0, len(key), 4):
        words.append(load_le32(key, offset))
    var m = len(words)
    var rounds = 42 if m == 3 else 44
    var z = UInt64(0x7369F885192C0EF5 if m == 3 else 0xFC2CE51207A635DB)
    var keys = List[UInt32](capacity=rounds)
    for i in range(m):
        keys.append(words[i])
    for i in range(m, rounds):
        var value = (
            UInt32(0xFFFFFFFC)
            ^ UInt32(z & 1)
            ^ keys[i - m]
            ^ _r32(keys[i - 1], 3)
            ^ _r32(keys[i - 1], 4)
        )
        if m == 4:
            value ^= keys[i - 3] ^ _r32(keys[i - 3], 1)
        keys.append(value)
        z >>= 1
    return keys^


def _keys64[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt64]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("SIMON-128 key must be 16, 24, or 32 bytes")
    var words = List[UInt64](capacity=len(key) // 8)
    for offset in range(0, len(key), 8):
        words.append(load_le64(key, offset))
    var m = len(words)
    var rounds = 66 + m if m < 4 else 72
    var z = UInt64(
        0x7369F885192C0EF5 if m
        == 2 else (0xFC2CE51207A635DB if m == 3 else 0xFDC94C3A046D678B)
    )
    var keys = List[UInt64](capacity=rounds)
    for i in range(m):
        keys.append(words[i])
    for i in range(m, rounds):
        var bit = z & 1
        if i - m >= 64:
            bit = UInt64(
                1 if (m == 2 and i == 66)
                or (m == 3 and i == 68)
                or (m == 4 and i == 69) else 0
            )
        var value = (
            UInt64(0xFFFFFFFFFFFFFFFC)
            ^ bit
            ^ keys[i - m]
            ^ _r64(keys[i - 1], 3)
            ^ _r64(keys[i - 1], 4)
        )
        if m == 4:
            value ^= keys[i - 3] ^ _r64(keys[i - 3], 1)
        keys.append(value)
        z >>= 1
    return keys^


def prepare32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    return _keys32(key)


def prepare64[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt64]:
    return _keys64(key)


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
        raise Error("SIMON-64 block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("SIMON-64 output span is too short")
    var x = load_le32(block, 4)
    var y = load_le32(block, 0)
    comptime if decrypt:
        for offset in range(len(keys)):
            var previous = x ^ _f32(y) ^ keys[len(keys) - 1 - offset]
            x = y
            y = previous
    else:
        for key in keys:
            var next = y ^ _f32(x) ^ key
            y = x
            x = next
    store_le32(y, output, output_offset)
    store_le32(x, output, output_offset + 4)


def process_prepared64_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt64],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("SIMON-128 block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("SIMON-128 output span is too short")
    var x = load_le64(block, 8)
    var y = load_le64(block, 0)
    comptime if decrypt:
        for offset in range(len(keys)):
            var previous = x ^ _f64(y) ^ keys[len(keys) - 1 - offset]
            x = y
            y = previous
    else:
        for key in keys:
            var next = y ^ _f64(x) ^ key
            y = x
            x = next
    store_le64(y, output, output_offset)
    store_le64(x, output, output_offset + 8)


def encrypt_prepared32[
    block_origin: Origin
](keys: List[UInt32], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("SIMON-64 block must be 8 bytes")
    var x = load_le32(block, 4)
    var y = load_le32(block, 0)
    for key in keys:
        var next = y ^ _f32(x) ^ key
        y = x
        x = next
    var output = List[UInt8](length=8, fill=0)
    var output_span = Span(output)
    store_le32(y, output_span, 0)
    store_le32(x, output_span, 4)
    return output^


def decrypt_prepared32[
    block_origin: Origin
](keys: List[UInt32], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("SIMON-64 block must be 8 bytes")
    var x = load_le32(block, 4)
    var y = load_le32(block, 0)
    for offset in range(len(keys)):
        var previous = x ^ _f32(y) ^ keys[len(keys) - 1 - offset]
        x = y
        y = previous
    var output = List[UInt8](length=8, fill=0)
    var output_span = Span(output)
    store_le32(y, output_span, 0)
    store_le32(x, output_span, 4)
    return output^


def encrypt_prepared64[
    block_origin: Origin
](keys: List[UInt64], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    if len(block) != 16:
        raise Error("SIMON-128 block must be 16 bytes")
    var x = load_le64(block, 8)
    var y = load_le64(block, 0)
    for key in keys:
        var next = y ^ _f64(x) ^ key
        y = x
        x = next
    var output = List[UInt8](length=16, fill=0)
    var output_span = Span(output)
    store_le64(y, output_span, 0)
    store_le64(x, output_span, 8)
    return output^


def decrypt_prepared64[
    block_origin: Origin
](keys: List[UInt64], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    if len(block) != 16:
        raise Error("SIMON-128 block must be 16 bytes")
    var x = load_le64(block, 8)
    var y = load_le64(block, 0)
    for offset in range(len(keys)):
        var previous = x ^ _f64(y) ^ keys[len(keys) - 1 - offset]
        x = y
        y = previous
    var output = List[UInt8](length=16, fill=0)
    var output_span = Span(output)
    store_le64(y, output_span, 0)
    store_le64(x, output_span, 8)
    return output^


def process_four64[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    keys: List[UInt64],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 64:
        raise Error("four SIMON-128 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SIMON-128 output span is too short")
    var x = SIMD[DType.uint64, 4](0)
    var y = SIMD[DType.uint64, 4](0)
    comptime for lane in range(4):
        y[lane] = load_le64(blocks, lane * 16)
        x[lane] = load_le64(blocks, lane * 16 + 8)
    if decrypt:
        for offset in range(len(keys)):
            var previous = (
                x
                ^ (
                    (rotate_bits_left[1](y) & rotate_bits_left[8](y))
                    ^ rotate_bits_left[2](y)
                )
                ^ SIMD[DType.uint64, 4](keys[len(keys) - 1 - offset])
            )
            x = y
            y = previous
    else:
        for key in keys:
            var next = (
                y
                ^ (
                    (rotate_bits_left[1](x) & rotate_bits_left[8](x))
                    ^ rotate_bits_left[2](x)
                )
                ^ SIMD[DType.uint64, 4](key)
            )
            y = x
            x = next
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(4):
        comptime for word in range(2):
            var value = UInt64(y[lane] if word == 0 else x[lane])
            comptime for byte in range(8):
                output_pointer.unsafe_store(
                    output_offset + lane * 16 + word * 8 + byte,
                    UInt8(value >> UInt64(byte * 8)),
                )


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
        raise Error("eight SIMON-64 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SIMON-64 output span is too short")
    var x = SIMD[DType.uint32, 8](0)
    var y = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        y[lane] = load_le32(blocks, lane * 8)
        x[lane] = load_le32(blocks, lane * 8 + 4)
    if decrypt:
        for offset in range(len(keys)):
            var previous = (
                x
                ^ (
                    (rotate_bits_left[1](y) & rotate_bits_left[8](y))
                    ^ rotate_bits_left[2](y)
                )
                ^ SIMD[DType.uint32, 8](keys[len(keys) - 1 - offset])
            )
            x = y
            y = previous
    else:
        for key in keys:
            var next = (
                y
                ^ (
                    (rotate_bits_left[1](x) & rotate_bits_left[8](x))
                    ^ rotate_bits_left[2](x)
                )
                ^ SIMD[DType.uint32, 8](key)
            )
            y = x
            x = next
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        comptime for word in range(2):
            var value = UInt32(y[lane] if word == 0 else x[lane])
            comptime for byte in range(4):
                output_pointer.unsafe_store(
                    output_offset + lane * 8 + word * 4 + byte,
                    UInt8(value >> UInt32(byte * 8)),
                )


def encrypt[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.SIMON64:
        return encrypt_prepared32(_keys32(key), block)
    if algorithm == BlockCipherAlgorithm.SIMON128:
        return encrypt_prepared64(_keys64(key), block)
    raise Error("unknown SIMON variant")


def decrypt[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.SIMON64:
        return decrypt_prepared32(_keys32(key), block)
    if algorithm == BlockCipherAlgorithm.SIMON128:
        return decrypt_prepared64(_keys64(key), block)
    raise Error("unknown SIMON variant")
