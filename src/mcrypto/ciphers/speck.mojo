"""SPECK-64 and SPECK-128 block ciphers."""

from std.bit import rotate_bits_left
from std.memory import bitcast

from ..internal.bytes import load_le32, load_le64, store_le32, store_le64
from .algorithm import BlockCipherAlgorithm


@always_inline("nodebug")
def _ror32(x: UInt32) -> UInt32:
    return (x >> 8) | (x << 24)


@always_inline("nodebug")
def _rol32(x: UInt32) -> UInt32:
    return (x << 3) | (x >> 29)


@always_inline("nodebug")
def _ror3_32(x: UInt32) -> UInt32:
    return (x >> 3) | (x << 29)


@always_inline("nodebug")
def _rol8_32(x: UInt32) -> UInt32:
    return (x << 8) | (x >> 24)


@always_inline("nodebug")
def _ror64(x: UInt64) -> UInt64:
    return (x >> 8) | (x << 56)


@always_inline("nodebug")
def _rol64(x: UInt64) -> UInt64:
    return (x << 3) | (x >> 61)


def _keys32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 12 and len(key) != 16:
        raise Error("SPECK-64 key must be 12 or 16 bytes")
    var words = List[UInt32](capacity=len(key) // 4)
    for offset in range(0, len(key), 4):
        words.append(load_le32(key, offset))
    var a = words[0]
    var l = List[UInt32](capacity=len(words) - 1)
    for offset in range(1, len(words)):
        l.append(words[offset])
    var rounds = 26 if len(key) == 12 else 27
    var keys = List[UInt32](capacity=rounds)
    keys.append(a)
    for i in range(rounds - 1):
        var index = i % (len(words) - 1)
        var x = _ror32(l[index])
        x += a
        x ^= UInt32(i)
        a = _rol32(a) ^ x
        l[index] = x
        keys.append(a)
    return keys^


def _keys64[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt64]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("SPECK-128 key must be 16, 24, or 32 bytes")
    var words = List[UInt64](capacity=len(key) // 8)
    for offset in range(0, len(key), 8):
        words.append(load_le64(key, offset))
    var a = words[0]
    var l = List[UInt64](capacity=len(words) - 1)
    for offset in range(1, len(words)):
        l.append(words[offset])
    var rounds = 30 + len(words)
    var keys = List[UInt64](capacity=rounds)
    keys.append(a)
    for i in range(rounds - 1):
        var index = i % (len(words) - 1)
        var x = _ror64(l[index])
        x += a
        x ^= UInt64(i)
        a = _rol64(a) ^ x
        l[index] = x
        keys.append(a)
    return keys^


def prepare32[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    return _keys32(key)


def prepare64[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt64]:
    return _keys64(key)


@always_inline("nodebug")
def _process_prepared32_into[
    decrypting: Bool,
    rounds: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    var x = load_le32(block, 4)
    var y = load_le32(block, 0)
    var key_pointer = Span(keys).unsafe_ptr()
    comptime if decrypting:
        comptime for offset in range(rounds):
            var k = key_pointer.unsafe_load(rounds - 1 - offset)
            y = _ror3_32(y ^ x)
            x = _rol8_32((x ^ k) - y)
    else:
        comptime for round in range(rounds):
            x = _ror32(x)
            x += y
            x ^= key_pointer.unsafe_load(round)
            y = _rol32(y) ^ x
    store_le32(y, output, output_offset)
    store_le32(x, output, output_offset + 4)


def process_prepared32_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 8:
        raise Error("SPECK-64 block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("SPECK-64 output span is too short")
    if len(keys) == 26:
        _process_prepared32_into[decrypting, 26](
            keys, block, output, output_offset
        )
        return
    if len(keys) == 27:
        _process_prepared32_into[decrypting, 27](
            keys, block, output, output_offset
        )
        return
    raise Error("invalid SPECK-64 round-key count")


def encrypt_prepared32[
    block_origin: Origin
](keys: List[UInt32], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared32_into[False](keys, block, Span(output), 0)
    return output^


def decrypt_prepared32[
    block_origin: Origin
](keys: List[UInt32], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared32_into[True](keys, block, Span(output), 0)
    return output^


@always_inline("nodebug")
def _process_prepared64_into[
    decrypting: Bool,
    rounds: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt64],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    var x = load_le64(block, 8)
    var y = load_le64(block, 0)
    var key_pointer = Span(keys).unsafe_ptr()
    comptime if decrypting:
        comptime for offset in range(rounds):
            var k = key_pointer.unsafe_load(rounds - 1 - offset)
            y = (y ^ x) >> 3 | ((y ^ x) << 61)
            x = (x ^ k) - y
            x = (x << 8) | (x >> 56)
    else:
        comptime for round in range(rounds):
            x = _ror64(x)
            x += y
            x ^= key_pointer.unsafe_load(round)
            y = _rol64(y) ^ x
    store_le64(y, output, output_offset)
    store_le64(x, output, output_offset + 8)


def process_prepared64_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt64],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("SPECK-128 block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("SPECK-128 output span is too short")
    if len(keys) == 32:
        _process_prepared64_into[decrypting, 32](
            keys, block, output, output_offset
        )
        return
    if len(keys) == 33:
        _process_prepared64_into[decrypting, 33](
            keys, block, output, output_offset
        )
        return
    if len(keys) == 34:
        _process_prepared64_into[decrypting, 34](
            keys, block, output, output_offset
        )
        return
    raise Error("invalid SPECK-128 round-key count")


def encrypt_prepared64[
    block_origin: Origin
](keys: List[UInt64], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared64_into[False](keys, block, Span(output), 0)
    return output^


def decrypt_prepared64[
    block_origin: Origin
](keys: List[UInt64], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared64_into[True](keys, block, Span(output), 0)
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
        raise Error("four SPECK-128 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SPECK-128 output span is too short")
    var x = SIMD[DType.uint64, 4](0)
    var y = SIMD[DType.uint64, 4](0)
    var input_pointer = blocks.unsafe_ptr()
    comptime for lane in range(4):
        var words = bitcast[DType.uint64, 2](
            input_pointer.unsafe_load[width=16](lane * 16)
        )
        y[lane] = words[0]
        x[lane] = words[1]
    var key_pointer = Span(keys).unsafe_ptr()
    if decrypt:
        for offset in range(len(keys)):
            var round_key = SIMD[DType.uint64, 4](
                key_pointer.unsafe_load(len(keys) - 1 - offset)
            )
            y = rotate_bits_left[61](y ^ x)
            x = rotate_bits_left[8]((x ^ round_key) - y)
    else:
        for round in range(len(keys)):
            x = rotate_bits_left[56](x)
            x += y
            x ^= SIMD[DType.uint64, 4](key_pointer.unsafe_load(round))
            y = rotate_bits_left[3](y) ^ x
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(4):
        var words = SIMD[DType.uint64, 2](0)
        words[0] = y[lane]
        words[1] = x[lane]
        output_pointer.unsafe_store[width=16](
            output_offset + lane * 16,
            bitcast[DType.uint8, 16](words),
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
        raise Error("eight SPECK-64 blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("SPECK-64 output span is too short")
    var x = SIMD[DType.uint32, 8](0)
    var y = SIMD[DType.uint32, 8](0)
    var input_pointer = blocks.unsafe_ptr()
    comptime for lane in range(8):
        var words = bitcast[DType.uint32, 2](
            input_pointer.unsafe_load[width=8](lane * 8)
        )
        y[lane] = words[0]
        x[lane] = words[1]
    var key_pointer = Span(keys).unsafe_ptr()
    if decrypt:
        for offset in range(len(keys)):
            var round_key = SIMD[DType.uint32, 8](
                key_pointer.unsafe_load(len(keys) - 1 - offset)
            )
            y = rotate_bits_left[29](y ^ x)
            x = rotate_bits_left[8]((x ^ round_key) - y)
    else:
        for round in range(len(keys)):
            x = rotate_bits_left[24](x)
            x += y
            x ^= SIMD[DType.uint32, 8](key_pointer.unsafe_load(round))
            y = rotate_bits_left[3](y) ^ x
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        var words = SIMD[DType.uint32, 2](0)
        words[0] = y[lane]
        words[1] = x[lane]
        output_pointer.unsafe_store[width=8](
            output_offset + lane * 8,
            bitcast[DType.uint8, 8](words),
        )


def encrypt[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.SPECK64:
        return encrypt_prepared32(_keys32(key), block)
    if algorithm == BlockCipherAlgorithm.SPECK128:
        return encrypt_prepared64(_keys64(key), block)
    raise Error("unknown SPECK variant")


def decrypt[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if algorithm == BlockCipherAlgorithm.SPECK64:
        return decrypt_prepared32(_keys32(key), block)
    if algorithm == BlockCipherAlgorithm.SPECK128:
        return decrypt_prepared64(_keys64(key), block)
    raise Error("unknown SPECK variant")
