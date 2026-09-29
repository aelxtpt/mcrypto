"""TEA and XTEA 64-bit block ciphers."""

from ..internal.bytes import load_be32, store_be32
from .algorithm import BlockCipherAlgorithm


def _key[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 16:
        raise Error("TEA key must be 16 bytes")
    return [
        load_be32(key, 0),
        load_be32(key, 4),
        load_be32(key, 8),
        load_be32(key, 12),
    ]


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    return _key(key)


def process_prepared_into[
    xtea: Bool,
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 4 or len(block) != 8:
        raise Error(
            "TEA-family cipher requires a prepared key and 8-byte block"
        )
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("TEA-family output span is too short")
    var y = load_be32(block, 0)
    var z = load_be32(block, 4)
    var delta = UInt32(0x9E3779B9)
    var sum = delta * 32 if decrypt else UInt32(0)
    comptime if xtea:
        comptime if decrypt:
            comptime for _ in range(32):
                z -= (((y << 4) ^ (y >> 5)) + y) ^ (
                    sum + keys[Int((sum >> 11) & 3)]
                )
                sum -= delta
                y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + keys[Int(sum & 3)])
        else:
            comptime for _ in range(32):
                y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + keys[Int(sum & 3)])
                sum += delta
                z += (((y << 4) ^ (y >> 5)) + y) ^ (
                    sum + keys[Int((sum >> 11) & 3)]
                )
    else:
        comptime if decrypt:
            comptime for _ in range(32):
                z -= ((y << 4) + keys[2]) ^ (y + sum) ^ ((y >> 5) + keys[3])
                y -= ((z << 4) + keys[0]) ^ (z + sum) ^ ((z >> 5) + keys[1])
                sum -= delta
        else:
            comptime for _ in range(32):
                sum += delta
                y += ((z << 4) + keys[0]) ^ (z + sum) ^ ((z >> 5) + keys[1])
                z += ((y << 4) + keys[2]) ^ (y + sum) ^ ((y >> 5) + keys[3])
    store_be32(y, output, output_offset)
    store_be32(z, output, output_offset + 4)


def process_eight[
    block_origin: Origin, output_origin: MutOrigin
](
    algorithm: BlockCipherAlgorithm,
    decrypt: Bool,
    keys: List[UInt32],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) != 64:
        raise Error("eight TEA-family blocks must total 64 bytes")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("TEA-family output span is too short")
    var y = SIMD[DType.uint32, 8](0)
    var z = SIMD[DType.uint32, 8](0)
    comptime for lane in range(8):
        y[lane] = load_be32(blocks, lane * 8)
        z[lane] = load_be32(blocks, lane * 8 + 4)
    var delta = UInt32(0x9E3779B9)
    var sum = delta * 32 if decrypt else UInt32(0)
    if algorithm == BlockCipherAlgorithm.TEA:
        if decrypt:
            comptime for _ in range(32):
                z -= (
                    ((y << 4) + SIMD[DType.uint32, 8](keys[2]))
                    ^ (y + SIMD[DType.uint32, 8](sum))
                    ^ ((y >> 5) + SIMD[DType.uint32, 8](keys[3]))
                )
                y -= (
                    ((z << 4) + SIMD[DType.uint32, 8](keys[0]))
                    ^ (z + SIMD[DType.uint32, 8](sum))
                    ^ ((z >> 5) + SIMD[DType.uint32, 8](keys[1]))
                )
                sum -= delta
        else:
            comptime for _ in range(32):
                sum += delta
                y += (
                    ((z << 4) + SIMD[DType.uint32, 8](keys[0]))
                    ^ (z + SIMD[DType.uint32, 8](sum))
                    ^ ((z >> 5) + SIMD[DType.uint32, 8](keys[1]))
                )
                z += (
                    ((y << 4) + SIMD[DType.uint32, 8](keys[2]))
                    ^ (y + SIMD[DType.uint32, 8](sum))
                    ^ ((y >> 5) + SIMD[DType.uint32, 8](keys[3]))
                )
    elif algorithm == BlockCipherAlgorithm.XTEA:
        if decrypt:
            comptime for _ in range(32):
                z -= (((y << 4) ^ (y >> 5)) + y) ^ SIMD[DType.uint32, 8](
                    sum + keys[Int((sum >> 11) & 3)]
                )
                sum -= delta
                y -= (((z << 4) ^ (z >> 5)) + z) ^ SIMD[DType.uint32, 8](
                    sum + keys[Int(sum & 3)]
                )
        else:
            comptime for _ in range(32):
                y += (((z << 4) ^ (z >> 5)) + z) ^ SIMD[DType.uint32, 8](
                    sum + keys[Int(sum & 3)]
                )
                sum += delta
                z += (((y << 4) ^ (y >> 5)) + y) ^ SIMD[DType.uint32, 8](
                    sum + keys[Int((sum >> 11) & 3)]
                )
    else:
        raise Error("unknown TEA-family cipher")
    var output_pointer = output.unsafe_ptr()
    comptime for lane in range(8):
        comptime for word in range(2):
            var value = UInt32(y[lane] if word == 0 else z[lane])
            comptime for byte in range(4):
                output_pointer.unsafe_store(
                    output_offset + lane * 8 + word * 4 + byte,
                    UInt8(value >> UInt32(24 - byte * 8)),
                )


def _output(y: UInt32, z: UInt32) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    var span = Span(output)
    store_be32(y, span, 0)
    store_be32(z, span, 4)
    return output^


def tea_encrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("TEA block must be 8 bytes")
    var k = _key(key)
    var y = load_be32(block, 0)
    var z = load_be32(block, 4)
    var sum = UInt32(0)
    var delta = UInt32(0x9E3779B9)
    for _ in range(32):
        sum += delta
        y += ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1])
        z += ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3])
    return _output(y, z)


def tea_decrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("TEA block must be 8 bytes")
    var k = _key(key)
    var y = load_be32(block, 0)
    var z = load_be32(block, 4)
    var delta = UInt32(0x9E3779B9)
    var sum = delta * 32
    for _ in range(32):
        z -= ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3])
        y -= ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1])
        sum -= delta
    return _output(y, z)


def xtea_encrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("XTEA block must be 8 bytes")
    var k = _key(key)
    var y = load_be32(block, 0)
    var z = load_be32(block, 4)
    var sum = UInt32(0)
    var delta = UInt32(0x9E3779B9)
    for _ in range(32):
        y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[Int(sum & 3)])
        sum += delta
        z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + k[Int((sum >> 11) & 3)])
    return _output(y, z)


def xtea_decrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    if len(block) != 8:
        raise Error("XTEA block must be 8 bytes")
    var k = _key(key)
    var y = load_be32(block, 0)
    var z = load_be32(block, 4)
    var delta = UInt32(0x9E3779B9)
    var sum = delta * 32
    for _ in range(32):
        z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + k[Int((sum >> 11) & 3)])
        sum -= delta
        y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[Int(sum & 3)])
    return _output(y, z)
