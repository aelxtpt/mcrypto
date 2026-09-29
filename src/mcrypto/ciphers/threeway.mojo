"""3-Way 96-bit block cipher."""

from ..internal.bytes import load_be32, load_le32, store_be32, store_le32


@always_inline("nodebug")
def _rol(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _reverse_bits_in_bytes(value: UInt32) -> UInt32:
    var x = ((value & 0xAAAAAAAA) >> 1) | ((value & 0x55555555) << 1)
    x = ((x & 0xCCCCCCCC) >> 2) | ((x & 0x33333333) << 2)
    return ((x & 0xF0F0F0F0) >> 4) | ((x & 0x0F0F0F0F) << 4)


@always_inline("nodebug")
def _mu_words(
    a0: UInt32, a1: UInt32, a2: UInt32
) -> Tuple[UInt32, UInt32, UInt32]:
    return (
        _reverse_bits_in_bytes(a2),
        _reverse_bits_in_bytes(a1),
        _reverse_bits_in_bytes(a0),
    )


@always_inline("nodebug")
def _theta_words(
    a0: UInt32, a1: UInt32, a2: UInt32
) -> Tuple[UInt32, UInt32, UInt32]:
    var c = a0 ^ a1 ^ a2
    c = _rol(c, 16) ^ _rol(c, 8)
    var b0 = (a0 << 24) ^ (a2 >> 8) ^ (a1 << 8) ^ (a0 >> 24)
    var b1 = (a1 << 24) ^ (a0 >> 8) ^ (a2 << 8) ^ (a1 >> 24)
    return (
        a0 ^ c ^ b0,
        a1 ^ c ^ b1,
        a2 ^ c ^ (b0 >> 16) ^ (b1 << 16),
    )


@always_inline("nodebug")
def _rho_words(
    mut a0: UInt32, mut a1: UInt32, mut a2: UInt32
) -> Tuple[UInt32, UInt32, UInt32]:
    a0, a1, a2 = _theta_words(a0, a1, a2)
    var b2 = _rol(a2, 1)
    var b0 = _rol(a0, 22)
    return (
        _rol(b0 ^ (a1 | (~b2)), 1),
        a1 ^ (b2 | (~b0)),
        _rol(b2 ^ (b0 | (~a1)), 22),
    )


@always_inline("nodebug")
def _byte_swap(value: UInt32) -> UInt32:
    return (
        ((value & 0xFF) << 24)
        | ((value & 0xFF00) << 8)
        | ((value >> 8) & 0xFF00)
        | (value >> 24)
    )


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> List[UInt32]:
    if len(key) != 12:
        raise Error("3-Way requires a 12-byte key")
    var k0 = load_be32(key, 0)
    var k1 = load_be32(key, 4)
    var k2 = load_be32(key, 8)
    if decrypt:
        k0, k1, k2 = _theta_words(k0, k1, k2)
        k0, k1, k2 = _mu_words(k0, k1, k2)
        k0 = _byte_swap(k0)
        k1 = _byte_swap(k1)
        k2 = _byte_swap(k2)
    return [k0, k1, k2]


def process_prepared_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 3 or len(block) != 12:
        raise Error("3-Way requires a prepared key and 12-byte block")
    if output_offset < 0 or output_offset + 12 > len(output):
        raise Error("3-Way output span is too short")
    var a0 = load_le32(block, 0) if decrypt else load_be32(block, 0)
    var a1 = load_le32(block, 4) if decrypt else load_be32(block, 4)
    var a2 = load_le32(block, 8) if decrypt else load_be32(block, 8)
    comptime if decrypt:
        a0, a1, a2 = _mu_words(a0, a1, a2)
    var rc = UInt32(0xB1B1 if decrypt else 0x0B0B)
    comptime for _ in range(11):
        a0 ^= keys[0] ^ (rc << 16)
        a1 ^= keys[1]
        a2 ^= keys[2] ^ rc
        a0, a1, a2 = _rho_words(a0, a1, a2)
        rc <<= 1
        if rc & 0x10000:
            rc ^= 0x11011
    a0 ^= keys[0] ^ (rc << 16)
    a1 ^= keys[1]
    a2 ^= keys[2] ^ rc
    a0, a1, a2 = _theta_words(a0, a1, a2)
    comptime if decrypt:
        a0, a1, a2 = _mu_words(a0, a1, a2)
        store_le32(a0, output, output_offset)
        store_le32(a1, output, output_offset + 4)
        store_le32(a2, output, output_offset + 8)
    else:
        store_be32(a0, output, output_offset)
        store_be32(a1, output, output_offset + 4)
        store_be32(a2, output, output_offset + 8)


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=12, fill=0)
    if decrypt:
        process_prepared_into[True](keys, block, Span(output), 0)
    else:
        process_prepared_into[False](keys, block, Span(output), 0)
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var keys = prepare(key, decrypt)
    return process_prepared(decrypt, keys, block)
