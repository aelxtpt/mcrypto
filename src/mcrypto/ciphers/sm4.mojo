"""GB/T 32907 SM4 block cipher."""

from ..internal.bytes import load_be32, store_be32
from std.builtin.globals import global_constant

comptime _S: InlineArray[UInt8, 256] = [
    0xD6,
    0x90,
    0xE9,
    0xFE,
    0xCC,
    0xE1,
    0x3D,
    0xB7,
    0x16,
    0xB6,
    0x14,
    0xC2,
    0x28,
    0xFB,
    0x2C,
    0x05,
    0x2B,
    0x67,
    0x9A,
    0x76,
    0x2A,
    0xBE,
    0x04,
    0xC3,
    0xAA,
    0x44,
    0x13,
    0x26,
    0x49,
    0x86,
    0x06,
    0x99,
    0x9C,
    0x42,
    0x50,
    0xF4,
    0x91,
    0xEF,
    0x98,
    0x7A,
    0x33,
    0x54,
    0x0B,
    0x43,
    0xED,
    0xCF,
    0xAC,
    0x62,
    0xE4,
    0xB3,
    0x1C,
    0xA9,
    0xC9,
    0x08,
    0xE8,
    0x95,
    0x80,
    0xDF,
    0x94,
    0xFA,
    0x75,
    0x8F,
    0x3F,
    0xA6,
    0x47,
    0x07,
    0xA7,
    0xFC,
    0xF3,
    0x73,
    0x17,
    0xBA,
    0x83,
    0x59,
    0x3C,
    0x19,
    0xE6,
    0x85,
    0x4F,
    0xA8,
    0x68,
    0x6B,
    0x81,
    0xB2,
    0x71,
    0x64,
    0xDA,
    0x8B,
    0xF8,
    0xEB,
    0x0F,
    0x4B,
    0x70,
    0x56,
    0x9D,
    0x35,
    0x1E,
    0x24,
    0x0E,
    0x5E,
    0x63,
    0x58,
    0xD1,
    0xA2,
    0x25,
    0x22,
    0x7C,
    0x3B,
    0x01,
    0x21,
    0x78,
    0x87,
    0xD4,
    0x00,
    0x46,
    0x57,
    0x9F,
    0xD3,
    0x27,
    0x52,
    0x4C,
    0x36,
    0x02,
    0xE7,
    0xA0,
    0xC4,
    0xC8,
    0x9E,
    0xEA,
    0xBF,
    0x8A,
    0xD2,
    0x40,
    0xC7,
    0x38,
    0xB5,
    0xA3,
    0xF7,
    0xF2,
    0xCE,
    0xF9,
    0x61,
    0x15,
    0xA1,
    0xE0,
    0xAE,
    0x5D,
    0xA4,
    0x9B,
    0x34,
    0x1A,
    0x55,
    0xAD,
    0x93,
    0x32,
    0x30,
    0xF5,
    0x8C,
    0xB1,
    0xE3,
    0x1D,
    0xF6,
    0xE2,
    0x2E,
    0x82,
    0x66,
    0xCA,
    0x60,
    0xC0,
    0x29,
    0x23,
    0xAB,
    0x0D,
    0x53,
    0x4E,
    0x6F,
    0xD5,
    0xDB,
    0x37,
    0x45,
    0xDE,
    0xFD,
    0x8E,
    0x2F,
    0x03,
    0xFF,
    0x6A,
    0x72,
    0x6D,
    0x6C,
    0x5B,
    0x51,
    0x8D,
    0x1B,
    0xAF,
    0x92,
    0xBB,
    0xDD,
    0xBC,
    0x7F,
    0x11,
    0xD9,
    0x5C,
    0x41,
    0x1F,
    0x10,
    0x5A,
    0xD8,
    0x0A,
    0xC1,
    0x31,
    0x88,
    0xA5,
    0xCD,
    0x7B,
    0xBD,
    0x2D,
    0x74,
    0xD0,
    0x12,
    0xB8,
    0xE5,
    0xB4,
    0xB0,
    0x89,
    0x69,
    0x97,
    0x4A,
    0x0C,
    0x96,
    0x77,
    0x7E,
    0x65,
    0xB9,
    0xF1,
    0x09,
    0xC5,
    0x6E,
    0xC6,
    0x84,
    0x18,
    0xF0,
    0x7D,
    0xEC,
    0x3A,
    0xDC,
    0x4D,
    0x20,
    0x79,
    0xEE,
    0x5F,
    0x3E,
    0xD7,
    0xCB,
    0x39,
    0x48,
]
comptime _CK: InlineArray[UInt32, 32] = [
    0x00070E15,
    0x1C232A31,
    0x383F464D,
    0x545B6269,
    0x70777E85,
    0x8C939AA1,
    0xA8AFB6BD,
    0xC4CBD2D9,
    0xE0E7EEF5,
    0xFC030A11,
    0x181F262D,
    0x343B4249,
    0x50575E65,
    0x6C737A81,
    0x888F969D,
    0xA4ABB2B9,
    0xC0C7CED5,
    0xDCE3EAF1,
    0xF8FF060D,
    0x141B2229,
    0x30373E45,
    0x4C535A61,
    0x686F767D,
    0x848B9299,
    0xA0A7AEB5,
    0xBCC3CAD1,
    0xD8DFE6ED,
    0xF4FB0209,
    0x10171E25,
    0x2C333A41,
    0x484F565D,
    0x646B7279,
]


@always_inline("nodebug")
def _rol(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


def _tau(x: UInt32) -> UInt32:
    var s = materialize[_S]()
    return (
        UInt32(s[Int(x >> 24)]) << 24
        | UInt32(s[Int((x >> 16) & 255)]) << 16
        | UInt32(s[Int((x >> 8) & 255)]) << 8
        | UInt32(s[Int(x & 255)])
    )


def _l(x: UInt32) -> UInt32:
    return x ^ _rol(x, 2) ^ _rol(x, 10) ^ _rol(x, 18) ^ _rol(x, 24)


def _lp(x: UInt32) -> UInt32:
    return x ^ _rol(x, 13) ^ _rol(x, 23)


def _precomputed_tables() -> InlineArray[UInt32, 1024]:
    var s = materialize[_S]()
    var tables = InlineArray[UInt32, 1024](fill=0)
    comptime for position in range(4):
        comptime shift = 24 - position * 8
        comptime for value in range(256):
            tables[position * 256 + value] = _l(
                UInt32(s[value]) << UInt32(shift)
            )
    return tables^


comptime _ROUND_TABLES = _precomputed_tables()


def prepare_tables() -> List[UInt32]:
    # Rounds read the immutable table directly from constant storage.
    return List[UInt32]()


@always_inline("nodebug")
def _t(value: UInt32, tables: List[UInt32]) -> UInt32:
    ref constant_tables = global_constant[_ROUND_TABLES]()
    var pointer = Span(constant_tables).unsafe_ptr()
    return (
        pointer.unsafe_load(Int(value >> 24))
        ^ pointer.unsafe_load(256 + Int((value >> 16) & 255))
        ^ pointer.unsafe_load(512 + Int((value >> 8) & 255))
        ^ pointer.unsafe_load(768 + Int(value & 255))
    )


def _keys[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    if len(key) != 16:
        raise Error("SM4 key must be 16 bytes")
    var k: List[UInt32] = [
        load_be32(key, 0) ^ 0xA3B1BAC6,
        load_be32(key, 4) ^ 0x56AA3350,
        load_be32(key, 8) ^ 0x677D9197,
        load_be32(key, 12) ^ 0xB27022DC,
    ]
    var keys = List[UInt32](capacity=32)
    var ck = materialize[_CK]()
    for i in range(32):
        var next = k[i] ^ _lp(_tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck[i]))
        k.append(next)
        keys.append(next)
    return keys^


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt32]:
    return _keys(key)


def process_prepared_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("SM4 block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("SM4 output span is too short")
    var x0 = load_be32(block, 0)
    var x1 = load_be32(block, 4)
    var x2 = load_be32(block, 8)
    var x3 = load_be32(block, 12)
    comptime for round in range(32):
        comptime if decrypting:
            var next = x0 ^ _l(_tau(x1 ^ x2 ^ x3 ^ keys[31 - round]))
            x0 = x1
            x1 = x2
            x2 = x3
            x3 = next
        else:
            var next = x0 ^ _l(_tau(x1 ^ x2 ^ x3 ^ keys[round]))
            x0 = x1
            x1 = x2
            x2 = x3
            x3 = next
    store_be32(x3, output, output_offset)
    store_be32(x2, output, output_offset + 4)
    store_be32(x1, output, output_offset + 8)
    store_be32(x0, output, output_offset + 12)


def process_prepared_tables_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("SM4 block must be 16 bytes")
    if len(keys) != 32:
        raise Error("SM4 key schedule is invalid")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("SM4 output span is too short")
    var x0 = load_be32(block, 0)
    var x1 = load_be32(block, 4)
    var x2 = load_be32(block, 8)
    var x3 = load_be32(block, 12)
    comptime for round in range(32):
        comptime if decrypting:
            var next = x0 ^ _t(x1 ^ x2 ^ x3 ^ keys[31 - round], tables)
            x0 = x1
            x1 = x2
            x2 = x3
            x3 = next
        else:
            var next = x0 ^ _t(x1 ^ x2 ^ x3 ^ keys[round], tables)
            x0 = x1
            x1 = x2
            x2 = x3
            x3 = next
    store_be32(x3, output, output_offset)
    store_be32(x2, output, output_offset + 4)
    store_be32(x1, output, output_offset + 8)
    store_be32(x0, output, output_offset + 12)


def process_prepared[
    block_origin: Origin
](
    keys: List[UInt32],
    block: Span[UInt8, block_origin],
    decrypt: Bool = False,
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    if decrypt:
        process_prepared_into[True](keys, block, Span(output), 0)
    else:
        process_prepared_into[False](keys, block, Span(output), 0)
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    decrypt: Bool = False,
) raises -> List[UInt8]:
    return process_prepared(_keys(key), block, decrypt)
