"""NIST Skipjack 64-bit block cipher in pure Mojo."""


comptime _F: InlineArray[UInt8, 256] = [
    0xA3,
    0xD7,
    0x09,
    0x83,
    0xF8,
    0x48,
    0xF6,
    0xF4,
    0xB3,
    0x21,
    0x15,
    0x78,
    0x99,
    0xB1,
    0xAF,
    0xF9,
    0xE7,
    0x2D,
    0x4D,
    0x8A,
    0xCE,
    0x4C,
    0xCA,
    0x2E,
    0x52,
    0x95,
    0xD9,
    0x1E,
    0x4E,
    0x38,
    0x44,
    0x28,
    0x0A,
    0xDF,
    0x02,
    0xA0,
    0x17,
    0xF1,
    0x60,
    0x68,
    0x12,
    0xB7,
    0x7A,
    0xC3,
    0xE9,
    0xFA,
    0x3D,
    0x53,
    0x96,
    0x84,
    0x6B,
    0xBA,
    0xF2,
    0x63,
    0x9A,
    0x19,
    0x7C,
    0xAE,
    0xE5,
    0xF5,
    0xF7,
    0x16,
    0x6A,
    0xA2,
    0x39,
    0xB6,
    0x7B,
    0x0F,
    0xC1,
    0x93,
    0x81,
    0x1B,
    0xEE,
    0xB4,
    0x1A,
    0xEA,
    0xD0,
    0x91,
    0x2F,
    0xB8,
    0x55,
    0xB9,
    0xDA,
    0x85,
    0x3F,
    0x41,
    0xBF,
    0xE0,
    0x5A,
    0x58,
    0x80,
    0x5F,
    0x66,
    0x0B,
    0xD8,
    0x90,
    0x35,
    0xD5,
    0xC0,
    0xA7,
    0x33,
    0x06,
    0x65,
    0x69,
    0x45,
    0x00,
    0x94,
    0x56,
    0x6D,
    0x98,
    0x9B,
    0x76,
    0x97,
    0xFC,
    0xB2,
    0xC2,
    0xB0,
    0xFE,
    0xDB,
    0x20,
    0xE1,
    0xEB,
    0xD6,
    0xE4,
    0xDD,
    0x47,
    0x4A,
    0x1D,
    0x42,
    0xED,
    0x9E,
    0x6E,
    0x49,
    0x3C,
    0xCD,
    0x43,
    0x27,
    0xD2,
    0x07,
    0xD4,
    0xDE,
    0xC7,
    0x67,
    0x18,
    0x89,
    0xCB,
    0x30,
    0x1F,
    0x8D,
    0xC6,
    0x8F,
    0xAA,
    0xC8,
    0x74,
    0xDC,
    0xC9,
    0x5D,
    0x5C,
    0x31,
    0xA4,
    0x70,
    0x88,
    0x61,
    0x2C,
    0x9F,
    0x0D,
    0x2B,
    0x87,
    0x50,
    0x82,
    0x54,
    0x64,
    0x26,
    0x7D,
    0x03,
    0x40,
    0x34,
    0x4B,
    0x1C,
    0x73,
    0xD1,
    0xC4,
    0xFD,
    0x3B,
    0xCC,
    0xFB,
    0x7F,
    0xAB,
    0xE6,
    0x3E,
    0x5B,
    0xA5,
    0xAD,
    0x04,
    0x23,
    0x9C,
    0x14,
    0x51,
    0x22,
    0xF0,
    0x29,
    0x79,
    0x71,
    0x7E,
    0xFF,
    0x8C,
    0x0E,
    0xE2,
    0x0C,
    0xEF,
    0xBC,
    0x72,
    0x75,
    0x6F,
    0x37,
    0xA1,
    0xEC,
    0xD3,
    0x8E,
    0x62,
    0x8B,
    0x86,
    0x10,
    0xE8,
    0x08,
    0x77,
    0x11,
    0xBE,
    0x92,
    0x4F,
    0x24,
    0xC5,
    0x32,
    0x36,
    0x9D,
    0xCF,
    0xF3,
    0xA6,
    0xBB,
    0xAC,
    0x5E,
    0x6C,
    0xA9,
    0x13,
    0x57,
    0x25,
    0xB5,
    0xE3,
    0xBD,
    0xA8,
    0x3A,
    0x01,
    0x05,
    0x59,
    0x2A,
    0x46,
]


def prepare[
    origin: Origin
](key: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    if len(key) != 10:
        raise Error("Skipjack requires a 10-byte key")
    var prepared_key = List[UInt8](capacity=10)
    for byte in key:
        prepared_key.append(byte)
    var constants = materialize[_F]()
    var table = List[UInt8](capacity=256)
    for byte in constants:
        table.append(byte)
    return (prepared_key^, table^)


@always_inline("nodebug")
def _g[
    round: Int, inverse: Bool
](value: UInt16, key: List[UInt8], table: List[UInt8],) -> UInt16:
    var table_pointer = Span(table).unsafe_ptr()
    var key_pointer = Span(key).unsafe_ptr()
    var current = value
    comptime if inverse:
        comptime for offset in range(4):
            comptime step = 3 - offset
            comptime index = (4 * round + step) % 10
            var key_byte = key_pointer.unsafe_load(9 - index)
            comptime if step % 2 == 0:
                current ^= (
                    UInt16(
                        table_pointer.unsafe_load(
                            Int(UInt8(current) ^ key_byte)
                        )
                    )
                    << 8
                )
            else:
                current ^= UInt16(
                    table_pointer.unsafe_load(
                        Int(UInt8(current >> 8) ^ key_byte)
                    )
                )
    else:
        comptime for step in range(4):
            comptime index = (4 * round + step) % 10
            var key_byte = key_pointer.unsafe_load(9 - index)
            comptime if step % 2 == 0:
                current ^= (
                    UInt16(
                        table_pointer.unsafe_load(
                            Int(UInt8(current) ^ key_byte)
                        )
                    )
                    << 8
                )
            else:
                current ^= UInt16(
                    table_pointer.unsafe_load(
                        Int(UInt8(current >> 8) ^ key_byte)
                    )
                )
    return current


def process_prepared_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    key: List[UInt8],
    table: List[UInt8],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(key) != 10 or len(table) != 256 or len(block) != 8:
        raise Error("invalid prepared Skipjack parameters")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("Skipjack output span is too short")
    var w4 = UInt16(block[0]) | (UInt16(block[1]) << 8)
    var w3 = UInt16(block[2]) | (UInt16(block[3]) << 8)
    var w2 = UInt16(block[4]) | (UInt16(block[5]) << 8)
    var w1 = UInt16(block[6]) | (UInt16(block[7]) << 8)
    comptime if decrypting:
        comptime for offset in range(32):
            comptime round = 31 - offset
            comptime position = round % 4
            comptime if (round < 8) or (round >= 16 and round < 24):
                comptime if position == 0:
                    w4 ^= w1 ^ UInt16(round + 1)
                    w1 = _g[round, True](w1, key, table)
                elif position == 1:
                    w3 ^= w4 ^ UInt16(round + 1)
                    w4 = _g[round, True](w4, key, table)
                elif position == 2:
                    w2 ^= w3 ^ UInt16(round + 1)
                    w3 = _g[round, True](w3, key, table)
                else:
                    w1 ^= w2 ^ UInt16(round + 1)
                    w2 = _g[round, True](w2, key, table)
            else:
                comptime if position == 0:
                    w1 = _g[round, True](w1, key, table)
                    w2 ^= w1 ^ UInt16(round + 1)
                elif position == 1:
                    w4 = _g[round, True](w4, key, table)
                    w1 ^= w4 ^ UInt16(round + 1)
                elif position == 2:
                    w3 = _g[round, True](w3, key, table)
                    w4 ^= w3 ^ UInt16(round + 1)
                else:
                    w2 = _g[round, True](w2, key, table)
                    w3 ^= w2 ^ UInt16(round + 1)
    else:
        comptime for round in range(32):
            comptime position = round % 4
            comptime if (round < 8) or (round >= 16 and round < 24):
                comptime if position == 0:
                    w1 = _g[round, False](w1, key, table)
                    w4 ^= w1 ^ UInt16(round + 1)
                elif position == 1:
                    w4 = _g[round, False](w4, key, table)
                    w3 ^= w4 ^ UInt16(round + 1)
                elif position == 2:
                    w3 = _g[round, False](w3, key, table)
                    w2 ^= w3 ^ UInt16(round + 1)
                else:
                    w2 = _g[round, False](w2, key, table)
                    w1 ^= w2 ^ UInt16(round + 1)
            else:
                comptime if position == 0:
                    w2 ^= w1 ^ UInt16(round + 1)
                    w1 = _g[round, False](w1, key, table)
                elif position == 1:
                    w1 ^= w4 ^ UInt16(round + 1)
                    w4 = _g[round, False](w4, key, table)
                elif position == 2:
                    w4 ^= w3 ^ UInt16(round + 1)
                    w3 = _g[round, False](w3, key, table)
                else:
                    w3 ^= w2 ^ UInt16(round + 1)
                    w2 = _g[round, False](w2, key, table)
    var words: InlineArray[UInt16, 4] = [w4, w3, w2, w1]
    comptime for i in range(4):
        output[output_offset + 2 * i] = UInt8(words[i])
        output[output_offset + 2 * i + 1] = UInt8(words[i] >> 8)


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var prepared = prepare(key)
    var output = List[UInt8](length=8, fill=0)
    if decrypt:
        process_prepared_into[True](
            prepared[0], prepared[1], block, Span(output), 0
        )
    else:
        process_prepared_into[False](
            prepared[0], prepared[1], block, Span(output), 0
        )
    return output^
