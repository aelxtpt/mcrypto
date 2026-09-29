"""HIGHT 64-bit block cipher with a 128-bit key."""


comptime _DELTA: InlineArray[UInt8, 128] = [
    0x5A,
    0x6D,
    0x36,
    0x1B,
    0x0D,
    0x06,
    0x03,
    0x41,
    0x60,
    0x30,
    0x18,
    0x4C,
    0x66,
    0x33,
    0x59,
    0x2C,
    0x56,
    0x2B,
    0x15,
    0x4A,
    0x65,
    0x72,
    0x39,
    0x1C,
    0x4E,
    0x67,
    0x73,
    0x79,
    0x3C,
    0x5E,
    0x6F,
    0x37,
    0x5B,
    0x2D,
    0x16,
    0x0B,
    0x05,
    0x42,
    0x21,
    0x50,
    0x28,
    0x54,
    0x2A,
    0x55,
    0x6A,
    0x75,
    0x7A,
    0x7D,
    0x3E,
    0x5F,
    0x2F,
    0x17,
    0x4B,
    0x25,
    0x52,
    0x29,
    0x14,
    0x0A,
    0x45,
    0x62,
    0x31,
    0x58,
    0x6C,
    0x76,
    0x3B,
    0x1D,
    0x0E,
    0x47,
    0x63,
    0x71,
    0x78,
    0x7C,
    0x7E,
    0x7F,
    0x3F,
    0x1F,
    0x0F,
    0x07,
    0x43,
    0x61,
    0x70,
    0x38,
    0x5C,
    0x6E,
    0x77,
    0x7B,
    0x3D,
    0x1E,
    0x4F,
    0x27,
    0x53,
    0x69,
    0x34,
    0x1A,
    0x4D,
    0x26,
    0x13,
    0x49,
    0x24,
    0x12,
    0x09,
    0x04,
    0x02,
    0x01,
    0x40,
    0x20,
    0x10,
    0x08,
    0x44,
    0x22,
    0x11,
    0x48,
    0x64,
    0x32,
    0x19,
    0x0C,
    0x46,
    0x23,
    0x51,
    0x68,
    0x74,
    0x3A,
    0x5D,
    0x2E,
    0x57,
    0x6B,
    0x35,
    0x5A,
]


@always_inline("nodebug")
def _rol(value: UInt8, amount: Int) -> UInt8:
    return (value << UInt8(amount)) | (value >> UInt8(8 - amount))


@always_inline("nodebug")
def _f0(value: UInt8) -> UInt8:
    return _rol(value, 1) ^ _rol(value, 2) ^ _rol(value, 7)


@always_inline("nodebug")
def _f1(value: UInt8) -> UInt8:
    return _rol(value, 3) ^ _rol(value, 4) ^ _rol(value, 6)


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[UInt8]:
    if len(key) != 16:
        raise Error("HIGHT key must be 16 bytes")
    var delta = materialize[_DELTA]()
    var round_keys = List[UInt8](length=136, fill=0)
    for i in range(4):
        round_keys[i] = key[i + 12]
        round_keys[i + 4] = key[i]
    for i in range(8):
        for j in range(8):
            round_keys[8 + 16 * i + j] = key[(j - i) & 7] + delta[16 * i + j]
            round_keys[16 + 16 * i + j] = (
                key[((j - i) & 7) + 8] + delta[16 * i + j + 8]
            )
    return round_keys^


def process_prepared_into[
    decrypting: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt8],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 136:
        raise Error("HIGHT round-key schedule must contain 136 bytes")
    if len(block) != 8:
        raise Error("HIGHT block must be 8 bytes")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("HIGHT output span is too short")
    var state = InlineArray[UInt8, 8](fill=0)
    comptime if decrypting:
        state[1] = block[0] - keys[4]
        state[2] = block[1]
        state[3] = block[2] ^ keys[5]
        state[4] = block[3]
        state[5] = block[4] - keys[6]
        state[6] = block[5]
        state[7] = block[6] ^ keys[7]
        state[0] = block[7]
        comptime for offset in range(32):
            comptime round = 31 - offset
            state[(1 - round) & 7] -= (
                _f1(state[-round & 7]) ^ keys[8 + 4 * round]
            )
            state[(3 - round) & 7] ^= (
                _f0(state[(2 - round) & 7]) + keys[9 + 4 * round]
            )
            state[(5 - round) & 7] -= (
                _f1(state[(4 - round) & 7]) ^ keys[10 + 4 * round]
            )
            state[(7 - round) & 7] ^= (
                _f0(state[(6 - round) & 7]) + keys[11 + 4 * round]
            )
        output[output_offset] = state[0] - keys[0]
        output[output_offset + 1] = state[1]
        output[output_offset + 2] = state[2] ^ keys[1]
        output[output_offset + 3] = state[3]
        output[output_offset + 4] = state[4] - keys[2]
        output[output_offset + 5] = state[5]
        output[output_offset + 6] = state[6] ^ keys[3]
        output[output_offset + 7] = state[7]
    else:
        state[0] = block[0] + keys[0]
        state[1] = block[1]
        state[2] = block[2] ^ keys[1]
        state[3] = block[3]
        state[4] = block[4] + keys[2]
        state[5] = block[5]
        state[6] = block[6] ^ keys[3]
        state[7] = block[7]
        comptime for round in range(32):
            state[(7 - round) & 7] ^= (
                _f0(state[(6 - round) & 7]) + keys[11 + 4 * round]
            )
            state[(5 - round) & 7] += (
                _f1(state[(4 - round) & 7]) ^ keys[10 + 4 * round]
            )
            state[(3 - round) & 7] ^= (
                _f0(state[(2 - round) & 7]) + keys[9 + 4 * round]
            )
            state[(1 - round) & 7] += (
                _f1(state[-round & 7]) ^ keys[8 + 4 * round]
            )
        output[output_offset] = state[1] + keys[4]
        output[output_offset + 1] = state[2]
        output[output_offset + 2] = state[3] ^ keys[5]
        output[output_offset + 3] = state[4]
        output[output_offset + 4] = state[5] + keys[6]
        output[output_offset + 5] = state[6]
        output[output_offset + 6] = state[7] ^ keys[7]
        output[output_offset + 7] = state[0]


def process_prepared[
    decrypting: Bool, block_origin: Origin
](keys: List[UInt8], block: Span[UInt8, block_origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    process_prepared_into[decrypting](keys, block, Span(output), 0)
    return output^


def encrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    var keys = prepare(key)
    return process_prepared[False](keys, block)


def decrypt[
    key_origin: Origin, block_origin: Origin
](
    key: Span[UInt8, key_origin], block: Span[UInt8, block_origin]
) raises -> List[UInt8]:
    var keys = prepare(key)
    return process_prepared[True](keys, block)
