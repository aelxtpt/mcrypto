"""GOST 28147-89 block cipher using the Applied Cryptography S-boxes."""

from ..internal.bytes import load_le32, store_le32


comptime _S: InlineArray[UInt8, 128] = [
    4,
    10,
    9,
    2,
    13,
    8,
    0,
    14,
    6,
    11,
    1,
    12,
    7,
    15,
    5,
    3,
    14,
    11,
    4,
    12,
    6,
    13,
    15,
    10,
    2,
    3,
    8,
    1,
    0,
    7,
    5,
    9,
    5,
    8,
    1,
    13,
    10,
    3,
    4,
    2,
    14,
    15,
    12,
    7,
    6,
    0,
    9,
    11,
    7,
    13,
    10,
    1,
    0,
    8,
    9,
    15,
    14,
    4,
    6,
    12,
    11,
    2,
    5,
    3,
    6,
    12,
    7,
    1,
    5,
    15,
    13,
    8,
    4,
    10,
    9,
    14,
    0,
    3,
    11,
    2,
    4,
    11,
    10,
    0,
    7,
    2,
    1,
    13,
    3,
    6,
    8,
    5,
    9,
    12,
    15,
    14,
    13,
    11,
    4,
    1,
    3,
    15,
    5,
    9,
    0,
    10,
    14,
    7,
    6,
    8,
    2,
    12,
    1,
    15,
    13,
    0,
    5,
    7,
    10,
    4,
    9,
    2,
    3,
    14,
    6,
    11,
    8,
    12,
]


@always_inline("nodebug")
def _rol11(value: UInt32) -> UInt32:
    return (value << 11) | (value >> 21)


def _precomputed_tables() -> InlineArray[UInt32, 1024]:
    var sbox = materialize[_S]()
    var tables = InlineArray[UInt32, 1024](fill=0)
    comptime for byte_position in range(4):
        comptime for value in range(256):
            var substituted = sbox[2 * byte_position * 16 + (value & 15)] | (
                sbox[(2 * byte_position + 1) * 16 + (value >> 4)] << 4
            )
            tables[byte_position * 256 + value] = _rol11(
                UInt32(substituted) << UInt32(8 * byte_position)
            )
    return tables^


def _prepare_tables() -> List[UInt32]:
    comptime values = _precomputed_tables()
    var source = materialize[values]()
    var tables = List[UInt32](length=1024, fill=0)
    var source_pointer = Span(source).unsafe_ptr()
    var output_pointer = Span(tables).unsafe_ptr()
    for offset in range(0, 1024, 8):
        output_pointer.unsafe_store[width=8](
            offset, source_pointer.unsafe_load[width=8](offset)
        )
    return tables^


@always_inline("nodebug")
def _f(value: UInt32, tables: List[UInt32]) -> UInt32:
    return (
        tables[Int(UInt8(value))]
        ^ tables[256 + Int(UInt8(value >> 8))]
        ^ tables[512 + Int(UInt8(value >> 16))]
        ^ tables[768 + Int(UInt8(value >> 24))]
    )


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> Tuple[List[UInt32], List[UInt32]]:
    if len(key) != 32:
        raise Error("GOST requires a 32-byte key")
    var keys = List[UInt32](capacity=8)
    for i in range(8):
        keys.append(load_le32(key, i * 4))
    return (keys^, _prepare_tables())


def process_prepared_into[
    decrypt: Bool,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(keys) != 8 or len(tables) != 1024 or len(block) != 8:
        raise Error("GOST requires a prepared key, tables, and 8-byte block")
    if output_offset < 0 or output_offset + 8 > len(output):
        raise Error("GOST output span is too short")
    var left = load_le32(block, 0)
    var right = load_le32(block, 4)
    comptime for i in range(32):
        comptime key_index = (
            i if i < 8 else 7 - ((i - 8) % 8)
        ) if decrypt else (i % 8 if i < 24 else 7 - (i - 24))
        var next = right ^ _f(left + keys[key_index], tables)
        comptime if i != 31:
            right = left
            left = next
        else:
            right = next
    store_le32(left, output, output_offset)
    store_le32(right, output, output_offset + 4)


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=8, fill=0)
    if decrypt:
        process_prepared_into[True](keys, tables, block, Span(output), 0)
    else:
        process_prepared_into[False](keys, tables, block, Span(output), 0)
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var prepared = prepare(key)
    return process_prepared(decrypt, prepared[0], prepared[1], block)
