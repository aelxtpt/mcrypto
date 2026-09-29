"""Twofish 128-bit block cipher."""

from ..internal.bytes import load_le32, store_le32
from std.builtin.globals import global_constant


@always_inline("nodebug")
def _rol(value: UInt32, amount: Int) -> UInt32:
    var n = amount & 31
    if n == 0:
        return value
    return (value << UInt32(n)) | (value >> UInt32(32 - n))


@always_inline("nodebug")
def _ror(value: UInt32, amount: Int) -> UInt32:
    return _rol(value, 32 - (amount & 31))


@always_inline("nodebug")
def _ror4(value: UInt8) -> UInt8:
    return UInt8((value >> 1) | ((value & 1) << 3))


comptime _Q0: InlineArray[UInt8, 64] = [
    8,
    1,
    7,
    13,
    6,
    15,
    3,
    2,
    0,
    11,
    5,
    9,
    14,
    12,
    10,
    4,
    14,
    12,
    11,
    8,
    1,
    2,
    3,
    5,
    15,
    4,
    10,
    6,
    7,
    0,
    9,
    13,
    11,
    10,
    5,
    14,
    6,
    13,
    9,
    0,
    12,
    8,
    15,
    3,
    2,
    4,
    7,
    1,
    13,
    7,
    15,
    4,
    1,
    2,
    6,
    14,
    9,
    11,
    3,
    0,
    8,
    5,
    12,
    10,
]
comptime _Q1: InlineArray[UInt8, 64] = [
    2,
    8,
    11,
    13,
    15,
    7,
    6,
    14,
    3,
    1,
    9,
    4,
    0,
    10,
    12,
    5,
    1,
    14,
    2,
    11,
    4,
    12,
    3,
    7,
    6,
    13,
    10,
    5,
    15,
    9,
    0,
    8,
    4,
    12,
    7,
    5,
    1,
    6,
    9,
    10,
    0,
    14,
    13,
    8,
    2,
    11,
    3,
    15,
    11,
    9,
    5,
    1,
    12,
    3,
    13,
    14,
    6,
    4,
    7,
    15,
    2,
    0,
    8,
    10,
]


@always_inline("nodebug")
def _q_table(value: UInt8, table: InlineArray[UInt8, 64]) -> UInt8:
    var a0 = value >> 4
    var b0 = value & 15
    var a1 = a0 ^ b0
    var b1 = a0 ^ _ror4(b0) ^ UInt8((a0 << 3) & 15)
    var a2 = table[Int(a1)]
    var b2 = table[16 + Int(b1)]
    var a3 = a2 ^ b2
    var b3 = a2 ^ _ror4(b2) ^ UInt8((a2 << 3) & 15)
    return UInt8((table[48 + Int(b3)] << 4) | table[32 + Int(a3)])


def _precomputed_q0() -> InlineArray[UInt8, 256]:
    var source = materialize[_Q0]()
    var output = InlineArray[UInt8, 256](uninitialized=True)
    comptime for value in range(256):
        output[value] = _q_table(UInt8(value), source)
    return output^


def _precomputed_q1() -> InlineArray[UInt8, 256]:
    var source = materialize[_Q1]()
    var output = InlineArray[UInt8, 256](uninitialized=True)
    comptime for value in range(256):
        output[value] = _q_table(UInt8(value), source)
    return output^


comptime _Q0_BYTES = _precomputed_q0()
comptime _Q1_BYTES = _precomputed_q1()


@always_inline("nodebug")
def _q(value: UInt8, which: Int) -> UInt8:
    if which == 0:
        ref q0 = global_constant[_Q0_BYTES]()
        return q0[Int(value)]
    ref q1 = global_constant[_Q1_BYTES]()
    return q1[Int(value)]


@always_inline("nodebug")
def _byte(value: UInt32, index: Int) -> UInt8:
    return UInt8(value >> UInt32(index * 8))


@always_inline("nodebug")
def _xtime(value: UInt8) -> UInt8:
    var wide = UInt16(value) << 1
    if wide & 0x100:
        wide ^= 0x169
    return UInt8(wide)


@always_inline("nodebug")
def _gf_products(value: UInt8) -> Tuple[UInt8, UInt8]:
    var x2 = _xtime(value)
    var x4 = _xtime(x2)
    var x8 = _xtime(x4)
    var x16 = _xtime(x8)
    var x32 = _xtime(x16)
    var x64 = _xtime(x32)
    var x128 = _xtime(x64)
    return (
        x64 ^ x16 ^ x8 ^ x2 ^ value,
        x128 ^ x64 ^ x32 ^ x8 ^ x4 ^ x2 ^ value,
    )


@always_inline("nodebug")
def _qword(a: Int, b: Int, c: Int, d: Int, value: UInt32) -> UInt32:
    return (
        UInt32(_q(_byte(value, 0), a))
        | (UInt32(_q(_byte(value, 1), b)) << 8)
        | (UInt32(_q(_byte(value, 2), c)) << 16)
        | (UInt32(_q(_byte(value, 3), d)) << 24)
    )


@always_inline("nodebug")
def _h0[
    key_origin: Origin
](
    value: UInt32,
    key: Span[UInt32, key_origin],
    key_words: Int,
    replicate: Bool = True,
) -> UInt32:
    var x = (
        value
        | (value << 8)
        | (value << 16)
        | (value << 24) if replicate else value
    )
    if key_words == 4:
        x = _qword(1, 0, 0, 1, x) ^ key[6]
    if key_words >= 3:
        x = _qword(1, 1, 0, 0, x) ^ key[4]
    x = _qword(0, 1, 0, 1, x) ^ key[2]
    return _qword(0, 0, 1, 1, x) ^ key[0]


@always_inline("nodebug")
def _mds(value: UInt32) -> UInt32:
    var x0 = _q(_byte(value, 0), 1)
    var x1 = _q(_byte(value, 1), 0)
    var x2 = _q(_byte(value, 2), 1)
    var x3 = _q(_byte(value, 3), 0)
    var p0 = _gf_products(x0)
    var p1 = _gf_products(x1)
    var p2 = _gf_products(x2)
    var p3 = _gf_products(x3)
    var result0 = (
        UInt32(x0)
        | (UInt32(p0[0]) << 8)
        | (UInt32(p0[1]) << 16)
        | (UInt32(p0[1]) << 24)
    )
    var result1 = (
        UInt32(p1[1])
        | (UInt32(p1[1]) << 8)
        | (UInt32(p1[0]) << 16)
        | (UInt32(x1) << 24)
    )
    var result2 = (
        UInt32(p2[0])
        | (UInt32(p2[1]) << 8)
        | (UInt32(x2) << 16)
        | (UInt32(p2[1]) << 24)
    )
    var result3 = (
        UInt32(p3[0])
        | (UInt32(x3) << 8)
        | (UInt32(p3[1]) << 16)
        | (UInt32(p3[0]) << 24)
    )
    return result0 ^ result1 ^ result2 ^ result3


@always_inline("nodebug")
def _h[
    key_origin: Origin
](value: UInt32, key: Span[UInt32, key_origin], key_words: Int) -> UInt32:
    return _mds(_h0(value, key, key_words))


@always_inline("nodebug")
def _mod_rs(value: UInt32) -> UInt32:
    var c2 = (value << 1) ^ (UInt32(0x14D) if value & 0x80 else UInt32(0))
    var c1 = c2 ^ (value >> 1) ^ (UInt32(0xA6) if value & 1 else UInt32(0))
    return value | (c1 << 8) | (c2 << 16) | (c1 << 24)


def _reed_solomon(high_input: UInt32, low_input: UInt32) -> UInt32:
    var high = high_input
    var low = low_input
    for _ in range(8):
        high = _mod_rs(high >> 24) ^ (high << 8) ^ (low >> 24)
        low <<= 8
    return high


@no_inline
def _schedule_fixed[
    key_words: Int,
    key_origin: Origin,
    round_origin: MutOrigin,
    svec_origin: MutOrigin,
](
    key_bytes: Span[UInt8, key_origin],
    round_keys: Span[mut=True, UInt32, round_origin],
    svec: Span[mut=True, UInt32, svec_origin],
) raises:
    var key = InlineArray[UInt32, 8](fill=0)
    var odd_key = InlineArray[UInt32, 8](fill=0)
    comptime for i in range(key_words):
        key[2 * i] = load_le32(key_bytes, i * 8)
        key[2 * i + 1] = load_le32(key_bytes, i * 8 + 4)
        odd_key[2 * i] = key[2 * i + 1]
    var key_span = Span(key)
    var odd_span = Span(odd_key)
    for i in range(0, 40, 2):
        var a = _h(UInt32(i), key_span, key_words)
        var b = _rol(_h(UInt32(i + 1), odd_span, key_words), 8)
        round_keys[i] = a + b
        round_keys[i + 1] = _rol(a + b + b, 9)
    comptime for i in range(key_words):
        svec[2 * (key_words - i - 1)] = _reed_solomon(
            key[2 * i + 1], key[2 * i]
        )


def _schedule_into[
    key_origin: Origin,
    round_origin: MutOrigin,
    svec_origin: MutOrigin,
](
    key_bytes: Span[UInt8, key_origin],
    round_keys: Span[mut=True, UInt32, round_origin],
    svec: Span[mut=True, UInt32, svec_origin],
) raises -> Int:
    if len(key_bytes) == 16:
        _schedule_fixed[2](key_bytes, round_keys, svec)
        return 2
    if len(key_bytes) == 24:
        _schedule_fixed[3](key_bytes, round_keys, svec)
        return 3
    if len(key_bytes) == 32:
        _schedule_fixed[4](key_bytes, round_keys, svec)
        return 4
    raise Error("Twofish key must be 16, 24, or 32 bytes")


def _schedule[
    key_origin: Origin
](key_bytes: Span[UInt8, key_origin]) raises -> Tuple[
    List[UInt32], List[UInt32], Int
]:
    var key_words = len(key_bytes) // 8
    var round_keys = List[UInt32](length=40, fill=0)
    var svec = List[UInt32](length=key_words * 2, fill=0)
    key_words = _schedule_into(key_bytes, Span(round_keys), Span(svec))
    return (round_keys^, svec^, key_words)


@always_inline("nodebug")
def _g1[
    svec_origin: Origin
](value: UInt32, svec: Span[UInt32, svec_origin], key_words: Int) -> UInt32:
    return _mds(_h0(value, svec, key_words, False))


@always_inline("nodebug")
def _g2[
    svec_origin: Origin
](value: UInt32, svec: Span[UInt32, svec_origin], key_words: Int) -> UInt32:
    return _g1(_rol(value, 8), svec, key_words)


@always_inline("nodebug")
def _key_byte[
    key_origin: Origin
](key: Span[UInt32, key_origin], word: Int, position: Int) -> UInt8:
    return UInt8(key[word] >> UInt32(position * 8))


@always_inline("nodebug")
def _h0_byte[
    key_origin: Origin
](
    value: UInt8,
    position: Int,
    key: Span[UInt32, key_origin],
    key_words: Int,
) -> UInt8:
    var result = value
    if key_words == 4:
        result = _q(
            result, 1 if position == 0 or position == 3 else 0
        ) ^ _key_byte(key, 6, position)
    if key_words >= 3:
        result = _q(
            result, 1 if position == 0 or position == 1 else 0
        ) ^ _key_byte(key, 4, position)
    result = _q(result, 1 if position == 1 or position == 3 else 0) ^ _key_byte(
        key, 2, position
    )
    return _q(result, 1 if position == 2 or position == 3 else 0) ^ _key_byte(
        key, 0, position
    )


@always_inline("nodebug")
def _mds_component_slow(value: UInt8, position: Int) -> UInt32:
    var x = _q(value, 1 if position == 0 or position == 2 else 0)
    var products = _gf_products(x)
    if position == 0:
        return (
            UInt32(x)
            | (UInt32(products[0]) << 8)
            | (UInt32(products[1]) << 16)
            | (UInt32(products[1]) << 24)
        )
    if position == 1:
        return (
            UInt32(products[1])
            | (UInt32(products[1]) << 8)
            | (UInt32(products[0]) << 16)
            | (UInt32(x) << 24)
        )
    if position == 2:
        return (
            UInt32(products[0])
            | (UInt32(products[1]) << 8)
            | (UInt32(x) << 16)
            | (UInt32(products[1]) << 24)
        )
    return (
        UInt32(products[0])
        | (UInt32(x) << 8)
        | (UInt32(products[1]) << 16)
        | (UInt32(products[0]) << 24)
    )


def _precomputed_mds_components() -> InlineArray[UInt32, 1024]:
    var output = InlineArray[UInt32, 1024](uninitialized=True)
    comptime for position in range(4):
        comptime for value in range(256):
            output[position * 256 + value] = _mds_component_slow(
                UInt8(value), position
            )
    return output^


comptime _MDS_COMPONENTS = _precomputed_mds_components()


@always_inline("nodebug")
def _mds_component(value: UInt8, position: Int) -> UInt32:
    ref components = global_constant[_MDS_COMPONENTS]()
    return components[position * 256 + Int(value)]


def prepare_tables(svec: List[UInt32], key_words: Int) -> List[UInt32]:
    var tables = List[UInt32](length=1024, fill=0)
    var svec_span = Span(svec)
    for position in range(4):
        for value in range(256):
            tables[position * 256 + value] = _mds_component(
                _h0_byte(UInt8(value), position, svec_span, key_words),
                position,
            )
    return tables^


@always_inline("nodebug")
def _g1_table[
    table_origin: Origin
](value: UInt32, tables: Span[UInt32, table_origin]) -> UInt32:
    return (
        tables[Int(UInt8(value))]
        ^ tables[256 + Int(UInt8(value >> 8))]
        ^ tables[512 + Int(UInt8(value >> 16))]
        ^ tables[768 + Int(UInt8(value >> 24))]
    )


@always_inline("nodebug")
def _g2_table[
    table_origin: Origin
](value: UInt32, tables: Span[UInt32, table_origin]) -> UInt32:
    return _g1_table(_rol(value, 8), tables)


@no_inline
def _process_into[
    decrypt: Bool,
    key_words: Int,
    round_origin: Origin,
    svec_origin: Origin,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    round_keys: Span[UInt32, round_origin],
    svec: Span[UInt32, svec_origin],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(block) != 16:
        raise Error("Twofish block must be 16 bytes")
    var a: UInt32
    var b: UInt32
    var c: UInt32
    var d: UInt32
    comptime if decrypt:
        c = load_le32(block, 0) ^ round_keys[4]
        d = load_le32(block, 4) ^ round_keys[5]
        a = load_le32(block, 8) ^ round_keys[6]
        b = load_le32(block, 12) ^ round_keys[7]
        comptime for pair in range(8):
            comptime round = 15 - 2 * pair
            var x = _g1(c, svec, key_words)
            var y = _g2(d, svec, key_words)
            x += y
            y += x
            b ^= y + round_keys[8 + 2 * round + 1]
            b = _ror(b, 1)
            a = _rol(a, 1)
            a ^= x + round_keys[8 + 2 * round]
            comptime next_round = round - 1
            x = _g1(a, svec, key_words)
            y = _g2(b, svec, key_words)
            x += y
            y += x
            d ^= y + round_keys[8 + 2 * next_round + 1]
            d = _ror(d, 1)
            c = _rol(c, 1)
            c ^= x + round_keys[8 + 2 * next_round]
        a ^= round_keys[0]
        b ^= round_keys[1]
        c ^= round_keys[2]
        d ^= round_keys[3]
    else:
        a = load_le32(block, 0) ^ round_keys[0]
        b = load_le32(block, 4) ^ round_keys[1]
        c = load_le32(block, 8) ^ round_keys[2]
        d = load_le32(block, 12) ^ round_keys[3]
        comptime for pair in range(8):
            comptime round = 2 * pair
            var x = _g1(a, svec, key_words)
            var y = _g2(b, svec, key_words)
            x += y
            y += x + round_keys[8 + 2 * round + 1]
            c ^= x + round_keys[8 + 2 * round]
            c = _ror(c, 1)
            d = _rol(d, 1) ^ y
            comptime next_round = round + 1
            x = _g1(c, svec, key_words)
            y = _g2(d, svec, key_words)
            x += y
            y += x + round_keys[8 + 2 * next_round + 1]
            a ^= x + round_keys[8 + 2 * next_round]
            a = _ror(a, 1)
            b = _rol(b, 1) ^ y
        c ^= round_keys[4]
        d ^= round_keys[5]
        a ^= round_keys[6]
        b ^= round_keys[7]
    comptime if decrypt:
        store_le32(a, output, 0)
        store_le32(b, output, 4)
        store_le32(c, output, 8)
        store_le32(d, output, 12)
    else:
        store_le32(c, output, 0)
        store_le32(d, output, 4)
        store_le32(a, output, 8)
        store_le32(b, output, 12)


@no_inline
def _process_selected[
    decrypt: Bool,
    round_origin: Origin,
    svec_origin: Origin,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    round_keys: Span[UInt32, round_origin],
    svec: Span[UInt32, svec_origin],
    key_words: Int,
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if key_words == 2:
        _process_into[decrypt, 2](round_keys, svec, block, output)
    elif key_words == 3:
        _process_into[decrypt, 3](round_keys, svec, block, output)
    else:
        _process_into[decrypt, 4](round_keys, svec, block, output)


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    round_keys: List[UInt32],
    svec: List[UInt32],
    key_words: Int,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    if decrypt:
        _process_selected[True](
            Span(round_keys), Span(svec), key_words, block, Span(output)
        )
    else:
        _process_selected[False](
            Span(round_keys), Span(svec), key_words, block, Span(output)
        )
    return output^


@no_inline
def _process_tables_into[
    decrypt: Bool,
    round_origin: Origin,
    table_origin: Origin,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    round_keys: Span[UInt32, round_origin],
    tables: Span[UInt32, table_origin],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("Twofish block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("Twofish output span is too short")
    var a: UInt32
    var b: UInt32
    var c: UInt32
    var d: UInt32
    comptime if decrypt:
        c = load_le32(block, 0) ^ round_keys[4]
        d = load_le32(block, 4) ^ round_keys[5]
        a = load_le32(block, 8) ^ round_keys[6]
        b = load_le32(block, 12) ^ round_keys[7]
        comptime for offset in range(16):
            comptime round = 15 - offset
            var x: UInt32
            var y: UInt32
            if round & 1:
                x = _g1_table(c, tables)
                y = _g2_table(d, tables)
                x += y
                y += x
                b ^= y + round_keys[8 + 2 * round + 1]
                b = _ror(b, 1)
                a = _rol(a, 1)
                a ^= x + round_keys[8 + 2 * round]
            else:
                x = _g1_table(a, tables)
                y = _g2_table(b, tables)
                x += y
                y += x
                d ^= y + round_keys[8 + 2 * round + 1]
                d = _ror(d, 1)
                c = _rol(c, 1)
                c ^= x + round_keys[8 + 2 * round]
        a ^= round_keys[0]
        b ^= round_keys[1]
        c ^= round_keys[2]
        d ^= round_keys[3]
    else:
        a = load_le32(block, 0) ^ round_keys[0]
        b = load_le32(block, 4) ^ round_keys[1]
        c = load_le32(block, 8) ^ round_keys[2]
        d = load_le32(block, 12) ^ round_keys[3]
        comptime for round in range(16):
            var x: UInt32
            var y: UInt32
            if round & 1:
                x = _g1_table(c, tables)
                y = _g2_table(d, tables)
                x += y
                y += x + round_keys[8 + 2 * round + 1]
                a ^= x + round_keys[8 + 2 * round]
                a = _ror(a, 1)
                b = _rol(b, 1) ^ y
            else:
                x = _g1_table(a, tables)
                y = _g2_table(b, tables)
                x += y
                y += x + round_keys[8 + 2 * round + 1]
                c ^= x + round_keys[8 + 2 * round]
                c = _ror(c, 1)
                d = _rol(d, 1) ^ y
        c ^= round_keys[4]
        d ^= round_keys[5]
        a ^= round_keys[6]
        b ^= round_keys[7]
    comptime if decrypt:
        store_le32(a, output, output_offset)
        store_le32(b, output, output_offset + 4)
        store_le32(c, output, output_offset + 8)
        store_le32(d, output, output_offset + 12)
    else:
        store_le32(c, output, output_offset)
        store_le32(d, output, output_offset + 4)
        store_le32(a, output, output_offset + 8)
        store_le32(b, output, output_offset + 12)


def process_prepared_tables_into[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    round_keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if decrypt:
        _process_tables_into[True](
            Span(round_keys), Span(tables), block, output, output_offset
        )
    else:
        _process_tables_into[False](
            Span(round_keys), Span(tables), block, output, output_offset
        )


def process_prepared_tables[
    block_origin: Origin
](
    decrypt: Bool,
    round_keys: List[UInt32],
    tables: List[UInt32],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared_tables_into(
        decrypt,
        round_keys,
        tables,
        block,
        Span(output),
        0,
    )
    return output^


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> Tuple[
    List[UInt32], List[UInt32], Int
]:
    return _schedule(key)


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var round_keys = InlineArray[UInt32, 40](fill=0)
    var svec = InlineArray[UInt32, 8](fill=0)
    var key_words = _schedule_into(key, Span(round_keys), Span(svec))
    var output = List[UInt8](length=16, fill=0)
    if decrypt:
        _process_selected[True](
            Span(round_keys), Span(svec), key_words, block, Span(output)
        )
    else:
        _process_selected[False](
            Span(round_keys), Span(svec), key_words, block, Span(output)
        )
    return output^
