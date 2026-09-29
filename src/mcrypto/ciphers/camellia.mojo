"""RFC 3713 Camellia block cipher for 128-, 192-, and 256-bit keys."""

from ..internal.bytes import load_be64, store_be64
from std.builtin.globals import global_constant

comptime _S1: InlineArray[UInt8, 256] = [
    0x70,
    0x82,
    0x2C,
    0xEC,
    0xB3,
    0x27,
    0xC0,
    0xE5,
    0xE4,
    0x85,
    0x57,
    0x35,
    0xEA,
    0x0C,
    0xAE,
    0x41,
    0x23,
    0xEF,
    0x6B,
    0x93,
    0x45,
    0x19,
    0xA5,
    0x21,
    0xED,
    0x0E,
    0x4F,
    0x4E,
    0x1D,
    0x65,
    0x92,
    0xBD,
    0x86,
    0xB8,
    0xAF,
    0x8F,
    0x7C,
    0xEB,
    0x1F,
    0xCE,
    0x3E,
    0x30,
    0xDC,
    0x5F,
    0x5E,
    0xC5,
    0x0B,
    0x1A,
    0xA6,
    0xE1,
    0x39,
    0xCA,
    0xD5,
    0x47,
    0x5D,
    0x3D,
    0xD9,
    0x01,
    0x5A,
    0xD6,
    0x51,
    0x56,
    0x6C,
    0x4D,
    0x8B,
    0x0D,
    0x9A,
    0x66,
    0xFB,
    0xCC,
    0xB0,
    0x2D,
    0x74,
    0x12,
    0x2B,
    0x20,
    0xF0,
    0xB1,
    0x84,
    0x99,
    0xDF,
    0x4C,
    0xCB,
    0xC2,
    0x34,
    0x7E,
    0x76,
    0x05,
    0x6D,
    0xB7,
    0xA9,
    0x31,
    0xD1,
    0x17,
    0x04,
    0xD7,
    0x14,
    0x58,
    0x3A,
    0x61,
    0xDE,
    0x1B,
    0x11,
    0x1C,
    0x32,
    0x0F,
    0x9C,
    0x16,
    0x53,
    0x18,
    0xF2,
    0x22,
    0xFE,
    0x44,
    0xCF,
    0xB2,
    0xC3,
    0xB5,
    0x7A,
    0x91,
    0x24,
    0x08,
    0xE8,
    0xA8,
    0x60,
    0xFC,
    0x69,
    0x50,
    0xAA,
    0xD0,
    0xA0,
    0x7D,
    0xA1,
    0x89,
    0x62,
    0x97,
    0x54,
    0x5B,
    0x1E,
    0x95,
    0xE0,
    0xFF,
    0x64,
    0xD2,
    0x10,
    0xC4,
    0x00,
    0x48,
    0xA3,
    0xF7,
    0x75,
    0xDB,
    0x8A,
    0x03,
    0xE6,
    0xDA,
    0x09,
    0x3F,
    0xDD,
    0x94,
    0x87,
    0x5C,
    0x83,
    0x02,
    0xCD,
    0x4A,
    0x90,
    0x33,
    0x73,
    0x67,
    0xF6,
    0xF3,
    0x9D,
    0x7F,
    0xBF,
    0xE2,
    0x52,
    0x9B,
    0xD8,
    0x26,
    0xC8,
    0x37,
    0xC6,
    0x3B,
    0x81,
    0x96,
    0x6F,
    0x4B,
    0x13,
    0xBE,
    0x63,
    0x2E,
    0xE9,
    0x79,
    0xA7,
    0x8C,
    0x9F,
    0x6E,
    0xBC,
    0x8E,
    0x29,
    0xF5,
    0xF9,
    0xB6,
    0x2F,
    0xFD,
    0xB4,
    0x59,
    0x78,
    0x98,
    0x06,
    0x6A,
    0xE7,
    0x46,
    0x71,
    0xBA,
    0xD4,
    0x25,
    0xAB,
    0x42,
    0x88,
    0xA2,
    0x8D,
    0xFA,
    0x72,
    0x07,
    0xB9,
    0x55,
    0xF8,
    0xEE,
    0xAC,
    0x0A,
    0x36,
    0x49,
    0x2A,
    0x68,
    0x3C,
    0x38,
    0xF1,
    0xA4,
    0x40,
    0x28,
    0xD3,
    0x7B,
    0xBB,
    0xC9,
    0x43,
    0xC1,
    0x15,
    0xE3,
    0xAD,
    0xF4,
    0x77,
    0xC7,
    0x80,
    0x9E,
]


@always_inline("nodebug")
def _rol8(value: UInt8, amount: Int) -> UInt8:
    return UInt8(
        (UInt16(value) << UInt16(amount))
        | (UInt16(value) >> UInt16(8 - amount))
    )


@always_inline("nodebug")
def _rol32(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _f(value: UInt64, key: UInt64, s: InlineArray[UInt8, 256]) -> UInt64:
    var s_pointer = Span(s).unsafe_ptr()
    var x = value ^ key
    var t0 = s_pointer.unsafe_load(Int(UInt8(x >> 56)))
    var t1 = _rol8(s_pointer.unsafe_load(Int(UInt8(x >> 48))), 1)
    var t2 = _rol8(s_pointer.unsafe_load(Int(UInt8(x >> 40))), 7)
    var t3 = s_pointer.unsafe_load(Int(_rol8(UInt8(x >> 32), 1)))
    var t4 = _rol8(s_pointer.unsafe_load(Int(UInt8(x >> 24))), 1)
    var t5 = _rol8(s_pointer.unsafe_load(Int(UInt8(x >> 16))), 7)
    var t6 = s_pointer.unsafe_load(Int(_rol8(UInt8(x >> 8), 1)))
    var t7 = s_pointer.unsafe_load(Int(UInt8(x)))
    return (
        (UInt64(t0 ^ t2 ^ t3 ^ t5 ^ t6 ^ t7) << 56)
        | (UInt64(t0 ^ t1 ^ t3 ^ t4 ^ t6 ^ t7) << 48)
        | (UInt64(t0 ^ t1 ^ t2 ^ t4 ^ t5 ^ t7) << 40)
        | (UInt64(t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6) << 32)
        | (UInt64(t0 ^ t1 ^ t5 ^ t6 ^ t7) << 24)
        | (UInt64(t1 ^ t2 ^ t4 ^ t6 ^ t7) << 16)
        | (UInt64(t2 ^ t3 ^ t4 ^ t5 ^ t7) << 8)
        | UInt64(t0 ^ t3 ^ t4 ^ t5 ^ t6)
    )


def _precomputed_tables() -> InlineArray[UInt64, 2048]:
    var s = materialize[_S1]()
    var s_pointer = Span(s).unsafe_ptr()
    var tables = InlineArray[UInt64, 2048](fill=0)
    comptime for position in range(8):
        comptime for value in range(256):
            var substituted: UInt8
            if position == 0 or position == 7:
                substituted = s_pointer.unsafe_load(value)
            elif position == 1 or position == 4:
                substituted = _rol8(s_pointer.unsafe_load(value), 1)
            elif position == 2 or position == 5:
                substituted = _rol8(s_pointer.unsafe_load(value), 7)
            else:
                substituted = s_pointer.unsafe_load(Int(_rol8(UInt8(value), 1)))
            comptime for output in range(8):
                var included = (
                    (
                        output == 0
                        and (
                            position == 0
                            or position == 2
                            or position == 3
                            or position == 5
                            or position == 6
                            or position == 7
                        )
                    )
                    or (
                        output == 1
                        and (
                            position == 0
                            or position == 1
                            or position == 3
                            or position == 4
                            or position == 6
                            or position == 7
                        )
                    )
                    or (
                        output == 2
                        and (
                            position == 0
                            or position == 1
                            or position == 2
                            or position == 4
                            or position == 5
                            or position == 7
                        )
                    )
                    or (
                        output == 3
                        and (
                            position == 1
                            or position == 2
                            or position == 3
                            or position == 4
                            or position == 5
                            or position == 6
                        )
                    )
                    or (
                        output == 4
                        and (
                            position == 0
                            or position == 1
                            or position == 5
                            or position == 6
                            or position == 7
                        )
                    )
                    or (
                        output == 5
                        and (
                            position == 1
                            or position == 2
                            or position == 4
                            or position == 6
                            or position == 7
                        )
                    )
                    or (
                        output == 6
                        and (
                            position == 2
                            or position == 3
                            or position == 4
                            or position == 5
                            or position == 7
                        )
                    )
                    or (
                        output == 7
                        and (
                            position == 0
                            or position == 3
                            or position == 4
                            or position == 5
                            or position == 6
                        )
                    )
                )
                if included:
                    tables[position * 256 + value] |= UInt64(
                        substituted
                    ) << UInt64(56 - output * 8)
    return tables^


comptime _ROUND_TABLES = _precomputed_tables()


def prepare_tables() -> List[UInt64]:
    # Rounds read the immutable table directly from constant storage.
    return List[UInt64]()


@always_inline("nodebug")
def _f_table(value: UInt64, key: UInt64, tables: List[UInt64]) -> UInt64:
    ref constant_tables = global_constant[_ROUND_TABLES]()
    var x = value ^ key
    var table_pointer = Span(constant_tables).unsafe_ptr()
    var output = UInt64(0)
    comptime for position in range(8):
        output ^= table_pointer.unsafe_load(
            position * 256 + Int(UInt8(x >> UInt64(56 - position * 8)))
        )
    return output


@always_inline("nodebug")
def _fl(value: UInt64, key: UInt64) -> UInt64:
    var x1 = UInt32(value >> 32)
    var x2 = UInt32(value)
    var k1 = UInt32(key >> 32)
    var k2 = UInt32(key)
    x2 ^= _rol32(x1 & k1, 1)
    x1 ^= x2 | k2
    return (UInt64(x1) << 32) | UInt64(x2)


@always_inline("nodebug")
def _flinv(value: UInt64, key: UInt64) -> UInt64:
    var x1 = UInt32(value >> 32)
    var x2 = UInt32(value)
    var k1 = UInt32(key >> 32)
    var k2 = UInt32(key)
    x1 ^= x2 | k2
    x2 ^= _rol32(x1 & k1, 1)
    return (UInt64(x1) << 32) | UInt64(x2)


@always_inline("nodebug")
def _rotate128(high: UInt64, low: UInt64, amount: Int) -> Tuple[UInt64, UInt64]:
    var n = amount % 128
    if n == 0:
        return (high, low)
    if n < 64:
        return (
            (high << UInt64(n)) | (low >> UInt64(64 - n)),
            (low << UInt64(n)) | (high >> UInt64(64 - n)),
        )
    n -= 64
    if n == 0:
        return (low, high)
    return (
        (low << UInt64(n)) | (high >> UInt64(64 - n)),
        (high << UInt64(n)) | (low >> UInt64(64 - n)),
    )


def _generate[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    decrypt: Bool,
    s: InlineArray[UInt8, 256],
) raises -> Tuple[List[UInt64], List[UInt64], List[UInt64]]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("Camellia key must be 16, 24, or 32 bytes")
    var kl0 = load_be64(key, 0)
    var kl1 = load_be64(key, 8)
    var kr0 = UInt64(0)
    var kr1 = UInt64(0)
    if len(key) == 24:
        kr0 = load_be64(key, 16)
        kr1 = ~kr0
    elif len(key) == 32:
        kr0 = load_be64(key, 16)
        kr1 = load_be64(key, 24)
    var d1 = kl0 ^ kr0
    var d2 = kl1 ^ kr1
    d2 ^= _f(d1, 0xA09E667F3BCC908B, s)
    d1 ^= _f(d2, 0xB67AE8584CAA73B2, s)
    d1 ^= kl0
    d2 ^= kl1
    d2 ^= _f(d1, 0xC6EF372FE94F82BE, s)
    d1 ^= _f(d2, 0x54FF53A5F1D36F1C, s)
    var ka0 = d1
    var ka1 = d2
    d1 = ka0 ^ kr0
    d2 = ka1 ^ kr1
    d2 ^= _f(d1, 0x10E527FADE682D1D, s)
    d1 ^= _f(d2, 0xB05688C2B3E6C1FD, s)
    var kb0 = d1
    var kb1 = d2
    var short_key = len(key) == 16
    var kw = List[UInt64](capacity=4)
    var rounds = List[UInt64](capacity=18 if short_key else 24)
    var extra = List[UInt64](capacity=4 if short_key else 6)
    if short_key:
        var r0 = _rotate128(kl0, kl1, 0)
        kw.append(r0[0])
        kw.append(r0[1])
        r0 = _rotate128(ka0, ka1, 0)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 15)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 15)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 30)
        extra.append(r0[0])
        extra.append(r0[1])
        r0 = _rotate128(kl0, kl1, 45)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 45)
        rounds.append(r0[0])
        r0 = _rotate128(kl0, kl1, 60)
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 60)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 77)
        extra.append(r0[0])
        extra.append(r0[1])
        r0 = _rotate128(kl0, kl1, 94)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 94)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 111)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 111)
        kw.append(r0[0])
        kw.append(r0[1])
    else:
        var r0 = _rotate128(kl0, kl1, 0)
        kw.append(r0[0])
        kw.append(r0[1])
        r0 = _rotate128(kb0, kb1, 0)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kr0, kr1, 15)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 15)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kr0, kr1, 30)
        extra.append(r0[0])
        extra.append(r0[1])
        r0 = _rotate128(kb0, kb1, 30)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 45)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 45)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 60)
        extra.append(r0[0])
        extra.append(r0[1])
        r0 = _rotate128(kr0, kr1, 60)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kb0, kb1, 60)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 77)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 77)
        extra.append(r0[0])
        extra.append(r0[1])
        r0 = _rotate128(kr0, kr1, 94)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(ka0, ka1, 94)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kl0, kl1, 111)
        rounds.append(r0[0])
        rounds.append(r0[1])
        r0 = _rotate128(kb0, kb1, 111)
        kw.append(r0[0])
        kw.append(r0[1])
    if decrypt:
        for i in range(len(rounds) // 2):
            var opposite = len(rounds) - 1 - i
            var temporary = rounds[i]
            rounds[i] = rounds[opposite]
            rounds[opposite] = temporary
        for i in range(len(extra) // 2):
            var opposite = len(extra) - 1 - i
            var temporary = extra[i]
            extra[i] = extra[opposite]
            extra[opposite] = temporary
        var old0 = kw[0]
        var old1 = kw[1]
        kw[0] = kw[2]
        kw[1] = kw[3]
        kw[2] = old0
        kw[3] = old1
    return (kw^, rounds^, extra^)


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> Tuple[
    List[UInt64], List[UInt64], List[UInt64]
]:
    var s = materialize[_S1]()
    return _generate(key, decrypt, s)


@always_inline("nodebug")
def _process_prepared[
    block_origin: Origin
](
    kw: List[UInt64],
    keys: List[UInt64],
    extra: List[UInt64],
    block: Span[UInt8, block_origin],
    s: InlineArray[UInt8, 256],
) raises -> List[UInt8]:
    if len(block) != 16:
        raise Error("Camellia block must be 16 bytes")
    var kw_pointer = Span(kw).unsafe_ptr()
    var key_pointer = Span(keys).unsafe_ptr()
    var extra_pointer = Span(extra).unsafe_ptr()
    var d1 = load_be64(block, 0) ^ kw_pointer.unsafe_load(0)
    var d2 = load_be64(block, 8) ^ kw_pointer.unsafe_load(1)
    var layers = len(extra) // 2
    for group in range(layers + 1):
        comptime for j in range(6):
            var round = group * 6 + j
            comptime if j % 2 == 0:
                d2 ^= _f(d1, key_pointer.unsafe_load(round), s)
            else:
                d1 ^= _f(d2, key_pointer.unsafe_load(round), s)
        if group < layers:
            d1 = _fl(d1, extra_pointer.unsafe_load(group * 2))
            d2 = _flinv(d2, extra_pointer.unsafe_load(group * 2 + 1))
    d2 ^= kw_pointer.unsafe_load(2)
    d1 ^= kw_pointer.unsafe_load(3)
    var output = List[UInt8](length=16, fill=0)
    var output_span = Span(output)
    store_be64(d2, output_span, 0)
    store_be64(d1, output_span, 8)
    return output^


def process_prepared[
    block_origin: Origin
](
    kw: List[UInt64],
    keys: List[UInt64],
    extra: List[UInt64],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var s = materialize[_S1]()
    return _process_prepared(kw, keys, extra, block, s)


def process_prepared_tables_into[
    block_origin: Origin, output_origin: MutOrigin
](
    kw: List[UInt64],
    keys: List[UInt64],
    extra: List[UInt64],
    tables: List[UInt64],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("Camellia block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("Camellia output span is too short")
    var kw_pointer = Span(kw).unsafe_ptr()
    var key_pointer = Span(keys).unsafe_ptr()
    var extra_pointer = Span(extra).unsafe_ptr()
    var d1 = load_be64(block, 0) ^ kw_pointer.unsafe_load(0)
    var d2 = load_be64(block, 8) ^ kw_pointer.unsafe_load(1)
    var layers = len(extra) // 2
    for group in range(layers + 1):
        comptime for j in range(6):
            var round = group * 6 + j
            comptime if j % 2 == 0:
                d2 ^= _f_table(d1, key_pointer.unsafe_load(round), tables)
            else:
                d1 ^= _f_table(d2, key_pointer.unsafe_load(round), tables)
        if group < layers:
            d1 = _fl(d1, extra_pointer.unsafe_load(group * 2))
            d2 = _flinv(d2, extra_pointer.unsafe_load(group * 2 + 1))
    d2 ^= kw_pointer.unsafe_load(2)
    d1 ^= kw_pointer.unsafe_load(3)
    store_be64(d2, output, output_offset)
    store_be64(d1, output, output_offset + 8)


def process_prepared_tables[
    block_origin: Origin
](
    kw: List[UInt64],
    keys: List[UInt64],
    extra: List[UInt64],
    tables: List[UInt64],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared_tables_into(
        kw, keys, extra, tables, block, Span(output), 0
    )
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var s = materialize[_S1]()
    var schedule = _generate(key, decrypt, s)
    return _process_prepared(
        schedule[0],
        schedule[1],
        schedule[2],
        block,
        s,
    )
