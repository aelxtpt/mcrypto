"""Adler-32, CRC-32, and CRC-32C in pure Mojo."""

from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic
from std.memory import bitcast


comptime _CRC32_NIBBLES: InlineArray[UInt32, 16] = [
    0x00000000,
    0x1DB71064,
    0x3B6E20C8,
    0x26D930AC,
    0x76DC4190,
    0x6B6B51F4,
    0x4DB26158,
    0x5005713C,
    0xEDB88320,
    0xF00F9344,
    0xD6D6A3E8,
    0xCB61B38C,
    0x9B64C2B0,
    0x86D3D2D4,
    0xA00AE278,
    0xBDBDF21C,
]
comptime _CRC32C_NIBBLES: InlineArray[UInt32, 16] = [
    0x00000000,
    0x105EC76F,
    0x20BD8EDE,
    0x30E349B1,
    0x417B1DBC,
    0x5125DAD3,
    0x61C69362,
    0x7198540D,
    0x82F63B78,
    0x92A8FC17,
    0xA24BB5A6,
    0xB21572C9,
    0xC38D26C4,
    0xD3D3E1AB,
    0xE330A81A,
    0xF36E6F75,
]


@always_inline("nodebug")
def _be32_into[
    output_origin: MutOrigin
](output: Span[mut=True, UInt8, output_origin], value: UInt32,):
    output[0] = UInt8(value >> 24)
    output[1] = UInt8(value >> 16)
    output[2] = UInt8(value >> 8)
    output[3] = UInt8(value)


@always_inline("nodebug")
def _be32(value: UInt32) -> List[UInt8]:
    var output = List[UInt8](unsafe_uninit_length=4)
    _be32_into(Span(output), value)
    return output^


def _adler32_value[origin: Origin](data: Span[UInt8, origin]) -> UInt32:
    var s1 = UInt32(1)
    var s2 = UInt32(0)
    var offset = 0
    var data_pointer = data.unsafe_ptr()
    var weights = SIMD[DType.uint16, 16](
        16,
        15,
        14,
        13,
        12,
        11,
        10,
        9,
        8,
        7,
        6,
        5,
        4,
        3,
        2,
        1,
    )
    while offset < len(data):
        var end = offset + min(5552, len(data) - offset)
        while offset + 128 <= end:
            var totals = InlineArray[UInt32, 8](uninitialized=True)
            var weighted = InlineArray[UInt32, 8](uninitialized=True)
            comptime for chunk in range(8):
                var words = data_pointer.unsafe_load[width=16](
                    offset + chunk * 16
                ).cast[DType.uint16]()
                totals[chunk] = UInt32(words.reduce_add())
                weighted[chunk] = UInt32((words * weights).reduce_add())
            s2 += UInt32(128) * s1
            comptime for chunk in range(8):
                s2 += weighted[chunk] + UInt32(112 - chunk * 16) * totals[chunk]
                s1 += totals[chunk]
            offset += 128
        while offset + 16 <= end:
            var words = data_pointer.unsafe_load[width=16](offset).cast[
                DType.uint16
            ]()
            var total = UInt32(words.reduce_add())
            var weighted = UInt32((words * weights).reduce_add())
            s2 += UInt32(16) * s1 + weighted
            s1 += total
            offset += 16
        while offset < end:
            s1 += UInt32(data_pointer.unsafe_load(offset))
            s2 += s1
            offset += 1
        s1 %= 65521
        s2 %= 65521
    return (s2 << 16) | s1


def adler32_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) != 4:
        raise Error("Adler-32 output span must be 4 bytes")
    _be32_into(output, _adler32_value(data))


def adler32[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    return _be32(_adler32_value(data))


def _precomputed_crc32_bytes() -> InlineArray[UInt32, 256]:
    var nibbles = materialize[_CRC32_NIBBLES]()
    var table = InlineArray[UInt32, 256](fill=0)
    comptime for index in range(256):
        var entry = UInt32(index)
        entry = (entry >> 4) ^ nibbles[Int(entry & 15)]
        entry = (entry >> 4) ^ nibbles[Int(entry & 15)]
        table[index] = entry
    return table^


comptime _CRC32_BYTES = _precomputed_crc32_bytes()


def _precomputed_crc32_slices() -> InlineArray[UInt32, 2048]:
    var first = materialize[_CRC32_BYTES]()
    var tables = InlineArray[UInt32, 2048](fill=0)
    comptime for index in range(256):
        tables[index] = first[index]
    comptime for slice in range(1, 8):
        comptime for index in range(256):
            var previous = tables[(slice - 1) * 256 + index]
            tables[slice * 256 + index] = (previous >> 8) ^ first[
                Int(UInt8(previous))
            ]
    return tables^


comptime _CRC32_SLICES = _precomputed_crc32_slices()


def _crc32_large[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var tables = materialize[_CRC32_SLICES]()
    var table_pointer = Span(tables).unsafe_ptr()
    var value = UInt32(0xFFFFFFFF)
    var offset = 0
    var data_pointer = data.unsafe_ptr()
    while offset + 8 <= len(data):
        var word = bitcast[DType.uint64, 1](
            data_pointer.unsafe_load[width=8](offset)
        )[0] ^ UInt64(value)
        value = (
            table_pointer.unsafe_load(1792 + Int(UInt8(word)))
            ^ table_pointer.unsafe_load(1536 + Int(UInt8(word >> 8)))
            ^ table_pointer.unsafe_load(1280 + Int(UInt8(word >> 16)))
            ^ table_pointer.unsafe_load(1024 + Int(UInt8(word >> 24)))
            ^ table_pointer.unsafe_load(768 + Int(UInt8(word >> 32)))
            ^ table_pointer.unsafe_load(512 + Int(UInt8(word >> 40)))
            ^ table_pointer.unsafe_load(256 + Int(UInt8(word >> 48)))
            ^ table_pointer.unsafe_load(Int(UInt8(word >> 56)))
        )
        offset += 8
    while offset < len(data):
        value = (value >> 8) ^ table_pointer.unsafe_load(
            Int(UInt8(value) ^ data_pointer.unsafe_load(offset))
        )
        offset += 1
    return _be32(~value)


def _crc32_small_value[
    origin: Origin
](data: Span[UInt8, origin],) -> UInt32:
    var table = materialize[_CRC32_BYTES]()
    var table_pointer = Span(table).unsafe_ptr()
    var data_pointer = data.unsafe_ptr()
    var value = UInt32(0xFFFFFFFF)
    for i in range(len(data)):
        value = (value >> 8) ^ table_pointer.unsafe_load(
            Int(UInt8(value) ^ data_pointer.unsafe_load(i))
        )
    return ~value


def _crc32_small[
    origin: Origin
](data: Span[UInt8, origin],) -> List[UInt8]:
    return _be32(_crc32_small_value(data))


def _crc[
    origin: Origin
](data: Span[UInt8, origin], table: InlineArray[UInt32, 16],) -> List[UInt8]:
    if len(data) < 512:
        var value = UInt32(0xFFFFFFFF)
        for byte in data:
            value ^= UInt32(byte)
            value = (value >> 4) ^ table[Int(value & 15)]
            value = (value >> 4) ^ table[Int(value & 15)]
        return _be32(~value)
    var tables = InlineArray[UInt32, 2048](fill=0)
    for index in range(256):
        var entry = UInt32(index)
        entry = (entry >> 4) ^ table[Int(entry & 15)]
        entry = (entry >> 4) ^ table[Int(entry & 15)]
        tables[index] = entry
    for slice in range(1, 8):
        for index in range(256):
            var previous = tables[(slice - 1) * 256 + index]
            tables[slice * 256 + index] = (previous >> 8) ^ tables[
                Int(UInt8(previous))
            ]
    var value = UInt32(0xFFFFFFFF)
    var offset = 0
    var data_pointer = data.unsafe_ptr()
    while offset + 8 <= len(data):
        var word = bitcast[DType.uint64, 1](
            data_pointer.unsafe_load[width=8](offset)
        )[0] ^ UInt64(value)
        value = (
            tables[1792 + Int(UInt8(word))]
            ^ tables[1536 + Int(UInt8(word >> 8))]
            ^ tables[1280 + Int(UInt8(word >> 16))]
            ^ tables[1024 + Int(UInt8(word >> 24))]
            ^ tables[768 + Int(UInt8(word >> 32))]
            ^ tables[512 + Int(UInt8(word >> 40))]
            ^ tables[256 + Int(UInt8(word >> 48))]
            ^ tables[Int(UInt8(word >> 56))]
        )
        offset += 8
    while offset < len(data):
        value = (value >> 8) ^ tables[Int(UInt8(value) ^ data[offset])]
        offset += 1
    return _be32(~value)


def crc32[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    if len(data) < 512:
        return _crc32_small(data)
    return _crc32_large(data)


def crc32_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) != 4:
        raise Error("CRC-32 output span must be 4 bytes")
    if len(data) < 512:
        _be32_into(output, _crc32_small_value(data))
        return
    var digest = _crc32_large(data)
    output.unsafe_ptr().unsafe_store[width=4](
        Span(digest).unsafe_ptr().unsafe_load[width=4]()
    )


@always_inline("nodebug")
def _crc32c_u64(value: UInt64, word: UInt64) -> UInt64:
    return llvm_intrinsic[
        "llvm.x86.sse42.crc32.64.64",
        UInt64,
        has_side_effect=False,
    ](value, word)


def crc32c_four_into[
    input0_origin: Origin,
    input1_origin: Origin,
    input2_origin: Origin,
    input3_origin: Origin,
    output0_origin: MutOrigin,
    output1_origin: MutOrigin,
    output2_origin: MutOrigin,
    output3_origin: MutOrigin,
](
    input0: Span[UInt8, input0_origin],
    input1: Span[UInt8, input1_origin],
    input2: Span[UInt8, input2_origin],
    input3: Span[UInt8, input3_origin],
    output0: Span[mut=True, UInt8, output0_origin],
    output1: Span[mut=True, UInt8, output1_origin],
    output2: Span[mut=True, UInt8, output2_origin],
    output3: Span[mut=True, UInt8, output3_origin],
) raises:
    """Hash four equal-length messages with independent CRC32C chains."""
    if (
        len(input1) != len(input0)
        or len(input2) != len(input0)
        or len(input3) != len(input0)
    ):
        raise Error("four-way CRC32C inputs must have equal lengths")
    if (
        len(output0) != 4
        or len(output1) != 4
        or len(output2) != 4
        or len(output3) != 4
    ):
        raise Error("four-way CRC32C outputs must be 4 bytes")
    comptime if (CompilationTarget.is_x86() and CompilationTarget.has_sse4()):
        var pointer0 = input0.unsafe_ptr()
        var pointer1 = input1.unsafe_ptr()
        var pointer2 = input2.unsafe_ptr()
        var pointer3 = input3.unsafe_ptr()
        var value0 = UInt64(0xFFFFFFFF)
        var value1 = UInt64(0xFFFFFFFF)
        var value2 = UInt64(0xFFFFFFFF)
        var value3 = UInt64(0xFFFFFFFF)
        var offset = 0
        while offset + 8 <= len(input0):
            value0 = _crc32c_u64(
                value0,
                bitcast[DType.uint64, 1](pointer0.unsafe_load[width=8](offset))[
                    0
                ],
            )
            value1 = _crc32c_u64(
                value1,
                bitcast[DType.uint64, 1](pointer1.unsafe_load[width=8](offset))[
                    0
                ],
            )
            value2 = _crc32c_u64(
                value2,
                bitcast[DType.uint64, 1](pointer2.unsafe_load[width=8](offset))[
                    0
                ],
            )
            value3 = _crc32c_u64(
                value3,
                bitcast[DType.uint64, 1](pointer3.unsafe_load[width=8](offset))[
                    0
                ],
            )
            offset += 8
        var tail0 = UInt32(value0)
        var tail1 = UInt32(value1)
        var tail2 = UInt32(value2)
        var tail3 = UInt32(value3)
        if offset < len(input0):
            var table = materialize[_CRC32C_NIBBLES]()
            while offset < len(input0):
                tail0 ^= UInt32(pointer0.unsafe_load(offset))
                tail0 = (tail0 >> 4) ^ table[Int(tail0 & 15)]
                tail0 = (tail0 >> 4) ^ table[Int(tail0 & 15)]
                tail1 ^= UInt32(pointer1.unsafe_load(offset))
                tail1 = (tail1 >> 4) ^ table[Int(tail1 & 15)]
                tail1 = (tail1 >> 4) ^ table[Int(tail1 & 15)]
                tail2 ^= UInt32(pointer2.unsafe_load(offset))
                tail2 = (tail2 >> 4) ^ table[Int(tail2 & 15)]
                tail2 = (tail2 >> 4) ^ table[Int(tail2 & 15)]
                tail3 ^= UInt32(pointer3.unsafe_load(offset))
                tail3 = (tail3 >> 4) ^ table[Int(tail3 & 15)]
                tail3 = (tail3 >> 4) ^ table[Int(tail3 & 15)]
                offset += 1
        _be32_into(output0, ~tail0)
        _be32_into(output1, ~tail1)
        _be32_into(output2, ~tail2)
        _be32_into(output3, ~tail3)
        return
    var table = materialize[_CRC32C_NIBBLES]()
    var digest0 = _crc(input0, table)
    var digest1 = _crc(input1, table)
    var digest2 = _crc(input2, table)
    var digest3 = _crc(input3, table)
    for i in range(4):
        output0[i] = digest0[i]
        output1[i] = digest1[i]
        output2[i] = digest2[i]
        output3[i] = digest3[i]


def crc32c[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    comptime if (CompilationTarget.is_x86() and CompilationTarget.has_sse4()):
        var data_length = len(data)
        var data_pointer = data.unsafe_ptr()
        var value = UInt64(0xFFFFFFFF)
        var offset = 0
        while offset + 64 <= data_length:
            comptime for lane in range(8):
                value = _crc32c_u64(
                    value,
                    bitcast[DType.uint64, 1](
                        data_pointer.unsafe_load[width=8](offset + lane * 8)
                    )[0],
                )
            offset += 64
        while offset + 8 <= data_length:
            value = _crc32c_u64(
                value,
                bitcast[DType.uint64, 1](
                    data_pointer.unsafe_load[width=8](offset)
                )[0],
            )
            offset += 8
        var tail = UInt32(value)
        if offset < data_length:
            var table = materialize[_CRC32C_NIBBLES]()
            while offset < data_length:
                tail ^= UInt32(data_pointer.unsafe_load(offset))
                tail = (tail >> 4) ^ table[Int(tail & 15)]
                tail = (tail >> 4) ^ table[Int(tail & 15)]
                offset += 1
        return _be32(~tail)
    return _crc(data, materialize[_CRC32C_NIBBLES]())
