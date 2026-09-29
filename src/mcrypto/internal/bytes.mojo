"""Allocation-free byte and word operations for pure-Mojo primitives."""
from std.memory import bitcast
from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic


@always_inline("nodebug")
def load_le32[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> UInt32:
    if offset < 0 or offset + 4 > len(data):
        raise Error("load_le32 out of bounds")
    comptime if CompilationTarget.is_x86():
        return bitcast[DType.uint32, 1](
            data.unsafe_ptr().unsafe_load[width=4](offset)
        )[0]
    else:
        return (
            UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        )


@always_inline("nodebug")
def load_be32[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> UInt32:
    if offset < 0 or offset + 4 > len(data):
        raise Error("load_be32 out of bounds")
    comptime if CompilationTarget.is_x86():
        var value = bitcast[DType.uint32, 1](
            data.unsafe_ptr().unsafe_load[width=4](offset)
        )[0]
        return llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
            value
        )
    else:
        return (
            (UInt32(data[offset]) << 24)
            | (UInt32(data[offset + 1]) << 16)
            | (UInt32(data[offset + 2]) << 8)
            | UInt32(data[offset + 3])
        )


@always_inline("nodebug")
def load_le64[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> UInt64:
    if offset < 0 or offset + 8 > len(data):
        raise Error("load_le64 out of bounds")
    comptime if CompilationTarget.is_x86():
        return bitcast[DType.uint64, 1](
            data.unsafe_ptr().unsafe_load[width=8](offset)
        )[0]
    else:
        var value = UInt64(0)
        for i in range(8):
            value |= UInt64(data[offset + i]) << UInt64(i * 8)
        return value


@always_inline("nodebug")
def load_be64[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> UInt64:
    if offset < 0 or offset + 8 > len(data):
        raise Error("load_be64 out of bounds")
    comptime if CompilationTarget.is_x86():
        var value = bitcast[DType.uint64, 1](
            data.unsafe_ptr().unsafe_load[width=8](offset)
        )[0]
        return llvm_intrinsic["llvm.bswap.i64", UInt64, has_side_effect=False](
            value
        )
    else:
        var value = UInt64(0)
        for i in range(8):
            value = (value << 8) | UInt64(data[offset + i])
        return value


@always_inline("nodebug")
def store_le32[
    origin: MutOrigin
](value: UInt32, output: Span[mut=True, UInt8, origin], offset: Int) raises:
    if offset < 0 or offset + 4 > len(output):
        raise Error("store_le32 out of bounds")
    comptime if CompilationTarget.is_x86():
        output.unsafe_ptr().unsafe_store[width=4](
            offset, bitcast[DType.uint8, 4](SIMD[DType.uint32, 1](value))
        )
    else:
        for i in range(4):
            output[offset + i] = UInt8(value >> UInt32(i * 8))


@always_inline("nodebug")
def store_be32[
    origin: MutOrigin
](value: UInt32, output: Span[mut=True, UInt8, origin], offset: Int) raises:
    if offset < 0 or offset + 4 > len(output):
        raise Error("store_be32 out of bounds")
    comptime if CompilationTarget.is_x86():
        var swapped = llvm_intrinsic[
            "llvm.bswap.i32", UInt32, has_side_effect=False
        ](value)
        output.unsafe_ptr().unsafe_store[width=4](
            offset, bitcast[DType.uint8, 4](SIMD[DType.uint32, 1](swapped))
        )
    else:
        for i in range(4):
            output[offset + i] = UInt8(value >> UInt32(24 - i * 8))


@always_inline("nodebug")
def store_le64[
    origin: MutOrigin
](value: UInt64, output: Span[mut=True, UInt8, origin], offset: Int) raises:
    if offset < 0 or offset + 8 > len(output):
        raise Error("store_le64 out of bounds")
    comptime if CompilationTarget.is_x86():
        output.unsafe_ptr().unsafe_store[width=8](
            offset, bitcast[DType.uint8, 8](SIMD[DType.uint64, 1](value))
        )
    else:
        for i in range(8):
            output[offset + i] = UInt8(value >> UInt64(i * 8))


@always_inline("nodebug")
def store_be64[
    origin: MutOrigin
](value: UInt64, output: Span[mut=True, UInt8, origin], offset: Int) raises:
    if offset < 0 or offset + 8 > len(output):
        raise Error("store_be64 out of bounds")
    comptime if CompilationTarget.is_x86():
        var swapped = llvm_intrinsic[
            "llvm.bswap.i64", UInt64, has_side_effect=False
        ](value)
        output.unsafe_ptr().unsafe_store[width=8](
            offset, bitcast[DType.uint8, 8](SIMD[DType.uint64, 1](swapped))
        )
    else:
        for i in range(8):
            output[offset + i] = UInt8(value >> UInt64(56 - i * 8))


@always_inline("nodebug")
def xor_into[
    a_origin: Origin, b_origin: Origin, output_origin: MutOrigin
](
    a: Span[UInt8, a_origin],
    b: Span[UInt8, b_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(a) != len(b) or len(output) != len(a):
        raise Error("xor spans must have equal length")
    for i in range(len(a)):
        output[i] = a[i] ^ b[i]


@always_inline("nodebug")
def copy_into[
    source_origin: Origin, destination_origin: MutOrigin
](
    source: Span[UInt8, source_origin],
    destination: Span[mut=True, UInt8, destination_origin],
    destination_offset: Int = 0,
) raises:
    if destination_offset < 0 or destination_offset + len(source) > len(
        destination
    ):
        raise Error("byte copy exceeds destination")
    var source_pointer = source.unsafe_ptr()
    var destination_pointer = destination.unsafe_ptr()
    var offset = 0
    while offset + 16 <= len(source):
        destination_pointer.unsafe_store[width=16](
            destination_offset + offset,
            source_pointer.unsafe_load[width=16](offset),
        )
        offset += 16
    while offset < len(source):
        destination_pointer.unsafe_store(
            destination_offset + offset,
            source_pointer.unsafe_load(offset),
        )
        offset += 1


def copy_bytes[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=len(data), fill=0)
    copy_into(data, Span(output))
    return output^
