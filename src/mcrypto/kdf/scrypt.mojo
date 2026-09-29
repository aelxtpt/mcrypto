"""RFC 7914 scrypt with Salsa20/8 in pure Mojo."""

from .pbkdf import _pbkdf2_prepared
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import _HMACKey
from std.collections import InlineArray
from std.memory import bitcast
from std.bit import rotate_bits_left


@always_inline("nodebug")
def _salsa20_8(mut x: InlineArray[UInt32, 16]):
    var a = SIMD[DType.uint32, 4](0)
    var b = SIMD[DType.uint32, 4](0)
    var c = SIMD[DType.uint32, 4](0)
    var d = SIMD[DType.uint32, 4](0)
    a[0] = x[0]
    a[1] = x[5]
    a[2] = x[10]
    a[3] = x[15]
    b[0] = x[4]
    b[1] = x[9]
    b[2] = x[14]
    b[3] = x[3]
    c[0] = x[8]
    c[1] = x[13]
    c[2] = x[2]
    c[3] = x[7]
    d[0] = x[12]
    d[1] = x[1]
    d[2] = x[6]
    d[3] = x[11]
    comptime for _ in range(4):
        b ^= rotate_bits_left[7](a + d)
        c ^= rotate_bits_left[9](b + a)
        d ^= rotate_bits_left[13](c + b)
        a ^= rotate_bits_left[18](d + c)

        var row_b = d.shuffle[1, 2, 3, 0]()
        var row_c = c.shuffle[2, 3, 0, 1]()
        var row_d = b.shuffle[3, 0, 1, 2]()
        row_b ^= rotate_bits_left[7](a + row_d)
        row_c ^= rotate_bits_left[9](row_b + a)
        row_d ^= rotate_bits_left[13](row_c + row_b)
        a ^= rotate_bits_left[18](row_d + row_c)
        b = row_d.shuffle[1, 2, 3, 0]()
        c = row_c.shuffle[2, 3, 0, 1]()
        d = row_b.shuffle[3, 0, 1, 2]()
    x[0] += a[0]
    x[5] += a[1]
    x[10] += a[2]
    x[15] += a[3]
    x[4] += b[0]
    x[9] += b[1]
    x[14] += b[2]
    x[3] += b[3]
    x[8] += c[0]
    x[13] += c[1]
    x[2] += c[2]
    x[7] += c[3]
    x[12] += d[0]
    x[1] += d[1]
    x[6] += d[2]
    x[11] += d[3]


def _block_mix(mut block: List[UInt32], mut scratch: List[UInt32], r: Int):
    var block_pointer = Span(block).unsafe_ptr()
    var scratch_pointer = Span(scratch).unsafe_ptr()
    var x = InlineArray[UInt32, 16](uninitialized=True)
    var x_pointer = Span(x).unsafe_ptr()
    x_pointer.unsafe_store[width=16](
        0, block_pointer.unsafe_load[width=16]((2 * r - 1) * 16)
    )
    for i in range(2 * r):
        x_pointer.unsafe_store[width=16](
            0,
            x_pointer.unsafe_load[width=16](0)
            ^ block_pointer.unsafe_load[width=16](i * 16),
        )
        _salsa20_8(x)
        scratch_pointer.unsafe_store[width=16](
            i * 16, x_pointer.unsafe_load[width=16](0)
        )
    for i in range(r):
        block_pointer.unsafe_store[width=16](
            i * 16, scratch_pointer.unsafe_load[width=16](2 * i * 16)
        )
        block_pointer.unsafe_store[width=16](
            (i + r) * 16,
            scratch_pointer.unsafe_load[width=16]((2 * i + 1) * 16),
        )


def _smix(
    mut block: List[UInt32],
    mut v: List[UInt32],
    mut scratch: List[UInt32],
    r: Int,
    cost: Int,
):
    var words = 32 * r
    var block_pointer = Span(block).unsafe_ptr()
    var v_pointer = Span(v).unsafe_ptr()
    for i in range(cost):
        for j in range(0, words, 8):
            v_pointer.unsafe_store[width=8](
                i * words + j, block_pointer.unsafe_load[width=8](j)
            )
        _block_mix(block, scratch, r)
    for _ in range(cost):
        var base = (2 * r - 1) * 16
        var integer = UInt64(block_pointer.unsafe_load(base)) | (
            UInt64(block_pointer.unsafe_load(base + 1)) << 32
        )
        var index = Int(integer & UInt64(cost - 1))
        for j in range(0, words, 8):
            block_pointer.unsafe_store[width=8](
                j,
                block_pointer.unsafe_load[width=8](j)
                ^ v_pointer.unsafe_load[width=8](index * words + j),
            )
        _block_mix(block, scratch, r)


def scrypt[
    password_origin: Origin, salt_origin: Origin
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    cost: Int,
    block_size: Int,
    parallelization: Int,
) raises -> List[UInt8]:
    if (
        cost < 2
        or (cost & (cost - 1)) != 0
        or block_size <= 0
        or parallelization <= 0
        or output_bytes <= 0
    ):
        raise Error("invalid scrypt parameters")
    var b_bytes = 128 * block_size * parallelization
    if b_bytes <= 0:
        raise Error("invalid PBKDF2 parameters")
    var prepared = _HMACKey(HmacAlgorithm.SHA256, password)
    var b = _pbkdf2_prepared(
        prepared,
        salt,
        b_bytes,
        1,
        32,
    )
    var b_pointer = Span(b).unsafe_ptr()
    var lane_bytes = 128 * block_size
    var words = 32 * block_size
    var lane_block = List[UInt32](length=words, fill=0)
    var v = List[UInt32](length=cost * words, fill=0)
    var scratch = List[UInt32](length=words, fill=0)
    var lane_pointer = Span(lane_block).unsafe_ptr()
    for lane in range(parallelization):
        var lane_offset = lane * lane_bytes
        for offset in range(0, lane_bytes, 16):
            lane_pointer.unsafe_store[width=4](
                offset // 4,
                bitcast[DType.uint32, 4](
                    b_pointer.unsafe_load[width=16](lane_offset + offset)
                ),
            )
        _smix(lane_block, v, scratch, block_size, cost)
        for offset in range(0, lane_bytes, 16):
            b_pointer.unsafe_store[width=16](
                lane_offset + offset,
                bitcast[DType.uint8, 16](
                    lane_pointer.unsafe_load[width=4](offset // 4)
                ),
            )
    return _pbkdf2_prepared(prepared, Span(b), output_bytes, 1, 32)
