"""Shared FIPS 203 polynomial arithmetic and sampling for ranks 2 and 3."""
from ..hashes.keccak import shake

comptime _Q = 3329
comptime _N = 256
comptime _POLY_BYTES = 384
comptime _DU_BYTES = 320
comptime _DV_BYTES = 128
comptime SEED_BYTES = 64
comptime ENCAPS_SEED_BYTES = 32

comptime _ZETAS: InlineArray[Int, 128] = [
    2285,
    2571,
    2970,
    1812,
    1493,
    1422,
    287,
    202,
    3158,
    622,
    1577,
    182,
    962,
    2127,
    1855,
    1468,
    573,
    2004,
    264,
    383,
    2500,
    1458,
    1727,
    3199,
    2648,
    1017,
    732,
    608,
    1787,
    411,
    3124,
    1758,
    1223,
    652,
    2777,
    1015,
    2036,
    1491,
    3047,
    1785,
    516,
    3321,
    3009,
    2663,
    1711,
    2167,
    126,
    1469,
    2476,
    3239,
    3058,
    830,
    107,
    1908,
    3082,
    2378,
    2931,
    961,
    1821,
    2604,
    448,
    2264,
    677,
    2054,
    2226,
    430,
    555,
    843,
    2078,
    871,
    1550,
    105,
    422,
    587,
    177,
    3094,
    3038,
    2869,
    1574,
    1653,
    3083,
    778,
    1159,
    3182,
    2552,
    1483,
    2727,
    1119,
    1739,
    644,
    2457,
    349,
    418,
    329,
    3173,
    3254,
    817,
    1097,
    603,
    610,
    1322,
    2044,
    1864,
    384,
    2114,
    3193,
    1218,
    1994,
    2455,
    220,
    2142,
    1670,
    2144,
    1799,
    2051,
    794,
    1819,
    2475,
    2459,
    478,
    3221,
    3021,
    996,
    991,
    958,
    1869,
    1522,
    1628,
]


def _montgomery(a: Int) -> Int:
    var t = (a * 62209) & 65535
    t -= ((t >> 15) & 1) * 65536
    return (a - t * _Q) >> 16


@always_inline("nodebug")
def _montgomery4(a: SIMD[DType.int, 4]) -> SIMD[DType.int, 4]:
    var t = (a * 62209) & 65535
    t -= ((t >> 15) & 1) * 65536
    return (a - t * _Q) >> 16


@always_inline("nodebug")
def _barrett4(a: SIMD[DType.int, 4]) -> SIMD[DType.int, 4]:
    return a - ((a * 20159) >> 26) * _Q


@always_inline("nodebug")
def _csubq4(a: SIMD[DType.int, 4]) -> SIMD[DType.int, 4]:
    var result = a - _Q
    return result + ((result >> 63) & 1) * _Q


def _barrett(a: Int) -> Int:
    var t = (a * 20159) >> 26
    return a - t * _Q


def _ntt[
    p_origin: MutOrigin, z_origin: Origin
](p: Span[mut=True, Int, p_origin], zetas: Span[Int, z_origin], off: Int = 0,):
    var z_pointer = zetas.unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
    var k = 1
    var length = 128
    while length >= 2:
        var start = 0
        while start < _N:
            var zeta = z_pointer.unsafe_load(k)
            k += 1
            if length >= 4:
                for j in range(start, start + length, 4):
                    var high = p_pointer.unsafe_load[width=4](off + j + length)
                    var t = _montgomery4(zeta * high)
                    var low = p_pointer.unsafe_load[width=4](off + j)
                    p_pointer.unsafe_store[width=4](off + j + length, low - t)
                    p_pointer.unsafe_store[width=4](off + j, low + t)
            else:
                for j in range(start, start + length):
                    var high = p_pointer.unsafe_load(off + j + length)
                    var t = _montgomery(zeta * high)
                    var low = p_pointer.unsafe_load(off + j)
                    p_pointer.unsafe_store(off + j + length, low - t)
                    p_pointer.unsafe_store(off + j, low + t)
            start += 2 * length
        length //= 2


def _invntt[
    p_origin: MutOrigin, z_origin: Origin
](p: Span[mut=True, Int, p_origin], zetas: Span[Int, z_origin], off: Int = 0,):
    var z_pointer = zetas.unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
    var k = 127
    var length = 2
    while length <= 128:
        var start = 0
        while start < _N:
            var zeta = z_pointer.unsafe_load(k)
            k -= 1
            if length >= 4:
                for j in range(start, start + length, 4):
                    var low = p_pointer.unsafe_load[width=4](off + j)
                    var high = p_pointer.unsafe_load[width=4](off + j + length)
                    p_pointer.unsafe_store[width=4](
                        off + j, _barrett4(low + high)
                    )
                    p_pointer.unsafe_store[width=4](
                        off + j + length, _montgomery4(zeta * (high - low))
                    )
            else:
                for j in range(start, start + length):
                    var low = p_pointer.unsafe_load(off + j)
                    var high = p_pointer.unsafe_load(off + j + length)
                    p_pointer.unsafe_store(off + j, _barrett(low + high))
                    p_pointer.unsafe_store(
                        off + j + length, _montgomery(zeta * (high - low))
                    )
            start += 2 * length
        length *= 2
    for j in range(0, _N, 4):
        p_pointer.unsafe_store[width=4](
            off + j,
            _montgomery4(1441 * p_pointer.unsafe_load[width=4](off + j)),
        )


def _reduce[
    p_origin: MutOrigin
](p: Span[mut=True, Int, p_origin], off: Int = 0):
    var pointer = p.unsafe_ptr()
    for i in range(0, _N, 4):
        pointer.unsafe_store[width=4](
            off + i, _barrett4(pointer.unsafe_load[width=4](off + i))
        )


def _canonicalize[
    p_origin: MutOrigin
](p: Span[mut=True, Int, p_origin], off: Int = 0):
    var pointer = p.unsafe_ptr()
    for i in range(0, _N, 4):
        pointer.unsafe_store[width=4](
            off + i, _csubq4(pointer.unsafe_load[width=4](off + i))
        )


@always_inline("nodebug")
def _basemul_impl[
    accumulate: Bool,
    out_origin: MutOrigin,
    a_origin: Origin,
    b_origin: Origin,
    z_origin: Origin,
](
    output: Span[mut=True, Int, out_origin],
    oo: Int,
    a: Span[Int, a_origin],
    ao: Int,
    b: Span[Int, b_origin],
    bo: Int,
    zetas: Span[Int, z_origin],
):
    var z_pointer = zetas.unsafe_ptr()
    var out_pointer = output.unsafe_ptr()
    var a_pointer = a.unsafe_ptr()
    var b_pointer = b.unsafe_ptr()
    for i in range(64):
        var j = 4 * i
        var q = z_pointer.unsafe_load(64 + i)
        var left = a_pointer.unsafe_load[width=4](ao + j)
        var right = b_pointer.unsafe_load[width=4](bo + j)
        var products = _montgomery4(left * right)
        var adjusted = _montgomery4(products * SIMD[DType.int, 4](0, q, 0, -q))
        var cross = _montgomery4(left * right.shuffle[1, 0, 3, 2]())
        var result = SIMD[DType.int, 4](
            products[0] + adjusted[1],
            cross[0] + cross[1],
            products[2] + adjusted[3],
            cross[2] + cross[3],
        )
        comptime if accumulate:
            result += out_pointer.unsafe_load[width=4](oo + j)
        out_pointer.unsafe_store[width=4](oo + j, result)


def _poly_to_bytes[
    p_origin: Origin, out_origin: MutOrigin
](
    p: Span[Int, p_origin],
    off: Int,
    output: Span[mut=True, UInt8, out_origin],
    oo: Int,
):
    var p_pointer = p.unsafe_ptr()
    var out_pointer = output.unsafe_ptr()
    for i in range(128):
        var a = p_pointer.unsafe_load(off + 2 * i)
        var b = p_pointer.unsafe_load(off + 2 * i + 1)
        out_pointer.unsafe_store(oo + 3 * i, UInt8(a))
        out_pointer.unsafe_store(oo + 3 * i + 1, UInt8((a >> 8) | (b << 4)))
        out_pointer.unsafe_store(oo + 3 * i + 2, UInt8(b >> 4))


def _poly_from_bytes[
    data_origin: Origin, p_origin: MutOrigin
](
    data: Span[UInt8, data_origin],
    off: Int,
    p: Span[mut=True, Int, p_origin],
    po: Int,
):
    var data_pointer = data.unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
    for i in range(128):
        var middle = Int(data_pointer.unsafe_load(off + 3 * i + 1))
        p_pointer.unsafe_store(
            po + 2 * i,
            (Int(data_pointer.unsafe_load(off + 3 * i)) | (middle << 8)) & 4095,
        )
        p_pointer.unsafe_store(
            po + 2 * i + 1,
            (
                (middle >> 4)
                | (Int(data_pointer.unsafe_load(off + 3 * i + 2)) << 4)
            )
            & 4095,
        )


def _noise_into[
    eta: Int, seed_origin: Origin, p_origin: MutOrigin
](
    seed: Span[UInt8, seed_origin],
    nonce: Int,
    p: Span[mut=True, Int, p_origin],
    po: Int = 0,
) raises:
    var ext = InlineArray[UInt8, 33](uninitialized=True)
    var ext_pointer = Span(ext).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    ext_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    ext_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    ext[32] = UInt8(nonce)
    comptime assert eta == 2 or eta == 3, "unsupported ML-KEM noise parameter"
    var buf = shake(256, Span(ext), eta * 64)
    var buf_pointer = Span(buf).unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
    comptime if eta == 3:
        # FIPS 203 SamplePolyCBD: each coefficient subtracts two 3-bit
        # population counts. Four coefficients consume exactly three bytes.
        comptime mask = 0x00249249
        for i in range(64):
            var word = (
                Int(buf[3 * i])
                | (Int(buf[3 * i + 1]) << 8)
                | (Int(buf[3 * i + 2]) << 16)
            )
            var counts = (
                (word & mask) + ((word >> 1) & mask) + ((word >> 2) & mask)
            )
            for j in range(4):
                var positive = (counts >> (6 * j)) & 7
                var negative = (counts >> (6 * j + 3)) & 7
                p[po + 4 * i + j] = positive - negative
    else:
        var shifts = SIMD[DType.int, 8](0, 4, 8, 12, 16, 20, 24, 28)
        for i in range(32):
            var t = (
                Int(buf_pointer.unsafe_load(4 * i))
                | (Int(buf_pointer.unsafe_load(4 * i + 1)) << 8)
                | (Int(buf_pointer.unsafe_load(4 * i + 2)) << 16)
                | (Int(buf_pointer.unsafe_load(4 * i + 3)) << 24)
            )
            var d = (t & 0x55555555) + ((t >> 1) & 0x55555555)
            var packed = SIMD[DType.int, 8](d) >> shifts
            p_pointer.unsafe_store[width=8](
                po + 8 * i, (packed & 3) - ((packed >> 2) & 3)
            )


@always_inline("nodebug")
def _rejection_sample[
    buffer_origin: Origin, matrix_origin: MutOrigin
](
    buffer: Span[UInt8, buffer_origin],
    matrix: Span[mut=True, Int, matrix_origin],
    matrix_offset: Int,
) -> Int:
    var buf_pointer = buffer.unsafe_ptr()
    var matrix_pointer = matrix.unsafe_ptr()
    var ctr = 0
    var pos = 0
    while ctr < _N and pos + 3 <= len(buffer):
        var first = buf_pointer.unsafe_load(pos)
        var second = buf_pointer.unsafe_load(pos + 1)
        var third = buf_pointer.unsafe_load(pos + 2)
        var a = (Int(first) | (Int(second) << 8)) & 4095
        var b = ((Int(second) >> 4) | (Int(third) << 4)) & 4095
        pos += 3
        if a < _Q:
            matrix_pointer.unsafe_store(matrix_offset + ctr, a)
            ctr += 1
        if ctr < _N and b < _Q:
            matrix_pointer.unsafe_store(matrix_offset + ctr, b)
            ctr += 1
    return ctr


def _fill_matrix_entry[
    seed_origin: Origin, matrix_origin: MutOrigin
](
    seed: Span[UInt8, seed_origin],
    suffix: UInt16,
    buffer: List[UInt8],
    matrix: Span[mut=True, Int, matrix_origin],
    matrix_offset: Int,
) raises:
    var ctr = _rejection_sample(Span(buffer), matrix, matrix_offset)
    if ctr == _N:
        return
    var ext = InlineArray[UInt8, 34](uninitialized=True)
    var ext_pointer = Span(ext).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    ext_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    ext_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    ext[32] = UInt8(suffix)
    ext[33] = UInt8(suffix >> 8)
    var expanded = shake(128, Span(ext), 4096)
    ctr = _rejection_sample(Span(expanded), matrix, matrix_offset)
    if ctr != _N:
        raise Error("SHAKE rejection buffer exhausted")


def _poly_from_msg[
    msg_origin: Origin, p_origin: MutOrigin
](msg: Span[UInt8, msg_origin], p: Span[mut=True, Int, p_origin],):
    var p_pointer = p.unsafe_ptr()
    var shifts = SIMD[DType.int, 8](0, 1, 2, 3, 4, 5, 6, 7)
    for i in range(32):
        var bits = (SIMD[DType.int, 8](Int(msg[i])) >> shifts) & 1
        p_pointer.unsafe_store[width=8](8 * i, bits * ((_Q + 1) // 2))


def _poly_to_msg[p_origin: Origin](p: Span[Int, p_origin]) -> List[UInt8]:
    var out = List[UInt8](length=32, fill=0)
    var p_pointer = p.unsafe_ptr()
    var out_pointer = Span(out).unsafe_ptr()
    for i in range(32):
        var values = p_pointer.unsafe_load[width=8](8 * i)
        values += values >> 63 & _Q
        var bits = ((((values << 1) + _Q // 2) * 80635) >> 28) & 1
        out_pointer.unsafe_store(
            i,
            UInt8(
                bits[0]
                | (bits[1] << 1)
                | (bits[2] << 2)
                | (bits[3] << 3)
                | (bits[4] << 4)
                | (bits[5] << 5)
                | (bits[6] << 6)
                | (bits[7] << 7)
            ),
        )
    return out^


def _compress_du[
    p_origin: Origin, out_origin: MutOrigin
](
    p: Span[Int, p_origin],
    off: Int,
    output: Span[mut=True, UInt8, out_origin],
    oo: Int,
):
    var p_pointer = p.unsafe_ptr()
    var out_pointer = output.unsafe_ptr()
    for i in range(64):
        var values = p_pointer.unsafe_load[width=4](off + 4 * i)
        values += values >> 63 & _Q
        var t = ((((values << 10) + _Q // 2) * 161271) >> 29) & 1023
        out_pointer.unsafe_store(oo + 5 * i, UInt8(t[0]))
        out_pointer.unsafe_store(
            oo + 5 * i + 1, UInt8((t[0] >> 8) | (t[1] << 2))
        )
        out_pointer.unsafe_store(
            oo + 5 * i + 2, UInt8((t[1] >> 6) | (t[2] << 4))
        )
        out_pointer.unsafe_store(
            oo + 5 * i + 3, UInt8((t[2] >> 4) | (t[3] << 6))
        )
        out_pointer.unsafe_store(oo + 5 * i + 4, UInt8(t[3] >> 2))


def _decompress_du[
    data_origin: Origin, p_origin: MutOrigin
](
    data: Span[UInt8, data_origin],
    off: Int,
    p: Span[mut=True, Int, p_origin],
    po: Int,
):
    var data_pointer = data.unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
    for i in range(64):
        var b0 = Int(data_pointer.unsafe_load(off + 5 * i))
        var b1 = Int(data_pointer.unsafe_load(off + 5 * i + 1))
        var b2 = Int(data_pointer.unsafe_load(off + 5 * i + 2))
        var b3 = Int(data_pointer.unsafe_load(off + 5 * i + 3))
        var b4 = Int(data_pointer.unsafe_load(off + 5 * i + 4))
        var t = SIMD[DType.int, 4](
            (b0 | (b1 << 8)) & 1023,
            ((b1 >> 2) | (b2 << 6)) & 1023,
            ((b2 >> 4) | (b3 << 4)) & 1023,
            ((b3 >> 6) | (b4 << 2)) & 1023,
        )
        p_pointer.unsafe_store[width=4](po + 4 * i, (t * _Q + 512) >> 10)


def _compress_dv[
    p_origin: Origin, out_origin: MutOrigin
](p: Span[Int, p_origin], output: Span[mut=True, UInt8, out_origin], off: Int,):
    var p_pointer = p.unsafe_ptr()
    var out_pointer = output.unsafe_ptr()
    for i in range(128):
        var values = p_pointer.unsafe_load[width=2](2 * i)
        values += values >> 63 & _Q
        var t = ((((values << 4) + _Q // 2) * 161271) >> 29) & 15
        out_pointer.unsafe_store(off + i, UInt8(t[0] | (t[1] << 4)))


def _decompress_dv[
    data_origin: Origin, p_origin: MutOrigin
](data: Span[UInt8, data_origin], off: Int, p: Span[mut=True, Int, p_origin],):
    var data_pointer = data.unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
    for i in range(128):
        var byte = data_pointer.unsafe_load(off + i)
        p_pointer.unsafe_store[width=2](
            2 * i,
            (SIMD[DType.int, 2](Int(byte & 15), Int(byte >> 4)) * _Q + 8) >> 4,
        )
