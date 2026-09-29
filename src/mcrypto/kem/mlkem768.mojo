"""FIPS 203 ML-KEM-768 in pure Mojo.

Byte formats follow FIPS 203/interop: the 1184-byte encapsulation key is
`t_hat[1152] || rho[32]`; the 2400-byte decapsulation key is
`s_hat[1152] || ek[1184] || H(ek)[32] || z[32]`; ciphertexts are 1088 bytes
(`u[960] || v[128]`) and shared secrets are 32 bytes.  `seed_keypair` takes
`d[32] || z[32]`; `encapsulate_deterministic` takes a 32-byte message seed.
"""

from ..hashes.keccak import _shake128_four, sha3, shake
from ..random.entropy import system_entropy

comptime PUBLIC_KEY_BYTES = 1184
comptime SECRET_KEY_BYTES = 2400
comptime CIPHERTEXT_BYTES = 1088
comptime SHARED_SECRET_BYTES = 32
comptime SEED_BYTES = 64
comptime ENCAPS_SEED_BYTES = 32
comptime _Q = 3329
comptime _N = 256
comptime _K = 3
comptime _POLY_BYTES = 384
comptime _POLYVEC_BYTES = 1152
comptime _DU_BYTES = 320
comptime _DV_BYTES = 128


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
    if t >= 32768:
        t -= 65536
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


def _basemul_acc[
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
    _basemul_impl[False](output, oo, a, ao, b, bo, zetas)
    for v in range(1, _K):
        _basemul_impl[True](output, oo, a, ao + v * _N, b, bo + v * _N, zetas)
    _reduce(output, oo)


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


def _vec_to_bytes[
    p_origin: Origin
](p: Span[Int, p_origin], output_bytes: Int = _POLYVEC_BYTES) -> List[UInt8]:
    var out = List[UInt8](length=output_bytes, fill=0)
    for i in range(_K):
        _poly_to_bytes(p, i * _N, Span(out), i * _POLY_BYTES)
    return out^


def _vec_from_bytes_into[
    data_origin: Origin, p_origin: MutOrigin
](
    data: Span[UInt8, data_origin],
    p: Span[mut=True, Int, p_origin],
    off: Int = 0,
):
    for i in range(_K):
        _poly_from_bytes(data, off + i * _POLY_BYTES, p, i * _N)


def _noise_into[
    seed_origin: Origin, p_origin: MutOrigin
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
    var buf = shake(256, Span(ext), 128)
    var buf_pointer = Span(buf).unsafe_ptr()
    var p_pointer = p.unsafe_ptr()
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


def _matrix_into[
    seed_origin: Origin, matrix_origin: MutOrigin
](
    seed: Span[UInt8, seed_origin],
    transposed: Bool,
    matrix: Span[mut=True, Int, matrix_origin],
) raises:
    for base in range(0, _K * _K, 4):
        # All four suffix lanes are assigned below, including padded final lanes.
        var suffixes = InlineArray[UInt16, 4](uninitialized=True)
        comptime for lane in range(4):
            var index = min(base + lane, _K * _K - 1)
            var i = index // _K
            var j = index % _K
            var first = i if transposed else j
            var second = j if transposed else i
            suffixes[lane] = UInt16(first | (second << 8))
        var buffers = _shake128_four(seed, suffixes, 768)
        _fill_matrix_entry(seed, suffixes[0], buffers[0], matrix, base * _N)
        if base + 1 < _K * _K:
            _fill_matrix_entry(
                seed, suffixes[1], buffers[1], matrix, (base + 1) * _N
            )
        if base + 2 < _K * _K:
            _fill_matrix_entry(
                seed, suffixes[2], buffers[2], matrix, (base + 2) * _N
            )
        if base + 3 < _K * _K:
            _fill_matrix_entry(
                seed, suffixes[3], buffers[3], matrix, (base + 3) * _N
            )


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


def _indcpa_keypair[
    encode_secret: Bool, origin: Origin
](
    seed: Span[UInt8, origin],
    public_output_bytes: Int = PUBLIC_KEY_BYTES,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    var expanded = sha3(512, seed)
    var zetas = materialize[_ZETAS]()
    var matrix = InlineArray[Int, _K * _K * _N](uninitialized=True)
    _matrix_into(expanded[0:32], False, Span(matrix))
    var s = InlineArray[Int, _K * _N](uninitialized=True)
    var e = InlineArray[Int, _K * _N](uninitialized=True)
    for i in range(_K):
        _noise_into(expanded[32:64], i, Span(s), i * _N)
        _noise_into(expanded[32:64], i + _K, Span(e), i * _N)
        _ntt(Span(s), Span(zetas), i * _N)
        _ntt(Span(e), Span(zetas), i * _N)
    var pk = InlineArray[Int, _K * _N](uninitialized=True)
    var pk_pointer = Span(pk).unsafe_ptr()
    var e_pointer = Span(e).unsafe_ptr()
    for i in range(_K):
        _basemul_acc(
            Span(pk),
            i * _N,
            Span(matrix),
            i * _K * _N,
            Span(s),
            0,
            Span(zetas),
        )
        for j in range(0, _N, 4):
            var offset = i * _N + j
            pk_pointer.unsafe_store[width=4](
                offset,
                _montgomery4(1353 * pk_pointer.unsafe_load[width=4](offset))
                + e_pointer.unsafe_load[width=4](offset),
            )
        _reduce(Span(pk), i * _N)
        _canonicalize(Span(pk), i * _N)
        _reduce(Span(s), i * _N)
        _canonicalize(Span(s), i * _N)
    # Optional trailing storage lets hybrid callers append without a second key copy.
    var pkb = _vec_to_bytes(Span(pk), public_output_bytes)
    var pkb_pointer = Span(pkb).unsafe_ptr()
    pkb_pointer.unsafe_store[width=16](
        _POLYVEC_BYTES,
        Span(expanded).unsafe_ptr().unsafe_load[width=16](0),
    )
    pkb_pointer.unsafe_store[width=16](
        _POLYVEC_BYTES + 16,
        Span(expanded).unsafe_ptr().unsafe_load[width=16](16),
    )
    comptime if encode_secret:
        var skb = _vec_to_bytes(Span(s))
        return (pkb^, skb^)
    else:
        var empty = List[UInt8]()
        return (pkb^, empty^)


def _indcpa_enc_parsed[
    msg_origin: Origin,
    pk_origin: Origin,
    coin_origin: Origin,
    pv_origin: Origin,
](
    msg: Span[UInt8, msg_origin],
    pk: Span[UInt8, pk_origin],
    coins: Span[UInt8, coin_origin],
    pv: Span[Int, pv_origin],
    ciphertext_output_bytes: Int = CIPHERTEXT_BYTES,
) raises -> List[UInt8]:
    var zetas = materialize[_ZETAS]()
    # `pv` is the caller's canonical, fully decoded public polynomial vector.
    var matrix = InlineArray[Int, _K * _K * _N](uninitialized=True)
    _matrix_into(pk[_POLYVEC_BYTES : _POLYVEC_BYTES + 32], True, Span(matrix))
    var sp = InlineArray[Int, _K * _N](uninitialized=True)
    var ep = InlineArray[Int, _K * _N](uninitialized=True)
    for i in range(_K):
        _noise_into(coins, i, Span(sp), i * _N)
        _noise_into(coins, i + _K, Span(ep), i * _N)
        _ntt(Span(sp), Span(zetas), i * _N)
        _reduce(Span(sp), i * _N)
    var epp = InlineArray[Int, _N](uninitialized=True)
    _noise_into(coins, 2 * _K, Span(epp))
    var b = InlineArray[Int, _K * _N](uninitialized=True)
    var v = InlineArray[Int, _N](uninitialized=True)
    for i in range(_K):
        _basemul_acc(
            Span(b),
            i * _N,
            Span(matrix),
            i * _K * _N,
            Span(sp),
            0,
            Span(zetas),
        )
    _basemul_acc(Span(v), 0, Span(pv), 0, Span(sp), 0, Span(zetas))
    for i in range(_K):
        _invntt(Span(b), Span(zetas), i * _N)
    _invntt(Span(v), Span(zetas))
    var m = InlineArray[Int, _N](uninitialized=True)
    _poly_from_msg(msg, Span(m))
    var b_pointer = Span(b).unsafe_ptr()
    var ep_pointer = Span(ep).unsafe_ptr()
    for i in range(0, _K * _N, 4):
        b_pointer.unsafe_store[width=4](
            i,
            b_pointer.unsafe_load[width=4](i)
            + ep_pointer.unsafe_load[width=4](i),
        )
    var v_pointer = Span(v).unsafe_ptr()
    var epp_pointer = Span(epp).unsafe_ptr()
    var m_pointer = Span(m).unsafe_ptr()
    for i in range(0, _N, 4):
        v_pointer.unsafe_store[width=4](
            i,
            v_pointer.unsafe_load[width=4](i)
            + epp_pointer.unsafe_load[width=4](i)
            + m_pointer.unsafe_load[width=4](i),
        )
    for i in range(_K):
        _reduce(Span(b), i * _N)
        _canonicalize(Span(b), i * _N)
    _reduce(Span(v))
    _canonicalize(Span(v))
    # Optional trailing storage is reserved for hybrid ciphertext components.
    var out = List[UInt8](length=ciphertext_output_bytes, fill=0)
    for i in range(_K):
        _compress_du(Span(b), i * _N, Span(out), i * _DU_BYTES)
    _compress_dv(Span(v), Span(out), _K * _DU_BYTES)
    return out^


def _indcpa_enc[
    msg_origin: Origin, pk_origin: Origin, coin_origin: Origin
](
    msg: Span[UInt8, msg_origin],
    pk: Span[UInt8, pk_origin],
    coins: Span[UInt8, coin_origin],
) raises -> List[UInt8]:
    var pv = InlineArray[Int, _K * _N](uninitialized=True)
    _vec_from_bytes_into(pk, Span(pv))
    return _indcpa_enc_parsed(msg, pk, coins, Span(pv), CIPHERTEXT_BYTES)


def _indcpa_dec[
    ct_origin: Origin, sk_origin: Origin
](ct: Span[UInt8, ct_origin], sk: Span[UInt8, sk_origin]) -> List[UInt8]:
    var zetas = materialize[_ZETAS]()
    var b = InlineArray[Int, _K * _N](uninitialized=True)
    for i in range(_K):
        _decompress_du(ct, i * _DU_BYTES, Span(b), i * _N)
    var v = InlineArray[Int, _N](uninitialized=True)
    _decompress_dv(ct, _K * _DU_BYTES, Span(v))
    var s = InlineArray[Int, _K * _N](uninitialized=True)
    _vec_from_bytes_into(sk, Span(s))
    for i in range(_K):
        _ntt(Span(b), Span(zetas), i * _N)
        _reduce(Span(b), i * _N)
    var m = InlineArray[Int, _N](uninitialized=True)
    _basemul_acc(Span(m), 0, Span(s), 0, Span(b), 0, Span(zetas))
    _invntt(Span(m), Span(zetas))
    var m_pointer = Span(m).unsafe_ptr()
    var v_pointer = Span(v).unsafe_ptr()
    for i in range(0, _N, 4):
        m_pointer.unsafe_store[width=4](
            i,
            v_pointer.unsafe_load[width=4](i)
            - m_pointer.unsafe_load[width=4](i),
        )
    _reduce(Span(m))
    _canonicalize(Span(m))
    return _poly_to_msg(Span(m))


def _seed_keypair_public[
    origin: Origin
](
    seed: Span[UInt8, origin],
    output_bytes: Int = PUBLIC_KEY_BYTES,
) raises -> List[UInt8]:
    if len(seed) != SEED_BYTES:
        raise Error("ML-KEM-768 key seed must be 64 bytes")
    var ind = InlineArray[UInt8, 33](uninitialized=True)
    var ind_pointer = Span(ind).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    ind_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    ind_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    ind[32] = UInt8(_K)
    var keys = _indcpa_keypair[False](Span(ind), output_bytes)
    # Consume the tuple so the generated key and reserved tail are not recopied.
    var public_key = List[UInt8]()

    @parameter
    def take_public_key[idx: Int](var key: keys.element_types[idx]):
        comptime if idx == 0:
            public_key = key^

    keys^.consume_elements[take_public_key]()
    return public_key^


def seed_keypair[
    origin: Origin
](seed: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Derive `(ek, dk)` from exactly 64 bytes `d || z`."""
    if len(seed) != SEED_BYTES:
        raise Error("ML-KEM-768 key seed must be 64 bytes")
    var ind = InlineArray[UInt8, 33](uninitialized=True)
    var ind_pointer = Span(ind).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    ind_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    ind_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    ind[32] = UInt8(_K)
    var keys = _indcpa_keypair[True](Span(ind))
    # Consume the tuple so neither 1184-byte polynomial vector is recopied.
    var pk = List[UInt8]()
    var encoded_secret = List[UInt8]()

    @parameter
    def take_key[idx: Int](var key: keys.element_types[idx]):
        comptime if idx == 0:
            pk = key^
        else:
            encoded_secret = key^

    keys^.consume_elements[take_key]()
    var h = sha3(256, Span(pk))
    var sk = List[UInt8](length=SECRET_KEY_BYTES, fill=0)
    var sk_pointer = Span(sk).unsafe_ptr()
    var encoded_secret_pointer = Span(encoded_secret).unsafe_ptr()
    var pk_pointer = Span(pk).unsafe_ptr()
    var h_pointer = Span(h).unsafe_ptr()
    for i in range(0, _POLYVEC_BYTES, 16):
        sk_pointer.unsafe_store[width=16](
            i, encoded_secret_pointer.unsafe_load[width=16](i)
        )
    for i in range(0, PUBLIC_KEY_BYTES, 16):
        sk_pointer.unsafe_store[width=16](
            _POLYVEC_BYTES + i, pk_pointer.unsafe_load[width=16](i)
        )
    sk_pointer.unsafe_store[width=16](
        _POLYVEC_BYTES + PUBLIC_KEY_BYTES,
        h_pointer.unsafe_load[width=16](0),
    )
    sk_pointer.unsafe_store[width=16](
        _POLYVEC_BYTES + PUBLIC_KEY_BYTES + 16,
        h_pointer.unsafe_load[width=16](16),
    )
    sk_pointer.unsafe_store[width=16](
        SECRET_KEY_BYTES - 32,
        seed_pointer.unsafe_load[width=16](32),
    )
    sk_pointer.unsafe_store[width=16](
        SECRET_KEY_BYTES - 16,
        seed_pointer.unsafe_load[width=16](48),
    )
    return (pk^, sk^)


def keypair() raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = system_entropy(SEED_BYTES)
    return seed_keypair(Span(seed))


def _encapsulate_deterministic_padded[
    pk_origin: Origin, seed_origin: Origin
](
    public_key: Span[UInt8, pk_origin],
    seed: Span[UInt8, seed_origin],
    ciphertext_output_bytes: Int,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encapsulate while reserving a caller-owned ciphertext tail."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise Error("ML-KEM-768 public key must be 1184 bytes")
    if len(seed) != ENCAPS_SEED_BYTES:
        raise Error("ML-KEM-768 encapsulation seed must be 32 bytes")
    var parsed = InlineArray[Int, _K * _N](uninitialized=True)
    _vec_from_bytes_into(public_key, Span(parsed))
    for x in parsed:
        if x >= _Q:
            raise Error("non-canonical ML-KEM-768 public key")
    var input = InlineArray[UInt8, 64](uninitialized=True)
    var input_pointer = Span(input).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    input_pointer.unsafe_store[width=16](
        0, seed_pointer.unsafe_load[width=16](0)
    )
    input_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    var h = sha3(256, public_key)
    var h_pointer = Span(h).unsafe_ptr()
    input_pointer.unsafe_store[width=16](32, h_pointer.unsafe_load[width=16](0))
    input_pointer.unsafe_store[width=16](
        48, h_pointer.unsafe_load[width=16](16)
    )
    var kr = sha3(512, Span(input))
    # Reuse the vector decoded for canonical validation; decoding twice is redundant.
    var ct = _indcpa_enc_parsed(
        seed,
        public_key,
        kr[32:64],
        Span(parsed),
        ciphertext_output_bytes,
    )
    var ss = List[UInt8](length=32, fill=0)
    var ss_pointer = Span(ss).unsafe_ptr()
    var kr_pointer = Span(kr).unsafe_ptr()
    ss_pointer.unsafe_store[width=16](0, kr_pointer.unsafe_load[width=16](0))
    ss_pointer.unsafe_store[width=16](16, kr_pointer.unsafe_load[width=16](16))
    return (ct^, ss^)


def encapsulate_deterministic[
    pk_origin: Origin, seed_origin: Origin
](
    public_key: Span[UInt8, pk_origin], seed: Span[UInt8, seed_origin]
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encapsulate with a supplied 32-byte FIPS randomness input."""
    return _encapsulate_deterministic_padded(public_key, seed, CIPHERTEXT_BYTES)


def encapsulate[
    origin: Origin
](public_key: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = system_entropy(ENCAPS_SEED_BYTES)
    return encapsulate_deterministic(public_key, Span(seed))


def decapsulate[
    ct_origin: Origin, sk_origin: Origin
](
    ciphertext: Span[UInt8, ct_origin], secret_key: Span[UInt8, sk_origin]
) raises -> List[UInt8]:
    """Decapsulate, returning FIPS 203 implicit-rejection output for invalid ciphertext.
    """
    if len(ciphertext) != CIPHERTEXT_BYTES:
        raise Error("ML-KEM-768 ciphertext must be 1088 bytes")
    if len(secret_key) != SECRET_KEY_BYTES:
        raise Error("ML-KEM-768 secret key must be 2400 bytes")
    var msg = _indcpa_dec(ciphertext, secret_key[0:_POLYVEC_BYTES])
    var input = InlineArray[UInt8, 64](uninitialized=True)
    var input_pointer = Span(input).unsafe_ptr()
    var msg_pointer = Span(msg).unsafe_ptr()
    var secret_pointer = secret_key.unsafe_ptr()
    input_pointer.unsafe_store[width=16](
        0, msg_pointer.unsafe_load[width=16](0)
    )
    input_pointer.unsafe_store[width=16](
        16, msg_pointer.unsafe_load[width=16](16)
    )
    input_pointer.unsafe_store[width=16](
        32,
        secret_pointer.unsafe_load[width=16](_POLYVEC_BYTES + PUBLIC_KEY_BYTES),
    )
    input_pointer.unsafe_store[width=16](
        48,
        secret_pointer.unsafe_load[width=16](
            _POLYVEC_BYTES + PUBLIC_KEY_BYTES + 16
        ),
    )
    var kr = sha3(512, Span(input))
    var expected = _indcpa_enc(
        Span(msg),
        secret_key[_POLYVEC_BYTES : _POLYVEC_BYTES + PUBLIC_KEY_BYTES],
        kr[32:64],
    )
    # Accumulate every byte without an early exit; validity remains data-oblivious.
    var different = UInt8(0)
    for i in range(CIPHERTEXT_BYTES):
        different |= ciphertext[i] ^ expected[i]
    var reject_input = InlineArray[UInt8, 32 + CIPHERTEXT_BYTES](
        uninitialized=True
    )
    var reject_pointer = Span(reject_input).unsafe_ptr()
    var ciphertext_pointer = ciphertext.unsafe_ptr()
    reject_pointer.unsafe_store[width=16](
        0, secret_pointer.unsafe_load[width=16](SECRET_KEY_BYTES - 32)
    )
    reject_pointer.unsafe_store[width=16](
        16, secret_pointer.unsafe_load[width=16](SECRET_KEY_BYTES - 16)
    )
    comptime for i in range(0, CIPHERTEXT_BYTES, 16):
        reject_pointer.unsafe_store[width=16](
            32 + i, ciphertext_pointer.unsafe_load[width=16](i)
        )
    # Rejection derivation is unconditional and the final choice is mask-only.
    var rejected = shake(256, Span(reject_input), 32)
    var reject_bit = UInt8((UInt16(different) + 255) >> 8)
    var reject_mask = UInt8(0) - reject_bit
    var shared_secret = List[UInt8](length=32, fill=0)
    var shared_pointer = Span(shared_secret).unsafe_ptr()
    var kr_pointer = Span(kr).unsafe_ptr()
    var rejected_pointer = Span(rejected).unsafe_ptr()
    var reject_vector = SIMD[DType.uint8, 16](reject_mask)
    comptime for i in range(0, 32, 16):
        shared_pointer.unsafe_store[width=16](
            i,
            (
                kr_pointer.unsafe_load[width=16](i) & ~reject_vector
                | rejected_pointer.unsafe_load[width=16](i) & reject_vector
            ),
        )
    return shared_secret^
