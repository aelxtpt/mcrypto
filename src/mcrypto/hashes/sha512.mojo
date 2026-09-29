"""Native SHA-384 and SHA-512 for Mojo 1.0."""

from std.bit import rotate_bits_right
from std.collections import InlineArray
from std.memory import bitcast
from std.sys import llvm_intrinsic
from ..traits import Digest

comptime SHA512_BLOCK_BYTES = 128

comptime _K: InlineArray[UInt64, 80] = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
]
comptime SHA384_DIGEST_BYTES = 48
comptime SHA512_DIGEST_BYTES = 64


@always_inline("nodebug")
def _ch(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return z ^ (x & (y ^ z))


@always_inline("nodebug")
def _maj(x: UInt64, y: UInt64, z: UInt64) -> UInt64:
    return (x & y) | (z & (x | y))


@always_inline("nodebug")
def _big_sigma0(x: UInt64) -> UInt64:
    return (
        rotate_bits_right[28](x)
        ^ rotate_bits_right[34](x)
        ^ rotate_bits_right[39](x)
    )


@always_inline("nodebug")
def _big_sigma1(x: UInt64) -> UInt64:
    return (
        rotate_bits_right[14](x)
        ^ rotate_bits_right[18](x)
        ^ rotate_bits_right[41](x)
    )


@always_inline("nodebug")
def _small_sigma0(x: UInt64) -> UInt64:
    return rotate_bits_right[1](x) ^ rotate_bits_right[8](x) ^ (x >> 7)


@always_inline("nodebug")
def _small_sigma1(x: UInt64) -> UInt64:
    return rotate_bits_right[19](x) ^ rotate_bits_right[61](x) ^ (x >> 6)


@always_inline("nodebug")
def _load_be64[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> UInt64:
    var packed = data.unsafe_ptr().unsafe_load[width=8](offset)
    return llvm_intrinsic["llvm.bswap.i64", UInt64, has_side_effect=False](
        bitcast[DType.uint64, 1](packed)[0]
    )


@always_inline("nodebug")
def _load_words[
    origin: Origin
](mut words: InlineArray[UInt64, 16], block: Span[UInt8, origin]):
    comptime for i in range(16):
        words[i] = _load_be64(block, i * 8)


@always_inline("nodebug")
def _store_be64(mut output: List[UInt8], value: UInt64):
    comptime for i in range(8):
        output.append(UInt8(value >> UInt64(56 - i * 8)))


struct SHA2_64[is384: Bool](Digest, Movable):
    """Incremental SHA-384 or SHA-512 state."""

    comptime block_bytes = SHA512_BLOCK_BYTES
    comptime digest_bytes = SHA384_DIGEST_BYTES if Self.is384 else SHA512_DIGEST_BYTES

    var _state: InlineArray[UInt64, 8]
    var _buffer: InlineArray[UInt8, SHA512_BLOCK_BYTES]
    var _buffer_len: Int
    var _total_len: UInt128
    var _finalized: Bool

    def __init__(out self):
        comptime if Self.is384:
            self._state = [
                UInt64(0xCBBB9D5DC1059ED8),
                UInt64(0x629A292A367CD507),
                UInt64(0x9159015A3070DD17),
                UInt64(0x152FECD8F70E5939),
                UInt64(0x67332667FFC00B31),
                UInt64(0x8EB44A8768581511),
                UInt64(0xDB0C2E0D64F98FA7),
                UInt64(0x47B5481DBEFA4FA4),
            ]
        else:
            self._state = [
                UInt64(0x6A09E667F3BCC908),
                UInt64(0xBB67AE8584CAA73B),
                UInt64(0x3C6EF372FE94F82B),
                UInt64(0xA54FF53A5F1D36F1),
                UInt64(0x510E527FADE682D1),
                UInt64(0x9B05688C2B3E6C1F),
                UInt64(0x1F83D9ABFB41BD6B),
                UInt64(0x5BE0CD19137E2179),
            ]
        self._buffer = InlineArray[UInt8, SHA512_BLOCK_BYTES](
            uninitialized=True
        )
        self._buffer_len = 0
        self._total_len = 0
        self._finalized = False

    @always_inline("nodebug")
    def _compress_words(mut self, mut words: InlineArray[UInt64, 16]):
        var a = self._state[0]
        var b = self._state[1]
        var c = self._state[2]
        var d = self._state[3]
        var e = self._state[4]
        var f = self._state[5]
        var g = self._state[6]
        var h = self._state[7]
        comptime for round in range(80):
            comptime slot = round % 16
            comptime if round >= 16:
                words[slot] = (
                    _small_sigma1(words[(round - 2) % 16])
                    + words[(round - 7) % 16]
                    + _small_sigma0(words[(round - 15) % 16])
                    + words[slot]
                )
            var t1 = (
                h
                + _big_sigma1(e)
                + _ch(e, f, g)
                + materialize[_K[round]]()
                + words[slot]
            )
            var t2 = _big_sigma0(a) + _maj(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        self._state[0] += a
        self._state[1] += b
        self._state[2] += c
        self._state[3] += d
        self._state[4] += e
        self._state[5] += f
        self._state[6] += g
        self._state[7] += h

    @always_inline("nodebug")
    def _compress[origin: Origin](mut self, block: Span[UInt8, origin]):
        var words = InlineArray[UInt64, 16](uninitialized=True)
        _load_words(words, block)
        self._compress_words(words)

    @always_inline("nodebug")
    def _compress_buffer(mut self):
        var words = InlineArray[UInt64, 16](uninitialized=True)
        _load_words(words, Span(self._buffer))
        self._compress_words(words)

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        if self._finalized:
            raise Error("SHA-2 state already finalized")
        self._total_len += UInt128(len(data))
        var offset = 0
        if self._buffer_len != 0:
            while offset < len(data) and self._buffer_len < SHA512_BLOCK_BYTES:
                self._buffer[self._buffer_len] = data[offset]
                self._buffer_len += 1
                offset += 1
            if self._buffer_len == SHA512_BLOCK_BYTES:
                self._compress_buffer()
                self._buffer_len = 0
        while offset + SHA512_BLOCK_BYTES <= len(data):
            self._compress(data[offset : offset + SHA512_BLOCK_BYTES])
            offset += SHA512_BLOCK_BYTES
        while offset < len(data):
            self._buffer[self._buffer_len] = data[offset]
            self._buffer_len += 1
            offset += 1

    def finalize_into[
        output_origin: MutOrigin
    ](mut self, output: Span[mut=True, UInt8, output_origin],) raises:
        if self._finalized:
            raise Error("SHA-2 state already finalized")
        if len(output) != Self.digest_bytes:
            raise Error("SHA-2 output span has invalid length")
        var bit_len = self._total_len * 8
        self._buffer[self._buffer_len] = 0x80
        self._buffer_len += 1
        if self._buffer_len > 112:
            while self._buffer_len < SHA512_BLOCK_BYTES:
                self._buffer[self._buffer_len] = 0
                self._buffer_len += 1
            self._compress_buffer()
            self._buffer_len = 0
        while self._buffer_len < 112:
            self._buffer[self._buffer_len] = 0
            self._buffer_len += 1
        for i in range(16):
            self._buffer[112 + i] = UInt8(bit_len >> UInt128(120 - i * 8))
        self._compress_buffer()
        self._buffer_len = 0
        self._finalized = True

        var serialized = Span(self._state).unsafe_ptr().unsafe_load[width=8]()
        comptime for i in range(8):
            serialized[i] = llvm_intrinsic[
                "llvm.bswap.i64", UInt64, has_side_effect=False
            ](serialized[i])
        var output_pointer = output.unsafe_ptr()
        comptime if Self.is384:
            output_pointer.unsafe_store[width=32](
                0,
                bitcast[DType.uint8, 32](
                    SIMD[DType.uint64, 4](
                        serialized[0],
                        serialized[1],
                        serialized[2],
                        serialized[3],
                    )
                ),
            )
            output_pointer.unsafe_store[width=16](
                32,
                bitcast[DType.uint8, 16](
                    SIMD[DType.uint64, 2](serialized[4], serialized[5])
                ),
            )
        else:
            output_pointer.unsafe_store[width=64](
                0, bitcast[DType.uint8, 64](serialized)
            )

    def finalize(mut self) raises -> List[UInt8]:
        var output = List[UInt8](length=Self.digest_bytes, fill=0)
        self.finalize_into(Span(output))
        return output^


@always_inline("nodebug")
def _compress_four[
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
](
    mut state: InlineArray[SIMD[DType.uint64, 4], 8],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    offset: Int,
):
    var words = InlineArray[SIMD[DType.uint64, 4], 16](uninitialized=True)
    comptime for i in range(16):
        var word_offset = offset + i * 8
        words[i] = SIMD[DType.uint64, 4](
            _load_be64(first, word_offset),
            _load_be64(second, word_offset),
            _load_be64(third, word_offset),
            _load_be64(fourth, word_offset),
        )
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    comptime for round in range(80):
        comptime slot = round % 16
        comptime if round >= 16:
            words[slot] = (
                (
                    rotate_bits_right[19](words[(round - 2) % 16])
                    ^ rotate_bits_right[61](words[(round - 2) % 16])
                    ^ (words[(round - 2) % 16] >> 6)
                )
                + words[(round - 7) % 16]
                + (
                    rotate_bits_right[1](words[(round - 15) % 16])
                    ^ rotate_bits_right[8](words[(round - 15) % 16])
                    ^ (words[(round - 15) % 16] >> 7)
                )
                + words[slot]
            )
        var sigma1 = (
            rotate_bits_right[14](e)
            ^ rotate_bits_right[18](e)
            ^ rotate_bits_right[41](e)
        )
        var choose = g ^ (e & (f ^ g))
        var t1 = (
            h
            + sigma1
            + choose
            + SIMD[DType.uint64, 4](materialize[_K[round]]())
            + words[slot]
        )
        var sigma0 = (
            rotate_bits_right[28](a)
            ^ rotate_bits_right[34](a)
            ^ rotate_bits_right[39](a)
        )
        var majority = (a & b) | (c & (a | b))
        var t2 = sigma0 + majority
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h


def sha2_64_four_into[
    is384: Bool,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Hash four equal-length messages in parallel with four UInt64 SIMD lanes.
    """
    comptime digest_bytes = SHA384_DIGEST_BYTES if is384 else SHA512_DIGEST_BYTES
    if (
        len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way SHA-2 inputs must have equal lengths")
    if (
        len(first_output) != digest_bytes
        or len(second_output) != digest_bytes
        or len(third_output) != digest_bytes
        or len(fourth_output) != digest_bytes
    ):
        raise Error("four-way SHA-2 output span has invalid length")
    var state = InlineArray[SIMD[DType.uint64, 4], 8](uninitialized=True)
    comptime if is384:
        state[0] = SIMD[DType.uint64, 4](0xCBBB9D5DC1059ED8)
        state[1] = SIMD[DType.uint64, 4](0x629A292A367CD507)
        state[2] = SIMD[DType.uint64, 4](0x9159015A3070DD17)
        state[3] = SIMD[DType.uint64, 4](0x152FECD8F70E5939)
        state[4] = SIMD[DType.uint64, 4](0x67332667FFC00B31)
        state[5] = SIMD[DType.uint64, 4](0x8EB44A8768581511)
        state[6] = SIMD[DType.uint64, 4](0xDB0C2E0D64F98FA7)
        state[7] = SIMD[DType.uint64, 4](0x47B5481DBEFA4FA4)
    else:
        state[0] = SIMD[DType.uint64, 4](0x6A09E667F3BCC908)
        state[1] = SIMD[DType.uint64, 4](0xBB67AE8584CAA73B)
        state[2] = SIMD[DType.uint64, 4](0x3C6EF372FE94F82B)
        state[3] = SIMD[DType.uint64, 4](0xA54FF53A5F1D36F1)
        state[4] = SIMD[DType.uint64, 4](0x510E527FADE682D1)
        state[5] = SIMD[DType.uint64, 4](0x9B05688C2B3E6C1F)
        state[6] = SIMD[DType.uint64, 4](0x1F83D9ABFB41BD6B)
        state[7] = SIMD[DType.uint64, 4](0x5BE0CD19137E2179)
    var offset = 0
    while offset + SHA512_BLOCK_BYTES <= len(first):
        _compress_four(state, first, second, third, fourth, offset)
        offset += SHA512_BLOCK_BYTES
    var first_tail = InlineArray[UInt8, 256](fill=0)
    var second_tail = InlineArray[UInt8, 256](fill=0)
    var third_tail = InlineArray[UInt8, 256](fill=0)
    var fourth_tail = InlineArray[UInt8, 256](fill=0)
    var remainder = len(first) - offset
    for i in range(remainder):
        first_tail[i] = first[offset + i]
        second_tail[i] = second[offset + i]
        third_tail[i] = third[offset + i]
        fourth_tail[i] = fourth[offset + i]
    first_tail[remainder] = 0x80
    second_tail[remainder] = 0x80
    third_tail[remainder] = 0x80
    fourth_tail[remainder] = 0x80
    var final_bytes = 128 if remainder < 112 else 256
    var bit_length = UInt128(len(first)) * 8
    for i in range(16):
        var byte = UInt8(bit_length >> UInt128(120 - i * 8))
        first_tail[final_bytes - 16 + i] = byte
        second_tail[final_bytes - 16 + i] = byte
        third_tail[final_bytes - 16 + i] = byte
        fourth_tail[final_bytes - 16 + i] = byte
    _compress_four(
        state,
        Span(first_tail),
        Span(second_tail),
        Span(third_tail),
        Span(fourth_tail),
        0,
    )
    if final_bytes == 256:
        _compress_four(
            state,
            Span(first_tail),
            Span(second_tail),
            Span(third_tail),
            Span(fourth_tail),
            128,
        )
    for i in range(digest_bytes):
        var word = i // 8
        var shift = UInt64(56 - (i % 8) * 8)
        first_output[i] = UInt8(state[word][0] >> shift)
        second_output[i] = UInt8(state[word][1] >> shift)
        third_output[i] = UInt8(state[word][2] >> shift)
        fourth_output[i] = UInt8(state[word][3] >> shift)


comptime SHA384 = SHA2_64[True]
comptime SHA512 = SHA2_64[False]


def sha384[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var state = SHA384()
    state.update(data)
    return state.finalize()


def sha384(text: String) raises -> List[UInt8]:
    return sha384(text.as_bytes())


def sha512[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var state = SHA512()
    state.update(data)
    return state.finalize()


def sha512(text: String) raises -> List[UInt8]:
    return sha512(text.as_bytes())
