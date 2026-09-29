"""SHA-2 primitives implemented in native Mojo.

The compression loop is allocation-free. Public one-shot helpers accept a byte
Span; the String overload is only a convenience for UTF-8 test messages.
"""

from std.bit import rotate_bits_right
from std.collections import InlineArray
from std.memory import bitcast
from std.sys import llvm_intrinsic
from ..traits import Digest

comptime SHA256_BLOCK_BYTES = 64

comptime _K: InlineArray[UInt32, 64] = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]
comptime SHA256_DIGEST_BYTES = 32
comptime SHA224_DIGEST_BYTES = 28


@always_inline("nodebug")
def _ch(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return z ^ (x & (y ^ z))


@always_inline("nodebug")
def _maj(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    return (x & y) | (z & (x | y))


@always_inline("nodebug")
def _big_sigma0(x: UInt32) -> UInt32:
    return (
        rotate_bits_right[2](x)
        ^ rotate_bits_right[13](x)
        ^ rotate_bits_right[22](x)
    )


@always_inline("nodebug")
def _big_sigma1(x: UInt32) -> UInt32:
    return (
        rotate_bits_right[6](x)
        ^ rotate_bits_right[11](x)
        ^ rotate_bits_right[25](x)
    )


@always_inline("nodebug")
def _small_sigma0(x: UInt32) -> UInt32:
    return rotate_bits_right[7](x) ^ rotate_bits_right[18](x) ^ (x >> 3)


@always_inline("nodebug")
def _small_sigma1(x: UInt32) -> UInt32:
    return rotate_bits_right[17](x) ^ rotate_bits_right[19](x) ^ (x >> 10)


@always_inline("nodebug")
def _load_be32[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> UInt32:
    var packed = data.unsafe_ptr().unsafe_load[width=4](offset)
    return llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
        bitcast[DType.uint32, 1](packed)[0]
    )


@always_inline("nodebug")
def _load_words[
    origin: Origin
](mut words: InlineArray[UInt32, 16], block: Span[UInt8, origin]):
    comptime for i in range(16):
        words[i] = _load_be32(block, i * 4)


@always_inline("nodebug")
def _store_be32(mut output: List[UInt8], value: UInt32):
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


struct SHA2_32[is224: Bool](Digest, Movable):
    """Incremental SHA-224 or SHA-256 state."""

    comptime block_bytes = SHA256_BLOCK_BYTES
    comptime digest_bytes = SHA224_DIGEST_BYTES if Self.is224 else SHA256_DIGEST_BYTES

    var _state: InlineArray[UInt32, 8]
    var _buffer: InlineArray[UInt8, SHA256_BLOCK_BYTES]
    var _buffer_len: Int
    var _total_len: UInt64
    var _finalized: Bool

    def __init__(out self):
        comptime if Self.is224:
            self._state = [
                UInt32(0xC1059ED8),
                UInt32(0x367CD507),
                UInt32(0x3070DD17),
                UInt32(0xF70E5939),
                UInt32(0xFFC00B31),
                UInt32(0x68581511),
                UInt32(0x64F98FA7),
                UInt32(0xBEFA4FA4),
            ]
        else:
            self._state = [
                UInt32(0x6A09E667),
                UInt32(0xBB67AE85),
                UInt32(0x3C6EF372),
                UInt32(0xA54FF53A),
                UInt32(0x510E527F),
                UInt32(0x9B05688C),
                UInt32(0x1F83D9AB),
                UInt32(0x5BE0CD19),
            ]
        self._buffer = InlineArray[UInt8, SHA256_BLOCK_BYTES](
            uninitialized=True
        )
        self._buffer_len = 0
        self._total_len = 0
        self._finalized = False

    @always_inline("nodebug")
    def _compress_words(mut self, mut words: InlineArray[UInt32, 16]):
        var a = self._state[0]
        var b = self._state[1]
        var c = self._state[2]
        var d = self._state[3]
        var e = self._state[4]
        var f = self._state[5]
        var g = self._state[6]
        var h = self._state[7]
        comptime for i in range(64):
            comptime slot = i % 16
            comptime if i >= 16:
                words[slot] = (
                    _small_sigma1(words[(i - 2) % 16])
                    + words[(i - 7) % 16]
                    + _small_sigma0(words[(i - 15) % 16])
                    + words[slot]
                )
            var t1 = (
                h
                + _big_sigma1(e)
                + _ch(e, f, g)
                + materialize[_K[i]]()
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
        var words = InlineArray[UInt32, 16](uninitialized=True)
        _load_words(words, block)
        self._compress_words(words)

    @always_inline("nodebug")
    def _compress_buffer(mut self):
        var words = InlineArray[UInt32, 16](uninitialized=True)
        _load_words(words, Span(self._buffer))
        self._compress_words(words)

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        if self._finalized:
            raise Error("SHA-2 state already finalized")
        self._total_len += UInt64(len(data))
        var offset = 0
        if self._buffer_len != 0:
            while offset < len(data) and self._buffer_len < SHA256_BLOCK_BYTES:
                self._buffer[self._buffer_len] = data[offset]
                self._buffer_len += 1
                offset += 1
            if self._buffer_len == SHA256_BLOCK_BYTES:
                self._compress_buffer()
                self._buffer_len = 0
        while offset + SHA256_BLOCK_BYTES <= len(data):
            self._compress(data[offset : offset + SHA256_BLOCK_BYTES])
            offset += SHA256_BLOCK_BYTES
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
        if self._buffer_len > 56:
            while self._buffer_len < SHA256_BLOCK_BYTES:
                self._buffer[self._buffer_len] = 0
                self._buffer_len += 1
            self._compress_buffer()
            self._buffer_len = 0
        while self._buffer_len < 56:
            self._buffer[self._buffer_len] = 0
            self._buffer_len += 1
        for i in range(8):
            self._buffer[56 + i] = UInt8(bit_len >> UInt64(56 - i * 8))
        self._compress_buffer()
        self._buffer_len = 0
        self._finalized = True

        var serialized = Span(self._state).unsafe_ptr().unsafe_load[width=8]()
        comptime for i in range(8):
            serialized[i] = llvm_intrinsic[
                "llvm.bswap.i32", UInt32, has_side_effect=False
            ](serialized[i])
        var output_pointer = output.unsafe_ptr()
        comptime if Self.is224:
            output_pointer.unsafe_store[width=16](
                0,
                bitcast[DType.uint8, 16](
                    SIMD[DType.uint32, 4](
                        serialized[0],
                        serialized[1],
                        serialized[2],
                        serialized[3],
                    )
                ),
            )
            output_pointer.unsafe_store[width=8](
                16,
                bitcast[DType.uint8, 8](
                    SIMD[DType.uint32, 2](serialized[4], serialized[5])
                ),
            )
            output_pointer.unsafe_store[width=4](
                24,
                bitcast[DType.uint8, 4](SIMD[DType.uint32, 1](serialized[6])),
            )
        else:
            output_pointer.unsafe_store[width=32](
                0, bitcast[DType.uint8, 32](serialized)
            )

    def finalize(mut self) raises -> List[UInt8]:
        var output = List[UInt8](length=Self.digest_bytes, fill=0)
        self.finalize_into(Span(output))
        return output^


comptime SHA224 = SHA2_32[True]
comptime SHA256 = SHA2_32[False]


def sha224[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var state = SHA224()
    state.update(data)
    return state.finalize()


def sha224(text: String) raises -> List[UInt8]:
    return sha224(text.as_bytes())


def sha256[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var state = SHA256()
    state.update(data)
    return state.finalize()


def sha256(text: String) raises -> List[UInt8]:
    return sha256(text.as_bytes())
