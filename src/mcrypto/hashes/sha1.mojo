"""SHA-1 implemented in pure Mojo for compatibility protocols."""

from std.bit import rotate_bits_left
from std.collections import InlineArray
from std.memory import bitcast
from std.sys.intrinsics import llvm_intrinsic
from ..traits import Digest


comptime SHA1_BLOCK_BYTES = 64
comptime SHA1_DIGEST_BYTES = 20


@always_inline("nodebug")
def _append_be32(mut output: List[UInt8], value: UInt32):
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


@always_inline("nodebug")
def _schedule_word[round: Int](mut words: InlineArray[UInt32, 16]) -> UInt32:
    comptime if round >= 16:
        words[round % 16] = rotate_bits_left[1](
            words[(round - 3) % 16]
            ^ words[(round - 8) % 16]
            ^ words[(round - 14) % 16]
            ^ words[round % 16]
        )
    return words[round % 16]


@always_inline("nodebug")
def _load_words[
    origin: Origin
](
    mut words: InlineArray[UInt32, 16],
    block: Span[UInt8, origin],
    block_offset: Int,
):
    var block_pointer = block.unsafe_ptr()
    comptime for i in range(16):
        words[i] = llvm_intrinsic[
            "llvm.bswap.i32", UInt32, has_side_effect=False
        ](
            bitcast[DType.uint32, 1](
                block_pointer.unsafe_load[width=4](block_offset + i * 4)
            )[0]
        )


struct SHA1(Digest, Movable):
    comptime block_bytes = SHA1_BLOCK_BYTES
    comptime digest_bytes = SHA1_DIGEST_BYTES

    var _state: InlineArray[UInt32, 5]
    var _buffer: InlineArray[UInt8, SHA1_BLOCK_BYTES]
    var _buffer_len: Int
    var _total_len: UInt64
    var _finalized: Bool

    def __init__(out self):
        self._state = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
        self._buffer = InlineArray[UInt8, SHA1_BLOCK_BYTES](uninitialized=True)
        self._buffer_len = 0
        self._total_len = 0
        self._finalized = False

    def __init__(out self, *, deinit move: Self):
        self._state = move._state^
        self._buffer = move._buffer^
        self._buffer_len = move._buffer_len
        self._total_len = move._total_len
        self._finalized = move._finalized

    @always_inline("nodebug")
    def _compress_words(mut self, mut words: InlineArray[UInt32, 16]):
        var a = self._state[0]
        var b = self._state[1]
        var c = self._state[2]
        var d = self._state[3]
        var e = self._state[4]
        comptime for i in range(20):
            var word = _schedule_word[i](words)
            var temporary = (
                rotate_bits_left[5](a)
                + (d ^ (b & (c ^ d)))
                + e
                + UInt32(0x5A827999)
                + word
            )
            e = d
            d = c
            c = rotate_bits_left[30](b)
            b = a
            a = temporary
        comptime for i in range(20, 40):
            var word = _schedule_word[i](words)
            var temporary = (
                rotate_bits_left[5](a)
                + (b ^ c ^ d)
                + e
                + UInt32(0x6ED9EBA1)
                + word
            )
            e = d
            d = c
            c = rotate_bits_left[30](b)
            b = a
            a = temporary
        comptime for i in range(40, 60):
            var word = _schedule_word[i](words)
            var temporary = (
                rotate_bits_left[5](a)
                + ((b & c) | (d & (b | c)))
                + e
                + UInt32(0x8F1BBCDC)
                + word
            )
            e = d
            d = c
            c = rotate_bits_left[30](b)
            b = a
            a = temporary
        comptime for i in range(60, 80):
            var word = _schedule_word[i](words)
            var temporary = (
                rotate_bits_left[5](a)
                + (b ^ c ^ d)
                + e
                + UInt32(0xCA62C1D6)
                + word
            )
            e = d
            d = c
            c = rotate_bits_left[30](b)
            b = a
            a = temporary
        self._state[0] += a
        self._state[1] += b
        self._state[2] += c
        self._state[3] += d
        self._state[4] += e

    @always_inline("nodebug")
    def _compress[
        origin: Origin
    ](mut self, block: Span[UInt8, origin], block_offset: Int):
        var words = InlineArray[UInt32, 16](uninitialized=True)
        _load_words(words, block, block_offset)
        self._compress_words(words)

    @always_inline("nodebug")
    def _compress_buffer(mut self):
        var words = InlineArray[UInt32, 16](uninitialized=True)
        _load_words(words, Span(self._buffer), 0)
        self._compress_words(words)

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        if self._finalized:
            raise Error("SHA-1 state already finalized")
        self._total_len += UInt64(len(data))
        var offset = 0
        if self._buffer_len != 0:
            var needed = SHA1_BLOCK_BYTES - self._buffer_len
            var count = min(needed, len(data))
            for i in range(count):
                self._buffer[self._buffer_len + i] = data[i]
            self._buffer_len += count
            offset = count
            if self._buffer_len == SHA1_BLOCK_BYTES:
                self._compress_buffer()
                self._buffer_len = 0
        while offset + SHA1_BLOCK_BYTES <= len(data):
            self._compress(data, offset)
            offset += SHA1_BLOCK_BYTES
        while offset < len(data):
            self._buffer[self._buffer_len] = data[offset]
            self._buffer_len += 1
            offset += 1

    def finalize_into[
        output_origin: MutOrigin
    ](mut self, output: Span[mut=True, UInt8, output_origin],) raises:
        if self._finalized:
            raise Error("SHA-1 state already finalized")
        if len(output) != SHA1_DIGEST_BYTES:
            raise Error("SHA-1 output span has invalid length")
        var bit_length = self._total_len * 8
        self._buffer[self._buffer_len] = 0x80
        self._buffer_len += 1
        if self._buffer_len > 56:
            while self._buffer_len < SHA1_BLOCK_BYTES:
                self._buffer[self._buffer_len] = 0
                self._buffer_len += 1
            self._compress_buffer()
            self._buffer_len = 0
        while self._buffer_len < 56:
            self._buffer[self._buffer_len] = 0
            self._buffer_len += 1
        for i in range(8):
            self._buffer[56 + i] = UInt8(bit_length >> UInt64(56 - i * 8))
        self._compress_buffer()
        self._buffer_len = 0
        self._finalized = True
        var output_pointer = output.unsafe_ptr()
        comptime for i in range(5):
            var word = llvm_intrinsic[
                "llvm.bswap.i32", UInt32, has_side_effect=False
            ](self._state[i])
            output_pointer.unsafe_store[width=4](
                i * 4, bitcast[DType.uint8, 4](SIMD[DType.uint32, 1](word))
            )

    def finalize(mut self) raises -> List[UInt8]:
        var output = List[UInt8](length=SHA1_DIGEST_BYTES, fill=0)
        self.finalize_into(Span(output))
        return output^


def sha1[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    var state = SHA1()
    state.update(data)
    return state.finalize()


def sha1(text: String) raises -> List[UInt8]:
    return sha1(text.as_bytes())
