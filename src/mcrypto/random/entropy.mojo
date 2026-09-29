"""Operating-system entropy and deterministic ChaCha-based generation."""

from std.bit import rotate_bits_left
from std.ffi import external_call
from std.sys import CompilationTarget
from std.sys._libc_errno import ErrNo, get_errno
from ..internal.bytes import load_le32, store_le32


@always_inline("nodebug")
def _quarter_round(mut state: List[UInt32], a: Int, b: Int, c: Int, d: Int):
    state[a] += state[b]
    state[d] = rotate_bits_left[16](state[d] ^ state[a])
    state[c] += state[d]
    state[b] = rotate_bits_left[12](state[b] ^ state[c])
    state[a] += state[b]
    state[d] = rotate_bits_left[8](state[d] ^ state[a])
    state[c] += state[d]
    state[b] = rotate_bits_left[7](state[b] ^ state[c])


def system_entropy(output_bytes: Int) raises -> List[UInt8]:
    if output_bytes < 0:
        raise Error("entropy length cannot be negative")
    if output_bytes == 0:
        return List[UInt8]()
    var output = List[UInt8](length=output_bytes, fill=0)
    var filled = 0
    comptime if CompilationTarget.is_linux():
        while filled < output_bytes:
            var tail = Span(output)[filled:]
            var received = external_call["getrandom", Int](
                tail.unsafe_ptr(), UInt(len(tail)), UInt32(0)
            )
            if received == -1:
                if get_errno() == ErrNo.EINTR:
                    continue
                raise Error("operating-system getrandom call failed")
            if received <= 0 or received > len(tail):
                raise Error("operating-system getrandom call failed")
            filled += received
    elif CompilationTarget.is_macos():
        while filled < output_bytes:
            var remaining = output_bytes - filled
            var chunk_length = 256 if remaining > 256 else remaining
            var tail = Span(output)[filled:]
            if (
                external_call["getentropy", Int32](
                    tail.unsafe_ptr(), UInt(chunk_length)
                )
                != 0
            ):
                raise Error("operating-system getentropy call failed")
            filled += chunk_length
    else:
        CompilationTarget.unsupported_target_error[operation="system_entropy"]()
    return output^


struct ChaChaRNG(Movable):
    var _state: List[UInt32]
    var _block: List[UInt8]
    var _offset: Int

    def __init__[
        key_origin: Origin, nonce_origin: Origin
    ](
        out self,
        key: Span[UInt8, key_origin],
        nonce: Span[UInt8, nonce_origin],
        counter: UInt32 = 0,
    ) raises:
        if len(key) != 32 or len(nonce) != 12:
            raise Error("ChaChaRNG requires a 32-byte key and 12-byte nonce")
        self._state = List[UInt32](length=16, fill=0)
        self._state[0] = 0x61707865
        self._state[1] = 0x3320646E
        self._state[2] = 0x79622D32
        self._state[3] = 0x6B206574
        for i in range(8):
            self._state[4 + i] = load_le32(key, i * 4)
        self._state[12] = counter
        for i in range(3):
            self._state[13 + i] = load_le32(nonce, i * 4)
        self._block = List[UInt8](length=64, fill=0)
        self._offset = 64

    def __init__(out self, *, deinit move: Self):
        self._state = move._state^
        self._block = move._block^
        self._offset = move._offset

    def _refill(mut self) raises:
        var working = self._state.copy()
        for _ in range(10):
            _quarter_round(working, 0, 4, 8, 12)
            _quarter_round(working, 1, 5, 9, 13)
            _quarter_round(working, 2, 6, 10, 14)
            _quarter_round(working, 3, 7, 11, 15)
            _quarter_round(working, 0, 5, 10, 15)
            _quarter_round(working, 1, 6, 11, 12)
            _quarter_round(working, 2, 7, 8, 13)
            _quarter_round(working, 3, 4, 9, 14)
        var block_span = Span(self._block)
        for i in range(16):
            store_le32(working[i] + self._state[i], block_span, i * 4)
        if self._state[12] == UInt32(0xFFFFFFFF):
            raise Error("ChaChaRNG counter exhausted")
        self._state[12] += 1
        self._offset = 0

    def fill[
        origin: MutOrigin
    ](mut self, output: Span[mut=True, UInt8, origin]) raises:
        for i in range(len(output)):
            if self._offset == 64:
                self._refill()
            output[i] = self._block[self._offset]
            self._offset += 1

    def random_bytes(mut self, output_bytes: Int) raises -> List[UInt8]:
        if output_bytes < 0:
            raise Error("random output length cannot be negative")
        var output = List[UInt8](length=output_bytes, fill=0)
        var output_span = Span(output)
        self.fill(output_span)
        return output^


def seeded_rng() raises -> ChaChaRNG:
    var seed = system_entropy(44)
    var key = List[UInt8](capacity=32)
    var nonce = List[UInt8](capacity=12)
    for i in range(32):
        key.append(seed[i])
    for i in range(12):
        nonce.append(seed[32 + i])
    return ChaChaRNG(Span(key), Span(nonce))
