"""HMAC-SHA1, HMAC-SHA256, HMAC-SHA512, and HMAC-SHA512-256."""

from .algorithm import HmacAlgorithm
from ..hashes.sha1 import SHA1, sha1
from ..hashes.sha256 import SHA256, sha256
from ..hashes.sha512 import SHA512, sha512
from std.collections import InlineArray
from std.memory import bitcast
from std.sys import llvm_intrinsic
from ..hashes.ripemd import ripemd160


@always_inline("nodebug")
def _finalize_sha1_into(mut state: SHA1, mut output: InlineArray[UInt8, 64]):
    var bit_length = state._total_len * 8
    state._buffer[state._buffer_len] = 0x80
    state._buffer_len += 1
    if state._buffer_len > 56:
        while state._buffer_len < 64:
            state._buffer[state._buffer_len] = 0
            state._buffer_len += 1
        state._compress_buffer()
        state._buffer_len = 0
    while state._buffer_len < 56:
        state._buffer[state._buffer_len] = 0
        state._buffer_len += 1
    for i in range(8):
        state._buffer[56 + i] = UInt8(bit_length >> UInt64(56 - i * 8))
    state._compress_buffer()
    for i in range(5):
        var word = state._state[i]
        output[i * 4] = UInt8(word >> 24)
        output[i * 4 + 1] = UInt8(word >> 16)
        output[i * 4 + 2] = UInt8(word >> 8)
        output[i * 4 + 3] = UInt8(word)


@always_inline("nodebug")
def _finalize_sha256_into(
    mut state: SHA256, mut output: InlineArray[UInt8, 64]
):
    var bit_length = state._total_len * 8
    state._buffer[state._buffer_len] = 0x80
    state._buffer_len += 1
    if state._buffer_len > 56:
        while state._buffer_len < 64:
            state._buffer[state._buffer_len] = 0
            state._buffer_len += 1
        state._compress_buffer()
        state._buffer_len = 0
    while state._buffer_len < 56:
        state._buffer[state._buffer_len] = 0
        state._buffer_len += 1
    for i in range(8):
        state._buffer[56 + i] = UInt8(bit_length >> UInt64(56 - i * 8))
    state._compress_buffer()
    var serialized = Span(state._state).unsafe_ptr().unsafe_load[width=8]()
    comptime for i in range(8):
        serialized[i] = llvm_intrinsic[
            "llvm.bswap.i32", UInt32, has_side_effect=False
        ](serialized[i])
    Span(output).unsafe_ptr().unsafe_store[width=32](
        0, bitcast[DType.uint8, 32](serialized)
    )


@always_inline("nodebug")
def _finalize_sha512_into(
    mut state: SHA512, mut output: InlineArray[UInt8, 64]
):
    var bit_length = state._total_len * 8
    state._buffer[state._buffer_len] = 0x80
    state._buffer_len += 1
    if state._buffer_len > 112:
        while state._buffer_len < 128:
            state._buffer[state._buffer_len] = 0
            state._buffer_len += 1
        state._compress_buffer()
        state._buffer_len = 0
    while state._buffer_len < 112:
        state._buffer[state._buffer_len] = 0
        state._buffer_len += 1
    for i in range(16):
        state._buffer[112 + i] = UInt8(bit_length >> UInt128(120 - i * 8))
    state._compress_buffer()
    var serialized = Span(state._state).unsafe_ptr().unsafe_load[width=8]()
    comptime for i in range(8):
        serialized[i] = llvm_intrinsic[
            "llvm.bswap.i64", UInt64, has_side_effect=False
        ](serialized[i])
    Span(output).unsafe_ptr().unsafe_store[width=64](
        0, bitcast[DType.uint8, 64](serialized)
    )


struct _HMACKey(Movable):
    """Reusable SHA HMAC key schedule for iterative KDFs."""

    var _kind: UInt8
    var _inner_state: InlineArray[UInt64, 8]
    var _outer_state: InlineArray[UInt64, 8]

    def __init__[
        origin: Origin
    ](out self, algorithm: HmacAlgorithm, key: Span[UInt8, origin]) raises:
        var kind: UInt8
        if algorithm == HmacAlgorithm.SHA1:
            kind = 1
        elif algorithm == HmacAlgorithm.SHA256:
            kind = 2
        elif algorithm == HmacAlgorithm.SHA512:
            kind = 3
        else:
            raise Error("unknown reusable HMAC")
        self._kind = kind
        self._inner_state = InlineArray[UInt64, 8](fill=0)
        self._outer_state = InlineArray[UInt64, 8](fill=0)
        if kind == 1:
            var pad = InlineArray[UInt8, 64](fill=0x36)
            if len(key) > 64:
                var digest = sha1(key)
                for i in range(20):
                    pad[i] ^= digest[i]
            else:
                for i in range(len(key)):
                    pad[i] ^= key[i]
            var inner = SHA1()
            inner.update(Span(pad))
            for i in range(5):
                self._inner_state[i] = UInt64(inner._state[i])
            for i in range(64):
                pad[i] ^= 0x6A
            var outer = SHA1()
            outer.update(Span(pad))
            for i in range(5):
                self._outer_state[i] = UInt64(outer._state[i])
            return
        if kind == 2:
            var pad = InlineArray[UInt8, 64](fill=0x36)
            if len(key) > 64:
                var digest = sha256(key)
                for i in range(32):
                    pad[i] ^= digest[i]
            else:
                for i in range(len(key)):
                    pad[i] ^= key[i]
            var inner = SHA256()
            inner.update(Span(pad))
            for i in range(8):
                self._inner_state[i] = UInt64(inner._state[i])
            for i in range(64):
                pad[i] ^= 0x6A
            var outer = SHA256()
            outer.update(Span(pad))
            for i in range(8):
                self._outer_state[i] = UInt64(outer._state[i])
            return
        var pad = InlineArray[UInt8, 128](fill=0x36)
        if len(key) > 128:
            var digest = sha512(key)
            for i in range(64):
                pad[i] ^= digest[i]
        else:
            for i in range(len(key)):
                pad[i] ^= key[i]
        var inner = SHA512()
        inner.update(Span(pad))
        for i in range(8):
            self._inner_state[i] = inner._state[i]
        for i in range(128):
            pad[i] ^= 0x6A
        var outer = SHA512()
        outer.update(Span(pad))
        for i in range(8):
            self._outer_state[i] = outer._state[i]

    def _authenticate_parts[
        use_second: Bool,
        use_third: Bool,
        first_origin: Origin,
        second_origin: Origin,
        third_origin: Origin,
    ](
        self,
        first: Span[UInt8, first_origin],
        second: Span[UInt8, second_origin],
        third: Span[UInt8, third_origin],
    ) raises -> List[UInt8]:
        if self._kind == 1:
            var inner = SHA1()
            for i in range(5):
                inner._state[i] = UInt32(self._inner_state[i])
            inner._total_len = 64
            inner.update(first)
            comptime if use_second:
                inner.update(second)
            comptime if use_third:
                inner.update(third)
            var digest = inner.finalize()
            var outer = SHA1()
            for i in range(5):
                outer._state[i] = UInt32(self._outer_state[i])
            outer._total_len = 64
            outer.update(Span(digest))
            return outer.finalize()
        if self._kind == 2:
            var inner = SHA256()
            for i in range(8):
                inner._state[i] = UInt32(self._inner_state[i])
            inner._total_len = 64
            inner.update(first)
            comptime if use_second:
                inner.update(second)
            comptime if use_third:
                inner.update(third)
            var digest = inner.finalize()
            var outer = SHA256()
            for i in range(8):
                outer._state[i] = UInt32(self._outer_state[i])
            outer._total_len = 64
            outer.update(Span(digest))
            return outer.finalize()
        var inner = SHA512()
        for i in range(8):
            inner._state[i] = self._inner_state[i]
        inner._total_len = 128
        inner.update(first)
        comptime if use_second:
            inner.update(second)
        comptime if use_third:
            inner.update(third)
        var digest = inner.finalize()
        var outer = SHA512()
        for i in range(8):
            outer._state[i] = self._outer_state[i]
        outer._total_len = 128
        outer.update(Span(digest))
        return outer.finalize()

    def _authenticate_parts_into[
        use_second: Bool,
        use_third: Bool,
        first_origin: Origin,
        second_origin: Origin,
        third_origin: Origin,
    ](
        self,
        first: Span[UInt8, first_origin],
        second: Span[UInt8, second_origin],
        third: Span[UInt8, third_origin],
        mut output: InlineArray[UInt8, 64],
    ) raises:
        var digest = InlineArray[UInt8, 64](uninitialized=True)
        if self._kind == 1:
            var inner = SHA1()
            for i in range(5):
                inner._state[i] = UInt32(self._inner_state[i])
            inner._total_len = 64
            inner.update(first)
            comptime if use_second:
                inner.update(second)
            comptime if use_third:
                inner.update(third)
            _finalize_sha1_into(inner, digest)
            var outer = SHA1()
            for i in range(5):
                outer._state[i] = UInt32(self._outer_state[i])
            outer._total_len = 64
            outer.update(Span(digest)[0:20])
            _finalize_sha1_into(outer, output)
            return
        if self._kind == 2:
            var inner = SHA256()
            for i in range(8):
                inner._state[i] = UInt32(self._inner_state[i])
            inner._total_len = 64
            inner.update(first)
            comptime if use_second:
                inner.update(second)
            comptime if use_third:
                inner.update(third)
            _finalize_sha256_into(inner, digest)
            var outer = SHA256()
            for i in range(8):
                outer._state[i] = UInt32(self._outer_state[i])
            outer._total_len = 64
            outer.update(Span(digest)[0:32])
            _finalize_sha256_into(outer, output)
            return
        var inner = SHA512()
        for i in range(8):
            inner._state[i] = self._inner_state[i]
        inner._total_len = 128
        inner.update(first)
        comptime if use_second:
            inner.update(second)
        comptime if use_third:
            inner.update(third)
        _finalize_sha512_into(inner, digest)
        var outer = SHA512()
        for i in range(8):
            outer._state[i] = self._outer_state[i]
        outer._total_len = 128
        outer.update(Span(digest))
        _finalize_sha512_into(outer, output)

    def authenticate_into[
        origin: Origin
    ](
        self,
        data: Span[UInt8, origin],
        mut output: InlineArray[UInt8, 64],
    ) raises:
        if self._kind == 2 and len(data) == 32:
            var inner = SHA256()
            comptime for i in range(8):
                inner._state[i] = UInt32(self._inner_state[i])
            Span(inner._buffer).unsafe_ptr().unsafe_store[width=32](
                0, data.unsafe_ptr().unsafe_load[width=32](0)
            )
            inner._buffer_len = 32
            inner._total_len = 96
            var digest = InlineArray[UInt8, 64](uninitialized=True)
            _finalize_sha256_into(inner, digest)
            var outer = SHA256()
            comptime for i in range(8):
                outer._state[i] = UInt32(self._outer_state[i])
            Span(outer._buffer).unsafe_ptr().unsafe_store[width=32](
                0, Span(digest).unsafe_ptr().unsafe_load[width=32](0)
            )
            outer._buffer_len = 32
            outer._total_len = 96
            _finalize_sha256_into(outer, output)
            return
        if self._kind == 2 and len(data) == 64:
            var inner = SHA256()
            comptime for i in range(8):
                inner._state[i] = UInt32(self._inner_state[i])
            inner._compress(data)
            inner._total_len = 128
            var digest = InlineArray[UInt8, 64](uninitialized=True)
            _finalize_sha256_into(inner, digest)
            var outer = SHA256()
            comptime for i in range(8):
                outer._state[i] = UInt32(self._outer_state[i])
            Span(outer._buffer).unsafe_ptr().unsafe_store[width=32](
                0, Span(digest).unsafe_ptr().unsafe_load[width=32](0)
            )
            outer._buffer_len = 32
            outer._total_len = 96
            _finalize_sha256_into(outer, output)
            return
        if self._kind == 3 and len(data) == 64:
            var inner = SHA512()
            comptime for i in range(8):
                inner._state[i] = self._inner_state[i]
            Span(inner._buffer).unsafe_ptr().unsafe_store[width=64](
                0, data.unsafe_ptr().unsafe_load[width=64](0)
            )
            inner._buffer_len = 64
            inner._total_len = 192
            var digest = InlineArray[UInt8, 64](uninitialized=True)
            _finalize_sha512_into(inner, digest)
            var outer = SHA512()
            comptime for i in range(8):
                outer._state[i] = self._outer_state[i]
            Span(outer._buffer).unsafe_ptr().unsafe_store[width=64](
                0, Span(digest).unsafe_ptr().unsafe_load[width=64](0)
            )
            outer._buffer_len = 64
            outer._total_len = 192
            _finalize_sha512_into(outer, output)
            return
        var unused_second = InlineArray[UInt8, 1](fill=0)
        var unused_third = InlineArray[UInt8, 1](fill=0)
        self._authenticate_parts_into[False, False](
            data, Span(unused_second), Span(unused_third), output
        )

    def authenticate_parts_into[
        first_origin: Origin,
        second_origin: Origin,
        third_origin: Origin,
    ](
        self,
        first: Span[UInt8, first_origin],
        second: Span[UInt8, second_origin],
        third: Span[UInt8, third_origin],
        mut output: InlineArray[UInt8, 64],
    ) raises:
        self._authenticate_parts_into[True, True](first, second, third, output)

    def authenticate_pair_into[
        first_origin: Origin, second_origin: Origin
    ](
        self,
        first: Span[UInt8, first_origin],
        second: Span[UInt8, second_origin],
        mut output: InlineArray[UInt8, 64],
    ) raises:
        var unused_third = InlineArray[UInt8, 1](fill=0)
        self._authenticate_parts_into[True, False](
            first, second, Span(unused_third), output
        )

    def authenticate[
        origin: Origin
    ](self, data: Span[UInt8, origin]) raises -> List[UInt8]:
        var digest = InlineArray[UInt8, 64](uninitialized=True)
        self.authenticate_into(data, digest)
        var size = 20 if self._kind == 1 else (32 if self._kind == 2 else 64)
        var output = List[UInt8](length=size, fill=0)
        for i in range(size):
            output[i] = digest[i]
        return output^


def _hmac_sha1[
    key_origin: Origin, data_origin: Origin
](key: Span[UInt8, key_origin], data: Span[UInt8, data_origin]) raises -> List[
    UInt8
]:
    var prepared = _HMACKey(HmacAlgorithm.SHA1, key)
    return prepared.authenticate(data)


def _hmac_sha256[
    key_origin: Origin, data_origin: Origin
](key: Span[UInt8, key_origin], data: Span[UInt8, data_origin]) raises -> List[
    UInt8
]:
    var prepared = _HMACKey(HmacAlgorithm.SHA256, key)
    return prepared.authenticate(data)


def _hmac_sha512[
    key_origin: Origin, data_origin: Origin
](key: Span[UInt8, key_origin], data: Span[UInt8, data_origin]) raises -> List[
    UInt8
]:
    var prepared = _HMACKey(HmacAlgorithm.SHA512, key)
    return prepared.authenticate(data)


def _hmac_ripemd160[
    key_origin: Origin, data_origin: Origin
](key: Span[UInt8, key_origin], data: Span[UInt8, data_origin]) -> List[UInt8]:
    var normalized = List[UInt8](length=64, fill=0)
    if len(key) > 64:
        var digest = ripemd160(key)
        for i in range(20):
            normalized[i] = digest[i]
    else:
        for i in range(len(key)):
            normalized[i] = key[i]
    var inner = List[UInt8](capacity=64 + len(data))
    var outer = List[UInt8](capacity=84)
    for byte in normalized:
        inner.append(byte ^ 0x36)
        outer.append(byte ^ 0x5C)
    for byte in data:
        inner.append(byte)
    var digest = ripemd160(Span(inner))
    for byte in digest:
        outer.append(byte)
    return ripemd160(Span(outer))


def authenticate[
    key_origin: Origin, data_origin: Origin
](
    algorithm: HmacAlgorithm,
    key: Span[UInt8, key_origin],
    data: Span[UInt8, data_origin],
) raises -> List[UInt8]:
    if algorithm == HmacAlgorithm.SHA1:
        return _hmac_sha1(key, data)
    if algorithm == HmacAlgorithm.RIPEMD160:
        return _hmac_ripemd160(key, data)
    if algorithm == HmacAlgorithm.SHA256:
        return _hmac_sha256(key, data)
    if algorithm == HmacAlgorithm.SHA512:
        return _hmac_sha512(key, data)
    if algorithm == HmacAlgorithm.SHA512_256:
        var prepared = _HMACKey(HmacAlgorithm.SHA512, key)
        var digest = InlineArray[UInt8, 64](uninitialized=True)
        prepared.authenticate_into(data, digest)
        var output = List[UInt8](length=32, fill=0)
        Span(output).unsafe_ptr().unsafe_store[width=32](
            Span(digest).unsafe_ptr().unsafe_load[width=32]()
        )
        return output^
    raise Error("unknown authenticator")


def authenticate_eight[
    key_origin: Origin
](
    algorithm: HmacAlgorithm,
    key: Span[UInt8, key_origin],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    """Authenticate eight independent messages with one reusable key schedule.
    """
    if len(inputs) != 8:
        raise Error("eight-way HMAC batch has invalid dimensions")
    var outputs = List[List[UInt8]](capacity=8)
    if algorithm == HmacAlgorithm.RIPEMD160:
        for lane in range(8):
            outputs.append(authenticate(algorithm, key, Span(inputs[lane])))
        return outputs^
    var prepared_algorithm = (
        HmacAlgorithm.SHA512 if algorithm
        == HmacAlgorithm.SHA512_256 else algorithm
    )
    var prepared = _HMACKey(prepared_algorithm, key)
    for lane in range(8):
        if algorithm == HmacAlgorithm.SHA512_256:
            var digest = InlineArray[UInt8, 64](uninitialized=True)
            prepared.authenticate_into(Span(inputs[lane]), digest)
            var output = List[UInt8](length=32, fill=0)
            Span(output).unsafe_ptr().unsafe_store[width=32](
                Span(digest).unsafe_ptr().unsafe_load[width=32]()
            )
            outputs.append(output^)
        else:
            outputs.append(prepared.authenticate(Span(inputs[lane])))
    return outputs^
