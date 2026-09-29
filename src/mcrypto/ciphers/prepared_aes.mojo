"""Compact reusable AES key schedule for internal block-oriented consumers."""

from std.memory import bitcast
from std.sys import CompilationTarget

from .aes_block import (
    _decrypt_aesni_prepared_four_into,
    _decrypt_aesni_prepared_state,
    _encrypt_aesni_four_prepared_values,
    _encrypt_aesni_prepared_eight,
    _encrypt_aesni_prepared_four,
    _encrypt_aesni_prepared_state,
    _encrypt_aesni_prepared_value,
    _prepare_aesni,
    _prepare_aesni128,
    decrypt_expanded,
    encrypt_expanded_into,
    expand_key,
)


struct _PreparedAES(Movable):
    """Reusable AES schedule without the generic block-cipher dispatcher."""

    var schedule: List[UInt8]
    var _round_keys: List[SIMD[DType.uint64, 2]]
    var initialized: Bool

    def __init__(out self):
        self.schedule = List[UInt8]()
        self._round_keys = List[SIMD[DType.uint64, 2]]()
        self.initialized = False

    def __init__[
        key_origin: Origin
    ](out self, key: Span[UInt8, key_origin]) raises:
        self.schedule = List[UInt8]()
        self._round_keys = List[SIMD[DType.uint64, 2]]()
        self.initialized = True
        comptime if CompilationTarget.is_x86():
            if len(key) == 16:
                self._round_keys = _prepare_aesni128(key)
            else:
                self.schedule = expand_key(key)
                self._round_keys = _prepare_aesni(Span(self.schedule))
        else:
            self.schedule = expand_key(key)

    def __init__(out self, *, deinit move: Self):
        self.schedule = move.schedule^
        self._round_keys = move._round_keys^
        self.initialized = move.initialized

    @always_inline("nodebug")
    def encrypt_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        if not self.initialized:
            raise Error("AES key schedule is not initialized")
        if len(block) != 16:
            raise Error("AES block must be 16 bytes")
        if output_offset < 0 or output_offset + 16 > len(output):
            raise Error("AES output span is too short")
        comptime if CompilationTarget.is_x86():
            output.unsafe_ptr().unsafe_store[width=16](
                output_offset,
                bitcast[DType.uint8, 16](
                    _encrypt_aesni_prepared_state(self._round_keys, block, 0)
                ),
            )
        else:
            encrypt_expanded_into(
                Span(self.schedule), block, output, output_offset
            )

    @always_inline("nodebug")
    def decrypt_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        if not self.initialized:
            raise Error("AES key schedule is not initialized")
        if len(block) != 16:
            raise Error("AES block must be 16 bytes")
        if output_offset < 0 or output_offset + 16 > len(output):
            raise Error("AES output span is too short")
        comptime if CompilationTarget.is_x86():
            output.unsafe_ptr().unsafe_store[width=16](
                output_offset,
                bitcast[DType.uint8, 16](
                    _decrypt_aesni_prepared_state(self._round_keys, block, 0)
                ),
            )
        else:
            var transformed = decrypt_expanded(Span(self.schedule), block)
            comptime for i in range(16):
                output[output_offset + i] = transformed[i]

    @always_inline("nodebug")
    def _require_accelerated(self) raises:
        comptime if not CompilationTarget.is_x86():
            raise Error("accelerated AES is unavailable on this target")
        if not self.initialized or (
            len(self._round_keys) != 11
            and len(self._round_keys) != 13
            and len(self._round_keys) != 15
        ):
            raise Error("accelerated AES key schedule is unavailable")

    @always_inline("nodebug")
    def encrypt_value(
        self, input_state: SIMD[DType.uint64, 2]
    ) raises -> SIMD[DType.uint64, 2]:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            return _encrypt_aesni_prepared_value(self._round_keys, input_state)
        else:
            raise Error("accelerated AES is unavailable on this target")

    @always_inline("nodebug")
    def encrypt_four_values(
        self,
        mut first: SIMD[DType.uint64, 2],
        mut second: SIMD[DType.uint64, 2],
        mut third: SIMD[DType.uint64, 2],
        mut fourth: SIMD[DType.uint64, 2],
    ) raises:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            _encrypt_aesni_four_prepared_values(
                self._round_keys, first, second, third, fourth
            )
        else:
            raise Error("accelerated AES is unavailable on this target")

    @always_inline("nodebug")
    def encrypt_state[
        data_origin: Origin
    ](self, data: Span[UInt8, data_origin], offset: Int) raises -> SIMD[
        DType.uint64, 2
    ]:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            return _encrypt_aesni_prepared_state(self._round_keys, data, offset)
        else:
            raise Error("accelerated AES is unavailable on this target")

    @always_inline("nodebug")
    def decrypt_state[
        data_origin: Origin
    ](self, data: Span[UInt8, data_origin], offset: Int) raises -> SIMD[
        DType.uint64, 2
    ]:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            return _decrypt_aesni_prepared_state(self._round_keys, data, offset)
        else:
            raise Error("accelerated AES is unavailable on this target")

    @always_inline("nodebug")
    def encrypt_eight[
        blocks_origin: Origin,
        input_origin: Origin,
        output_origin: MutOrigin,
    ](
        self,
        blocks: Span[UInt8, blocks_origin],
        block_offset: Int,
        input: Span[UInt8, input_origin],
        input_offset: Int,
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            _encrypt_aesni_prepared_eight(
                self._round_keys,
                blocks,
                block_offset,
                input,
                input_offset,
                output,
                output_offset,
            )
        else:
            raise Error("accelerated AES is unavailable on this target")

    @always_inline("nodebug")
    def encrypt_four[
        blocks_origin: Origin,
        input_origin: Origin,
        output_origin: MutOrigin,
    ](
        self,
        blocks: Span[UInt8, blocks_origin],
        block_offset: Int,
        input: Span[UInt8, input_origin],
        input_offset: Int,
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            _encrypt_aesni_prepared_four(
                self._round_keys,
                blocks,
                block_offset,
                input,
                input_offset,
                output,
                output_offset,
            )
        else:
            raise Error("accelerated AES is unavailable on this target")

    @always_inline("nodebug")
    def decrypt_four_into[
        data_origin: Origin,
        output_origin: MutOrigin,
    ](
        self,
        data: Span[UInt8, data_origin],
        offset: Int,
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        comptime if CompilationTarget.is_x86():
            self._require_accelerated()
            _decrypt_aesni_prepared_four_into(
                self._round_keys, data, offset, output, output_offset
            )
        else:
            raise Error("accelerated AES is unavailable on this target")

    def encrypt[
        block_origin: Origin
    ](self, block: Span[UInt8, block_origin]) raises -> List[UInt8]:
        var output = List[UInt8](length=16, fill=0)
        self.encrypt_into(block, Span(output), 0)
        return output^

    def decrypt[
        block_origin: Origin
    ](self, block: Span[UInt8, block_origin]) raises -> List[UInt8]:
        var output = List[UInt8](length=16, fill=0)
        self.decrypt_into(block, Span(output), 0)
        return output^
