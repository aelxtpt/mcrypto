"""ANSI X9.17/X9.31 and AES-256 RandomPool generators in pure Mojo."""
from .algorithm import (
    HardwareRandomAlgorithm,
    RandomAlgorithm,
    X917Cipher,
)
from std.memory import bitcast
from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic

from ..ciphers.algorithm import BlockCipherAlgorithm
from ..ciphers.modes import _PreparedCipher
from ..ciphers.prepared_aes import _PreparedAES
from ..hashes.sha256 import sha256
from .entropy import system_entropy


@fieldwise_init
struct _HardwareRandomResult(TrivialRegisterPassable):
    var value: UInt64
    var success: Int32


@always_inline("nodebug")
def _rdrand_word() raises -> UInt64:
    for _ in range(64):
        var result = llvm_intrinsic[
            "llvm.x86.rdrand.64",
            _HardwareRandomResult,
            has_side_effect=True,
        ]()
        if result.success != 0:
            return result.value
    raise Error("RDRAND failed after 64 retries")


@always_inline("nodebug")
def _rdseed_word() raises -> UInt64:
    for _ in range(64):
        var result = llvm_intrinsic[
            "llvm.x86.rdseed.64",
            _HardwareRandomResult,
            has_side_effect=True,
        ]()
        if result.success != 0:
            return result.value
    raise Error("RDSEED failed after 64 retries")


def hardware_random(
    algorithm: HardwareRandomAlgorithm, output_bytes: Int
) raises -> List[UInt8]:
    """Read Intel RDRAND/RDSEED directly, with the carry flag checked."""
    if output_bytes < 0:
        raise Error("random output length cannot be negative")
    comptime if not CompilationTarget.is_x86():
        raise Error("x86 hardware RNG requested on a non-x86 target")
    # The selector type excludes software RNGs before entering this path.
    var output = List[UInt8](capacity=output_bytes)
    while len(output) < output_bytes:
        var word = (
            _rdrand_word() if algorithm
            == HardwareRandomAlgorithm.RDRAND else _rdseed_word()
        )
        for shift in range(0, 64, 8):
            if len(output) == output_bytes:
                break
            output.append(UInt8(word >> UInt64(shift)))
    return output^


@always_inline("nodebug")
def _increment(mut value: List[UInt8]):
    for offset in range(len(value)):
        var index = len(value) - 1 - offset
        value[index] += 1
        if value[index] != 0:
            return


def _copy_bytes[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var output = List[UInt8](capacity=len(data))
    for byte in data:
        output.append(byte)
    return output^


struct X917RNG(Movable):
    """Stateful ANSI X9.17 generator (X9.31 when AES is selected)."""

    var _is_aes: Bool
    var _prepared: _PreparedCipher
    var _seed: List[UInt8]
    var _time_vector: List[UInt8]
    var _last: List[UInt8]
    var _buffer: List[UInt8]
    var _offset: Int

    def __init__[
        ko: Origin, so: Origin, to: Origin
    ](
        out self,
        cipher: X917Cipher,
        key: Span[UInt8, ko],
        seed: Span[UInt8, so],
        deterministic_time_vector: Span[UInt8, to],
    ) raises:
        var block_size: Int
        if cipher == X917Cipher.AES:
            if len(key) != 16 and len(key) != 24 and len(key) != 32:
                raise Error("X9.31 AES key must be 16, 24, or 32 bytes")
            block_size = 16
        elif cipher == X917Cipher.TDES:
            if len(key) != 24:
                raise Error("X9.17 3DES key must be 24 bytes")
            block_size = 8
        else:
            raise Error("unsupported X9.17 block cipher")
        if (
            len(seed) != block_size
            or len(deterministic_time_vector) != block_size
        ):
            raise Error(
                "X9.17 seed and time vector must match the cipher block size"
            )
        self._is_aes = cipher == X917Cipher.AES
        self._seed = _copy_bytes(seed)
        self._prepared = _PreparedCipher(
            BlockCipherAlgorithm.AES if cipher
            == X917Cipher.AES else BlockCipherAlgorithm.DES_EDE3,
            key,
        )
        self._time_vector = _copy_bytes(deterministic_time_vector)
        self._last = List[UInt8](length=block_size, fill=0)
        self._buffer = List[UInt8](length=block_size, fill=0)
        self._offset = block_size
        # Prime the continuous-output test by discarding one block.
        self._refill()
        self._offset = block_size

    def __init__(out self, *, deinit move: Self):
        self._is_aes = move._is_aes
        self._prepared = move._prepared^
        self._seed = move._seed^
        self._time_vector = move._time_vector^
        self._last = move._last^
        self._buffer = move._buffer^
        self._offset = move._offset

    @always_inline("nodebug")
    def _encrypt_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
    ) raises:
        if self._is_aes:
            self._prepared.encrypt_aes_into(block, output, 0)
        else:
            self._prepared.encrypt_into(block, output, 0)

    def _refill(mut self) raises:
        var block_size = len(self._seed)
        comptime if CompilationTarget.is_x86():
            if self._is_aes:
                var time_value = bitcast[DType.uint64, 2](
                    Span(self._time_vector).unsafe_ptr().unsafe_load[width=16]()
                )
                var encrypted_value = self._prepared.aes.encrypt_value(
                    time_value
                )
                _increment(self._time_vector)
                var seed_value = bitcast[DType.uint64, 2](
                    Span(self._seed).unsafe_ptr().unsafe_load[width=16]()
                )
                var random_value = self._prepared.aes.encrypt_value(
                    seed_value ^ encrypted_value
                )
                var last_value = bitcast[DType.uint64, 2](
                    Span(self._last).unsafe_ptr().unsafe_load[width=16]()
                )
                if (
                    random_value[0] == last_value[0]
                    and random_value[1] == last_value[1]
                ):
                    raise Error("X9.17 continuous random-number test failed")
                var random_bytes = bitcast[DType.uint8, 16](random_value)
                Span(self._last).unsafe_ptr().unsafe_store[width=16](
                    random_bytes
                )
                Span(self._buffer).unsafe_ptr().unsafe_store[width=16](
                    random_bytes
                )
                var next_seed_value = self._prepared.aes.encrypt_value(
                    random_value ^ encrypted_value
                )
                Span(self._seed).unsafe_ptr().unsafe_store[width=16](
                    bitcast[DType.uint8, 16](next_seed_value)
                )
                self._offset = 0
                return
        var time_block = InlineArray[UInt8, 16](uninitialized=True)
        var encrypted_time = InlineArray[UInt8, 16](uninitialized=True)
        var mixed = InlineArray[UInt8, 16](uninitialized=True)
        var random_block = InlineArray[UInt8, 16](uninitialized=True)
        var next_seed = InlineArray[UInt8, 16](uninitialized=True)
        for i in range(block_size):
            time_block[i] = self._time_vector[i]
        self._encrypt_into(
            Span(time_block)[0:block_size],
            Span(encrypted_time)[0:block_size],
        )
        _increment(self._time_vector)
        for i in range(block_size):
            mixed[i] = self._seed[i] ^ encrypted_time[i]
        self._encrypt_into(
            Span(mixed)[0:block_size],
            Span(random_block)[0:block_size],
        )
        var repeated = True
        for i in range(block_size):
            repeated = repeated and random_block[i] == self._last[i]
        if repeated:
            raise Error("X9.17 continuous random-number test failed")
        for i in range(block_size):
            self._last[i] = random_block[i]
            self._buffer[i] = random_block[i]
            random_block[i] ^= encrypted_time[i]
        self._encrypt_into(
            Span(random_block)[0:block_size],
            Span(next_seed)[0:block_size],
        )
        for i in range(block_size):
            self._seed[i] = next_seed[i]
        self._offset = 0

    def random_bytes(mut self, output_bytes: Int) raises -> List[UInt8]:
        if output_bytes < 0:
            raise Error("random output length cannot be negative")
        var output = List[UInt8](unsafe_uninit_length=output_bytes)
        var output_pointer = Span(output).unsafe_ptr()
        var produced = 0
        while produced < output_bytes:
            if self._offset == len(self._buffer):
                self._refill()
            var take = min(
                output_bytes - produced, len(self._buffer) - self._offset
            )
            if take == 16:
                output_pointer.unsafe_store[width=16](
                    produced,
                    Span(self._buffer)
                    .unsafe_ptr()
                    .unsafe_load[width=16](self._offset),
                )
            elif take == 8:
                output_pointer.unsafe_store[width=8](
                    produced,
                    Span(self._buffer)
                    .unsafe_ptr()
                    .unsafe_load[width=8](self._offset),
                )
            else:
                for i in range(take):
                    output[produced + i] = self._buffer[self._offset + i]
            produced += take
            self._offset += take
        return output^

    def reseed[
        so: Origin, to: Origin
    ](
        mut self,
        seed: Span[UInt8, so],
        deterministic_time_vector: Span[UInt8, to],
    ) raises:
        if len(seed) != len(self._seed) or len(
            deterministic_time_vector
        ) != len(self._seed):
            raise Error("X9.17 reseed values must match the cipher block size")
        self._seed = _copy_bytes(seed)
        self._time_vector = _copy_bytes(deterministic_time_vector)
        self._last = List[UInt8](length=len(self._seed), fill=0)
        self._offset = len(self._buffer)
        self._refill()
        self._offset = len(self._buffer)


struct RandomPool(Movable):
    """RandomPool design: SHA-256 entropy mixing and AES-256 stream."""

    var _key: List[UInt8]
    var _prepared: _PreparedAES
    var _seed: List[UInt8]
    var _key_set: Bool

    def __init__(out self) raises:
        self._key = List[UInt8](length=32, fill=0)
        self._seed = List[UInt8](length=16, fill=0)
        self._prepared = _PreparedAES(Span(self._key))
        self._key_set = False

    def __init__[origin: Origin](out self, seed: Span[UInt8, origin]) raises:
        var material = List[UInt8](unsafe_uninit_length=32 + len(seed))
        for i in range(32):
            material[i] = 0
        for i in range(len(seed)):
            material[32 + i] = seed[i]
        self._key = sha256(Span(material))
        self._seed = List[UInt8](length=16, fill=0)
        self._prepared = _PreparedAES(Span(self._key))
        self._key_set = False

    def __init__(out self, *, deinit move: Self):
        self._key = move._key^
        self._seed = move._seed^
        self._prepared = move._prepared^
        self._key_set = move._key_set

    def incorporate_entropy[
        origin: Origin
    ](mut self, input: Span[UInt8, origin]) raises:
        var material = List[UInt8](unsafe_uninit_length=32 + len(input))
        for i in range(32):
            material[i] = self._key[i]
        for i in range(len(input)):
            material[32 + i] = input[i]
        self._key = sha256(Span(material))
        self._prepared = _PreparedAES(Span(self._key))
        self._key_set = False

    def reseed[origin: Origin](mut self, input: Span[UInt8, origin]) raises:
        self.incorporate_entropy(input)

    def fill[
        output_origin: MutOrigin
    ](mut self, output: Span[mut=True, UInt8, output_origin],) raises:
        self._key_set = True
        comptime if CompilationTarget.is_x86():
            var seed_state = bitcast[DType.uint64, 2](
                Span(self._seed).unsafe_ptr().unsafe_load[width=16]()
            )
            var output_pointer = output.unsafe_ptr()
            var produced = 0
            while produced + 16 <= len(output):
                seed_state = self._prepared.encrypt_value(seed_state)
                output_pointer.unsafe_store[width=16](
                    produced, bitcast[DType.uint8, 16](seed_state)
                )
                produced += 16
            if produced < len(output):
                seed_state = self._prepared.encrypt_value(seed_state)
                var next_seed = bitcast[DType.uint8, 16](seed_state)
                for i in range(len(output) - produced):
                    output_pointer.unsafe_store(produced + i, next_seed[i])
            Span(self._seed).unsafe_ptr().unsafe_store[width=16](
                0, bitcast[DType.uint8, 16](seed_state)
            )
        else:
            var produced = 0
            while produced + 16 <= len(output):
                self._prepared.encrypt_into(Span(self._seed), output, produced)
                Span(self._seed).unsafe_ptr().unsafe_store[width=16](
                    output.unsafe_ptr().unsafe_load[width=16](produced)
                )
                produced += 16
            if produced < len(output):
                var next_seed = InlineArray[UInt8, 16](uninitialized=True)
                self._prepared.encrypt_into(
                    Span(self._seed), Span(next_seed), 0
                )
                Span(self._seed).unsafe_ptr().unsafe_store[width=16](
                    Span(next_seed).unsafe_ptr().unsafe_load[width=16]()
                )
                for i in range(len(output) - produced):
                    output[produced + i] = next_seed[i]

    def random_bytes(mut self, output_bytes: Int) raises -> List[UInt8]:
        if output_bytes < 0:
            raise Error("random output length cannot be negative")
        var output = List[UInt8](unsafe_uninit_length=output_bytes)
        self.fill(Span(output))
        return output^


def secure_random_pool() raises -> RandomPool:
    var entropy = system_entropy(32)
    return RandomPool(Span(entropy))


def secure_x917(cipher: X917Cipher = X917Cipher.AES) raises -> X917RNG:
    if cipher == X917Cipher.AES:
        var entropy = system_entropy(48)
        var key = _copy_bytes(Span(entropy)[0:16])
        var state = _copy_bytes(Span(entropy)[16:32])
        var time = _copy_bytes(Span(entropy)[32:48])
        return X917RNG(cipher, Span(key), Span(state), Span(time))
    if cipher == X917Cipher.TDES:
        var entropy = system_entropy(40)
        var key = _copy_bytes(Span(entropy)[0:24])
        var state = _copy_bytes(Span(entropy)[24:32])
        var time = _copy_bytes(Span(entropy)[32:40])
        return X917RNG(cipher, Span(key), Span(state), Span(time))
    raise Error("unsupported X9.17 block cipher")


def supported(algorithm: RandomAlgorithm) -> Bool:
    if (
        algorithm == RandomAlgorithm.ANSI_X917_3DES
        or algorithm == RandomAlgorithm.ANSI_X931_AES
        or algorithm == RandomAlgorithm.RANDOM_POOL
    ):
        return True
    comptime if CompilationTarget.is_x86():
        return (
            algorithm == RandomAlgorithm.RDRAND
            or algorithm == RandomAlgorithm.RDSEED
        )
    return False


def generate[
    origin: Origin
](
    algorithm: RandomAlgorithm,
    seed: Span[UInt8, origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    """Deterministic one-shot interface; hardware names never receive a software fallback.
    """
    if output_bytes < 0:
        raise Error("random output length cannot be negative")
    if algorithm == RandomAlgorithm.RANDOM_POOL:
        var rng = RandomPool(seed)
        return rng.random_bytes(output_bytes)
    if algorithm == RandomAlgorithm.ANSI_X931_AES:
        if len(seed) != 48:
            raise Error(
                "deterministic X9.31-AES seed must be key || V || DT (48 bytes)"
            )
        var material = _copy_bytes(seed)
        var key = List[UInt8](capacity=16)
        var state = List[UInt8](capacity=16)
        var time = List[UInt8](capacity=16)
        for i in range(16):
            key.append(material[i])
            state.append(material[16 + i])
            time.append(material[32 + i])
        var rng = X917RNG(X917Cipher.AES, Span(key), Span(state), Span(time))
        return rng.random_bytes(output_bytes)
    if algorithm == RandomAlgorithm.ANSI_X917_3DES:
        if len(seed) != 40:
            raise Error(
                "deterministic X9.17-3DES seed must be key || V || DT (40"
                " bytes)"
            )
        var material = _copy_bytes(seed)
        var key = List[UInt8](capacity=24)
        var state = List[UInt8](capacity=8)
        var time = List[UInt8](capacity=8)
        for i in range(24):
            key.append(material[i])
        for i in range(8):
            state.append(material[24 + i])
            time.append(material[32 + i])
        var rng = X917RNG(X917Cipher.TDES, Span(key), Span(state), Span(time))
        return rng.random_bytes(output_bytes)
    if algorithm == RandomAlgorithm.RDRAND:
        return hardware_random(HardwareRandomAlgorithm.RDRAND, output_bytes)
    if algorithm == RandomAlgorithm.RDSEED:
        return hardware_random(HardwareRandomAlgorithm.RDSEED, output_bytes)
    raise Error("unknown legacy RNG")
