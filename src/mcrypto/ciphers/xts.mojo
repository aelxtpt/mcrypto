"""XTS block-cipher mode with IEEE P1619 ciphertext stealing."""

from std.memory import bitcast
from std.sys import CompilationTarget

from .aes_block import (
    _decrypt_aesni_prepared_state,
    _encrypt_aesni_prepared_state,
    _encrypt_aesni_prepared_eight,
    _prepare_aesni,
    _prepare_aesni128,
    expand_key as aes_expand_key,
)

from .algorithm import BlockCipherAlgorithm
from .modes import _PreparedCipher, block_size


def _copy_range[
    origin: Origin
](input: Span[UInt8, origin], start: Int, count: Int) -> List[UInt8]:
    var output = List[UInt8](capacity=count)
    for i in range(count):
        output.append(input[start + i])
    return output^


def _gf_double(mut value: List[UInt8]):
    """Multiply a little-endian field element by x."""
    var carry = UInt8(0)
    for i in range(len(value)):
        var next_carry = value[i] >> 7
        value[i] = (value[i] << 1) | carry
        carry = next_carry
    if carry == 0:
        return
    if len(value) == 16:
        value[0] ^= 0x87
    elif len(value) == 32:
        value[0] ^= 0x25
        value[1] ^= 0x04
    elif len(value) == 64:
        value[0] ^= 0x25
        value[1] ^= 0x01
    elif len(value) == 128:
        value[0] ^= 0x43
        value[2] ^= 0x08


def _crypt_block(
    prepared: _PreparedCipher,
    encrypt: Bool,
    input: List[UInt8],
    tweak: List[UInt8],
) raises -> List[UInt8]:
    var mixed = List[UInt8](length=len(input), fill=0)
    for i in range(len(input)):
        mixed[i] = input[i] ^ tweak[i]
    var output = prepared.encrypt(Span(mixed)) if encrypt else prepared.decrypt(
        Span(mixed)
    )
    for i in range(len(output)):
        output[i] ^= tweak[i]
    return output^


@always_inline("nodebug")
def _crypt_aes_into[
    input_origin: Origin, output_origin: MutOrigin
](
    keys: List[SIMD[DType.uint64, 2]],
    encrypt: Bool,
    input: Span[UInt8, input_origin],
    input_offset: Int,
    tweak: List[UInt8],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var mixed = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        mixed[i] = input[input_offset + i] ^ tweak[i]
    var state = _encrypt_aesni_prepared_state(
        keys, Span(mixed), 0
    ) if encrypt else _decrypt_aesni_prepared_state(keys, Span(mixed), 0)
    output.unsafe_ptr().unsafe_store[width=16](
        output_offset, bitcast[DType.uint8, 16](state)
    )
    comptime for i in range(16):
        output[output_offset + i] ^= tweak[i]


def _validate(
    cipher: BlockCipherAlgorithm,
    key_length: Int,
    tweak_length: Int,
    input_length: Int,
) raises -> Int:
    if (
        cipher != BlockCipherAlgorithm.AES
        and cipher != BlockCipherAlgorithm.THREEFISH256
        and cipher != BlockCipherAlgorithm.THREEFISH512
        and cipher != BlockCipherAlgorithm.THREEFISH1024
    ):
        raise Error("XTS supports AES and Threefish")
    var size = block_size(cipher)
    if tweak_length != size:
        raise Error("XTS tweak must match the cipher block size")
    if input_length < size:
        raise Error("XTS data unit must contain at least one complete block")
    if key_length % 2 != 0:
        raise Error("XTS key must contain two equal cipher keys")
    var half = key_length // 2
    if cipher == BlockCipherAlgorithm.AES:
        if half != 16 and half != 24 and half != 32:
            raise Error("XTS-AES key must be 32, 48, or 64 bytes")
    elif half != size:
        raise Error("XTS-Threefish key must contain two full-width keys")
    return size


@always_inline("nodebug")
def _gf_double_aes(
    value: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var low = value[0]
    var high = value[1]
    var reduction = UInt64(0x87) if high >> 63 != 0 else UInt64(0)
    return SIMD[DType.uint64, 2](
        (low << 1) ^ reduction,
        (high << 1) | (low >> 63),
    )


def _prepare_aes_keys[
    key_origin: Origin
](key: Span[UInt8, key_origin]) raises -> List[SIMD[DType.uint64, 2]]:
    if len(key) == 16:
        return _prepare_aesni128(key)
    var expanded = aes_expand_key(key)
    return _prepare_aesni(Span(expanded))


def _process_aes_prepared[
    tweak_origin: Origin, input_origin: Origin
](
    encrypt: Bool,
    data_keys: List[SIMD[DType.uint64, 2]],
    tweak_keys: List[SIMD[DType.uint64, 2]],
    tweak: Span[UInt8, tweak_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    var tweak_state = _encrypt_aesni_prepared_state(tweak_keys, tweak, 0)
    var current_value = tweak_state
    var output = List[UInt8](length=len(input), fill=0)
    var full_blocks = len(input) // 16
    var tail = len(input) % 16
    var ordinary_blocks = full_blocks if tail == 0 else full_blocks - 1
    var block_index = 0
    if encrypt:
        var mixed = InlineArray[UInt8, 128](fill=0)
        var tweaks = InlineArray[UInt8, 128](fill=0)
        var mixed_pointer = Span(mixed).unsafe_ptr()
        var tweaks_pointer = Span(tweaks).unsafe_ptr()
        var input_pointer = input.unsafe_ptr()
        while block_index + 8 <= ordinary_blocks:
            comptime for lane in range(8):
                var tweak_bytes = bitcast[DType.uint8, 16](current_value)
                tweaks_pointer.unsafe_store[width=16](lane * 16, tweak_bytes)
                mixed_pointer.unsafe_store[width=16](
                    lane * 16,
                    input_pointer.unsafe_load[width=16](
                        (block_index + lane) * 16
                    )
                    ^ tweak_bytes,
                )
                current_value = _gf_double_aes(current_value)
            _encrypt_aesni_prepared_eight(
                data_keys,
                Span(mixed),
                0,
                Span(tweaks),
                0,
                Span(output),
                block_index * 16,
            )
            block_index += 8
    var mixed_block = InlineArray[UInt8, 16](fill=0)
    var mixed_pointer = Span(mixed_block).unsafe_ptr()
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    while block_index < ordinary_blocks:
        var offset = block_index * 16
        var tweak_bytes = bitcast[DType.uint8, 16](current_value)
        mixed_pointer.unsafe_store[width=16](
            0, input_pointer.unsafe_load[width=16](offset) ^ tweak_bytes
        )
        var state = _encrypt_aesni_prepared_state(
            data_keys, Span(mixed_block), 0
        ) if encrypt else _decrypt_aesni_prepared_state(
            data_keys, Span(mixed_block), 0
        )
        output_pointer.unsafe_store[width=16](
            offset, bitcast[DType.uint8, 16](state) ^ tweak_bytes
        )
        current_value = _gf_double_aes(current_value)
        block_index += 1
    if tail == 0:
        return output^
    var current = List[UInt8](length=16, fill=0)
    Span(current).unsafe_ptr().unsafe_store[width=16](
        0, bitcast[DType.uint8, 16](current_value)
    )
    var offset = ordinary_blocks * 16
    var next_tweak = current.copy()
    _gf_double(next_tweak)
    if encrypt:
        var stolen = List[UInt8](length=16, fill=0)
        _crypt_aes_into(
            data_keys, True, input, offset, current, Span(stolen), 0
        )
        var synthetic = List[UInt8](length=16, fill=0)
        for i in range(tail):
            output[offset + 16 + i] = stolen[i]
            synthetic[i] = input[offset + 16 + i]
        for i in range(tail, 16):
            synthetic[i] = stolen[i]
        _crypt_aes_into(
            data_keys,
            True,
            Span(synthetic),
            0,
            next_tweak,
            Span(output),
            offset,
        )
    else:
        var synthetic = List[UInt8](length=16, fill=0)
        _crypt_aes_into(
            data_keys,
            False,
            input,
            offset,
            next_tweak,
            Span(synthetic),
            0,
        )
        var stolen = List[UInt8](length=16, fill=0)
        for i in range(tail):
            output[offset + 16 + i] = synthetic[i]
            stolen[i] = input[offset + 16 + i]
        for i in range(tail, 16):
            stolen[i] = synthetic[i]
        _crypt_aes_into(
            data_keys,
            False,
            Span(stolen),
            0,
            current,
            Span(output),
            offset,
        )
    return output^


struct _PreparedAESXTS(Movable):
    """Reusable AES-XTS key schedules for independent data units."""

    var encrypt: Bool
    var data_keys: List[SIMD[DType.uint64, 2]]
    var tweak_keys: List[SIMD[DType.uint64, 2]]

    def __init__[
        key_origin: Origin
    ](out self, encrypt: Bool, key: Span[UInt8, key_origin]) raises:
        var half = len(key) // 2
        self.encrypt = encrypt
        self.data_keys = _prepare_aes_keys(key[0:half])
        self.tweak_keys = _prepare_aes_keys(key[half : 2 * half])

    def process[
        tweak_origin: Origin, input_origin: Origin
    ](
        self,
        tweak: Span[UInt8, tweak_origin],
        input: Span[UInt8, input_origin],
    ) raises -> List[UInt8]:
        return _process_aes_prepared(
            self.encrypt,
            self.data_keys,
            self.tweak_keys,
            tweak,
            input,
        )


def _process_aes[
    key_origin: Origin, tweak_origin: Origin, input_origin: Origin
](
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    tweak: Span[UInt8, tweak_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    var prepared = _PreparedAESXTS(encrypt, key)
    return prepared.process(tweak, input)


def process[
    key_origin: Origin, tweak_origin: Origin, input_origin: Origin
](
    cipher: BlockCipherAlgorithm,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    tweak: Span[UInt8, tweak_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    """Encrypt or decrypt one XTS data unit.

    ``key`` is the concatenation of the data and tweak keys. ``tweak`` is the
    block-sized little-endian data-unit value used by IEEE P1619.
    """
    var size = _validate(cipher, len(key), len(tweak), len(input))
    comptime if CompilationTarget.is_x86():
        if cipher == BlockCipherAlgorithm.AES:
            return _process_aes(encrypt, key, tweak, input)
    var half = len(key) // 2
    var data_key = _copy_range(key, 0, half)
    var tweak_key = _copy_range(key, half, half)
    var data_cipher = _PreparedCipher(cipher, Span(data_key), not encrypt)
    var tweak_cipher = _PreparedCipher(cipher, Span(tweak_key))
    var current = tweak_cipher.encrypt(tweak)
    var output = List[UInt8](length=len(input), fill=0)
    var full_blocks = len(input) // size
    var tail = len(input) % size
    var ordinary_blocks = full_blocks if tail == 0 else full_blocks - 1

    for block_index in range(ordinary_blocks):
        var offset = block_index * size
        var block = _copy_range(input, offset, size)
        var transformed = _crypt_block(data_cipher, encrypt, block^, current)
        for i in range(size):
            output[offset + i] = transformed[i]
        _gf_double(current)

    if tail == 0:
        return output^

    var offset = ordinary_blocks * size
    var next_tweak = current.copy()
    _gf_double(next_tweak)
    if encrypt:
        var last_plain = _copy_range(input, offset, size)
        var stolen = _crypt_block(data_cipher, True, last_plain^, current)
        var synthetic = List[UInt8](length=size, fill=0)
        for i in range(tail):
            output[offset + size + i] = stolen[i]
            synthetic[i] = input[offset + size + i]
        for i in range(tail, size):
            synthetic[i] = stolen[i]
        var last_cipher = _crypt_block(
            data_cipher, True, synthetic^, next_tweak
        )
        for i in range(size):
            output[offset + i] = last_cipher[i]
    else:
        var last_cipher = _copy_range(input, offset, size)
        var synthetic = _crypt_block(
            data_cipher, False, last_cipher^, next_tweak
        )
        var stolen = List[UInt8](length=size, fill=0)
        for i in range(tail):
            output[offset + size + i] = synthetic[i]
            stolen[i] = input[offset + size + i]
        for i in range(tail, size):
            stolen[i] = synthetic[i]
        var last_plain = _crypt_block(data_cipher, False, stolen^, current)
        for i in range(size):
            output[offset + i] = last_plain[i]
    return output^
