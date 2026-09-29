"""IPcrypt deterministic, ND, NDX, and PFX families in pure Mojo."""

from .algorithm import IpcryptAlgorithm
from std.collections import InlineArray
from std.memory import bitcast
from std.sys import CompilationTarget
from ..ciphers.aes_block import (
    _sub,
    _inv_sub,
    _shift,
    _mix,
    _xtime,
    _load_aesni,
    _aesni_round,
    _aesni_last_round,
    _aesni_inverse_key,
    _aesni_decrypt_round,
    _aesni_decrypt_last_round,
)


def _expand128_fixed[
    key_origin: Origin
](key: Span[UInt8, key_origin], key_offset: Int = 0) -> InlineArray[UInt8, 176]:
    """Expand an already-validated AES-128 key without heap storage."""
    var expanded = InlineArray[UInt8, 176](uninitialized=True)
    comptime for i in range(16):
        expanded[i] = key[key_offset + i]
    var generated = 16
    var rcon = UInt8(1)
    while generated < 176:
        var t0 = expanded[generated - 4]
        var t1 = expanded[generated - 3]
        var t2 = expanded[generated - 2]
        var t3 = expanded[generated - 1]
        if generated % 16 == 0:
            var first = t0
            t0 = _sub(t1) ^ rcon
            t1 = _sub(t2)
            t2 = _sub(t3)
            t3 = _sub(first)
            rcon = _xtime(rcon)
        expanded[generated] = expanded[generated - 16] ^ t0
        expanded[generated + 1] = expanded[generated - 15] ^ t1
        expanded[generated + 2] = expanded[generated - 14] ^ t2
        expanded[generated + 3] = expanded[generated - 13] ^ t3
        generated += 4
    return expanded^


@always_inline("nodebug")
def _encrypt128_value(
    expanded: InlineArray[UInt8, 176],
    input_state: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var state = input_state ^ _load_aesni(Span(expanded), 0)
    comptime for round in range(1, 10):
        state = _aesni_round(state, _load_aesni(Span(expanded), round * 16))
    return _aesni_last_round(state, _load_aesni(Span(expanded), 160))


@always_inline("nodebug")
def _decrypt128_value(
    expanded: InlineArray[UInt8, 176],
    input_state: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var state = input_state ^ _load_aesni(Span(expanded), 160)
    comptime for offset in range(1, 10):
        comptime round = 10 - offset
        state = _aesni_decrypt_round(
            state,
            _aesni_inverse_key(_load_aesni(Span(expanded), round * 16)),
        )
    return _aesni_decrypt_last_round(state, _load_aesni(Span(expanded), 0))


@always_inline("nodebug")
def _encrypt128_values_eight(
    expanded: InlineArray[UInt8, 176],
    mut states: InlineArray[SIMD[DType.uint64, 2], 8],
):
    var round_key = _load_aesni(Span(expanded), 0)
    comptime for lane in range(8):
        states[lane] ^= round_key
    comptime for round in range(1, 10):
        round_key = _load_aesni(Span(expanded), round * 16)
        comptime for lane in range(8):
            states[lane] = _aesni_round(states[lane], round_key)
    round_key = _load_aesni(Span(expanded), 160)
    comptime for lane in range(8):
        states[lane] = _aesni_last_round(states[lane], round_key)


@always_inline("nodebug")
def _decrypt128_values_eight(
    expanded: InlineArray[UInt8, 176],
    mut states: InlineArray[SIMD[DType.uint64, 2], 8],
):
    var round_key = _load_aesni(Span(expanded), 160)
    comptime for lane in range(8):
        states[lane] ^= round_key
    comptime for offset in range(1, 10):
        comptime round = 10 - offset
        round_key = _aesni_inverse_key(_load_aesni(Span(expanded), round * 16))
        comptime for lane in range(8):
            states[lane] = _aesni_decrypt_round(states[lane], round_key)
    round_key = _load_aesni(Span(expanded), 0)
    comptime for lane in range(8):
        states[lane] = _aesni_decrypt_last_round(states[lane], round_key)


def _encrypt128_into[
    block_origin: Origin, output_origin: MutOrigin
](
    expanded: InlineArray[UInt8, 176],
    block: Span[UInt8, block_origin],
    block_offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    comptime if CompilationTarget.is_x86():
        var state = _encrypt128_value(
            expanded, _load_aesni(block, block_offset)
        )
        output.unsafe_ptr().unsafe_store[width=16](
            output_offset, bitcast[DType.uint8, 16](state)
        )
    else:
        var state = InlineArray[UInt8, 16](uninitialized=True)
        comptime for i in range(16):
            state[i] = block[block_offset + i] ^ expanded[i]
        for round in range(1, 10):
            comptime for i in range(16):
                state[i] = _sub(state[i])
            _shift(state, False)
            _mix(state, False)
            comptime for i in range(16):
                state[i] ^= expanded[round * 16 + i]
        comptime for i in range(16):
            state[i] = _sub(state[i])
        _shift(state, False)
        comptime for i in range(16):
            output[output_offset + i] = state[i] ^ expanded[160 + i]


def _decrypt128_into[
    block_origin: Origin, output_origin: MutOrigin
](
    expanded: InlineArray[UInt8, 176],
    block: Span[UInt8, block_origin],
    block_offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    comptime if CompilationTarget.is_x86():
        var state = _decrypt128_value(
            expanded, _load_aesni(block, block_offset)
        )
        output.unsafe_ptr().unsafe_store[width=16](
            output_offset, bitcast[DType.uint8, 16](state)
        )
    else:
        var state = InlineArray[UInt8, 16](uninitialized=True)
        comptime for i in range(16):
            state[i] = block[block_offset + i] ^ expanded[160 + i]
        for offset in range(1, 10):
            var round = 10 - offset
            _shift(state, True)
            comptime for i in range(16):
                state[i] = _inv_sub(state[i])
                state[i] ^= expanded[round * 16 + i]
            _mix(state, True)
        _shift(state, True)
        comptime for i in range(16):
            output[output_offset + i] = _inv_sub(state[i]) ^ expanded[i]


def _block_to_list(block: InlineArray[UInt8, 16]) -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    comptime for i in range(16):
        output[i] = block[i]
    return output^


@always_inline("nodebug")
def _state_to_list(state: SIMD[DType.uint64, 2], size: Int = 16) -> List[UInt8]:
    var output = List[UInt8](length=size, fill=0)
    Span(output).unsafe_ptr().unsafe_store[width=16](
        size - 16, bitcast[DType.uint8, 16](state)
    )
    return output^


def _tweak_byte[
    tweak_origin: Origin
](tweak: Span[UInt8, tweak_origin], index: Int) -> UInt8:
    if index % 4 >= 2:
        return 0
    var pair = index // 4
    return tweak[pair * 2 + index % 4]


def _crypt_with_tweak_into[
    key_origin: Origin,
    input_origin: Origin,
    tweak_origin: Origin,
    output_origin: MutOrigin,
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
    input_offset: Int,
    tweak: Span[UInt8, tweak_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var expanded = _expand128_fixed(key)
    var round_tweak = InlineArray[UInt8, 16](uninitialized=True)
    comptime for i in range(16):
        round_tweak[i] = _tweak_byte(tweak, i)
    comptime if CompilationTarget.is_x86():
        var tweak_state = _load_aesni(Span(round_tweak), 0)
        var aes_state: SIMD[DType.uint64, 2]
        if not decrypt:
            aes_state = (
                _load_aesni(input, input_offset)
                ^ tweak_state
                ^ _load_aesni(Span(expanded), 0)
            )
            comptime for round in range(1, 10):
                aes_state = _aesni_round(
                    aes_state,
                    _load_aesni(Span(expanded), round * 16) ^ tweak_state,
                )
            aes_state = _aesni_last_round(
                aes_state,
                _load_aesni(Span(expanded), 160) ^ tweak_state,
            )
        else:
            aes_state = (
                _load_aesni(input, input_offset)
                ^ tweak_state
                ^ _load_aesni(Span(expanded), 160)
            )
            comptime for offset in range(1, 10):
                comptime round = 10 - offset
                aes_state = _aesni_decrypt_round(
                    aes_state,
                    _aesni_inverse_key(
                        _load_aesni(Span(expanded), round * 16) ^ tweak_state
                    ),
                )
            aes_state = _aesni_decrypt_last_round(
                aes_state,
                _load_aesni(Span(expanded), 0) ^ tweak_state,
            )
        output.unsafe_ptr().unsafe_store[width=16](
            output_offset, bitcast[DType.uint8, 16](aes_state)
        )
        return
    var state = InlineArray[UInt8, 16](uninitialized=True)
    comptime for i in range(16):
        state[i] = input[input_offset + i] ^ round_tweak[i]
    if not decrypt:
        comptime for i in range(16):
            state[i] ^= expanded[i]
        for round in range(1, 10):
            comptime for i in range(16):
                state[i] = _sub(state[i])
            _shift(state, False)
            _mix(state, False)
            comptime for i in range(16):
                state[i] ^= expanded[round * 16 + i] ^ round_tweak[i]
        comptime for i in range(16):
            state[i] = _sub(state[i])
        _shift(state, False)
        comptime for i in range(16):
            output[output_offset + i] = (
                state[i] ^ expanded[160 + i] ^ round_tweak[i]
            )
        return
    comptime for i in range(16):
        state[i] ^= expanded[160 + i]
    for offset in range(1, 10):
        var round = 10 - offset
        _shift(state, True)
        comptime for i in range(16):
            state[i] = _inv_sub(state[i])
            state[i] ^= expanded[round * 16 + i] ^ round_tweak[i]
        _mix(state, True)
    _shift(state, True)
    comptime for i in range(16):
        output[output_offset + i] = (
            _inv_sub(state[i]) ^ expanded[i] ^ round_tweak[i]
        )


def _nd[
    key_origin: Origin, tweak_origin: Origin, input_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    tweak: Span[UInt8, tweak_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 16:
        raise Error("IPcrypt-ND key must be 16 bytes")
    if decrypt:
        if len(input) != 24:
            raise Error("IPcrypt-ND ciphertext must be 24 bytes")
        var output = List[UInt8](length=16, fill=0)
        var encrypted_tweak = InlineArray[UInt8, 8](uninitialized=True)
        comptime for i in range(8):
            encrypted_tweak[i] = input[i]
        _crypt_with_tweak_into(
            True, key, input, 8, Span(encrypted_tweak), Span(output), 0
        )
        return output^
    if len(input) != 16 or len(tweak) != 8:
        raise Error("IPcrypt-ND requires 16-byte input and 8-byte tweak")
    var output = List[UInt8](length=24, fill=0)
    comptime for i in range(8):
        output[i] = tweak[i]
    _crypt_with_tweak_into(False, key, input, 0, tweak, Span(output), 8)
    return output^


def _ndx[
    key_origin: Origin, tweak_origin: Origin, input_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    tweak: Span[UInt8, tweak_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 32:
        raise Error("IPcrypt-NDX key must be 32 bytes")
    if decrypt:
        if len(input) != 32:
            raise Error("IPcrypt-NDX ciphertext must be 32 bytes")
    elif len(input) != 16 or len(tweak) != 16:
        raise Error("IPcrypt-NDX requires 16-byte input and tweak")
    var first = _expand128_fixed(key)
    var second = _expand128_fixed(key, 16)
    var output = List[UInt8](length=16 if decrypt else 32, fill=0)
    comptime if CompilationTarget.is_x86():
        var mask = _encrypt128_value(
            second,
            _load_aesni(input, 0) if decrypt else _load_aesni(tweak, 0),
        )
        var body_input = (
            _load_aesni(input, 16) if decrypt else _load_aesni(input, 0)
        ) ^ mask
        var body = (
            _decrypt128_value(
                first, body_input
            ) if decrypt else _encrypt128_value(first, body_input)
        ) ^ mask
        if not decrypt:
            comptime for i in range(16):
                output[i] = tweak[i]
        Span(output).unsafe_ptr().unsafe_store[width=16](
            0 if decrypt else 16, bitcast[DType.uint8, 16](body)
        )
        return output^
    else:
        var mask = InlineArray[UInt8, 16](uninitialized=True)
        if decrypt:
            _encrypt128_into(second, input, 0, Span(mask), 0)
        else:
            _encrypt128_into(second, tweak, 0, Span(mask), 0)
        var block = InlineArray[UInt8, 16](uninitialized=True)
        comptime for i in range(16):
            block[i] = input[(16 if decrypt else 0) + i] ^ mask[i]
        if decrypt:
            _decrypt128_into(first, Span(block), 0, Span(output), 0)
            comptime for i in range(16):
                output[i] ^= mask[i]
        else:
            comptime for i in range(16):
                output[i] = tweak[i]
            _encrypt128_into(first, Span(block), 0, Span(output), 16)
            comptime for i in range(16):
                output[16 + i] ^= mask[i]
        return output^


def _is_v4[input_origin: Origin](input: Span[UInt8, input_origin]) -> Bool:
    for i in range(10):
        if input[i] != 0:
            return False
    return input[10] == 0xFF and input[11] == 0xFF


def _get_bit[
    input_origin: Origin
](input: Span[UInt8, input_origin], index: Int) -> UInt8:
    return (input[15 - index // 8] >> UInt8(index % 8)) & 1


def _set_bit(mut value: InlineArray[UInt8, 16], index: Int, bit: UInt8):
    var i = 15 - index // 8
    var mask = UInt8(1) << UInt8(index % 8)
    value[i] = (value[i] & ~mask) | (mask if bit & 1 else 0)


@always_inline("nodebug")
def _shift_left(mut value: InlineArray[UInt8, 16]):
    var pointer = Span(value).unsafe_ptr()
    var current = pointer.unsafe_load[width=16]()
    var carries = (current >> 7).shuffle[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15
    ]()
    carries[15] = 0
    pointer.unsafe_store[width=16]((current + current) | carries)


def _pfx[
    key_origin: Origin, input_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 32 or len(input) != 16:
        raise Error("IPcrypt-PFX requires 32-byte key and 16-byte address")
    var difference = UInt8(0)
    comptime for i in range(16):
        difference |= key[i] ^ key[16 + i]
    if difference == 0:
        raise Error("IPcrypt-PFX key halves must be different")
    var first = _expand128_fixed(key)
    var second = _expand128_fixed(key, 16)
    var start = 96 if _is_v4(input) else 0
    var prefix = InlineArray[UInt8, 16](fill=0)
    var output = InlineArray[UInt8, 16](fill=0)
    if start == 0:
        prefix[15] = 1
    else:
        prefix[3] = 1
        prefix[14] = 0xFF
        prefix[15] = 0xFF
        output[10] = 0xFF
        output[11] = 0xFF
    comptime if CompilationTarget.is_x86():
        for length in range(start, 128):
            var prefix_state = _load_aesni(Span(prefix), 0)
            var first_state = prefix_state ^ _load_aesni(Span(first), 0)
            var second_state = prefix_state ^ _load_aesni(Span(second), 0)
            comptime for round in range(1, 10):
                first_state = _aesni_round(
                    first_state, _load_aesni(Span(first), round * 16)
                )
                second_state = _aesni_round(
                    second_state, _load_aesni(Span(second), round * 16)
                )
            first_state = _aesni_last_round(
                first_state, _load_aesni(Span(first), 160)
            )
            second_state = _aesni_last_round(
                second_state, _load_aesni(Span(second), 160)
            )
            var cipher_bit = (
                UInt8((UInt64(first_state[1]) ^ UInt64(second_state[1])) >> 56)
                & 1
            )
            var pos = 127 - length
            var source = _get_bit(input, pos)
            var original = source ^ cipher_bit if decrypt else source
            _set_bit(output, pos, source ^ cipher_bit)
            _shift_left(prefix)
            _set_bit(prefix, 0, original)
    else:
        var encrypted_first = InlineArray[UInt8, 16](uninitialized=True)
        var encrypted_second = InlineArray[UInt8, 16](uninitialized=True)
        for length in range(start, 128):
            _encrypt128_into(first, Span(prefix), 0, Span(encrypted_first), 0)
            _encrypt128_into(second, Span(prefix), 0, Span(encrypted_second), 0)
            var cipher_bit = (encrypted_first[15] ^ encrypted_second[15]) & 1
            var pos = 127 - length
            var source = _get_bit(input, pos)
            var original = source ^ cipher_bit if decrypt else source
            _set_bit(output, pos, source ^ cipher_bit)
            _shift_left(prefix)
            _set_bit(prefix, 0, original)
    return _block_to_list(output)


def ipcrypt_eight[
    key_origin: Origin
](
    algorithm: IpcryptAlgorithm,
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    tweaks: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    """Process eight independent addresses while sharing expanded AES keys."""
    if len(inputs) != 8 or len(tweaks) != 8:
        raise Error("IPcrypt batch requires eight tweaks and addresses")
    if algorithm == IpcryptAlgorithm.PFX:
        var outputs = List[List[UInt8]](capacity=8)
        comptime for lane in range(8):
            outputs.append(_pfx(decrypt, key, Span(inputs[lane])))
        return outputs^
    if algorithm == IpcryptAlgorithm.IPCRYPT:
        if len(key) != 16:
            raise Error("IPcrypt requires 16-byte key")
        var expanded = _expand128_fixed(key)
        var states = InlineArray[SIMD[DType.uint64, 2], 8](uninitialized=True)
        comptime for lane in range(8):
            if len(inputs[lane]) != 16:
                raise Error("IPcrypt batch address must be 16 bytes")
            states[lane] = _load_aesni(Span(inputs[lane]), 0)
        if decrypt:
            _decrypt128_values_eight(expanded, states)
        else:
            _encrypt128_values_eight(expanded, states)
        var outputs = List[List[UInt8]](capacity=8)
        comptime for lane in range(8):
            outputs.append(_state_to_list(states[lane]))
        return outputs^
    if algorithm == IpcryptAlgorithm.ND:
        if len(key) != 16:
            raise Error("IPcrypt-ND key must be 16 bytes")
        var expanded = _expand128_fixed(key)
        var states = InlineArray[SIMD[DType.uint64, 2], 8](uninitialized=True)
        var tweak_states = InlineArray[SIMD[DType.uint64, 2], 8](
            uninitialized=True
        )
        comptime for lane in range(8):
            if decrypt:
                if len(inputs[lane]) != 24:
                    raise Error("IPcrypt-ND batch ciphertext must be 24 bytes")
            elif len(inputs[lane]) != 16 or len(tweaks[lane]) != 8:
                raise Error(
                    "IPcrypt-ND batch requires 16-byte input and 8-byte tweak"
                )
            var round_tweak = InlineArray[UInt8, 16](uninitialized=True)
            comptime for i in range(16):
                if decrypt:
                    round_tweak[i] = (
                        inputs[lane][(i // 4) * 2 + i % 4] if i % 4 < 2 else 0
                    )
                else:
                    round_tweak[i] = (
                        tweaks[lane][(i // 4) * 2 + i % 4] if i % 4 < 2 else 0
                    )
            tweak_states[lane] = _load_aesni(Span(round_tweak), 0)
            states[lane] = (
                _load_aesni(Span(inputs[lane]), 8 if decrypt else 0)
                ^ tweak_states[lane]
                ^ _load_aesni(Span(expanded), 160 if decrypt else 0)
            )
        if decrypt:
            comptime for offset in range(1, 10):
                comptime round = 10 - offset
                var round_key = _load_aesni(Span(expanded), round * 16)
                comptime for lane in range(8):
                    states[lane] = _aesni_decrypt_round(
                        states[lane],
                        _aesni_inverse_key(round_key ^ tweak_states[lane]),
                    )
            var round_key = _load_aesni(Span(expanded), 0)
            comptime for lane in range(8):
                states[lane] = _aesni_decrypt_last_round(
                    states[lane], round_key ^ tweak_states[lane]
                )
        else:
            comptime for round in range(1, 10):
                var round_key = _load_aesni(Span(expanded), round * 16)
                comptime for lane in range(8):
                    states[lane] = _aesni_round(
                        states[lane], round_key ^ tweak_states[lane]
                    )
            var round_key = _load_aesni(Span(expanded), 160)
            comptime for lane in range(8):
                states[lane] = _aesni_last_round(
                    states[lane], round_key ^ tweak_states[lane]
                )
        var outputs = List[List[UInt8]](capacity=8)
        comptime for lane in range(8):
            var output = _state_to_list(states[lane], 16 if decrypt else 24)
            if not decrypt:
                comptime for i in range(8):
                    output[i] = tweaks[lane][i]
            outputs.append(output^)
        return outputs^
    if algorithm == IpcryptAlgorithm.NDX:
        if len(key) != 32:
            raise Error("IPcrypt-NDX key must be 32 bytes")
        var first = _expand128_fixed(key)
        var second = _expand128_fixed(key, 16)
        var masks = InlineArray[SIMD[DType.uint64, 2], 8](uninitialized=True)
        var states = InlineArray[SIMD[DType.uint64, 2], 8](uninitialized=True)
        comptime for lane in range(8):
            if decrypt:
                if len(inputs[lane]) != 32:
                    raise Error("IPcrypt-NDX batch ciphertext must be 32 bytes")
                masks[lane] = _load_aesni(Span(inputs[lane]), 0)
            else:
                if len(inputs[lane]) != 16 or len(tweaks[lane]) != 16:
                    raise Error(
                        "IPcrypt-NDX batch requires 16-byte input and tweak"
                    )
                masks[lane] = _load_aesni(Span(tweaks[lane]), 0)
        _encrypt128_values_eight(second, masks)
        comptime for lane in range(8):
            states[lane] = (
                _load_aesni(Span(inputs[lane]), 16 if decrypt else 0)
                ^ masks[lane]
            )
        if decrypt:
            _decrypt128_values_eight(first, states)
        else:
            _encrypt128_values_eight(first, states)
        var outputs = List[List[UInt8]](capacity=8)
        comptime for lane in range(8):
            states[lane] ^= masks[lane]
            var output = _state_to_list(states[lane], 16 if decrypt else 32)
            if not decrypt:
                comptime for i in range(16):
                    output[i] = tweaks[lane][i]
            outputs.append(output^)
        return outputs^
    raise Error("unknown IPcrypt batch family")


def ipcrypt[
    key_origin: Origin, tweak_origin: Origin, input_origin: Origin
](
    algorithm: IpcryptAlgorithm,
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    tweak: Span[UInt8, tweak_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if algorithm == IpcryptAlgorithm.IPCRYPT:
        if len(key) != 16 or len(input) != 16:
            raise Error("IPcrypt requires 16-byte key and block")
        var expanded = _expand128_fixed(key)
        var output = List[UInt8](length=16, fill=0)
        if decrypt:
            _decrypt128_into(expanded, input, 0, Span(output), 0)
        else:
            _encrypt128_into(expanded, input, 0, Span(output), 0)
        return output^
    if algorithm == IpcryptAlgorithm.ND:
        return _nd(decrypt, key, tweak, input)
    if algorithm == IpcryptAlgorithm.NDX:
        return _ndx(decrypt, key, tweak, input)
    if algorithm == IpcryptAlgorithm.PFX:
        return _pfx(decrypt, key, input)
    raise Error("unknown IPcrypt family")
