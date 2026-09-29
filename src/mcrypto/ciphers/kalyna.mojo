"""Kalyna-128, Kalyna-256, and Kalyna-512 (DSTU 7624:2014)."""

from ..internal.bytes import load_le64, store_le64
from .algorithm import BlockCipherAlgorithm
from .kalyna_forward_tables import _FORWARD_TRANSFORM_TABLES
from .kalyna_inverse_sboxes import _INVERSE_SBOXES
from .kalyna_inverse_tables import _INVERSE_TRANSFORM_TABLES
from std.builtin.globals import global_constant


def prepare_transform_tables() -> Tuple[List[UInt64], List[UInt8]]:
    # Transforms read immutable tables directly from constant storage.
    return (List[UInt64](), List[UInt8]())


@always_inline("nodebug")
def _transform_tables_into[
    words: Int, inverse: Bool
](
    state: InlineArray[UInt64, 8],
    mut output: InlineArray[UInt64, 8],
    tables: List[UInt64],
    inverse_sboxes: List[UInt8],
):
    comptime if inverse:
        ref constant_tables = global_constant[_INVERSE_TRANSFORM_TABLES]()
        ref constant_sboxes = global_constant[_INVERSE_SBOXES]()
        _transform_inverse_static_into[words](
            state, output, constant_tables, constant_sboxes
        )
    else:
        ref constant_tables = global_constant[_FORWARD_TRANSFORM_TABLES]()
        _transform_forward_static_into[words](state, output, constant_tables)


@always_inline("nodebug")
def _transform_forward_static_into[
    words: Int
](
    state: InlineArray[UInt64, 8],
    mut output: InlineArray[UInt64, 8],
    tables: InlineArray[UInt64, 2048],
):
    var table_pointer = Span(tables).unsafe_ptr()
    comptime for destination in range(words):
        var result = UInt64(0)
        comptime for row in range(8):
            comptime source = (destination - row * words // 8) % words
            result ^= table_pointer.unsafe_load(
                row * 256 + Int(UInt8(state[source] >> UInt64(row * 8)))
            )
        output[destination] = result


@always_inline("nodebug")
def _transform_inverse_static_into[
    words: Int
](
    state: InlineArray[UInt64, 8],
    mut output: InlineArray[UInt64, 8],
    tables: InlineArray[UInt64, 2048],
    inverse_sboxes: InlineArray[UInt8, 1024],
):
    var table_pointer = Span(tables).unsafe_ptr()
    var inverse_pointer = Span(inverse_sboxes).unsafe_ptr()
    var mixed = InlineArray[UInt64, 8](fill=0)
    comptime for destination in range(words):
        var result = UInt64(0)
        comptime for column in range(8):
            result ^= table_pointer.unsafe_load(
                column * 256
                + Int(UInt8(state[destination] >> UInt64(column * 8)))
            )
        mixed[destination] = result
    comptime for source in range(words):
        var result = UInt64(0)
        comptime for row in range(8):
            comptime destination = (source + row * words // 8) % words
            result |= UInt64(
                inverse_pointer.unsafe_load(
                    (row % 4) * 256
                    + Int(UInt8(mixed[destination] >> UInt64(row * 8)))
                )
            ) << UInt64(row * 8)
        output[source] = result


@always_inline("nodebug")
def _process_prepared_tables_into[
    word_count: Int,
    round_count: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    decrypt: Bool,
    keys: List[UInt64],
    tables: List[UInt64],
    inverse_sboxes: List[UInt8],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    var state = InlineArray[UInt64, 8](fill=0)
    var scratch = InlineArray[UInt64, 8](fill=0)
    var key_pointer = keys.unsafe_ptr()
    comptime for i in range(word_count):
        state[i] = load_le64(block, i * 8)
    if decrypt:
        comptime for i in range(word_count):
            state[i] -= key_pointer.unsafe_load(round_count * word_count + i)
        _transform_tables_into[word_count, True](
            state, scratch, tables, inverse_sboxes
        )
        comptime for offset in range(round_count - 1):
            comptime round = round_count - 1 - offset
            comptime if offset % 2 == 0:
                comptime for i in range(word_count):
                    scratch[i] ^= key_pointer.unsafe_load(
                        round * word_count + i
                    )
                _transform_tables_into[word_count, True](
                    scratch, state, tables, inverse_sboxes
                )
            else:
                comptime for i in range(word_count):
                    state[i] ^= key_pointer.unsafe_load(round * word_count + i)
                _transform_tables_into[word_count, True](
                    state, scratch, tables, inverse_sboxes
                )
        comptime for i in range(word_count):
            state[i] -= key_pointer.unsafe_load(i)
    else:
        comptime for i in range(word_count):
            state[i] += key_pointer.unsafe_load(i)
        comptime for round in range(1, round_count):
            comptime if round % 2 == 1:
                _transform_tables_into[word_count, False](
                    state, scratch, tables, inverse_sboxes
                )
                comptime for i in range(word_count):
                    scratch[i] ^= key_pointer.unsafe_load(
                        round * word_count + i
                    )
            else:
                _transform_tables_into[word_count, False](
                    scratch, state, tables, inverse_sboxes
                )
                comptime for i in range(word_count):
                    state[i] ^= key_pointer.unsafe_load(round * word_count + i)
        _transform_tables_into[word_count, False](
            scratch, state, tables, inverse_sboxes
        )
        comptime for i in range(word_count):
            state[i] += key_pointer.unsafe_load(round_count * word_count + i)
    comptime for i in range(word_count):
        store_le64(state[i], output, output_offset + i * 8)


def process_prepared_tables_into[
    block_origin: Origin, output_origin: MutOrigin
](
    decrypt: Bool,
    keys: List[UInt64],
    rounds: Int,
    words: Int,
    tables: List[UInt64],
    inverse_sboxes: List[UInt8],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != words * 8:
        raise Error("Kalyna block size does not match its name")
    if output_offset < 0 or output_offset + words * 8 > len(output):
        raise Error("Kalyna output span is too short")
    if words == 2 and rounds == 10:
        _process_prepared_tables_into[2, 10](
            decrypt, keys, tables, inverse_sboxes, block, output, output_offset
        )
        return
    if words == 2 and rounds == 14:
        _process_prepared_tables_into[2, 14](
            decrypt, keys, tables, inverse_sboxes, block, output, output_offset
        )
        return
    if words == 4 and rounds == 14:
        _process_prepared_tables_into[4, 14](
            decrypt, keys, tables, inverse_sboxes, block, output, output_offset
        )
        return
    if words == 4 and rounds == 18:
        _process_prepared_tables_into[4, 18](
            decrypt, keys, tables, inverse_sboxes, block, output, output_offset
        )
        return
    if words == 8 and rounds == 18:
        _process_prepared_tables_into[8, 18](
            decrypt, keys, tables, inverse_sboxes, block, output, output_offset
        )
        return
    raise Error("invalid Kalyna round configuration")


def process_prepared_tables[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt64],
    rounds: Int,
    words: Int,
    tables: List[UInt64],
    inverse_sboxes: List[UInt8],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=words * 8, fill=0)
    process_prepared_tables_into(
        decrypt,
        keys,
        rounds,
        words,
        tables,
        inverse_sboxes,
        block,
        Span(output),
        0,
    )
    return output^


@always_inline("nodebug")
def _round_keys_fixed[
    words: Int, key_words: Int, rounds: Int, key_origin: Origin
](
    key: Span[UInt8, key_origin],
    tables: InlineArray[UInt64, 2048],
) raises -> List[UInt64]:
    var key_data = InlineArray[UInt64, 8](fill=0)
    comptime for i in range(key_words):
        key_data[i] = load_le64(key, i * 8)

    var state = InlineArray[UInt64, 8](fill=0)
    var scratch = InlineArray[UInt64, 8](fill=0)
    var seed = InlineArray[UInt64, 8](fill=0)
    var round_constants = InlineArray[UInt64, 8](fill=0)
    comptime for i in range(words):
        state[i] = key_data[i]
    state[0] += UInt64(key_words + words + 1)
    _transform_forward_static_into[words](state, scratch, tables)
    comptime if key_words == words:
        comptime for i in range(words):
            scratch[i] ^= key_data[i]
    else:
        comptime for i in range(words):
            scratch[i] ^= key_data[i + words]
    _transform_forward_static_into[words](scratch, state, tables)
    comptime for i in range(words):
        state[i] += key_data[i]
    _transform_forward_static_into[words](state, seed, tables)

    var keys = List[UInt64](length=(rounds + 1) * words, fill=0)
    var constant = UInt64(0x0001000100010001)
    comptime for round in range(0, rounds + 1, 2):
        comptime for i in range(words):
            round_constants[i] = seed[i] + constant
        comptime offset = (
            0 if key_words == words or (round // 2) % 2 == 0 else words
        )
        comptime rotation = (round // 2 if key_words == words else round // 4)
        comptime for i in range(words):
            state[i] = (
                key_data[(rotation + offset + i) % key_words]
                + round_constants[i]
            )
        _transform_forward_static_into[words](state, scratch, tables)
        comptime for i in range(words):
            scratch[i] ^= round_constants[i]
        _transform_forward_static_into[words](scratch, state, tables)
        comptime for i in range(words):
            state[i] += round_constants[i]
            keys[round * words + i] = state[i]

        comptime if round < rounds:
            comptime shift = 7 if words == 2 else (11 if words == 4 else 19)
            comptime word_shift = shift // 8
            comptime bit_shift = (shift % 8) * 8
            comptime for i in range(words):
                comptime low = (i + word_shift) % words
                comptime high = (low + 1) % words
                keys[(round + 1) * words + i] = state[low] >> UInt64(
                    bit_shift
                ) | state[high] << UInt64(64 - bit_shift)
        constant <<= 1
    return keys^


@always_inline("nodebug")
def _encrypt_static_into[
    word_count: Int,
    round_count: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt64],
    tables: InlineArray[UInt64, 2048],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    var state = InlineArray[UInt64, 8](fill=0)
    var scratch = InlineArray[UInt64, 8](fill=0)
    var key_pointer = keys.unsafe_ptr()
    comptime for i in range(word_count):
        state[i] = load_le64(block, i * 8) + key_pointer.unsafe_load(i)
    comptime for round in range(1, round_count):
        comptime if round % 2 == 1:
            _transform_forward_static_into[word_count](state, scratch, tables)
            comptime for i in range(word_count):
                scratch[i] ^= key_pointer.unsafe_load(round * word_count + i)
        else:
            _transform_forward_static_into[word_count](scratch, state, tables)
            comptime for i in range(word_count):
                state[i] ^= key_pointer.unsafe_load(round * word_count + i)
    _transform_forward_static_into[word_count](scratch, state, tables)
    comptime for i in range(word_count):
        state[i] += key_pointer.unsafe_load(round_count * word_count + i)
        store_le64(state[i], output, i * 8)


@always_inline("nodebug")
def _decrypt_static_into[
    word_count: Int,
    round_count: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[UInt64],
    tables: InlineArray[UInt64, 2048],
    inverse_sboxes: InlineArray[UInt8, 1024],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    var state = InlineArray[UInt64, 8](fill=0)
    var scratch = InlineArray[UInt64, 8](fill=0)
    var key_pointer = keys.unsafe_ptr()
    comptime for i in range(word_count):
        state[i] = load_le64(block, i * 8) - key_pointer.unsafe_load(
            round_count * word_count + i
        )
    _transform_inverse_static_into[word_count](
        state, scratch, tables, inverse_sboxes
    )
    comptime for offset in range(round_count - 1):
        comptime round = round_count - 1 - offset
        comptime if offset % 2 == 0:
            comptime for i in range(word_count):
                scratch[i] ^= key_pointer.unsafe_load(round * word_count + i)
            _transform_inverse_static_into[word_count](
                scratch, state, tables, inverse_sboxes
            )
        else:
            comptime for i in range(word_count):
                state[i] ^= key_pointer.unsafe_load(round * word_count + i)
            _transform_inverse_static_into[word_count](
                state, scratch, tables, inverse_sboxes
            )
    comptime for i in range(word_count):
        state[i] -= key_pointer.unsafe_load(i)
        store_le64(state[i], output, i * 8)


def _process_static[
    word_count: Int,
    round_count: Int,
    block_origin: Origin,
](
    decrypt: Bool,
    keys: List[UInt64],
    forward_tables: InlineArray[UInt64, 2048],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=word_count * 8, fill=0)
    if decrypt:
        var inverse_tables = materialize[_INVERSE_TRANSFORM_TABLES]()
        var inverse_sboxes = materialize[_INVERSE_SBOXES]()
        _decrypt_static_into[word_count, round_count](
            keys, inverse_tables, inverse_sboxes, block, Span(output)
        )
    else:
        _encrypt_static_into[word_count, round_count](
            keys, forward_tables, block, Span(output)
        )
    return output^


def _process_one_shot[
    word_count: Int,
    key_words: Int,
    round_count: Int,
    key_origin: Origin,
    block_origin: Origin,
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
    forward_tables: InlineArray[UInt64, 2048],
) raises -> List[UInt8]:
    var keys = _round_keys_fixed[word_count, key_words, round_count](
        key, forward_tables
    )
    return _process_static[word_count, round_count](
        decrypt, keys, forward_tables, block
    )


@always_inline("nodebug")
def _validated_words(
    algorithm: BlockCipherAlgorithm, key_length: Int
) raises -> Int:
    var words: Int
    if algorithm == BlockCipherAlgorithm.KALYNA128:
        words = 2
    elif algorithm == BlockCipherAlgorithm.KALYNA256:
        words = 4
    elif algorithm == BlockCipherAlgorithm.KALYNA512:
        words = 8
    else:
        raise Error("unknown Kalyna width")
    if (
        (words == 2 and key_length != 16 and key_length != 32)
        or (words == 4 and key_length != 32 and key_length != 64)
        or (words == 8 and key_length != 64)
    ):
        raise Error("invalid Kalyna key size")
    return words


def prepare[
    key_origin: Origin
](
    algorithm: BlockCipherAlgorithm, key: Span[UInt8, key_origin]
) raises -> Tuple[List[UInt64], Int, Int]:
    var words = _validated_words(algorithm, len(key))
    var tables = materialize[_FORWARD_TRANSFORM_TABLES]()
    if words == 2 and len(key) == 16:
        return (_round_keys_fixed[2, 2, 10](key, tables), 10, words)
    if words == 2:
        return (_round_keys_fixed[2, 4, 14](key, tables), 14, words)
    if words == 4 and len(key) == 32:
        return (_round_keys_fixed[4, 4, 14](key, tables), 14, words)
    if words == 4:
        return (_round_keys_fixed[4, 8, 18](key, tables), 18, words)
    return (_round_keys_fixed[8, 8, 18](key, tables), 18, words)


def process_prepared[
    block_origin: Origin
](
    decrypt: Bool,
    keys: List[UInt64],
    rounds: Int,
    words: Int,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != words * 8:
        raise Error("Kalyna block size does not match its name")
    var output = List[UInt8](length=words * 8, fill=0)
    if decrypt:
        var inverse_tables = materialize[_INVERSE_TRANSFORM_TABLES]()
        var inverse_sboxes = materialize[_INVERSE_SBOXES]()
        if words == 2 and rounds == 10:
            _decrypt_static_into[2, 10](
                keys, inverse_tables, inverse_sboxes, block, Span(output)
            )
        elif words == 2 and rounds == 14:
            _decrypt_static_into[2, 14](
                keys, inverse_tables, inverse_sboxes, block, Span(output)
            )
        elif words == 4 and rounds == 14:
            _decrypt_static_into[4, 14](
                keys, inverse_tables, inverse_sboxes, block, Span(output)
            )
        elif words == 4 and rounds == 18:
            _decrypt_static_into[4, 18](
                keys, inverse_tables, inverse_sboxes, block, Span(output)
            )
        elif words == 8 and rounds == 18:
            _decrypt_static_into[8, 18](
                keys, inverse_tables, inverse_sboxes, block, Span(output)
            )
        else:
            raise Error("invalid Kalyna round configuration")
    else:
        var forward_tables = materialize[_FORWARD_TRANSFORM_TABLES]()
        if words == 2 and rounds == 10:
            _encrypt_static_into[2, 10](
                keys, forward_tables, block, Span(output)
            )
        elif words == 2 and rounds == 14:
            _encrypt_static_into[2, 14](
                keys, forward_tables, block, Span(output)
            )
        elif words == 4 and rounds == 14:
            _encrypt_static_into[4, 14](
                keys, forward_tables, block, Span(output)
            )
        elif words == 4 and rounds == 18:
            _encrypt_static_into[4, 18](
                keys, forward_tables, block, Span(output)
            )
        elif words == 8 and rounds == 18:
            _encrypt_static_into[8, 18](
                keys, forward_tables, block, Span(output)
            )
        else:
            raise Error("invalid Kalyna round configuration")
    return output^


def process[
    key_origin: Origin, block_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var words = _validated_words(algorithm, len(key))
    if len(block) != words * 8:
        raise Error("Kalyna block size does not match its name")
    var tables = materialize[_FORWARD_TRANSFORM_TABLES]()
    if words == 2 and len(key) == 16:
        return _process_one_shot[2, 2, 10](decrypt, key, block, tables)
    if words == 2:
        return _process_one_shot[2, 4, 14](decrypt, key, block, tables)
    if words == 4 and len(key) == 32:
        return _process_one_shot[4, 4, 14](decrypt, key, block, tables)
    if words == 4:
        return _process_one_shot[4, 8, 18](decrypt, key, block, tables)
    return _process_one_shot[8, 8, 18](decrypt, key, block, tables)
