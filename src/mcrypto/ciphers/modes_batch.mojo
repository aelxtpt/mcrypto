"""Specialized four-way CBC helpers."""

from .algorithm import BlockCipherAlgorithm
from .aria import (
    prepare as aria_prepare,
    prepare_tables as aria_prepare_tables,
    process_four_tables_into as aria_process_four_into,
)
from .speck import (
    prepare32 as speck_prepare32,
    prepare64 as speck_prepare64,
    process_four64 as speck_process_four64,
    process_eight32 as speck_process_eight32,
)


def _process_aria_cbc_four_into[
    key_origin: Origin,
    iv_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Process four independent equal-length ARIA-CBC messages."""
    if len(iv) != 16:
        raise Error("ARIA-CBC IV must be 16 bytes")
    if (
        len(first) % 16 != 0
        or len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way ARIA-CBC inputs must be equal complete blocks")
    if (
        len(first_output) != len(first)
        or len(second_output) != len(first)
        or len(third_output) != len(first)
        or len(fourth_output) != len(first)
    ):
        raise Error("four-way ARIA-CBC output span has invalid length")
    var schedule = aria_prepare(key, not encrypt)
    var round_keys = schedule[0].copy()
    var rounds = schedule[1]
    var tables = aria_prepare_tables()
    var first_feedback = InlineArray[UInt8, 16](fill=0)
    var second_feedback = InlineArray[UInt8, 16](fill=0)
    var third_feedback = InlineArray[UInt8, 16](fill=0)
    var fourth_feedback = InlineArray[UInt8, 16](fill=0)
    var iv_value = iv.unsafe_ptr().unsafe_load[width=16](0)
    Span(first_feedback).unsafe_ptr().unsafe_store[width=16](0, iv_value)
    Span(second_feedback).unsafe_ptr().unsafe_store[width=16](0, iv_value)
    Span(third_feedback).unsafe_ptr().unsafe_store[width=16](0, iv_value)
    Span(fourth_feedback).unsafe_ptr().unsafe_store[width=16](0, iv_value)
    var blocks = InlineArray[UInt8, 64](fill=0)
    var transformed = InlineArray[UInt8, 64](fill=0)
    var blocks_pointer = Span(blocks).unsafe_ptr()
    var transformed_pointer = Span(transformed).unsafe_ptr()
    var first_pointer = first.unsafe_ptr()
    var second_pointer = second.unsafe_ptr()
    var third_pointer = third.unsafe_ptr()
    var fourth_pointer = fourth.unsafe_ptr()
    var first_output_pointer = first_output.unsafe_ptr()
    var second_output_pointer = second_output.unsafe_ptr()
    var third_output_pointer = third_output.unsafe_ptr()
    var fourth_output_pointer = fourth_output.unsafe_ptr()
    for offset in range(0, len(first), 16):
        blocks_pointer.unsafe_store[width=16](
            0, first_pointer.unsafe_load[width=16](offset)
        )
        blocks_pointer.unsafe_store[width=16](
            16, second_pointer.unsafe_load[width=16](offset)
        )
        blocks_pointer.unsafe_store[width=16](
            32, third_pointer.unsafe_load[width=16](offset)
        )
        blocks_pointer.unsafe_store[width=16](
            48, fourth_pointer.unsafe_load[width=16](offset)
        )
        if encrypt:
            blocks_pointer.unsafe_store[width=16](
                0,
                blocks_pointer.unsafe_load[width=16](0)
                ^ Span(first_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            blocks_pointer.unsafe_store[width=16](
                16,
                blocks_pointer.unsafe_load[width=16](16)
                ^ Span(second_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            blocks_pointer.unsafe_store[width=16](
                32,
                blocks_pointer.unsafe_load[width=16](32)
                ^ Span(third_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            blocks_pointer.unsafe_store[width=16](
                48,
                blocks_pointer.unsafe_load[width=16](48)
                ^ Span(fourth_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
        if encrypt:
            aria_process_four_into(
                round_keys,
                rounds,
                tables,
                Span(blocks),
                Span(transformed),
                0,
            )
        else:
            aria_process_four_into(
                round_keys,
                rounds,
                tables,
                Span(blocks),
                Span(transformed),
                0,
            )
        if encrypt:
            var first_value = transformed_pointer.unsafe_load[width=16](0)
            var second_value = transformed_pointer.unsafe_load[width=16](16)
            var third_value = transformed_pointer.unsafe_load[width=16](32)
            var fourth_value = transformed_pointer.unsafe_load[width=16](48)
            first_output_pointer.unsafe_store[width=16](offset, first_value)
            second_output_pointer.unsafe_store[width=16](offset, second_value)
            third_output_pointer.unsafe_store[width=16](offset, third_value)
            fourth_output_pointer.unsafe_store[width=16](offset, fourth_value)
            Span(first_feedback).unsafe_ptr().unsafe_store[width=16](
                0, first_value
            )
            Span(second_feedback).unsafe_ptr().unsafe_store[width=16](
                0, second_value
            )
            Span(third_feedback).unsafe_ptr().unsafe_store[width=16](
                0, third_value
            )
            Span(fourth_feedback).unsafe_ptr().unsafe_store[width=16](
                0, fourth_value
            )
        else:
            first_output_pointer.unsafe_store[width=16](
                offset,
                transformed_pointer.unsafe_load[width=16](0)
                ^ Span(first_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            second_output_pointer.unsafe_store[width=16](
                offset,
                transformed_pointer.unsafe_load[width=16](16)
                ^ Span(second_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            third_output_pointer.unsafe_store[width=16](
                offset,
                transformed_pointer.unsafe_load[width=16](32)
                ^ Span(third_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            fourth_output_pointer.unsafe_store[width=16](
                offset,
                transformed_pointer.unsafe_load[width=16](48)
                ^ Span(fourth_feedback).unsafe_ptr().unsafe_load[width=16](0),
            )
            Span(first_feedback).unsafe_ptr().unsafe_store[width=16](
                0, first_pointer.unsafe_load[width=16](offset)
            )
            Span(second_feedback).unsafe_ptr().unsafe_store[width=16](
                0, second_pointer.unsafe_load[width=16](offset)
            )
            Span(third_feedback).unsafe_ptr().unsafe_store[width=16](
                0, third_pointer.unsafe_load[width=16](offset)
            )
            Span(fourth_feedback).unsafe_ptr().unsafe_store[width=16](
                0, fourth_pointer.unsafe_load[width=16](offset)
            )


def _process_speck_cbc_four_into[
    key_origin: Origin,
    iv_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    cipher: BlockCipherAlgorithm,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Process four independent equal-length SPECK-CBC messages."""
    if (
        cipher != BlockCipherAlgorithm.SPECK64
        and cipher != BlockCipherAlgorithm.SPECK128
    ):
        raise Error("four-way SPECK-CBC has unknown cipher")
    var size = 8 if cipher == BlockCipherAlgorithm.SPECK64 else 16
    if len(iv) != size:
        raise Error("SPECK-CBC IV has invalid length")
    if (
        len(first) % size != 0
        or len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way SPECK-CBC inputs must be equal complete blocks")
    if (
        len(first_output) != len(first)
        or len(second_output) != len(first)
        or len(third_output) != len(first)
        or len(fourth_output) != len(first)
    ):
        raise Error("four-way SPECK-CBC output span has invalid length")
    var keys32 = List[UInt32]()
    var keys64 = List[UInt64]()
    if size == 8:
        keys32 = speck_prepare32(key)
    else:
        keys64 = speck_prepare64(key)
    var first_feedback = InlineArray[UInt8, 16](fill=0)
    var second_feedback = InlineArray[UInt8, 16](fill=0)
    var third_feedback = InlineArray[UInt8, 16](fill=0)
    var fourth_feedback = InlineArray[UInt8, 16](fill=0)
    for i in range(size):
        first_feedback[i] = iv[i]
        second_feedback[i] = iv[i]
        third_feedback[i] = iv[i]
        fourth_feedback[i] = iv[i]
    var blocks = InlineArray[UInt8, 64](fill=0)
    var transformed = InlineArray[UInt8, 64](fill=0)
    for offset in range(0, len(first), size):
        for i in range(size):
            blocks[i] = first[offset + i]
            blocks[size + i] = second[offset + i]
            blocks[2 * size + i] = third[offset + i]
            blocks[3 * size + i] = fourth[offset + i]
            if encrypt:
                blocks[i] ^= first_feedback[i]
                blocks[size + i] ^= second_feedback[i]
                blocks[2 * size + i] ^= third_feedback[i]
                blocks[3 * size + i] ^= fourth_feedback[i]
        if size == 8:
            speck_process_eight32(
                not encrypt,
                keys32,
                Span(blocks),
                Span(transformed),
                0,
            )
        else:
            speck_process_four64(
                not encrypt,
                keys64,
                Span(blocks),
                Span(transformed),
                0,
            )
        for i in range(size):
            if encrypt:
                first_output[offset + i] = transformed[i]
                second_output[offset + i] = transformed[size + i]
                third_output[offset + i] = transformed[2 * size + i]
                fourth_output[offset + i] = transformed[3 * size + i]
                first_feedback[i] = transformed[i]
                second_feedback[i] = transformed[size + i]
                third_feedback[i] = transformed[2 * size + i]
                fourth_feedback[i] = transformed[3 * size + i]
            else:
                first_output[offset + i] = transformed[i] ^ first_feedback[i]
                second_output[offset + i] = (
                    transformed[size + i] ^ second_feedback[i]
                )
                third_output[offset + i] = (
                    transformed[2 * size + i] ^ third_feedback[i]
                )
                fourth_output[offset + i] = (
                    transformed[3 * size + i] ^ fourth_feedback[i]
                )
                first_feedback[i] = first[offset + i]
                second_feedback[i] = second[offset + i]
                third_feedback[i] = third[offset + i]
                fourth_feedback[i] = fourth[offset + i]
