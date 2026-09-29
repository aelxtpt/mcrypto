"""Two-Track-MAC (TTMAC) in pure Mojo."""

from std.bit import rotate_bits_left
from std.collections import InlineArray
from std.memory import bitcast
from ..hashes.ripemd import (
    _message_order,
    _parallel_order,
    _parallel_rotations,
    _rotations,
    _round160,
)


def _transform(
    mut state: InlineArray[UInt32, 10],
    words: InlineArray[UInt32, 16],
    order: InlineArray[Int, 80],
    parallel_order: InlineArray[Int, 80],
    rotations: InlineArray[Int, 80],
    parallel_rotations: InlineArray[Int, 80],
    constants: InlineArray[UInt32, 5],
    parallel_constants: InlineArray[UInt32, 5],
    final_block: Bool,
):
    var track_a_offset = 5 if final_block else 0
    var track_b_offset = 0 if final_block else 5
    var track_a: InlineArray[UInt32, 5] = [
        state[track_a_offset],
        state[track_a_offset + 1],
        state[track_a_offset + 2],
        state[track_a_offset + 3],
        state[track_a_offset + 4],
    ]
    var track_b: InlineArray[UInt32, 5] = [
        state[track_b_offset],
        state[track_b_offset + 1],
        state[track_b_offset + 2],
        state[track_b_offset + 3],
        state[track_b_offset + 4],
    ]
    var initial_a = track_a.copy()
    var initial_b = track_b.copy()
    comptime for i in range(80):
        comptime group = i // 16
        _round160[group](
            track_a,
            words[order[i]],
            rotations[i],
            constants[group],
        )
        _round160[4 - group](
            track_b,
            words[parallel_order[i]],
            parallel_rotations[i],
            parallel_constants[group],
        )
    for i in range(5):
        track_a[i] -= initial_a[i]
        track_b[i] -= initial_b[i]
    if final_block:
        for i in range(5):
            state[track_b_offset + i] = track_b[i] - track_a[i]
            state[track_a_offset + i] = 0
    else:
        state[track_a_offset] = track_a[1] + track_a[4] - track_b[3]
        state[track_a_offset + 1] = track_a[2] - track_b[4]
        state[track_a_offset + 2] = track_a[3] - track_b[0]
        state[track_a_offset + 3] = track_a[4] - track_b[1]
        state[track_a_offset + 4] = track_a[0] - track_b[2]
        state[track_b_offset] = track_a[3] - track_b[4]
        state[track_b_offset + 1] = track_a[4] + track_a[2] - track_b[0]
        state[track_b_offset + 2] = track_a[0] - track_b[1]
        state[track_b_offset + 3] = track_a[1] - track_b[2]
        state[track_b_offset + 4] = track_a[2] - track_b[3]


@always_inline("nodebug")
def _f_four[
    group: Int
](
    x: SIMD[DType.uint32, 4],
    y: SIMD[DType.uint32, 4],
    z: SIMD[DType.uint32, 4],
) -> SIMD[DType.uint32, 4]:
    comptime if group == 0:
        return x ^ y ^ z
    elif group == 1:
        return (x & y) | ((~x) & z)
    elif group == 2:
        return (x | (~y)) ^ z
    elif group == 3:
        return (x & z) | (y & (~z))
    else:
        return x ^ (y | (~z))


@always_inline("nodebug")
def _rotl_four(
    value: SIMD[DType.uint32, 4], amount: Int
) -> SIMD[DType.uint32, 4]:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _round_four[
    group: Int
](
    mut registers: InlineArray[SIMD[DType.uint32, 4], 5],
    word: SIMD[DType.uint32, 4],
    rotation: Int,
    constant: UInt32,
):
    var temporary = (
        _rotl_four(
            registers[0]
            + _f_four[group](registers[1], registers[2], registers[3])
            + word
            + SIMD[DType.uint32, 4](constant),
            rotation,
        )
        + registers[4]
    )
    registers[0] = registers[4]
    registers[4] = registers[3]
    registers[3] = rotate_bits_left[10](registers[2])
    registers[2] = registers[1]
    registers[1] = temporary


@always_inline("nodebug")
def _transform_four(
    mut state: InlineArray[SIMD[DType.uint32, 4], 10],
    words: InlineArray[SIMD[DType.uint32, 4], 16],
    order: InlineArray[Int, 80],
    parallel_order: InlineArray[Int, 80],
    rotations: InlineArray[Int, 80],
    parallel_rotations: InlineArray[Int, 80],
    constants: InlineArray[UInt32, 5],
    parallel_constants: InlineArray[UInt32, 5],
    final_block: Bool,
):
    var track_a_offset = 5 if final_block else 0
    var track_b_offset = 0 if final_block else 5
    var track_a: InlineArray[SIMD[DType.uint32, 4], 5] = [
        state[track_a_offset],
        state[track_a_offset + 1],
        state[track_a_offset + 2],
        state[track_a_offset + 3],
        state[track_a_offset + 4],
    ]
    var track_b: InlineArray[SIMD[DType.uint32, 4], 5] = [
        state[track_b_offset],
        state[track_b_offset + 1],
        state[track_b_offset + 2],
        state[track_b_offset + 3],
        state[track_b_offset + 4],
    ]
    var initial_a = track_a.copy()
    var initial_b = track_b.copy()
    comptime for i in range(80):
        comptime group = i // 16
        _round_four[group](
            track_a,
            words[order[i]],
            rotations[i],
            constants[group],
        )
        _round_four[4 - group](
            track_b,
            words[parallel_order[i]],
            parallel_rotations[i],
            parallel_constants[group],
        )
    for i in range(5):
        track_a[i] -= initial_a[i]
        track_b[i] -= initial_b[i]
    if final_block:
        for i in range(5):
            state[track_b_offset + i] = track_b[i] - track_a[i]
            state[track_a_offset + i] = 0
    else:
        state[track_a_offset] = track_a[1] + track_a[4] - track_b[3]
        state[track_a_offset + 1] = track_a[2] - track_b[4]
        state[track_a_offset + 2] = track_a[3] - track_b[0]
        state[track_a_offset + 3] = track_a[4] - track_b[1]
        state[track_a_offset + 4] = track_a[0] - track_b[2]
        state[track_b_offset] = track_a[3] - track_b[4]
        state[track_b_offset + 1] = track_a[4] + track_a[2] - track_b[0]
        state[track_b_offset + 2] = track_a[0] - track_b[1]
        state[track_b_offset + 3] = track_a[1] - track_b[2]
        state[track_b_offset + 4] = track_a[2] - track_b[3]


def authenticate[
    key_origin: Origin, message_origin: Origin
](
    key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int = 20,
) raises -> List[UInt8]:
    """Authenticate a message with a 20-byte Two-Track-MAC key.

    The reference-defined tag sizes are 4, 8, 12, 16, and 20 bytes.
    """
    if len(key) != 20:
        raise Error("Two-Track-MAC key must be 20 bytes")
    if not (
        tag_bytes == 4
        or tag_bytes == 8
        or tag_bytes == 12
        or tag_bytes == 16
        or tag_bytes == 20
    ):
        raise Error("Two-Track-MAC tag must be 4, 8, 12, 16, or 20 bytes")

    var state = InlineArray[UInt32, 10](fill=0)
    for i in range(5):
        var offset = i * 4
        var key_word = (
            UInt32(key[offset])
            | (UInt32(key[offset + 1]) << 8)
            | (UInt32(key[offset + 2]) << 16)
            | (UInt32(key[offset + 3]) << 24)
        )
        state[i] = key_word
        state[i + 5] = key_word

    # Materialize the RIPEMD schedules once per operation rather than once per
    # message block.
    var order = _message_order()
    var parallel_order = _parallel_order()
    var rotations = _rotations()
    var parallel_rotations = _parallel_rotations()
    var constants: InlineArray[UInt32, 5] = [
        0,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xA953FD4E,
    ]
    var parallel_constants: InlineArray[UInt32, 5] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0x7A6D76E9,
        0,
    ]
    var message_pointer = message.unsafe_ptr()
    var offset = 0
    while offset + 64 <= len(message):
        var words = InlineArray[UInt32, 16](uninitialized=True)
        comptime for i in range(16):
            words[i] = bitcast[DType.uint32, 1](
                message_pointer.unsafe_load[width=4](offset + i * 4)
            )[0]
        _transform(
            state,
            words,
            order,
            parallel_order,
            rotations,
            parallel_rotations,
            constants,
            parallel_constants,
            False,
        )
        offset += 64

    # Build at most two fixed final blocks in place.  The previous path copied
    # the entire message into a padded heap allocation before compression.
    var words = InlineArray[UInt32, 16](fill=0)
    var remainder = len(message) - offset
    for i in range(remainder):
        words[i // 4] |= UInt32(message[offset + i]) << UInt32((i % 4) * 8)
    words[remainder // 4] |= UInt32(0x80) << UInt32((remainder % 4) * 8)
    var bit_length = UInt64(len(message)) * 8
    if remainder >= 56:
        _transform(
            state,
            words,
            order,
            parallel_order,
            rotations,
            parallel_rotations,
            constants,
            parallel_constants,
            False,
        )
        words = InlineArray[UInt32, 16](fill=0)
    words[14] = UInt32(bit_length)
    words[15] = UInt32(bit_length >> 32)
    _transform(
        state,
        words,
        order,
        parallel_order,
        rotations,
        parallel_rotations,
        constants,
        parallel_constants,
        True,
    )

    var original_2 = state[2]
    var original_3 = state[3]
    if tag_bytes == 16:
        state[3] += state[1] + state[4]
    if tag_bytes == 16 or tag_bytes == 12:
        state[2] += state[0] + original_3
    if tag_bytes == 16 or tag_bytes == 12 or tag_bytes == 8:
        state[0] += state[1] + original_3
        state[1] += state[4] + original_2
    elif tag_bytes == 4:
        state[0] += state[1] + state[2] + state[3] + state[4]

    var output = List[UInt8](capacity=tag_bytes)
    for i in range(tag_bytes):
        output.append(UInt8(state[i // 4] >> UInt32((i % 4) * 8)))
    return output^


def authenticate_four_into[
    key_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    key: Span[UInt8, key_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Authenticate four equal-length messages with four SIMD lanes."""
    if len(key) != 20:
        raise Error("Two-Track-MAC key must be 20 bytes")
    var tag_bytes = len(first_output)
    if (
        (
            tag_bytes != 4
            and tag_bytes != 8
            and tag_bytes != 12
            and tag_bytes != 16
            and tag_bytes != 20
        )
        or len(second_output) != tag_bytes
        or len(third_output) != tag_bytes
        or len(fourth_output) != tag_bytes
    ):
        raise Error("four-way Two-Track-MAC output span has invalid length")
    if (
        len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way Two-Track-MAC inputs must have equal lengths")
    var state = InlineArray[SIMD[DType.uint32, 4], 10](
        fill=SIMD[DType.uint32, 4](0)
    )
    comptime for i in range(5):
        var key_word = bitcast[DType.uint32, 1](
            key.unsafe_ptr().unsafe_load[width=4](i * 4)
        )[0]
        state[i] = SIMD[DType.uint32, 4](key_word)
        state[i + 5] = SIMD[DType.uint32, 4](key_word)
    var order = _message_order()
    var parallel_order = _parallel_order()
    var rotations = _rotations()
    var parallel_rotations = _parallel_rotations()
    var constants: InlineArray[UInt32, 5] = [
        0,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xA953FD4E,
    ]
    var parallel_constants: InlineArray[UInt32, 5] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0x7A6D76E9,
        0,
    ]
    var first_pointer = first.unsafe_ptr()
    var second_pointer = second.unsafe_ptr()
    var third_pointer = third.unsafe_ptr()
    var fourth_pointer = fourth.unsafe_ptr()
    var offset = 0
    while offset + 64 <= len(first):
        var words = InlineArray[SIMD[DType.uint32, 4], 16](
            fill=SIMD[DType.uint32, 4](0)
        )
        comptime for i in range(16):
            var word_offset = offset + i * 4
            words[i] = SIMD[DType.uint32, 4](
                bitcast[DType.uint32, 1](
                    first_pointer.unsafe_load[width=4](word_offset)
                )[0],
                bitcast[DType.uint32, 1](
                    second_pointer.unsafe_load[width=4](word_offset)
                )[0],
                bitcast[DType.uint32, 1](
                    third_pointer.unsafe_load[width=4](word_offset)
                )[0],
                bitcast[DType.uint32, 1](
                    fourth_pointer.unsafe_load[width=4](word_offset)
                )[0],
            )
        _transform_four(
            state,
            words,
            order,
            parallel_order,
            rotations,
            parallel_rotations,
            constants,
            parallel_constants,
            False,
        )
        offset += 64
    var words = InlineArray[SIMD[DType.uint32, 4], 16](
        fill=SIMD[DType.uint32, 4](0)
    )
    var remainder = len(first) - offset
    for i in range(remainder):
        var shift = UInt32((i % 4) * 8)
        words[i // 4][0] |= UInt32(first[offset + i]) << shift
        words[i // 4][1] |= UInt32(second[offset + i]) << shift
        words[i // 4][2] |= UInt32(third[offset + i]) << shift
        words[i // 4][3] |= UInt32(fourth[offset + i]) << shift
    words[remainder // 4] |= SIMD[DType.uint32, 4](
        UInt32(0x80) << UInt32((remainder % 4) * 8)
    )
    var bit_length = UInt64(len(first)) * 8
    if remainder >= 56:
        _transform_four(
            state,
            words,
            order,
            parallel_order,
            rotations,
            parallel_rotations,
            constants,
            parallel_constants,
            False,
        )
        words = InlineArray[SIMD[DType.uint32, 4], 16](
            fill=SIMD[DType.uint32, 4](0)
        )
    words[14] = SIMD[DType.uint32, 4](UInt32(bit_length))
    words[15] = SIMD[DType.uint32, 4](UInt32(bit_length >> 32))
    _transform_four(
        state,
        words,
        order,
        parallel_order,
        rotations,
        parallel_rotations,
        constants,
        parallel_constants,
        True,
    )
    var original_2 = state[2]
    var original_3 = state[3]
    if tag_bytes == 16:
        state[3] += state[1] + state[4]
    if tag_bytes == 16 or tag_bytes == 12:
        state[2] += state[0] + original_3
    if tag_bytes == 16 or tag_bytes == 12 or tag_bytes == 8:
        state[0] += state[1] + original_3
        state[1] += state[4] + original_2
    elif tag_bytes == 4:
        state[0] += state[1] + state[2] + state[3] + state[4]
    for i in range(tag_bytes):
        var lanes = state[i // 4] >> UInt32((i % 4) * 8)
        first_output[i] = UInt8(lanes[0])
        second_output[i] = UInt8(lanes[1])
        third_output[i] = UInt8(lanes[2])
        fourth_output[i] = UInt8(lanes[3])
