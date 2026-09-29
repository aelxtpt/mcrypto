"""RFC 9106 Argon2i and Argon2id version 1.3 in pure Mojo."""
from .algorithm import Argon2Algorithm
from std.bit import rotate_bits_left

from ..hashes.blake2 import blake2b
from ..internal.bytes import load_le64


@always_inline("nodebug")
def _append_le32(mut output: List[UInt8], value: Int):
    var word = UInt32(value)
    for i in range(4):
        output.append(UInt8(word >> UInt32(8 * i)))


@always_inline("nodebug")
def _blamka4(
    x: SIMD[DType.uint64, 4], y: SIMD[DType.uint64, 4]
) -> SIMD[DType.uint64, 4]:
    var low_mask = SIMD[DType.uint64, 4](UInt64(0xFFFFFFFF))
    return x + y + SIMD[DType.uint64, 4](2) * (x & low_mask) * (y & low_mask)


@always_inline("nodebug")
def _g4(
    mut a: SIMD[DType.uint64, 4],
    mut b: SIMD[DType.uint64, 4],
    mut c: SIMD[DType.uint64, 4],
    mut d: SIMD[DType.uint64, 4],
):
    a = _blamka4(a, b)
    d = rotate_bits_left[32](d ^ a)
    c = _blamka4(c, d)
    b = rotate_bits_left[40](b ^ c)
    a = _blamka4(a, b)
    d = rotate_bits_left[48](d ^ a)
    c = _blamka4(c, d)
    b = rotate_bits_left[1](b ^ c)


@always_inline("nodebug")
def _round(mut values: List[UInt64], offset: Int, second_step: Int):
    var a = SIMD[DType.uint64, 4](0)
    var b = SIMD[DType.uint64, 4](0)
    var c = SIMD[DType.uint64, 4](0)
    var d = SIMD[DType.uint64, 4](0)
    if second_step == 1:
        var pointer = Span(values).unsafe_ptr()
        a = pointer.unsafe_load[width=4](offset)
        b = pointer.unsafe_load[width=4](offset + 4)
        c = pointer.unsafe_load[width=4](offset + 8)
        d = pointer.unsafe_load[width=4](offset + 12)
    else:
        var pointer = Span(values).unsafe_ptr()
        comptime for lane in range(4):
            a[lane] = pointer.unsafe_load(16 * (lane // 2) + offset + lane % 2)
            b[lane] = pointer.unsafe_load(
                16 * ((4 + lane) // 2) + offset + (4 + lane) % 2
            )
            c[lane] = pointer.unsafe_load(
                16 * ((8 + lane) // 2) + offset + (8 + lane) % 2
            )
            d[lane] = pointer.unsafe_load(
                16 * ((12 + lane) // 2) + offset + (12 + lane) % 2
            )
    _g4(a, b, c, d)
    var diagonal_b = b.shuffle[1, 2, 3, 0]()
    var diagonal_c = c.shuffle[2, 3, 0, 1]()
    var diagonal_d = d.shuffle[3, 0, 1, 2]()
    _g4(a, diagonal_b, diagonal_c, diagonal_d)
    b = diagonal_b.shuffle[3, 0, 1, 2]()
    c = diagonal_c.shuffle[2, 3, 0, 1]()
    d = diagonal_d.shuffle[1, 2, 3, 0]()
    if second_step == 1:
        var pointer = Span(values).unsafe_ptr()
        pointer.unsafe_store[width=4](offset, a)
        pointer.unsafe_store[width=4](offset + 4, b)
        pointer.unsafe_store[width=4](offset + 8, c)
        pointer.unsafe_store[width=4](offset + 12, d)
    else:
        var pointer = Span(values).unsafe_ptr()
        comptime for lane in range(4):
            pointer.unsafe_store(16 * (lane // 2) + offset + lane % 2, a[lane])
            pointer.unsafe_store(
                16 * ((4 + lane) // 2) + offset + (4 + lane) % 2,
                b[lane],
            )
            pointer.unsafe_store(
                16 * ((8 + lane) // 2) + offset + (8 + lane) % 2,
                c[lane],
            )
            pointer.unsafe_store(
                16 * ((12 + lane) // 2) + offset + (12 + lane) % 2,
                d[lane],
            )


def _fill_block(
    mut memory: List[UInt64],
    previous: Int,
    reference: Int,
    current: Int,
    with_xor: Bool,
    mut block: List[UInt64],
    mut original: List[UInt64],
):
    var memory_pointer = Span(memory).unsafe_ptr()
    var block_pointer = Span(block).unsafe_ptr()
    var original_pointer = Span(original).unsafe_ptr()
    var previous_offset = previous * 128
    var reference_offset = reference * 128
    var current_offset = current * 128
    for i in range(0, 128, 4):
        var mixed = memory_pointer.unsafe_load[width=4](
            previous_offset + i
        ) ^ memory_pointer.unsafe_load[width=4](reference_offset + i)
        block_pointer.unsafe_store[width=4](i, mixed)
        if with_xor:
            mixed ^= memory_pointer.unsafe_load[width=4](current_offset + i)
        original_pointer.unsafe_store[width=4](i, mixed)
    for i in range(8):
        _round(block, i * 16, 1)
    for i in range(8):
        _round(block, i * 2, 2)
    for i in range(0, 128, 4):
        memory_pointer.unsafe_store[width=4](
            current_offset + i,
            original_pointer.unsafe_load[width=4](i)
            ^ block_pointer.unsafe_load[width=4](i),
        )


def _hash_long[
    origin: Origin
](data: Span[UInt8, origin], output_bytes: Int) raises -> List[UInt8]:
    var prefixed = List[UInt8](capacity=len(data) + 4)
    _append_le32(prefixed, output_bytes)
    for byte in data:
        prefixed.append(byte)
    if output_bytes <= 64:
        return blake2b(Span(prefixed), output_bytes)
    var previous = blake2b(Span(prefixed), 64)
    var output = List[UInt8](capacity=output_bytes)
    for i in range(32):
        output.append(previous[i])
    var remaining = output_bytes - 32
    while remaining > 64:
        previous = blake2b(Span(previous), 64)
        for i in range(32):
            output.append(previous[i])
        remaining -= 32
    previous = blake2b(Span(previous), remaining)
    for byte in previous:
        output.append(byte)
    return output^


def _index_alpha(
    pass_number: Int,
    slice_number: Int,
    index: Int,
    pseudo: UInt32,
    same_lane: Bool,
    segment_length: Int,
    lane_length: Int,
) -> Int:
    var area: Int
    if pass_number == 0:
        if slice_number == 0:
            area = index - 1
        elif same_lane:
            area = slice_number * segment_length + index - 1
        else:
            area = slice_number * segment_length + (-1 if index == 0 else 0)
    else:
        if same_lane:
            area = lane_length - segment_length + index - 1
        else:
            area = lane_length - segment_length + (-1 if index == 0 else 0)
    var relative = UInt64(pseudo)
    relative = (relative * relative) >> 32
    relative = UInt64(area - 1) - ((UInt64(area) * relative) >> 32)
    var start = 0
    if pass_number != 0 and slice_number != 3:
        start = (slice_number + 1) * segment_length
    return (start + Int(relative)) % lane_length


def _fill_block_values(
    previous: List[UInt64],
    reference: List[UInt64],
    mut destination: List[UInt64],
    with_xor: Bool,
    mut block: List[UInt64],
    mut original: List[UInt64],
):
    var previous_pointer = Span(previous).unsafe_ptr()
    var reference_pointer = Span(reference).unsafe_ptr()
    var destination_pointer = Span(destination).unsafe_ptr()
    var block_pointer = Span(block).unsafe_ptr()
    var original_pointer = Span(original).unsafe_ptr()
    for i in range(0, 128, 4):
        var mixed = previous_pointer.unsafe_load[width=4](
            i
        ) ^ reference_pointer.unsafe_load[width=4](i)
        block_pointer.unsafe_store[width=4](i, mixed)
        if with_xor:
            mixed ^= destination_pointer.unsafe_load[width=4](i)
        original_pointer.unsafe_store[width=4](i, mixed)
    for i in range(8):
        _round(block, i * 16, 1)
    for i in range(8):
        _round(block, i * 2, 2)
    for i in range(0, 128, 4):
        destination_pointer.unsafe_store[width=4](
            i,
            original_pointer.unsafe_load[width=4](i)
            ^ block_pointer.unsafe_load[width=4](i),
        )


def derive[
    password_origin: Origin,
    salt_origin: Origin,
    secret_origin: Origin,
    ad_origin: Origin,
](
    algorithm: Argon2Algorithm,
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    secret: Span[UInt8, secret_origin],
    associated_data: Span[UInt8, ad_origin],
    output_bytes: Int = 32,
    passes: Int = 3,
    memory_kib: Int = 4096,
    lanes: Int = 1,
) raises -> List[UInt8]:
    if (
        algorithm != Argon2Algorithm.ARGON2I
        and algorithm != Argon2Algorithm.ARGON2ID
    ):
        raise Error("invalid Argon2 selector")
    # The selector type excludes unsupported Argon2 variants.
    if (
        output_bytes < 4
        or passes < 1
        or lanes < 1
        or memory_kib < 8 * lanes
        or len(salt) < 8
    ):
        raise Error("invalid Argon2 parameters")
    var kind_number = 1 if algorithm == Argon2Algorithm.ARGON2I else 2
    var segment_length = memory_kib // (lanes * 4)
    var memory_blocks = segment_length * lanes * 4
    var lane_length = segment_length * 4
    var initial = List[UInt8](
        capacity=40
        + len(password)
        + len(salt)
        + len(secret)
        + len(associated_data)
    )
    _append_le32(initial, lanes)
    _append_le32(initial, output_bytes)
    _append_le32(initial, memory_kib)
    _append_le32(initial, passes)
    _append_le32(initial, 0x13)
    _append_le32(initial, kind_number)
    _append_le32(initial, len(password))
    for byte in password:
        initial.append(byte)
    _append_le32(initial, len(salt))
    for byte in salt:
        initial.append(byte)
    _append_le32(initial, len(secret))
    for byte in secret:
        initial.append(byte)
    _append_le32(initial, len(associated_data))
    for byte in associated_data:
        initial.append(byte)
    var h0 = blake2b(Span(initial), 64)
    var memory = List[UInt64](length=memory_blocks * 128, fill=0)
    for lane in range(lanes):
        for block_number in range(2):
            var seed = h0.copy()
            _append_le32(seed, block_number)
            _append_le32(seed, lane)
            var block = _hash_long(Span(seed), 1024)
            var offset = (lane * lane_length + block_number) * 128
            for i in range(128):
                memory[offset + i] = load_le64(Span(block), i * 8)
    var work_block = List[UInt64](length=128, fill=0)
    var work_original = List[UInt64](length=128, fill=0)
    var zero_block = List[UInt64](length=128, fill=0)
    var address_input = List[UInt64](length=128, fill=0)
    var address_temporary = List[UInt64](length=128, fill=0)
    var address_block = List[UInt64](length=128, fill=0)
    for pass_number in range(passes):
        for slice_number in range(4):
            for lane in range(lanes):
                var independent = algorithm == Argon2Algorithm.ARGON2I or (
                    algorithm == Argon2Algorithm.ARGON2ID
                    and pass_number == 0
                    and slice_number < 2
                )
                if independent:
                    for i in range(128):
                        address_input[i] = 0
                    address_input[0] = UInt64(pass_number)
                    address_input[1] = UInt64(lane)
                    address_input[2] = UInt64(slice_number)
                    address_input[3] = UInt64(memory_blocks)
                    address_input[4] = UInt64(passes)
                    address_input[5] = UInt64(kind_number)
                var start_index = (
                    2 if pass_number == 0 and slice_number == 0 else 0
                )
                var current = (
                    lane * lane_length
                    + slice_number * segment_length
                    + start_index
                )
                var previous = (
                    current + lane_length - 1 if current % lane_length
                    == 0 else current - 1
                )
                for index in range(start_index, segment_length):
                    if current % lane_length == 1:
                        previous = current - 1
                    if independent and (
                        index == start_index or index % 128 == 0
                    ):
                        address_input[6] += 1
                        for j in range(128):
                            address_temporary[j] = 0
                            address_block[j] = 0
                        _fill_block_values(
                            zero_block,
                            address_input,
                            address_temporary,
                            True,
                            work_block,
                            work_original,
                        )
                        _fill_block_values(
                            zero_block,
                            address_temporary,
                            address_block,
                            True,
                            work_block,
                            work_original,
                        )
                    var pseudo = address_block[
                        index % 128
                    ] if independent else memory[previous * 128]
                    var reference_lane = Int(pseudo >> 32) % lanes
                    if pass_number == 0 and slice_number == 0:
                        reference_lane = lane
                    var reference_index = _index_alpha(
                        pass_number,
                        slice_number,
                        index,
                        UInt32(pseudo),
                        reference_lane == lane,
                        segment_length,
                        lane_length,
                    )
                    _fill_block(
                        memory,
                        previous,
                        reference_lane * lane_length + reference_index,
                        current,
                        pass_number != 0,
                        work_block,
                        work_original,
                    )
                    current += 1
                    previous += 1
    var final_bytes = List[UInt8](length=1024, fill=0)
    var last = (lane_length - 1) * 128
    for i in range(128):
        var word = memory[last + i]
        for lane in range(1, lanes):
            word ^= memory[(lane * lane_length + lane_length - 1) * 128 + i]
        for j in range(8):
            final_bytes[i * 8 + j] = UInt8(word >> UInt64(8 * j))
    return _hash_long(Span(final_bytes), output_bytes)


def argon2i[
    password_origin: Origin, salt_origin: Origin
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int = 32,
    passes: Int = 3,
    memory_kib: Int = 4096,
    lanes: Int = 1,
) raises -> List[UInt8]:
    var secret = List[UInt8]()
    var associated_data = List[UInt8]()
    return derive(
        Argon2Algorithm.ARGON2I,
        password,
        salt,
        Span(secret),
        Span(associated_data),
        output_bytes,
        passes,
        memory_kib,
        lanes,
    )


def argon2i_with_data[
    password_origin: Origin,
    salt_origin: Origin,
    secret_origin: Origin,
    ad_origin: Origin,
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    passes: Int,
    memory_kib: Int,
    lanes: Int,
    secret: Span[UInt8, secret_origin],
    associated_data: Span[UInt8, ad_origin],
) raises -> List[UInt8]:
    return derive(
        Argon2Algorithm.ARGON2I,
        password,
        salt,
        secret,
        associated_data,
        output_bytes,
        passes,
        memory_kib,
        lanes,
    )


def argon2id[
    password_origin: Origin, salt_origin: Origin
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int = 32,
    passes: Int = 3,
    memory_kib: Int = 4096,
    lanes: Int = 1,
) raises -> List[UInt8]:
    var secret = List[UInt8]()
    var associated_data = List[UInt8]()
    return derive(
        Argon2Algorithm.ARGON2ID,
        password,
        salt,
        Span(secret),
        Span(associated_data),
        output_bytes,
        passes,
        memory_kib,
        lanes,
    )


def argon2id_with_data[
    password_origin: Origin,
    salt_origin: Origin,
    secret_origin: Origin,
    ad_origin: Origin,
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    passes: Int,
    memory_kib: Int,
    lanes: Int,
    secret: Span[UInt8, secret_origin],
    associated_data: Span[UInt8, ad_origin],
) raises -> List[UInt8]:
    return derive(
        Argon2Algorithm.ARGON2ID,
        password,
        salt,
        secret,
        associated_data,
        output_bytes,
        passes,
        memory_kib,
        lanes,
    )
