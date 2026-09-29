"""Keccak-f[1600], SHA-3, Keccak, and SHAKE in pure Mojo."""

from std.bit import rotate_bits_left
from std.collections import InlineArray
from std.memory import bitcast


comptime _ROUND_CONSTANTS: InlineArray[UInt64, 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
comptime _ROTATIONS: InlineArray[Int, 25] = [
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
]
comptime _PILN: InlineArray[Int, 24] = [
    10,
    7,
    11,
    17,
    18,
    3,
    5,
    16,
    8,
    21,
    24,
    4,
    15,
    23,
    19,
    13,
    12,
    2,
    20,
    14,
    22,
    9,
    6,
    1,
]
comptime _ROTC: InlineArray[Int, 24] = [
    1,
    3,
    6,
    10,
    15,
    21,
    28,
    36,
    45,
    55,
    2,
    14,
    27,
    41,
    56,
    8,
    25,
    43,
    62,
    18,
    39,
    61,
    20,
    44,
]


@always_inline("nodebug")
def _rot(value: UInt64, amount: Int) -> UInt64:
    if amount == 0:
        return value
    return (value << UInt64(amount)) | (value >> UInt64(64 - amount))


@always_inline("nodebug")
def _keccak_permute[first_round: Int](mut state: InlineArray[UInt64, 25]):
    var columns = InlineArray[UInt64, 5](uninitialized=True)
    comptime for round in range(first_round, 24):
        comptime for x in range(5):
            columns[x] = (
                state[x]
                ^ state[x + 5]
                ^ state[x + 10]
                ^ state[x + 15]
                ^ state[x + 20]
            )
        comptime for x in range(5):
            var theta = columns[(x + 4) % 5] ^ rotate_bits_left[1](
                columns[(x + 1) % 5]
            )
            comptime for y in range(5):
                state[x + 5 * y] ^= theta
        var carried = state[1]
        comptime for step in range(24):
            comptime destination = _PILN[step]
            var displaced = state[destination]
            state[destination] = rotate_bits_left[_ROTC[step]](carried)
            carried = displaced
        comptime for y in range(5):
            comptime for x in range(5):
                columns[x] = state[x + 5 * y]
            comptime for x in range(5):
                state[x + 5 * y] = columns[x] ^ (
                    (~columns[(x + 1) % 5]) & columns[(x + 2) % 5]
                )
        state[0] ^= materialize[_ROUND_CONSTANTS[round]]()


def keccak_f1600(mut state: InlineArray[UInt64, 25]):
    _keccak_permute[0](state)


def keccak_p1600_12(mut state: InlineArray[UInt64, 25]):
    _keccak_permute[12](state)


@always_inline("nodebug")
def _keccak_permute_four(mut state: InlineArray[SIMD[DType.uint64, 4], 25]):
    comptime for round in range(24):
        var c = InlineArray[SIMD[DType.uint64, 4], 5](uninitialized=True)
        var d = InlineArray[SIMD[DType.uint64, 4], 5](uninitialized=True)
        comptime for x in range(5):
            c[x] = (
                state[x]
                ^ state[x + 5]
                ^ state[x + 10]
                ^ state[x + 15]
                ^ state[x + 20]
            )
        comptime for x in range(5):
            d[x] = c[(x + 4) % 5] ^ rotate_bits_left[1](c[(x + 1) % 5])
        comptime for y in range(5):
            comptime for x in range(5):
                state[x + 5 * y] ^= d[x]
        var b = InlineArray[SIMD[DType.uint64, 4], 25](uninitialized=True)
        comptime for y in range(5):
            comptime for x in range(5):
                comptime source = x + 5 * y
                comptime destination = y + 5 * ((2 * x + 3 * y) % 5)
                b[destination] = rotate_bits_left[_ROTATIONS[source]](
                    state[source]
                )
        comptime for y in range(5):
            comptime for x in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= materialize[_ROUND_CONSTANTS[round]]()


def _shake128_four[
    origin: Origin
](
    seed: Span[UInt8, origin],
    suffixes: InlineArray[UInt16, 4],
    output_bytes: Int,
) raises -> Tuple[List[UInt8], List[UInt8], List[UInt8], List[UInt8]]:
    """Four-way SHAKE128 for equal 34-byte `seed || suffix` inputs."""
    if len(seed) != 32 or output_bytes <= 0:
        raise Error("four-way SHAKE128 requires a 32-byte seed and output")
    var state = InlineArray[SIMD[DType.uint64, 4], 25](
        fill=SIMD[DType.uint64, 4](0)
    )
    var seed_pointer = seed.unsafe_ptr()
    comptime for word in range(4):
        state[word] = SIMD[DType.uint64, 4](
            bitcast[DType.uint64, 1](
                seed_pointer.unsafe_load[width=8](word * 8)
            )[0]
        )
    state[4] = SIMD[DType.uint64, 4](
        UInt64(suffixes[0]) | (UInt64(0x1F) << 16),
        UInt64(suffixes[1]) | (UInt64(0x1F) << 16),
        UInt64(suffixes[2]) | (UInt64(0x1F) << 16),
        UInt64(suffixes[3]) | (UInt64(0x1F) << 16),
    )
    state[20] = SIMD[DType.uint64, 4](UInt64(0x8000000000000000))
    var first = List[UInt8](length=output_bytes, fill=0)
    var second = List[UInt8](length=output_bytes, fill=0)
    var third = List[UInt8](length=output_bytes, fill=0)
    var fourth = List[UInt8](length=output_bytes, fill=0)
    var first_pointer = Span(first).unsafe_ptr()
    var second_pointer = Span(second).unsafe_ptr()
    var third_pointer = Span(third).unsafe_ptr()
    var fourth_pointer = Span(fourth).unsafe_ptr()
    var produced = 0
    while produced < output_bytes:
        _keccak_permute_four(state)
        var take = min(168, output_bytes - produced)
        for offset in range(take):
            var lanes = state[offset // 8] >> UInt64((offset % 8) * 8)
            first_pointer.unsafe_store(produced + offset, UInt8(lanes[0]))
            second_pointer.unsafe_store(produced + offset, UInt8(lanes[1]))
            third_pointer.unsafe_store(produced + offset, UInt8(lanes[2]))
            fourth_pointer.unsafe_store(produced + offset, UInt8(lanes[3]))
        produced += take
    return (first^, second^, third^, fourth^)


struct KeccakSponge(Movable):
    var _state: InlineArray[UInt64, 25]
    var _rate: Int
    var _domain: UInt8
    var _position: Int
    var _reduced_rounds: Bool
    var _squeezing: Bool

    def __init__(
        out self, rate_bytes: Int, domain: UInt8, reduced_rounds: Bool = False
    ) raises:
        if rate_bytes <= 0 or rate_bytes >= 200 or rate_bytes % 8 != 0:
            raise Error("invalid Keccak rate")
        self._state = InlineArray[UInt64, 25](fill=0)
        self._rate = rate_bytes
        self._domain = domain
        self._position = 0
        self._squeezing = False
        self._reduced_rounds = reduced_rounds

    def __init__(out self, *, deinit move: Self):
        self._state = move._state^
        self._rate = move._rate
        self._domain = move._domain
        self._position = move._position
        self._squeezing = move._squeezing
        self._reduced_rounds = move._reduced_rounds

    @always_inline("nodebug")
    def _permute(mut self):
        if self._reduced_rounds:
            keccak_p1600_12(self._state)
        else:
            keccak_f1600(self._state)

    @always_inline("nodebug")
    def _finish_absorb_block(mut self):
        self._permute()
        self._position = 0

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        if self._squeezing:
            raise Error("cannot absorb after Keccak squeezing starts")
        var offset = 0
        while offset < len(data) and self._position != 0:
            var position = self._position
            self._state[position // 8] ^= UInt64(data[offset]) << UInt64(
                (position % 8) * 8
            )
            self._position = position + 1
            offset += 1
            if self._position == self._rate:
                self._finish_absorb_block()
        var data_pointer = data.unsafe_ptr()
        while offset + self._rate <= len(data):
            for word in range(self._rate // 8):
                self._state[word] ^= bitcast[DType.uint64, 1](
                    data_pointer.unsafe_load[width=8](offset + word * 8)
                )[0]
            self._permute()
            offset += self._rate
        while offset < len(data):
            var position = self._position
            self._state[position // 8] ^= UInt64(data[offset]) << UInt64(
                (position % 8) * 8
            )
            self._position = position + 1
            offset += 1

    def _start_squeezing(mut self):
        self._state[self._position // 8] ^= UInt64(self._domain) << UInt64(
            (self._position % 8) * 8
        )
        self._state[(self._rate - 1) // 8] ^= UInt64(0x80) << 56
        self._finish_absorb_block()
        self._squeezing = True

    def squeeze(mut self, output_bytes: Int) raises -> List[UInt8]:
        if output_bytes < 0:
            raise Error("Keccak output length cannot be negative")
        if not self._squeezing:
            self._start_squeezing()
        var output = List[UInt8](length=output_bytes, fill=0)
        var output_pointer = Span(output).unsafe_ptr()
        var produced = 0
        while produced < output_bytes:
            if self._position == self._rate:
                self._permute()
                self._position = 0
            var take = min(self._rate - self._position, output_bytes - produced)
            var copied = 0
            while copied < take and (self._position % 8) != 0:
                output_pointer.unsafe_store(
                    produced,
                    UInt8(
                        self._state[self._position // 8]
                        >> UInt64((self._position % 8) * 8)
                    ),
                )
                self._position += 1
                produced += 1
                copied += 1
            var words = (take - copied) // 8
            for word in range(words):
                output_pointer.unsafe_store[width=8](
                    produced + word * 8,
                    bitcast[DType.uint8, 8](
                        self._state[self._position // 8 + word]
                    ),
                )
            var word_bytes = words * 8
            self._position += word_bytes
            produced += word_bytes
            copied += word_bytes
            while copied < take:
                output_pointer.unsafe_store(
                    produced,
                    UInt8(
                        self._state[self._position // 8]
                        >> UInt64((self._position % 8) * 8)
                    ),
                )
                self._position += 1
                produced += 1
                copied += 1
        return output^


@always_inline("nodebug")
def _sponge_rounds[
    rate: Int, reduced_rounds: Bool, origin: Origin
](data: Span[UInt8, origin], output_bytes: Int, domain: UInt8) raises -> List[
    UInt8
]:
    var state = InlineArray[UInt64, 25](fill=0)
    var data_pointer = data.unsafe_ptr()
    var offset = 0
    var data_length = len(data)
    while offset + rate <= data_length:
        comptime for word in range(rate // 8):
            state[word] ^= bitcast[DType.uint64, 1](
                data_pointer.unsafe_load[width=8](offset + word * 8)
            )[0]
        comptime if reduced_rounds:
            keccak_p1600_12(state)
        else:
            keccak_f1600(state)
        offset += rate
    var remaining = data_length - offset
    for word in range(remaining // 8):
        state[word] ^= bitcast[DType.uint64, 1](
            data_pointer.unsafe_load[width=8](offset + word * 8)
        )[0]
    for byte in range((remaining // 8) * 8, remaining):
        state[byte // 8] ^= UInt64(
            data_pointer.unsafe_load(offset + byte)
        ) << UInt64((byte % 8) * 8)
    state[remaining // 8] ^= UInt64(domain) << UInt64((remaining % 8) * 8)
    state[(rate - 1) // 8] ^= UInt64(0x80) << 56
    comptime if reduced_rounds:
        keccak_p1600_12(state)
    else:
        keccak_f1600(state)
    var output = List[UInt8](length=output_bytes, fill=0)
    var output_pointer = Span(output).unsafe_ptr()
    var produced = 0
    while produced < output_bytes:
        var take = min(rate, output_bytes - produced)
        for word in range(take // 8):
            output_pointer.unsafe_store[width=8](
                produced + word * 8,
                bitcast[DType.uint8, 8](state[word]),
            )
        for byte in range((take // 8) * 8, take):
            output_pointer.unsafe_store(
                produced + byte,
                UInt8(state[byte // 8] >> UInt64((byte % 8) * 8)),
            )
        produced += take
        if produced < output_bytes:
            comptime if reduced_rounds:
                keccak_p1600_12(state)
            else:
                keccak_f1600(state)
    return output^


@always_inline("nodebug")
def _sponge_four_into[
    rate: Int,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    domain: UInt8,
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
):
    var state = InlineArray[SIMD[DType.uint64, 4], 25](
        fill=SIMD[DType.uint64, 4](0)
    )
    var first_pointer = first.unsafe_ptr()
    var second_pointer = second.unsafe_ptr()
    var third_pointer = third.unsafe_ptr()
    var fourth_pointer = fourth.unsafe_ptr()
    var offset = 0
    while offset + rate <= len(first):
        comptime for word in range(rate // 8):
            var word_offset = offset + word * 8
            state[word] ^= SIMD[DType.uint64, 4](
                bitcast[DType.uint64, 1](
                    first_pointer.unsafe_load[width=8](word_offset)
                )[0],
                bitcast[DType.uint64, 1](
                    second_pointer.unsafe_load[width=8](word_offset)
                )[0],
                bitcast[DType.uint64, 1](
                    third_pointer.unsafe_load[width=8](word_offset)
                )[0],
                bitcast[DType.uint64, 1](
                    fourth_pointer.unsafe_load[width=8](word_offset)
                )[0],
            )
        _keccak_permute_four(state)
        offset += rate
    var remaining = len(first) - offset
    for word in range(remaining // 8):
        var word_offset = offset + word * 8
        state[word] ^= SIMD[DType.uint64, 4](
            bitcast[DType.uint64, 1](
                first_pointer.unsafe_load[width=8](word_offset)
            )[0],
            bitcast[DType.uint64, 1](
                second_pointer.unsafe_load[width=8](word_offset)
            )[0],
            bitcast[DType.uint64, 1](
                third_pointer.unsafe_load[width=8](word_offset)
            )[0],
            bitcast[DType.uint64, 1](
                fourth_pointer.unsafe_load[width=8](word_offset)
            )[0],
        )
    for byte in range((remaining // 8) * 8, remaining):
        var byte_offset = offset + byte
        state[byte // 8] ^= SIMD[DType.uint64, 4](
            UInt64(first_pointer.unsafe_load(byte_offset)),
            UInt64(second_pointer.unsafe_load(byte_offset)),
            UInt64(third_pointer.unsafe_load(byte_offset)),
            UInt64(fourth_pointer.unsafe_load(byte_offset)),
        ) << UInt64((byte % 8) * 8)
    state[remaining // 8] ^= SIMD[DType.uint64, 4](UInt64(domain)) << UInt64(
        (remaining % 8) * 8
    )
    state[(rate - 1) // 8] ^= SIMD[DType.uint64, 4](UInt64(0x80) << 56)
    _keccak_permute_four(state)
    for byte in range(len(first_output)):
        var lanes = state[byte // 8] >> UInt64((byte % 8) * 8)
        first_output[byte] = UInt8(lanes[0])
        second_output[byte] = UInt8(lanes[1])
        third_output[byte] = UInt8(lanes[2])
        fourth_output[byte] = UInt8(lanes[3])


def sha3_four_into[
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    bits: Int,
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Hash four equal-length messages with four Keccak SIMD lanes."""
    if (
        len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way SHA-3 inputs must have equal lengths")
    if (
        len(first_output) != bits // 8
        or len(second_output) != bits // 8
        or len(third_output) != bits // 8
        or len(fourth_output) != bits // 8
    ):
        raise Error("four-way SHA-3 output span has invalid length")
    if bits == 224:
        _sponge_four_into[144](
            first,
            second,
            third,
            fourth,
            0x06,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    if bits == 256:
        _sponge_four_into[136](
            first,
            second,
            third,
            fourth,
            0x06,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    if bits == 384:
        _sponge_four_into[104](
            first,
            second,
            third,
            fourth,
            0x06,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    if bits == 512:
        _sponge_four_into[72](
            first,
            second,
            third,
            fourth,
            0x06,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    raise Error("SHA-3 size must be 224, 256, 384, or 512")


def keccak_four_into[
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    bits: Int,
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    """Hash four equal-length messages with four Keccak SIMD lanes."""
    if (
        len(second) != len(first)
        or len(third) != len(first)
        or len(fourth) != len(first)
    ):
        raise Error("four-way Keccak inputs must have equal lengths")
    if (
        len(first_output) != bits // 8
        or len(second_output) != bits // 8
        or len(third_output) != bits // 8
        or len(fourth_output) != bits // 8
    ):
        raise Error("four-way Keccak output span has invalid length")
    if bits == 224:
        _sponge_four_into[144](
            first,
            second,
            third,
            fourth,
            0x01,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    if bits == 256:
        _sponge_four_into[136](
            first,
            second,
            third,
            fourth,
            0x01,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    if bits == 384:
        _sponge_four_into[104](
            first,
            second,
            third,
            fourth,
            0x01,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    if bits == 512:
        _sponge_four_into[72](
            first,
            second,
            third,
            fourth,
            0x01,
            first_output,
            second_output,
            third_output,
            fourth_output,
        )
        return
    raise Error("Keccak size must be 224, 256, 384, or 512")


@always_inline("nodebug")
def _sponge[
    rate: Int, domain: UInt8, origin: Origin
](data: Span[UInt8, origin], output_bytes: Int) raises -> List[UInt8]:
    return _sponge_rounds[rate, False](data, output_bytes, domain)


def sha3[
    origin: Origin
](bits: Int, data: Span[UInt8, origin]) raises -> List[UInt8]:
    if bits == 224:
        return _sponge[144, 0x06](data, 28)
    if bits == 256:
        return _sponge[136, 0x06](data, 32)
    if bits == 384:
        return _sponge[104, 0x06](data, 48)
    if bits == 512:
        return _sponge[72, 0x06](data, 64)
    raise Error("SHA-3 size must be 224, 256, 384, or 512")


def keccak[
    origin: Origin
](bits: Int, data: Span[UInt8, origin]) raises -> List[UInt8]:
    if bits == 224:
        return _sponge[144, 0x01](data, 28)
    if bits == 256:
        return _sponge[136, 0x01](data, 32)
    if bits == 384:
        return _sponge[104, 0x01](data, 48)
    if bits == 512:
        return _sponge[72, 0x01](data, 64)
    raise Error("Keccak size must be 224, 256, 384, or 512")


def shake[
    origin: Origin
](bits: Int, data: Span[UInt8, origin], output_bytes: Int) raises -> List[
    UInt8
]:
    if output_bytes <= 0:
        raise Error("SHAKE output must be positive")
    if bits == 128:
        return _sponge[168, 0x1F](data, output_bytes)
    if bits == 256:
        return _sponge[136, 0x1F](data, output_bytes)
    raise Error("SHAKE size must be 128 or 256")
