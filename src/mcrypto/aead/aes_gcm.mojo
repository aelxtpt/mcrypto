"""FIPS SP 800-38D AES-GCM authenticated encryption in pure Mojo."""

from std.memory import bitcast
from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic


from ..ciphers.aes_block import (
    _aes_schedule_transform,
    _encrypt_aesni_prepared_eight,
    _encrypt_aesni_prepared_state,
    _encrypt_aesni_prepared_value,
    _prepare_aesni,
    _prepare_aesni128,
    encrypt_expanded,
    encrypt_expanded_into,
    expand_key,
)
from ..traits import constant_time_equal

comptime _HAS_ACCELERATED_AES_GCM = (
    CompilationTarget.is_x86()
    # LLVM's AArch64 +aes feature gates both AES and PMULL instructions.
    or (
        CompilationTarget._has_feature["aes"]() and CompilationTarget.has_neon()
    )
)

comptime _GHASH_REDUCTION: InlineArray[UInt16, 16] = [
    0x0000,
    0x1C20,
    0x3840,
    0x2460,
    0x7080,
    0x6CA0,
    0x48C0,
    0x54E0,
    0xE100,
    0xFD20,
    0xD940,
    0xC560,
    0x9180,
    0x8DA0,
    0xA9C0,
    0xB5E0,
]


@always_inline("nodebug")
def _reverse_byte_bits(
    value: SIMD[DType.uint8, 16],
) -> SIMD[DType.uint8, 16]:
    var output = ((value & SIMD[DType.uint8, 16](0x55)) << 1) | (
        (value >> 1) & SIMD[DType.uint8, 16](0x55)
    )
    output = ((output & SIMD[DType.uint8, 16](0x33)) << 2) | (
        (output >> 2) & SIMD[DType.uint8, 16](0x33)
    )
    return (output << 4) | (output >> 4)


@always_inline("nodebug")
def _carryless_multiply(
    left: SIMD[DType.uint64, 2],
    right: SIMD[DType.uint64, 2],
    immediate: UInt8,
) -> SIMD[DType.uint64, 2]:
    comptime if CompilationTarget.is_x86():
        return llvm_intrinsic[
            "llvm.x86.pclmulqdq",
            SIMD[DType.uint64, 2],
            has_side_effect=False,
        ](left, right, immediate)
    elif _HAS_ACCELERATED_AES_GCM:
        var left_index = 1 if (immediate & 1) != 0 else 0
        var right_index = 1 if (immediate & 0x10) != 0 else 0
        return bitcast[DType.uint64, 2](
            llvm_intrinsic[
                "llvm.aarch64.neon.pmull64",
                SIMD[DType.uint8, 16],
                has_side_effect=False,
            ](UInt64(left[left_index]), UInt64(right[right_index]))
        )
    else:
        var left_index = 1 if (immediate & 1) != 0 else 0
        var right_index = 1 if (immediate & 0x10) != 0 else 0
        var multiplicand = UInt64(left[left_index])
        var multiplier = UInt64(right[right_index])
        var low = UInt64(0)
        var high = UInt64(0)
        for bit in range(64):
            var shift = UInt64(bit)
            if (multiplier >> shift) & 1:
                low ^= multiplicand << shift
                if bit != 0:
                    high ^= multiplicand >> UInt64(64 - bit)
        var output = SIMD[DType.uint64, 2](0)
        output[0] = low
        output[1] = high
        return output


@always_inline("nodebug")
def _multiply_hardware_reversed(
    left: SIMD[DType.uint64, 2],
    right: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var low_product = _carryless_multiply(left, right, 0)
    var high_product = _carryless_multiply(left, right, 0x11)
    var left_cross = SIMD[DType.uint64, 2](UInt64(left[0]) ^ UInt64(left[1]))
    var right_cross = SIMD[DType.uint64, 2](UInt64(right[0]) ^ UInt64(right[1]))
    var cross_product = (
        _carryless_multiply(left_cross, right_cross, 0)
        ^ low_product
        ^ high_product
    )
    var low0 = UInt64(low_product[0])
    var low1 = UInt64(low_product[1]) ^ UInt64(cross_product[0])
    var high0 = UInt64(high_product[0]) ^ UInt64(cross_product[1])
    var high1 = UInt64(high_product[1])
    var result0 = low0 ^ high0 ^ (high0 << 1) ^ (high0 << 2) ^ (high0 << 7)
    var result1 = (
        low1
        ^ high1
        ^ (high1 << 1)
        ^ (high0 >> 63)
        ^ (high1 << 2)
        ^ (high0 >> 62)
        ^ (high1 << 7)
        ^ (high0 >> 57)
    )
    var overflow = (high1 >> 63) ^ (high1 >> 62) ^ (high1 >> 57)
    result0 ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7)
    var result = SIMD[DType.uint64, 2](0)
    result[0] = result0
    result[1] = result1
    return result


@always_inline("nodebug")
def _multiply_hardware(
    x: SIMD[DType.uint8, 16],
    h: SIMD[DType.uint8, 16],
) -> SIMD[DType.uint8, 16]:
    var left = bitcast[DType.uint64, 2](_reverse_byte_bits(x))
    var right = bitcast[DType.uint64, 2](_reverse_byte_bits(h))
    return _reverse_byte_bits(
        bitcast[DType.uint8, 16](_multiply_hardware_reversed(left, right))
    )


@always_inline("nodebug")
def _byte_swap32(value: UInt32) -> UInt32:
    return llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
        value
    )


@always_inline("nodebug")
def _aesni_expand256_even[
    rcon: Int
](
    left: SIMD[DType.uint64, 2],
    right: SIMD[DType.uint64, 2],
) -> SIMD[
    DType.uint64, 2
]:
    var words = bitcast[DType.uint32, 4](left)
    comptime if CompilationTarget.is_x86():
        var assist = bitcast[DType.uint32, 4](
            llvm_intrinsic[
                "llvm.x86.aesni.aeskeygenassist",
                SIMD[DType.uint64, 2],
                has_side_effect=False,
            ](right, UInt8(rcon))
        )
        words[0] ^= assist[3]
    else:
        words[0] ^= _aes_schedule_transform(right, UInt8(rcon), True)
    words[1] ^= words[0]
    words[2] ^= words[1]
    words[3] ^= words[2]
    return bitcast[DType.uint64, 2](words)


@always_inline("nodebug")
def _aesni_expand256_odd(
    left: SIMD[DType.uint64, 2],
    right: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var words = bitcast[DType.uint32, 4](right)
    comptime if CompilationTarget.is_x86():
        var assist = bitcast[DType.uint32, 4](
            llvm_intrinsic[
                "llvm.x86.aesni.aeskeygenassist",
                SIMD[DType.uint64, 2],
                has_side_effect=False,
            ](left, UInt8(0))
        )
        words[0] ^= assist[2]
    else:
        words[0] ^= _aes_schedule_transform(left, UInt8(0), False)
    words[1] ^= words[0]
    words[2] ^= words[1]
    words[3] ^= words[2]
    return bitcast[DType.uint64, 2](words)


def _prepare_aesni256[
    origin: Origin
](key: Span[UInt8, origin]) raises -> List[SIMD[DType.uint64, 2]]:
    if len(key) != 32:
        raise Error("AES-256 key must be 32 bytes")
    var keys = List[SIMD[DType.uint64, 2]](capacity=15)
    var even = bitcast[DType.uint64, 2](
        key.unsafe_ptr().unsafe_load[width=16](0)
    )
    var odd = bitcast[DType.uint64, 2](
        key.unsafe_ptr().unsafe_load[width=16](16)
    )
    keys.append(even)
    keys.append(odd)
    even = _aesni_expand256_even[0x01](even, odd)
    keys.append(even)
    odd = _aesni_expand256_odd(even, odd)
    keys.append(odd)
    even = _aesni_expand256_even[0x02](even, odd)
    keys.append(even)
    odd = _aesni_expand256_odd(even, odd)
    keys.append(odd)
    even = _aesni_expand256_even[0x04](even, odd)
    keys.append(even)
    odd = _aesni_expand256_odd(even, odd)
    keys.append(odd)
    even = _aesni_expand256_even[0x08](even, odd)
    keys.append(even)
    odd = _aesni_expand256_odd(even, odd)
    keys.append(odd)
    even = _aesni_expand256_even[0x10](even, odd)
    keys.append(even)
    odd = _aesni_expand256_odd(even, odd)
    keys.append(odd)
    even = _aesni_expand256_even[0x20](even, odd)
    keys.append(even)
    odd = _aesni_expand256_odd(even, odd)
    keys.append(odd)
    even = _aesni_expand256_even[0x40](even, odd)
    keys.append(even)
    return keys^


@always_inline("nodebug")
def _reduce_hardware_products(
    low_product: SIMD[DType.uint64, 2],
    high_product: SIMD[DType.uint64, 2],
    cross_product: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    var low0 = UInt64(low_product[0])
    var low1 = UInt64(low_product[1]) ^ UInt64(cross_product[0])
    var high0 = UInt64(high_product[0]) ^ UInt64(cross_product[1])
    var high1 = UInt64(high_product[1])
    var result0 = low0 ^ high0 ^ (high0 << 1) ^ (high0 << 2) ^ (high0 << 7)
    var result1 = (
        low1
        ^ high1
        ^ (high1 << 1)
        ^ (high0 >> 63)
        ^ (high1 << 2)
        ^ (high0 >> 62)
        ^ (high1 << 7)
        ^ (high0 >> 57)
    )
    var overflow = (high1 >> 63) ^ (high1 >> 62) ^ (high1 >> 57)
    result0 ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7)
    var result = SIMD[DType.uint64, 2](0)
    result[0] = result0
    result[1] = result1
    return result


@always_inline("nodebug")
def _multiply_hardware_four(
    left0: SIMD[DType.uint64, 2],
    right0: SIMD[DType.uint64, 2],
    left1: SIMD[DType.uint64, 2],
    right1: SIMD[DType.uint64, 2],
    left2: SIMD[DType.uint64, 2],
    right2: SIMD[DType.uint64, 2],
    left3: SIMD[DType.uint64, 2],
    right3: SIMD[DType.uint64, 2],
) -> SIMD[DType.uint64, 2]:
    # Reduction is linear: fold four products before reducing once.
    var low = (
        _carryless_multiply(left0, right0, 0)
        ^ _carryless_multiply(left1, right1, 0)
        ^ _carryless_multiply(left2, right2, 0)
        ^ _carryless_multiply(left3, right3, 0)
    )
    var high = (
        _carryless_multiply(left0, right0, 0x11)
        ^ _carryless_multiply(left1, right1, 0x11)
        ^ _carryless_multiply(left2, right2, 0x11)
        ^ _carryless_multiply(left3, right3, 0x11)
    )
    var cross = (
        _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left0[0]) ^ UInt64(left0[1])),
            SIMD[DType.uint64, 2](UInt64(right0[0]) ^ UInt64(right0[1])),
            0,
        )
        ^ _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left1[0]) ^ UInt64(left1[1])),
            SIMD[DType.uint64, 2](UInt64(right1[0]) ^ UInt64(right1[1])),
            0,
        )
        ^ _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left2[0]) ^ UInt64(left2[1])),
            SIMD[DType.uint64, 2](UInt64(right2[0]) ^ UInt64(right2[1])),
            0,
        )
        ^ _carryless_multiply(
            SIMD[DType.uint64, 2](UInt64(left3[0]) ^ UInt64(left3[1])),
            SIMD[DType.uint64, 2](UInt64(right3[0]) ^ UInt64(right3[1])),
            0,
        )
        ^ low
        ^ high
    )
    return _reduce_hardware_products(low, high, cross)


@always_inline("nodebug")
def _prepare_ghash_x86(
    h_bytes: SIMD[DType.uint8, 16],
) -> InlineArray[SIMD[DType.uint64, 2], 4]:
    var powers = InlineArray[SIMD[DType.uint64, 2], 4](
        fill=SIMD[DType.uint64, 2](0)
    )
    powers[0] = bitcast[DType.uint64, 2](_reverse_byte_bits(h_bytes))
    powers[1] = _multiply_hardware_reversed(powers[0], powers[0])
    powers[2] = _multiply_hardware_reversed(powers[1], powers[0])
    powers[3] = _multiply_hardware_reversed(powers[2], powers[0])
    return powers^


@always_inline("nodebug")
def _absorb_x86[
    data_origin: Origin
](
    state: SIMD[DType.uint64, 2],
    powers: InlineArray[SIMD[DType.uint64, 2], 4],
    data: Span[UInt8, data_origin],
) -> SIMD[DType.uint64, 2]:
    var result = state
    var pointer = data.unsafe_ptr()
    var offset = 0
    while offset + 64 <= len(data):
        var block0 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset))
        )
        var block1 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset + 16))
        )
        var block2 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset + 32))
        )
        var block3 = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset + 48))
        )
        result = _multiply_hardware_four(
            result ^ block0,
            powers[3],
            block1,
            powers[2],
            block2,
            powers[1],
            block3,
            powers[0],
        )
        offset += 64
    while offset + 16 <= len(data):
        var block = bitcast[DType.uint64, 2](
            _reverse_byte_bits(pointer.unsafe_load[width=16](offset))
        )
        result = _multiply_hardware_reversed(result ^ block, powers[0])
        offset += 16
    if offset < len(data):
        var tail = SIMD[DType.uint8, 16](0)
        for i in range(len(data) - offset):
            tail[i] = pointer.unsafe_load(offset + i)
        result = _multiply_hardware_reversed(
            result ^ bitcast[DType.uint64, 2](_reverse_byte_bits(tail)),
            powers[0],
        )
    return result


@always_inline("nodebug")
def _finish_ghash_x86(
    state: SIMD[DType.uint64, 2],
    powers: InlineArray[SIMD[DType.uint64, 2], 4],
    first_bytes: Int,
    second_bytes: Int,
) -> SIMD[DType.uint8, 16]:
    var lengths = SIMD[DType.uint8, 16](0)
    var first_bits = UInt64(first_bytes) * 8
    var second_bits = UInt64(second_bytes) * 8
    comptime for i in range(8):
        lengths[i] = UInt8(first_bits >> UInt64(56 - 8 * i))
        lengths[8 + i] = UInt8(second_bits >> UInt64(56 - 8 * i))
    var result = _multiply_hardware_reversed(
        state ^ bitcast[DType.uint64, 2](_reverse_byte_bits(lengths)),
        powers[0],
    )
    return _reverse_byte_bits(bitcast[DType.uint8, 16](result))


def _ghash_x86[
    aad_origin: Origin, data_origin: Origin
](
    powers: InlineArray[SIMD[DType.uint64, 2], 4],
    aad: Span[UInt8, aad_origin],
    data: Span[UInt8, data_origin],
) -> SIMD[DType.uint8, 16]:
    var state = _absorb_x86(SIMD[DType.uint64, 2](0), powers, aad)
    state = _absorb_x86(state, powers, data)
    return _finish_ghash_x86(state, powers, len(aad), len(data))


def _initial_counter_x86[
    nonce_origin: Origin
](
    nonce: Span[UInt8, nonce_origin],
    powers: InlineArray[SIMD[DType.uint64, 2], 4],
) -> SIMD[DType.uint64, 2]:
    if len(nonce) == 12:
        var initial = SIMD[DType.uint8, 16](0)
        comptime for i in range(12):
            initial[i] = nonce[i]
        initial[15] = 1
        return bitcast[DType.uint64, 2](initial)
    var state = _absorb_x86(SIMD[DType.uint64, 2](0), powers, nonce)
    return bitcast[DType.uint64, 2](
        _finish_ghash_x86(state, powers, 0, len(nonce))
    )


def _crypt_x86[
    input_origin: Origin
](
    keys: List[SIMD[DType.uint64, 2]],
    initial: SIMD[DType.uint64, 2],
    input: Span[UInt8, input_origin],
) -> List[UInt8]:
    var counters = InlineArray[UInt8, 128](uninitialized=True)
    var counters_pointer = Span(counters).unsafe_ptr()
    var counter_words = bitcast[DType.uint32, 4](initial)
    var counter = _byte_swap32(UInt32(counter_words[3]))
    var output = List[UInt8](length=len(input), fill=0)
    var output_span = Span(output)
    var output_pointer = output_span.unsafe_ptr()
    var input_pointer = input.unsafe_ptr()
    var offset = 0
    while offset + 128 <= len(input):
        comptime for block in range(8):
            counter += 1
            counter_words[3] = _byte_swap32(counter)
            counters_pointer.unsafe_store[width=16](
                block * 16, bitcast[DType.uint8, 16](counter_words)
            )
        _encrypt_aesni_prepared_eight(
            keys,
            Span(counters),
            0,
            input,
            offset,
            output_span,
            offset,
        )
        offset += 128
    while offset + 16 <= len(input):
        counter += 1
        counter_words[3] = _byte_swap32(counter)
        var stream = bitcast[DType.uint8, 16](
            _encrypt_aesni_prepared_value(
                keys, bitcast[DType.uint64, 2](counter_words)
            )
        )
        output_pointer.unsafe_store[width=16](
            offset, stream ^ input_pointer.unsafe_load[width=16](offset)
        )
        offset += 16
    if offset < len(input):
        counter += 1
        counter_words[3] = _byte_swap32(counter)
        var stream = bitcast[DType.uint8, 16](
            _encrypt_aesni_prepared_value(
                keys, bitcast[DType.uint64, 2](counter_words)
            )
        )
        for i in range(len(input) - offset):
            output_pointer.unsafe_store(
                offset + i, input_pointer.unsafe_load(offset + i) ^ stream[i]
            )
    return output^


def _tag_value_x86[
    aad_origin: Origin, cipher_origin: Origin
](
    keys: List[SIMD[DType.uint64, 2]],
    initial: SIMD[DType.uint64, 2],
    powers: InlineArray[SIMD[DType.uint64, 2], 4],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
) -> SIMD[DType.uint8, 16]:
    var mask = bitcast[DType.uint8, 16](
        _encrypt_aesni_prepared_value(keys, initial)
    )
    return mask ^ _ghash_x86(powers, aad, ciphertext)


@always_inline("nodebug")
def _constant_time_tag_equal_x86[
    tag_origin: Origin
](expected: SIMD[DType.uint8, 16], tag: Span[UInt8, tag_origin]) -> Bool:
    var difference: UInt8 = 0
    for i in range(len(tag)):
        difference |= expected[i] ^ tag[i]
    return difference == 0


def _validate[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    tag_bytes: Int,
) raises:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("AES-GCM key must be 16, 24, or 32 bytes")
    if len(nonce) == 0:
        raise Error("AES-GCM nonce must not be empty")
    if tag_bytes < 12 or tag_bytes > 16:
        raise Error("AES-GCM tag must be 12..16 bytes")


def _shift_one(mut value: InlineArray[UInt8, 16]):
    var reduce = value[15] & 1
    var carry = UInt8(0)
    for i in range(16):
        var next_carry = value[i] & 1
        value[i] = (value[i] >> 1) | (carry << 7)
        carry = next_carry
    value[0] ^= UInt8(0xE1 if reduce else 0)


def _ghash_table[origin: Origin](h: Span[UInt8, origin]) -> List[UInt8]:
    var empty = InlineArray[UInt8, 16](fill=0)
    var basis = InlineArray[InlineArray[UInt8, 16], 4](fill=empty)
    for i in range(16):
        basis[0][i] = h[i]
    for bit in range(1, 4):
        basis[bit] = basis[bit - 1].copy()
        _shift_one(basis[bit])
    var table = List[UInt8](length=256, fill=0)
    for nibble in range(16):
        for bit in range(4):
            var mask = UInt8(0) - UInt8((nibble >> (3 - bit)) & 1)
            for i in range(16):
                table[nibble * 16 + i] ^= basis[bit][i] & mask
    return table^


def _prepare_ghash[origin: Origin](h: Span[UInt8, origin]) -> List[UInt8]:
    comptime if CompilationTarget.is_x86():
        # Keep H at the portable table offset and precompute the powers used by
        # the four-block hardware fold once per operation.
        var material = List[UInt8](length=192, fill=0)
        var material_pointer = Span(material).unsafe_ptr()
        material_pointer.unsafe_store[width=16](
            128, h.unsafe_ptr().unsafe_load[width=16](0)
        )
        var reversed_h = bitcast[DType.uint64, 2](
            _reverse_byte_bits(h.unsafe_ptr().unsafe_load[width=16](0))
        )
        var h2 = _multiply_hardware_reversed(reversed_h, reversed_h)
        var h3 = _multiply_hardware_reversed(h2, reversed_h)
        var h4 = _multiply_hardware_reversed(h3, reversed_h)
        material_pointer.unsafe_store[width=16](
            144, bitcast[DType.uint8, 16](h2)
        )
        material_pointer.unsafe_store[width=16](
            160, bitcast[DType.uint8, 16](h3)
        )
        material_pointer.unsafe_store[width=16](
            176, bitcast[DType.uint8, 16](h4)
        )
        return material^
    return _ghash_table(h)


def _shift_four(mut value: List[UInt8]):
    var low = Int(value[15] & 15)
    for offset in range(15):
        var i = 15 - offset
        value[i] = (value[i] >> 4) | (value[i - 1] << 4)
    value[0] >>= 4
    var reduction = materialize[_GHASH_REDUCTION]()[low]
    value[0] ^= UInt8(reduction >> 8)
    value[1] ^= UInt8(reduction)


def _multiply_into[
    origin: Origin
](x: Span[UInt8, origin], table: List[UInt8], mut product: List[UInt8],):
    """Multiply by H using a constant 4-bit table and Horner reduction."""
    for i in range(16):
        product[i] = 0
    for offset in range(32):
        var position = 31 - offset
        if offset != 0:
            _shift_four(product)
        var byte = x[position >> 1]
        var nibble = Int(byte >> 4) if (position & 1) == 0 else Int(byte & 15)
        for i in range(16):
            product[i] ^= table[nibble * 16 + i]


def _absorb_block[
    block_origin: Origin
](
    mut state: List[UInt8],
    table: List[UInt8],
    block: Span[UInt8, block_origin],
    mut product: List[UInt8],
):
    comptime if CompilationTarget.is_x86():
        var state_pointer = Span(state).unsafe_ptr()
        var result = _multiply_hardware(
            state_pointer.unsafe_load[width=16](0)
            ^ block.unsafe_ptr().unsafe_load[width=16](0),
            Span(table).unsafe_ptr().unsafe_load[width=16](128),
        )
        state_pointer.unsafe_store[width=16](0, result)
        return
    for i in range(16):
        state[i] ^= block[i]
    _multiply_into(Span(state), table, product)
    Span(state).unsafe_ptr().unsafe_store[width=16](
        0, Span(product).unsafe_ptr().unsafe_load[width=16](0)
    )


def _absorb[
    data_origin: Origin
](
    mut state: List[UInt8],
    table: List[UInt8],
    data: Span[UInt8, data_origin],
    mut product: List[UInt8],
):
    comptime if CompilationTarget.is_x86():
        var state_pointer = Span(state).unsafe_ptr()
        var state_value = bitcast[DType.uint64, 2](
            _reverse_byte_bits(state_pointer.unsafe_load[width=16](0))
        )
        var h = bitcast[DType.uint64, 2](
            _reverse_byte_bits(
                Span(table).unsafe_ptr().unsafe_load[width=16](128)
            )
        )
        var table_pointer = Span(table).unsafe_ptr()
        var h2 = bitcast[DType.uint64, 2](
            table_pointer.unsafe_load[width=16](144)
        )
        var h3 = bitcast[DType.uint64, 2](
            table_pointer.unsafe_load[width=16](160)
        )
        var h4 = bitcast[DType.uint64, 2](
            table_pointer.unsafe_load[width=16](176)
        )
        var data_pointer = data.unsafe_ptr()
        var offset = 0
        while offset + 64 <= len(data):
            var block0 = bitcast[DType.uint64, 2](
                _reverse_byte_bits(data_pointer.unsafe_load[width=16](offset))
            )
            var block1 = bitcast[DType.uint64, 2](
                _reverse_byte_bits(
                    data_pointer.unsafe_load[width=16](offset + 16)
                )
            )
            var block2 = bitcast[DType.uint64, 2](
                _reverse_byte_bits(
                    data_pointer.unsafe_load[width=16](offset + 32)
                )
            )
            var block3 = bitcast[DType.uint64, 2](
                _reverse_byte_bits(
                    data_pointer.unsafe_load[width=16](offset + 48)
                )
            )
            state_value = _multiply_hardware_four(
                state_value ^ block0,
                h4,
                block1,
                h3,
                block2,
                h2,
                block3,
                h,
            )
            offset += 64
        while offset + 16 <= len(data):
            var full_block = bitcast[DType.uint64, 2](
                _reverse_byte_bits(data_pointer.unsafe_load[width=16](offset))
            )
            state_value = _multiply_hardware_reversed(
                state_value ^ full_block, h
            )
            offset += 16
        if offset < len(data):
            var bytes = SIMD[DType.uint8, 16](0)
            for i in range(len(data) - offset):
                bytes[i] = data_pointer.unsafe_load(offset + i)
            var tail_block = bitcast[DType.uint64, 2](_reverse_byte_bits(bytes))
            state_value = _multiply_hardware_reversed(
                state_value ^ tail_block, h
            )
        state_pointer.unsafe_store[width=16](
            0,
            _reverse_byte_bits(bitcast[DType.uint8, 16](state_value)),
        )
        return
    var portable_block = List[UInt8](length=16, fill=0)
    for offset in range(0, len(data), 16):
        var count = min(16, len(data) - offset)
        for i in range(count):
            portable_block[i] = data[offset + i]
        for i in range(count, 16):
            portable_block[i] = 0
        _absorb_block(state, table, Span(portable_block), product)


def _store_be64(mut block: List[UInt8], offset: Int, value: UInt64):
    for i in range(8):
        block[offset + i] = UInt8(value >> UInt64(56 - 8 * i))


def _ghash[
    aad_origin: Origin, data_origin: Origin
](
    table: List[UInt8],
    aad: Span[UInt8, aad_origin],
    data: Span[UInt8, data_origin],
) -> List[UInt8]:
    var state = List[UInt8](length=16, fill=0)
    var product = List[UInt8](length=16, fill=0)
    _absorb(state, table, aad, product)
    _absorb(state, table, data, product)
    var lengths = List[UInt8](length=16, fill=0)
    _store_be64(lengths, 0, UInt64(len(aad)) * 8)
    _store_be64(lengths, 8, UInt64(len(data)) * 8)
    _absorb_block(state, table, Span(lengths), product)
    return state^


def _initial_counter[
    nonce_origin: Origin
](nonce: Span[UInt8, nonce_origin], table: List[UInt8],) -> List[UInt8]:
    if len(nonce) == 12:
        var counter = List[UInt8](capacity=16)
        for byte in nonce:
            counter.append(byte)
        counter.append(0)
        counter.append(0)
        counter.append(0)
        counter.append(1)
        return counter^
    var empty = List[UInt8]()
    return _ghash(table, Span(empty), nonce)


def _encrypt_prepared[
    schedule_origin: Origin, block_origin: Origin
](
    schedule: Span[UInt8, schedule_origin],
    keys: List[SIMD[DType.uint64, 2]],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    comptime if CompilationTarget.is_x86():
        var output = List[UInt8](length=16, fill=0)
        Span(output).unsafe_ptr().unsafe_store[width=16](
            0,
            bitcast[DType.uint8, 16](
                _encrypt_aesni_prepared_state(keys, block, 0)
            ),
        )
        return output^
    return encrypt_expanded(schedule, block)


def _increment(mut counter: List[UInt8]):
    for offset in range(4):
        var i = 15 - offset
        counter[i] += 1
        if counter[i] != 0:
            break


def _crypt[
    schedule_origin: Origin, input_origin: Origin
](
    schedule: Span[UInt8, schedule_origin],
    keys: List[SIMD[DType.uint64, 2]],
    initial: List[UInt8],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    comptime if CompilationTarget.is_x86():
        var counters = List[UInt8](length=128, fill=0)
        var counters_pointer = Span(counters).unsafe_ptr()
        var counter_words = bitcast[DType.uint32, 4](
            Span(initial).unsafe_ptr().unsafe_load[width=16](0)
        )
        var counter = _byte_swap32(UInt32(counter_words[3]))
        var output = List[UInt8](length=len(input), fill=0)
        var output_span = Span(output)
        var output_pointer = output_span.unsafe_ptr()
        var input_pointer = input.unsafe_ptr()
        var offset = 0
        while offset + 128 <= len(input):
            comptime for block in range(8):
                counter += 1
                counter_words[3] = _byte_swap32(counter)
                counters_pointer.unsafe_store[width=16](
                    block * 16,
                    bitcast[DType.uint8, 16](counter_words),
                )
            _encrypt_aesni_prepared_eight(
                keys,
                Span(counters),
                0,
                input,
                offset,
                output_span,
                offset,
            )
            offset += 128
        while offset < len(input):
            counter += 1
            counter_words[3] = _byte_swap32(counter)
            counters_pointer.unsafe_store[width=16](
                0, bitcast[DType.uint8, 16](counter_words)
            )
            var stream = bitcast[DType.uint8, 16](
                _encrypt_aesni_prepared_state(keys, Span(counters), 0)
            )
            var count = min(16, len(input) - offset)
            for i in range(count):
                output_pointer.unsafe_store(
                    offset + i,
                    input_pointer.unsafe_load(offset + i) ^ stream[i],
                )
            offset += 16
        return output^
    var counter = initial.copy()
    var output = List[UInt8](length=len(input), fill=0)
    var stream = List[UInt8](length=16, fill=0)
    for offset in range(0, len(input), 16):
        _increment(counter)
        encrypt_expanded_into(schedule, Span(counter), Span(stream))
        for i in range(min(16, len(input) - offset)):
            output[offset + i] = input[offset + i] ^ stream[i]
    return output^


def _tag[
    schedule_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
](
    schedule: Span[UInt8, schedule_origin],
    keys: List[SIMD[DType.uint64, 2]],
    initial: List[UInt8],
    table: List[UInt8],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag_bytes: Int,
) raises -> List[UInt8]:
    var mask = _encrypt_prepared(schedule, keys, Span(initial))
    var hash = _ghash(table, aad, ciphertext)
    var tag = List[UInt8](capacity=tag_bytes)
    for i in range(tag_bytes):
        tag.append(mask[i] ^ hash[i])
    return tag^


def encrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int = 16,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    _validate(key, nonce, tag_bytes)
    var schedule = List[UInt8]()
    var keys = List[SIMD[DType.uint64, 2]]()
    comptime if CompilationTarget.is_x86():
        if len(key) == 16:
            keys = _prepare_aesni128(key)
        elif len(key) == 32:
            keys = _prepare_aesni256(key)
        else:
            schedule = expand_key(key)
            keys = _prepare_aesni(Span(schedule))
    elif _HAS_ACCELERATED_AES_GCM:
        schedule = expand_key(key)
        keys = _prepare_aesni(Span(schedule))
    else:
        schedule = expand_key(key)
    comptime if _HAS_ACCELERATED_AES_GCM:
        var h_value = _encrypt_aesni_prepared_value(
            keys, SIMD[DType.uint64, 2](0)
        )
        var powers = _prepare_ghash_x86(bitcast[DType.uint8, 16](h_value))
        var initial = _initial_counter_x86(nonce, powers)
        var ciphertext = _crypt_x86(keys, initial, message)
        var full_tag = _tag_value_x86(
            keys, initial, powers, aad, Span(ciphertext)
        )
        var tag = List[UInt8](capacity=tag_bytes)
        for i in range(tag_bytes):
            tag.append(full_tag[i])
        return (ciphertext^, tag^)
    else:
        var zero = List[UInt8](length=16, fill=0)
        var h = _encrypt_prepared(Span(schedule), keys, Span(zero))
        var table = _prepare_ghash(Span(h))
        var initial = _initial_counter(nonce, table)
        var ciphertext = _crypt(Span(schedule), keys, initial, message)
        var tag = _tag(
            Span(schedule),
            keys,
            initial^,
            table,
            aad,
            Span(ciphertext),
            tag_bytes,
        )
        return (ciphertext^, tag^)


def decrypt[
    key_origin: Origin,
    nonce_origin: Origin,
    aad_origin: Origin,
    cipher_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    ciphertext: Span[UInt8, cipher_origin],
    tag: Span[UInt8, tag_origin],
) raises -> List[UInt8]:
    _validate(key, nonce, len(tag))
    var schedule = List[UInt8]()
    var keys = List[SIMD[DType.uint64, 2]]()
    comptime if CompilationTarget.is_x86():
        if len(key) == 16:
            keys = _prepare_aesni128(key)
        elif len(key) == 32:
            keys = _prepare_aesni256(key)
        else:
            schedule = expand_key(key)
            keys = _prepare_aesni(Span(schedule))
    elif _HAS_ACCELERATED_AES_GCM:
        schedule = expand_key(key)
        keys = _prepare_aesni(Span(schedule))
    else:
        schedule = expand_key(key)
    comptime if _HAS_ACCELERATED_AES_GCM:
        var h_value = _encrypt_aesni_prepared_value(
            keys, SIMD[DType.uint64, 2](0)
        )
        var powers = _prepare_ghash_x86(bitcast[DType.uint8, 16](h_value))
        var initial = _initial_counter_x86(nonce, powers)
        var expected = _tag_value_x86(keys, initial, powers, aad, ciphertext)
        if not _constant_time_tag_equal_x86(expected, tag):
            raise Error("AES-GCM authentication failed")
        return _crypt_x86(keys, initial, ciphertext)
    else:
        var zero = List[UInt8](length=16, fill=0)
        var h = _encrypt_prepared(Span(schedule), keys, Span(zero))
        var table = _prepare_ghash(Span(h))
        var initial = _initial_counter(nonce, table)
        var expected = _tag(
            Span(schedule), keys, initial, table, aad, ciphertext, len(tag)
        )
        if not constant_time_equal(Span(expected), tag):
            raise Error("AES-GCM authentication failed")
        return _crypt(Span(schedule), keys, initial^, ciphertext)
