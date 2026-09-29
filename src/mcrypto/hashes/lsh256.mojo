"""LSH-224 and LSH-256 in pure Mojo."""

from std.collections import InlineArray
from std.bit import rotate_bits_left
from std.memory import bitcast
from ..internal.bytes import load_le32


def _rotl(value: UInt32, shift: Int) -> UInt32:
    if shift == 0:
        return value
    return (value << UInt32(shift)) | (value >> UInt32(32 - shift))


def _constants() -> InlineArray[UInt32, 208]:
    return [
        0x917CAF90,
        0x6C1B10A2,
        0x6F352943,
        0xCF778243,
        0x2CEB7472,
        0x29E96FF2,
        0x8A9BA428,
        0x2EEB2642,
        0x0E2C4021,
        0x872BB30E,
        0xA45E6CB2,
        0x46F9C612,
        0x185FE69E,
        0x1359621B,
        0x263FCCB2,
        0x1A116870,
        0x3A6C612F,
        0xB2DEC195,
        0x02CB1F56,
        0x40BFD858,
        0x784684B6,
        0x6CBB7D2E,
        0x660C7ED8,
        0x2B79D88A,
        0xA6CD9069,
        0x91A05747,
        0xCDEA7558,
        0x00983098,
        0xBECB3B2E,
        0x2838AB9A,
        0x728B573E,
        0xA55262B5,
        0x745DFA0F,
        0x31F79ED8,
        0xB85FCE25,
        0x98C8C898,
        0x8A0669EC,
        0x60E445C2,
        0xFDE295B0,
        0xF7B5185A,
        0xD2580983,
        0x29967709,
        0x182DF3DD,
        0x61916130,
        0x90705676,
        0x452A0822,
        0xE07846AD,
        0xACCD7351,
        0x2A618D55,
        0xC00D8032,
        0x4621D0F5,
        0xF2F29191,
        0x00C6CD06,
        0x6F322A67,
        0x58BEF48D,
        0x7A40C4FD,
        0x8BEEE27F,
        0xCD8DB2F2,
        0x67F2C63B,
        0xE5842383,
        0xC793D306,
        0xA15C91D6,
        0x17B381E5,
        0xBB05C277,
        0x7AD1620A,
        0x5B40A5BF,
        0x5AB901A2,
        0x69A7A768,
        0x5B66D9CD,
        0xFDEE6877,
        0xCB3566FC,
        0xC0C83A32,
        0x4C336C84,
        0x9BE6651A,
        0x13BAA3FC,
        0x114F0FD1,
        0xC240A728,
        0xEC56E074,
        0x009C63C7,
        0x89026CF2,
        0x7F9FF0D0,
        0x824B7FB5,
        0xCE5EA00F,
        0x605EE0E2,
        0x02E7CFEA,
        0x43375560,
        0x9D002AC7,
        0x8B6F5F7B,
        0x1F90C14F,
        0xCDCB3537,
        0x2CFEAFDD,
        0xBF3FC342,
        0xEAB7B9EC,
        0x7A8CB5A3,
        0x9D2AF264,
        0xFACEDB06,
        0xB052106E,
        0x99006D04,
        0x2BAE8D09,
        0xFF030601,
        0xA271A6D6,
        0x0742591D,
        0xC81D5701,
        0xC9A9E200,
        0x02627F1E,
        0x996D719D,
        0xDA3B9634,
        0x02090800,
        0x14187D78,
        0x499B7624,
        0xE57458C9,
        0x738BE2C9,
        0x64E19D20,
        0x06DF0F36,
        0x15D1CB0E,
        0x0B110802,
        0x2C95F58C,
        0xE5119A6D,
        0x59CD22AE,
        0xFF6EAC3C,
        0x467EBD84,
        0xE5EE453C,
        0xE79CD923,
        0x1C190A0D,
        0xC28B81B8,
        0xF6AC0852,
        0x26EFD107,
        0x6E1AE93B,
        0xC53C41CA,
        0xD4338221,
        0x8475FD0A,
        0x35231729,
        0x4E0D3A7A,
        0xA2B45B48,
        0x16C0D82D,
        0x890424A9,
        0x017E0C8F,
        0x07B5A3F5,
        0xFA73078E,
        0x583A405E,
        0x5B47B4C8,
        0x570FA3EA,
        0xD7990543,
        0x8D28CE32,
        0x7F8A9B90,
        0xBD5998FC,
        0x6D7A9688,
        0x927A9EB6,
        0xA2FC7D23,
        0x66B38E41,
        0x709E491A,
        0xB5F700BF,
        0x0A262C0F,
        0x16F295B9,
        0xE8111EF5,
        0x0D195548,
        0x9F79A0C5,
        0x1A41CFA7,
        0x0EE7638A,
        0xACF7C074,
        0x30523B19,
        0x09884ECF,
        0xF93014DD,
        0x266E9D55,
        0x191A6664,
        0x5C1176C1,
        0xF64AED98,
        0xA4B83520,
        0x828D5449,
        0x91D71DD8,
        0x2944F2D6,
        0x950BF27B,
        0x3380CA7D,
        0x6D88381D,
        0x4138868E,
        0x5CED55C4,
        0x0FE19DCB,
        0x68F4F669,
        0x6E37C8FF,
        0xA0FE6E10,
        0xB44B47B0,
        0xF5C0558A,
        0x79BF14CF,
        0x4A431A20,
        0xF17F68DA,
        0x5DEB5FD1,
        0xA600C86D,
        0x9F6C7EB0,
        0xFF92F864,
        0xB615E07F,
        0x38D3E448,
        0x8D5D3A6A,
        0x70E843CB,
        0x494B312E,
        0xA6C93613,
        0x0BEB2F4F,
        0x928B5D63,
        0xCBF66035,
        0x0CB82C80,
        0xEA97A4F7,
        0x592C0F3B,
        0x947C5F77,
        0x6FFF49B9,
        0xF71A7E5A,
        0x1DE8C0F5,
        0xC2569600,
        0xC4E4AC8C,
        0x823C9CE1,
    ]


@always_inline("nodebug")
def _constant_vector[offset: Int]() -> SIMD[DType.uint32, 8]:
    comptime constants = _constants()
    return SIMD[DType.uint32, 8](
        materialize[constants[offset]](),
        materialize[constants[offset + 1]](),
        materialize[constants[offset + 2]](),
        materialize[constants[offset + 3]](),
        materialize[constants[offset + 4]](),
        materialize[constants[offset + 5]](),
        materialize[constants[offset + 6]](),
        materialize[constants[offset + 7]](),
    )


def _iv(bits: Int) raises -> InlineArray[UInt32, 16]:
    if bits == 224:
        return [
            0x068608D3,
            0x62D8F7A7,
            0xD76652AB,
            0x4C600A43,
            0xBDC40AA8,
            0x1ECA0B68,
            0xDA1A89BE,
            0x3147D354,
            0x707EB4F9,
            0xF65B3862,
            0x6B0B2ABE,
            0x56B8EC0A,
            0xCF237286,
            0xEE0D1727,
            0x33636595,
            0x8BB8D05F,
        ]
    if bits == 256:
        return [
            0x46A10F1F,
            0xFDDCE486,
            0xB41443A8,
            0x198E6B9D,
            0x3304388D,
            0xB0F5A3C7,
            0xB36061C4,
            0x7ADBD553,
            0x105D5378,
            0x2F74DE54,
            0x5C2F2D95,
            0xF2553FBE,
            0x8051357A,
            0x138668C8,
            0x47AA4484,
            0xE01AFB41,
        ]
    raise Error("LSH-256 family size must be 224 or 256")


@always_inline("nodebug")
def _permute(mut left: SIMD[DType.uint32, 8], mut right: SIMD[DType.uint32, 8]):
    var old_left = left
    var old_right = right
    left = old_left.shuffle[6, 4, 5, 7, 12, 15, 14, 13](old_right)
    right = old_left.shuffle[2, 0, 1, 3, 8, 11, 10, 9](old_right)


@always_inline("nodebug")
def _gamma(right: SIMD[DType.uint32, 8]) -> SIMD[DType.uint32, 8]:
    return bitcast[DType.uint32, 8](
        bitcast[DType.uint8, 32](right).shuffle[
            0,
            1,
            2,
            3,
            7,
            4,
            5,
            6,
            10,
            11,
            8,
            9,
            13,
            14,
            15,
            12,
            17,
            18,
            19,
            16,
            22,
            23,
            20,
            21,
            27,
            24,
            25,
            26,
            28,
            29,
            30,
            31,
        ]()
    )


@always_inline("nodebug")
def _mix[
    alpha: Int, beta: Int
](
    mut left: SIMD[DType.uint32, 8],
    mut right: SIMD[DType.uint32, 8],
    constant: SIMD[DType.uint32, 8],
):
    left += right
    left = rotate_bits_left[alpha](left) ^ constant
    right += left
    right = rotate_bits_left[beta](right)
    left += right
    right = _gamma(right)


@always_inline("nodebug")
def _mix_two[
    alpha: Int, beta: Int
](
    mut first_left: SIMD[DType.uint32, 8],
    mut first_right: SIMD[DType.uint32, 8],
    mut second_left: SIMD[DType.uint32, 8],
    mut second_right: SIMD[DType.uint32, 8],
    constant: SIMD[DType.uint32, 8],
):
    first_left += first_right
    second_left += second_right
    first_left = rotate_bits_left[alpha](first_left) ^ constant
    second_left = rotate_bits_left[alpha](second_left) ^ constant
    first_right += first_left
    second_right += second_left
    first_right = rotate_bits_left[beta](first_right)
    second_right = rotate_bits_left[beta](second_right)
    first_left += first_right
    second_left += second_right
    first_right = _gamma(first_right)
    second_right = _gamma(second_right)


@always_inline("nodebug")
def _compress[
    block_origin: Origin
](
    mut chaining_left: SIMD[DType.uint32, 8],
    mut chaining_right: SIMD[DType.uint32, 8],
    block: Span[UInt8, block_origin],
    block_offset: Int,
):
    var block_pointer = block.unsafe_ptr()
    var message0 = bitcast[DType.uint32, 8](
        block_pointer.unsafe_load[width=32](block_offset)
    )
    var message1 = bitcast[DType.uint32, 8](
        block_pointer.unsafe_load[width=32](block_offset + 32)
    )
    var message2 = bitcast[DType.uint32, 8](
        block_pointer.unsafe_load[width=32](block_offset + 64)
    )
    var message3 = bitcast[DType.uint32, 8](
        block_pointer.unsafe_load[width=32](block_offset + 96)
    )
    var left = chaining_left ^ message0
    var right = chaining_right ^ message1
    _mix[29, 1](left, right, _constant_vector[0]())
    _permute(left, right)
    left ^= message2
    right ^= message3
    _mix[5, 17](left, right, _constant_vector[8]())
    _permute(left, right)
    comptime for step in range(1, 13):
        message0 = message2 + message0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        message1 = message3 + message1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        left ^= message0
        right ^= message1
        _mix[29, 1](left, right, _constant_vector[16 * step]())
        _permute(left, right)
        message2 = message0 + message2.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        message3 = message1 + message3.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        left ^= message2
        right ^= message3
        _mix[5, 17](left, right, _constant_vector[16 * step + 8]())
        _permute(left, right)
    message0 = message2 + message0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    message1 = message3 + message1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    chaining_left = left ^ message0
    chaining_right = right ^ message1


@always_inline("nodebug")
def _compress_two[
    first_origin: Origin,
    second_origin: Origin,
](
    mut first_chaining_left: SIMD[DType.uint32, 8],
    mut first_chaining_right: SIMD[DType.uint32, 8],
    mut second_chaining_left: SIMD[DType.uint32, 8],
    mut second_chaining_right: SIMD[DType.uint32, 8],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    block_offset: Int,
):
    var first_pointer = first.unsafe_ptr()
    var second_pointer = second.unsafe_ptr()
    var fm0 = bitcast[DType.uint32, 8](
        first_pointer.unsafe_load[width=32](block_offset)
    )
    var fm1 = bitcast[DType.uint32, 8](
        first_pointer.unsafe_load[width=32](block_offset + 32)
    )
    var fm2 = bitcast[DType.uint32, 8](
        first_pointer.unsafe_load[width=32](block_offset + 64)
    )
    var fm3 = bitcast[DType.uint32, 8](
        first_pointer.unsafe_load[width=32](block_offset + 96)
    )
    var sm0 = bitcast[DType.uint32, 8](
        second_pointer.unsafe_load[width=32](block_offset)
    )
    var sm1 = bitcast[DType.uint32, 8](
        second_pointer.unsafe_load[width=32](block_offset + 32)
    )
    var sm2 = bitcast[DType.uint32, 8](
        second_pointer.unsafe_load[width=32](block_offset + 64)
    )
    var sm3 = bitcast[DType.uint32, 8](
        second_pointer.unsafe_load[width=32](block_offset + 96)
    )
    var first_left = first_chaining_left ^ fm0
    var first_right = first_chaining_right ^ fm1
    var second_left = second_chaining_left ^ sm0
    var second_right = second_chaining_right ^ sm1
    _mix_two[29, 1](
        first_left,
        first_right,
        second_left,
        second_right,
        _constant_vector[0](),
    )
    _permute(first_left, first_right)
    _permute(second_left, second_right)
    first_left ^= fm2
    first_right ^= fm3
    second_left ^= sm2
    second_right ^= sm3
    _mix_two[5, 17](
        first_left,
        first_right,
        second_left,
        second_right,
        _constant_vector[8](),
    )
    _permute(first_left, first_right)
    _permute(second_left, second_right)
    comptime for step in range(1, 13):
        fm0 = fm2 + fm0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        fm1 = fm3 + fm1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        sm0 = sm2 + sm0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        sm1 = sm3 + sm1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        first_left ^= fm0
        first_right ^= fm1
        second_left ^= sm0
        second_right ^= sm1
        _mix_two[29, 1](
            first_left,
            first_right,
            second_left,
            second_right,
            _constant_vector[16 * step](),
        )
        _permute(first_left, first_right)
        _permute(second_left, second_right)
        fm2 = fm0 + fm2.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        fm3 = fm1 + fm3.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        sm2 = sm0 + sm2.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        sm3 = sm1 + sm3.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        first_left ^= fm2
        first_right ^= fm3
        second_left ^= sm2
        second_right ^= sm3
        _mix_two[5, 17](
            first_left,
            first_right,
            second_left,
            second_right,
            _constant_vector[16 * step + 8](),
        )
        _permute(first_left, first_right)
        _permute(second_left, second_right)
    fm0 = fm2 + fm0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    fm1 = fm3 + fm1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    sm0 = sm2 + sm0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    sm1 = sm3 + sm1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    first_chaining_left = first_left ^ fm0
    first_chaining_right = first_right ^ fm1
    second_chaining_left = second_left ^ sm0
    second_chaining_right = second_right ^ sm1


@always_inline("nodebug")
def _write_output[
    output_origin: MutOrigin
](
    bits: Int,
    combined: SIMD[DType.uint32, 8],
    output: Span[mut=True, UInt8, output_origin],
):
    var output_pointer = output.unsafe_ptr()
    if bits == 256:
        output_pointer.unsafe_store[width=32](
            0, bitcast[DType.uint8, 32](combined)
        )
        return
    output_pointer.unsafe_store[width=16](
        0,
        bitcast[DType.uint8, 16](
            SIMD[DType.uint32, 4](
                combined[0], combined[1], combined[2], combined[3]
            )
        ),
    )
    output_pointer.unsafe_store[width=8](
        16,
        bitcast[DType.uint8, 8](
            SIMD[DType.uint32, 2](combined[4], combined[5])
        ),
    )
    output_pointer.unsafe_store[width=4](
        24,
        bitcast[DType.uint8, 4](SIMD[DType.uint32, 1](combined[6])),
    )


def lsh256_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    bits: Int,
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) != bits // 8:
        raise Error("LSH-256 output span has invalid length")
    var cv = _iv(bits)
    var cv_pointer = Span(cv).unsafe_ptr()
    var chaining_left = cv_pointer.unsafe_load[width=8](0)
    var chaining_right = cv_pointer.unsafe_load[width=8](8)
    var offset = 0
    var data_length = len(data)
    while offset + 128 <= data_length:
        _compress(chaining_left, chaining_right, data, offset)
        offset += 128
    var block = InlineArray[UInt8, 128](fill=0)
    var remainder = data_length - offset
    for i in range(remainder):
        block[i] = data[offset + i]
    block[remainder] = 0x80
    _compress(chaining_left, chaining_right, Span(block), 0)
    _write_output(bits, chaining_left ^ chaining_right, output)


def lsh256_two_into[
    first_origin: Origin,
    second_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
](
    bits: Int,
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
) raises:
    """Hash two equal-length messages with interleaved AVX2 dependency chains.
    """
    if len(second) != len(first):
        raise Error("two-way LSH-256 inputs must have equal lengths")
    if len(first_output) != bits // 8 or len(second_output) != bits // 8:
        raise Error("two-way LSH-256 output span has invalid length")
    var cv = _iv(bits)
    var cv_pointer = Span(cv).unsafe_ptr()
    var first_left = cv_pointer.unsafe_load[width=8](0)
    var first_right = cv_pointer.unsafe_load[width=8](8)
    var second_left = first_left
    var second_right = first_right
    var offset = 0
    while offset + 128 <= len(first):
        _compress_two(
            first_left,
            first_right,
            second_left,
            second_right,
            first,
            second,
            offset,
        )
        offset += 128
    var first_block = InlineArray[UInt8, 128](fill=0)
    var second_block = InlineArray[UInt8, 128](fill=0)
    var remainder = len(first) - offset
    for i in range(remainder):
        first_block[i] = first[offset + i]
        second_block[i] = second[offset + i]
    first_block[remainder] = 0x80
    second_block[remainder] = 0x80
    _compress_two(
        first_left,
        first_right,
        second_left,
        second_right,
        Span(first_block),
        Span(second_block),
        0,
    )
    _write_output(bits, first_left ^ first_right, first_output)
    _write_output(bits, second_left ^ second_right, second_output)


def lsh256[
    origin: Origin
](bits: Int, data: Span[UInt8, origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=bits // 8, fill=0)
    lsh256_into(bits, data, Span(output))
    return output^


def lsh224[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    return lsh256(224, data)
