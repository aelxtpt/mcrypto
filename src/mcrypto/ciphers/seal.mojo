"""SEAL 3.0 stream cipher in pure Mojo."""

from ..internal.bytes import load_be32, load_le32, store_be32, store_le32


@always_inline("nodebug")
def _rol(value: UInt32, amount: Int) -> UInt32:
    return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


@always_inline("nodebug")
def _ror(value: UInt32, amount: Int) -> UInt32:
    return (value >> UInt32(amount)) | (value << UInt32(32 - amount))


def _sha1_transform(mut state: InlineArray[UInt32, 5], index: UInt32):
    # Generate the SHA-1 schedule in a fixed 16-word ring instead of
    # materializing and walking an 80-word schedule.
    var words = InlineArray[UInt32, 16](fill=0)
    words[0] = index
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    for i in range(80):
        var slot = i & 15
        if i >= 16:
            words[slot] = _rol(
                words[(i - 3) & 15]
                ^ words[(i - 8) & 15]
                ^ words[(i - 14) & 15]
                ^ words[slot],
                1,
            )
        var f: UInt32
        var constant: UInt32
        if i < 20:
            f = (b & c) | ((~b) & d)
            constant = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            constant = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            constant = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            constant = 0xCA62C1D6
        var temporary = _rol(a, 5) + f + e + constant + words[slot]
        e = d
        d = c
        c = _rol(b, 30)
        b = a
        a = temporary
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e


@always_inline("nodebug")
def _xor_word[
    input_origin: Origin, output_origin: MutOrigin
](
    little_endian: Bool,
    word: UInt32,
    input: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
    position: Int,
) raises -> Int:
    var remaining = len(input) - position
    if remaining >= 4:
        if little_endian:
            store_le32(word ^ load_le32(input, position), output, position)
        else:
            store_be32(word ^ load_be32(input, position), output, position)
        return position + 4
    for j in range(remaining):
        var shift = 8 * j if little_endian else 24 - 8 * j
        output[position + j] = input[position + j] ^ UInt8(
            word >> UInt32(shift)
        )
    return len(input)


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    little_endian: Bool,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 20 or len(nonce) != 4:
        raise Error("SEAL 3.0 requires a 20-byte key and 4-byte nonce")
    var key_words = InlineArray[UInt32, 5](fill=0)
    for i in range(5):
        key_words[i] = load_be32(key, 4 * i)
    var table = InlineArray[UInt32, 512](fill=0)
    var sbox = InlineArray[UInt32, 256](fill=0)
    var r = InlineArray[UInt32, 16](fill=0)
    # Each compression yields five consecutive gamma words.  Keep that state
    # instead of recomputing the same compression once per output word.
    var gamma_state = key_words.copy()
    for i in range(512):
        if i % 5 == 0:
            gamma_state = key_words.copy()
            _sha1_transform(gamma_state, UInt32(i // 5))
        table[i] = gamma_state[i % 5]
    for i in range(256):
        var gamma_index = 0x1000 + i
        if i == 0 or gamma_index % 5 == 0:
            gamma_state = key_words.copy()
            _sha1_transform(gamma_state, UInt32(gamma_index // 5))
        sbox[i] = gamma_state[gamma_index % 5]
    for i in range(16):
        var gamma_index = 0x2000 + i
        if i == 0 or gamma_index % 5 == 0:
            gamma_state = key_words.copy()
            _sha1_transform(gamma_state, UInt32(gamma_index // 5))
        r[i] = gamma_state[gamma_index % 5]
    var counter = load_be32(nonce, 0)
    var inside_counter = 0
    var output = List[UInt8](length=len(input), fill=0)
    var output_span = Span(output)
    var output_position = 0
    while output_position < len(input):
        var a = counter ^ r[4 * inside_counter]
        var b = _ror(counter, 8) ^ r[4 * inside_counter + 1]
        var c = _ror(counter, 16) ^ r[4 * inside_counter + 2]
        var d = _ror(counter, 24) ^ r[4 * inside_counter + 3]
        for _ in range(2):
            var p = Int((a & 0x7FC) >> 2)
            b += table[p]
            a = _ror(a, 9)
            p = Int((b & 0x7FC) >> 2)
            c += table[p]
            b = _ror(b, 9)
            p = Int((c & 0x7FC) >> 2)
            d += table[p]
            c = _ror(c, 9)
            p = Int((d & 0x7FC) >> 2)
            a += table[p]
            d = _ror(d, 9)
        var n1 = d
        var n2 = b
        var n3 = a
        var n4 = c
        var p = Int((a & 0x7FC) >> 2)
        b += table[p]
        a = _ror(a, 9)
        p = Int((b & 0x7FC) >> 2)
        c += table[p]
        b = _ror(b, 9)
        p = Int((c & 0x7FC) >> 2)
        d += table[p]
        c = _ror(c, 9)
        p = Int((d & 0x7FC) >> 2)
        a += table[p]
        d = _ror(d, 9)
        for i in range(64):
            p = Int(a & 0x7FC)
            a = _ror(a, 9)
            b += table[p >> 2]
            b ^= a
            var q = Int(b & 0x7FC)
            b = _ror(b, 9)
            c ^= table[q >> 2]
            c += b
            p = (p + Int(c)) & 0x7FC
            c = _ror(c, 9)
            d += table[p >> 2]
            d ^= c
            q = (q + Int(d)) & 0x7FC
            d = _ror(d, 9)
            a ^= table[q >> 2]
            a += d
            p = (p + Int(a)) & 0x7FC
            b ^= table[p >> 2]
            a = _ror(a, 9)
            q = (q + Int(b)) & 0x7FC
            c += table[q >> 2]
            b = _ror(b, 9)
            p = (p + Int(c)) & 0x7FC
            d ^= table[p >> 2]
            c = _ror(c, 9)
            q = (q + Int(d)) & 0x7FC
            d = _ror(d, 9)
            a += table[q >> 2]
            output_position = _xor_word(
                little_endian,
                b + sbox[4 * i],
                input,
                output_span,
                output_position,
            )
            if output_position == len(input):
                return output^
            output_position = _xor_word(
                little_endian,
                c ^ sbox[4 * i + 1],
                input,
                output_span,
                output_position,
            )
            if output_position == len(input):
                return output^
            output_position = _xor_word(
                little_endian,
                d + sbox[4 * i + 2],
                input,
                output_span,
                output_position,
            )
            if output_position == len(input):
                return output^
            output_position = _xor_word(
                little_endian,
                a ^ sbox[4 * i + 3],
                input,
                output_span,
                output_position,
            )
            if output_position == len(input):
                return output^
            if i & 1:
                a += n3
                b += n4
                c ^= n3
                d ^= n4
            else:
                a += n1
                b += n2
                c ^= n1
                d ^= n2
        inside_counter += 1
        if inside_counter == 4:
            counter += 1
            inside_counter = 0
    return output^
