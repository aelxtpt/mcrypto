"""VMAC-AES as specified by RFC 4418 (64- and 128-bit tags)."""
from std.memory import bitcast

from ..ciphers.aes_block import expand_key, encrypt_expanded_into
from ..internal.bytes import load_be64 as _be64, load_le64 as _le64


comptime _P127 = (UInt128(1) << 127) - 1
comptime _P64 = UInt64(0xFFFFFFFFFFFFFEFF)
comptime _M62 = UInt64(0x3FFFFFFFFFFFFFFF)
comptime _MPOLY = UInt64(0x1FFFFFFF1FFFFFFF)


def _append_be64(mut output: List[UInt8], value: UInt64):
    for i in range(8):
        output.append(UInt8(value >> UInt64(56 - 8 * i)))


@always_inline("nodebug")
def _mod_add(a: UInt128, b: UInt128) -> UInt128:
    if a >= _P127 - b:
        return a - (_P127 - b)
    return a + b


@always_inline("nodebug")
def _mod_multiply(a: UInt128, b: UInt128) -> UInt128:
    var a0 = UInt64(a)
    var a1 = UInt64(a >> 64)
    var b0 = UInt64(b)
    var b1 = UInt64(b >> 64)
    var p00 = UInt128(a0) * UInt128(b0)
    var p01 = UInt128(a0) * UInt128(b1)
    var p10 = UInt128(a1) * UInt128(b0)
    var p11 = UInt128(a1) * UInt128(b1)
    var c0 = UInt64(p00)
    var sum1 = (
        UInt128(UInt64(p00 >> 64)) + UInt128(UInt64(p01)) + UInt128(UInt64(p10))
    )
    var c1 = UInt64(sum1)
    var sum2 = (
        UInt128(UInt64(p01 >> 64))
        + UInt128(UInt64(p10 >> 64))
        + UInt128(UInt64(p11))
        + (sum1 >> 64)
    )
    var c2 = UInt64(sum2)
    var c3 = UInt64((p11 >> 64) + (sum2 >> 64))
    var low = UInt128(c0) | (UInt128(c1 & 0x7FFFFFFFFFFFFFFF) << 64)
    var high_low = (
        UInt128(c1 >> 63)
        | (UInt128(c2) << 1)
        | (UInt128(c3 & 0x7FFFFFFFFFFFFFFF) << 65)
    )
    var folded = low + high_low
    var carry = UInt128(folded < low)
    var result = (
        (folded & _P127) + (folded >> 127) + ((carry + UInt128(c3 >> 63)) << 1)
    )
    if result >= _P127:
        result -= _P127
    return result


@always_inline("nodebug")
def _nh[
    message_origin: Origin
](
    message: Span[UInt8, message_origin],
    key_words: InlineArray[UInt64, 18],
    message_offset: Int,
    message_bytes: Int,
    key_word_offset: Int,
) raises -> UInt128:
    var total = UInt128(0)
    if message_bytes == 128:
        # Independent accumulators expose the eight NH multiplications to the
        # CPU instead of serializing them behind one add dependency.
        var sums = InlineArray[UInt128, 4](fill=0)
        var message_pointer = message.unsafe_ptr()
        comptime for offset in range(0, 128, 16):
            comptime lane = (offset // 16) % 4
            var word = offset // 8 + key_word_offset
            var left = (
                bitcast[DType.uint64, 1](
                    message_pointer.unsafe_load[width=8](
                        message_offset + offset
                    )
                )[0]
                + key_words[word]
            )
            var right = (
                bitcast[DType.uint64, 1](
                    message_pointer.unsafe_load[width=8](
                        message_offset + offset + 8
                    )
                )[0]
                + key_words[word + 1]
            )
            sums[lane] += UInt128(left) * UInt128(right)
        return (sums[0] + sums[1]) + (sums[2] + sums[3])
    var padded_size = ((message_bytes + 15) // 16) * 16
    for offset in range(0, padded_size, 16):
        var left = UInt64(0)
        var right = UInt64(0)
        if offset + 16 <= message_bytes:
            left = _le64(message, message_offset + offset)
            right = _le64(message, message_offset + offset + 8)
        else:
            for byte in range(8):
                if offset + byte < message_bytes:
                    left |= UInt64(
                        message[message_offset + offset + byte]
                    ) << UInt64(8 * byte)
                if offset + 8 + byte < message_bytes:
                    right |= UInt64(
                        message[message_offset + offset + 8 + byte]
                    ) << UInt64(8 * byte)
        var word = offset // 8 + key_word_offset
        left += key_words[word]
        right += key_words[word + 1]
        total += UInt128(left) * UInt128(right)
    return total


@always_inline("nodebug")
def _nh_pair[
    message_origin: Origin
](
    message: Span[UInt8, message_origin],
    key_words: InlineArray[UInt64, 18],
    message_offset: Int,
    message_bytes: Int,
) raises -> Tuple[UInt128, UInt128]:
    var total0 = UInt128(0)
    var total1 = UInt128(0)
    if message_bytes == 128:
        var sums0 = InlineArray[UInt128, 4](fill=0)
        var sums1 = InlineArray[UInt128, 4](fill=0)
        var message_pointer = message.unsafe_ptr()
        comptime for offset in range(0, 128, 16):
            comptime lane = (offset // 16) % 4
            comptime word = offset // 8
            var left = bitcast[DType.uint64, 1](
                message_pointer.unsafe_load[width=8](message_offset + offset)
            )[0]
            var right = bitcast[DType.uint64, 1](
                message_pointer.unsafe_load[width=8](
                    message_offset + offset + 8
                )
            )[0]
            sums0[lane] += UInt128(left + key_words[word]) * UInt128(
                right + key_words[word + 1]
            )
            sums1[lane] += UInt128(left + key_words[word + 2]) * UInt128(
                right + key_words[word + 3]
            )
        total0 = (sums0[0] + sums0[1]) + (sums0[2] + sums0[3])
        total1 = (sums1[0] + sums1[1]) + (sums1[2] + sums1[3])
        return (total0, total1)
    var padded_size = ((message_bytes + 15) // 16) * 16
    for offset in range(0, padded_size, 16):
        var left = UInt64(0)
        var right = UInt64(0)
        if offset + 16 <= message_bytes:
            left = _le64(message, message_offset + offset)
            right = _le64(message, message_offset + offset + 8)
        else:
            for byte in range(8):
                if offset + byte < message_bytes:
                    left |= UInt64(
                        message[message_offset + offset + byte]
                    ) << UInt64(8 * byte)
                if offset + 8 + byte < message_bytes:
                    right |= UInt64(
                        message[message_offset + offset + 8 + byte]
                    ) << UInt64(8 * byte)
        var word = offset // 8
        total0 += UInt128(left + key_words[word]) * UInt128(
            right + key_words[word + 1]
        )
        total1 += UInt128(left + key_words[word + 2]) * UInt128(
            right + key_words[word + 3]
        )
    return (total0, total1)


@always_inline("nodebug")
def _l3_hash(
    value: UInt128, key1: UInt64, key2: UInt64, bit_length: Int
) -> UInt64:
    var p1 = UInt64(value >> 64)
    var p2 = UInt64(value)
    var top = p1 >> 63
    p1 &= 0x7FFFFFFFFFFFFFFF
    var add_high = UInt64(bit_length)
    var old = p2
    p2 += top
    p1 += add_high + UInt64(p2 < old)
    var extra = UInt64(
        p1 > 0x7FFFFFFFFFFFFFFF
        or (p1 == 0x7FFFFFFFFFFFFFFF and p2 == 0xFFFFFFFFFFFFFFFF)
    )
    old = p2
    p2 += extra
    p1 += UInt64(p2 < old)
    p1 &= 0x7FFFFFFFFFFFFFFF
    var t = p1 + (p2 >> 32)
    t += t >> 32
    t += UInt64(UInt32(t) > 0xFFFFFFFE)
    p1 += t >> 32
    p2 += p1 << 32
    old = p1
    p1 += key1
    if p1 < old:
        p1 += 257
    old = p2
    p2 += key2
    if p2 < old:
        p2 += 257
    var multiplied = UInt128(p1) * UInt128(p2)
    var high = UInt64(multiplied >> 64)
    var low = UInt64(multiplied)
    t = high >> 56
    old = low
    low += high
    t += UInt64(low < old)
    var shifted = high << 8
    old = low
    low += shifted
    t += UInt64(low < old)
    t += t << 8
    old = low
    low += t
    if low < old:
        low += 257
    if low >= _P64:
        low += 257
    return low


struct _VMACKey(Movable):
    var expanded: List[UInt8]
    var nh_words: InlineArray[UInt64, 18]
    var poly_keys: InlineArray[UInt128, 2]
    var poly_powers: InlineArray[UInt128, 8]
    var l3_keys: InlineArray[UInt64, 4]
    var parts: Int

    def __init__[
        key_origin: Origin
    ](out self, key: Span[UInt8, key_origin], tag_size: Int,) raises:
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise Error("VMAC AES key must be 16, 24, or 32 bytes")
        if tag_size != 8 and tag_size != 16:
            raise Error("VMAC tag must be 8 or 16 bytes")
        self.parts = tag_size // 8
        self.expanded = expand_key(key)
        self.nh_words = InlineArray[UInt64, 18](fill=0)
        self.poly_keys = InlineArray[UInt128, 2](fill=0)
        self.poly_powers = InlineArray[UInt128, 8](fill=0)
        self.l3_keys = InlineArray[UInt64, 4](fill=0)
        var block = InlineArray[UInt8, 16](fill=0)
        var encrypted = InlineArray[UInt8, 16](fill=0)
        block[0] = 0x80
        for counter in range(9):
            block[15] = UInt8(counter)
            encrypt_expanded_into(
                Span(self.expanded), Span(block), Span(encrypted)
            )
            self.nh_words[counter * 2] = _be64(Span(encrypted), 0)
            self.nh_words[counter * 2 + 1] = _be64(Span(encrypted), 8)
        for part in range(self.parts):
            block[0] = 0xC0
            block[15] = UInt8(part)
            encrypt_expanded_into(
                Span(self.expanded), Span(block), Span(encrypted)
            )
            var high = _be64(Span(encrypted), 0) & _MPOLY
            var low = _be64(Span(encrypted), 8) & _MPOLY
            self.poly_keys[part] = (UInt128(high) << 64) | UInt128(low)
            var power_offset = part * 4
            self.poly_powers[power_offset] = self.poly_keys[part]
            self.poly_powers[power_offset + 1] = _mod_multiply(
                self.poly_keys[part], self.poly_keys[part]
            )
            self.poly_powers[power_offset + 2] = _mod_multiply(
                self.poly_powers[power_offset + 1], self.poly_keys[part]
            )
            self.poly_powers[power_offset + 3] = _mod_multiply(
                self.poly_powers[power_offset + 2], self.poly_keys[part]
            )
            var accepted = False
            var counter = part
            while not accepted:
                block[0] = 0xE0
                block[15] = UInt8(counter)
                encrypt_expanded_into(
                    Span(self.expanded), Span(block), Span(encrypted)
                )
                var first = _be64(Span(encrypted), 0)
                var second = _be64(Span(encrypted), 8)
                counter += 1
                if first < _P64 and second < _P64:
                    self.l3_keys[part * 2] = first
                    self.l3_keys[part * 2 + 1] = second
                    accepted = True

    def authenticate[
        nonce_origin: Origin, message_origin: Origin
    ](
        self,
        nonce: Span[UInt8, nonce_origin],
        message: Span[UInt8, message_origin],
    ) raises -> List[UInt8]:
        if len(nonce) < 1 or len(nonce) > 16:
            raise Error("VMAC nonce must be 1..16 bytes")
        var states = InlineArray[UInt128, 2](fill=0)
        var offset = 0
        var nh_mask = _P127 - (UInt128(1) << 126)
        if self.parts == 2:
            var first_chunk = True
            while offset < len(message):
                var chunk_size = min(128, len(message) - offset)
                var pair = _nh_pair(message, self.nh_words, offset, chunk_size)
                var nh0 = pair[0] & nh_mask
                var nh1 = pair[1] & nh_mask
                if first_chunk:
                    states[0] = _mod_add(nh0, self.poly_keys[0])
                    states[1] = _mod_add(nh1, self.poly_keys[1])
                    first_chunk = False
                else:
                    states[0] = _mod_add(
                        _mod_multiply(states[0], self.poly_keys[0]), nh0
                    )
                    states[1] = _mod_add(
                        _mod_multiply(states[1], self.poly_keys[1]), nh1
                    )
                offset += chunk_size
            if first_chunk:
                states[0] = self.poly_keys[0]
                states[1] = self.poly_keys[1]
        elif len(message) == 0:
            states[0] = self.poly_keys[0]
        else:
            states[0] = UInt128(1)
            while offset + 512 <= len(message):
                var nh0 = _nh(message, self.nh_words, offset, 128, 0) & nh_mask
                var nh1 = (
                    _nh(message, self.nh_words, offset + 128, 128, 0) & nh_mask
                )
                var nh2 = (
                    _nh(message, self.nh_words, offset + 256, 128, 0) & nh_mask
                )
                var nh3 = (
                    _nh(message, self.nh_words, offset + 384, 128, 0) & nh_mask
                )
                var weighted_state = _mod_multiply(
                    states[0], self.poly_powers[3]
                )
                var weighted0 = _mod_multiply(nh0, self.poly_powers[2])
                var weighted1 = _mod_multiply(nh1, self.poly_powers[1])
                var weighted2 = _mod_multiply(nh2, self.poly_powers[0])
                states[0] = _mod_add(
                    _mod_add(weighted_state, weighted0),
                    _mod_add(_mod_add(weighted1, weighted2), nh3),
                )
                offset += 512
            while offset < len(message):
                var chunk_size = min(128, len(message) - offset)
                var nh_value = (
                    _nh(
                        message,
                        self.nh_words,
                        offset,
                        chunk_size,
                        0,
                    )
                    & nh_mask
                )
                states[0] = _mod_add(
                    _mod_multiply(states[0], self.poly_keys[0]),
                    nh_value,
                )
                offset += chunk_size
        var residual_bits = (len(message) % 128) * 8
        var nonce_block = InlineArray[UInt8, 16](fill=0)
        for i in range(len(nonce)):
            nonce_block[16 - len(nonce) + i] = nonce[i]
        var nonce_parity = nonce_block[15] & 1
        if self.parts == 1:
            nonce_block[15] &= 0xFE
        var encrypted = InlineArray[UInt8, 16](fill=0)
        encrypt_expanded_into(
            Span(self.expanded), Span(nonce_block), Span(encrypted)
        )
        var output = List[UInt8](capacity=self.parts * 8)
        for part in range(self.parts):
            var hashed = _l3_hash(
                states[part],
                self.l3_keys[part * 2],
                self.l3_keys[part * 2 + 1],
                residual_bits,
            )
            var pad_offset = part * 8
            if self.parts == 1:
                pad_offset = Int(nonce_parity) * 8
            var tag_word = hashed + _be64(Span(encrypted), pad_offset)
            _append_be64(output, tag_word)
        return output^


def authenticate[
    key_origin: Origin,
    nonce_origin: Origin,
    message_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    message: Span[UInt8, message_origin],
    tag_size: Int = 16,
) raises -> List[UInt8]:
    var prepared = _VMACKey(key, tag_size)
    return prepared.authenticate(nonce, message)


def authenticate_eight[
    key_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonces: List[List[UInt8]],
    messages: List[List[UInt8]],
    tag_size: Int = 16,
) raises -> List[List[UInt8]]:
    """Authenticate eight independent messages with one VMAC key schedule."""
    if len(nonces) != 8 or len(messages) != 8:
        raise Error("eight-way VMAC batch has invalid dimensions")
    var prepared = _VMACKey(key, tag_size)
    var outputs = List[List[UInt8]](capacity=8)
    for lane in range(8):
        outputs.append(
            prepared.authenticate(Span(nonces[lane]), Span(messages[lane]))
        )
    return outputs^


def verify[
    key_origin: Origin,
    nonce_origin: Origin,
    message_origin: Origin,
    tag_origin: Origin,
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    message: Span[UInt8, message_origin],
    tag: Span[UInt8, tag_origin],
) -> Bool:
    if len(tag) != 8 and len(tag) != 16:
        return False
    try:
        var expected = authenticate(key, nonce, message, len(tag))
        var difference = UInt8(0)
        for i in range(len(tag)):
            difference |= expected[i] ^ tag[i]
        return difference == 0
    except:
        return False
