"""NIST SP 800-38C AES-CCM authenticated encryption in pure Mojo."""

from ..ciphers.prepared_aes import _PreparedAES
from std.sys import CompilationTarget
from ..traits import constant_time_equal


def _validate[
    key_origin: Origin, nonce_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    message_bytes: Int,
    tag_bytes: Int,
) raises -> Int:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("AES-CCM key must be 16, 24, or 32 bytes")
    if len(nonce) < 7 or len(nonce) > 13:
        raise Error("AES-CCM nonce must be between 7 and 13 bytes")
    if tag_bytes < 4 or tag_bytes > 16 or tag_bytes % 2 != 0:
        raise Error("AES-CCM tag must have an even length from 4 to 16 bytes")
    var q = 15 - len(nonce)
    if q < 8 and UInt64(message_bytes) >= (UInt64(1) << UInt64(8 * q)):
        raise Error("AES-CCM message is too long for the nonce length")
    return q


def _counter[
    nonce_origin: Origin
](nonce: Span[UInt8, nonce_origin], q: Int, value: UInt64,) -> List[UInt8]:
    var block = List[UInt8](length=16, fill=0)
    block[0] = UInt8(q - 1)
    for i in range(len(nonce)):
        block[1 + i] = nonce[i]
    for i in range(q):
        block[15 - i] = UInt8(value >> UInt64(8 * i))
    return block^


@always_inline("nodebug")
def _increment_counter(mut counter: List[UInt8], q: Int):
    for offset in range(q):
        var index = 15 - offset
        counter[index] += 1
        if counter[index] != 0:
            return


def _mac_block[
    block_origin: Origin
](
    prepared: _PreparedAES,
    mut state: List[UInt8],
    block: Span[UInt8, block_origin],
    mut combined: List[UInt8],
) raises:
    Span(combined).unsafe_ptr().unsafe_store[width=16](
        0,
        Span(state).unsafe_ptr().unsafe_load[width=16](0)
        ^ block.unsafe_ptr().unsafe_load[width=16](0),
    )
    prepared.encrypt_into(Span(combined), Span(state), 0)


def _mac_bytes[
    data_origin: Origin
](
    prepared: _PreparedAES,
    mut state: List[UInt8],
    data: Span[UInt8, data_origin],
    mut combined: List[UInt8],
) raises:
    var offset = 0
    var data_pointer = data.unsafe_ptr()
    var combined_pointer = Span(combined).unsafe_ptr()
    var state_pointer = Span(state).unsafe_ptr()
    while offset + 16 <= len(data):
        combined_pointer.unsafe_store[width=16](
            0,
            state_pointer.unsafe_load[width=16](0)
            ^ data_pointer.unsafe_load[width=16](offset),
        )
        prepared.encrypt_into(Span(combined), Span(state), 0)
        offset += 16
    if offset < len(data):
        var block = List[UInt8](length=16, fill=0)
        var take = len(data) - offset
        for i in range(take):
            block[i] = data[offset + i]
        _mac_block(prepared, state, Span(block), combined)


def _mac_aad[
    aad_origin: Origin
](
    prepared: _PreparedAES,
    mut state: List[UInt8],
    aad: Span[UInt8, aad_origin],
    mut combined: List[UInt8],
) raises:
    var encoded = _aad_encoding(len(aad))
    var block = List[UInt8](length=16, fill=0)
    var prefix_bytes = len(encoded)
    for i in range(prefix_bytes):
        block[i] = encoded[i]
    var first_aad_bytes = min(16 - prefix_bytes, len(aad))
    for i in range(first_aad_bytes):
        block[prefix_bytes + i] = aad[i]
    _mac_block(prepared, state, Span(block), combined)
    var offset = first_aad_bytes
    if offset < len(aad):
        _mac_bytes(prepared, state, aad[offset:], combined)


def _aad_encoding(aad_bytes: Int) -> List[UInt8]:
    var output = List[UInt8]()
    if aad_bytes < 0xFF00:
        output.append(UInt8(aad_bytes >> 8))
        output.append(UInt8(aad_bytes))
    elif UInt64(aad_bytes) <= UInt64(0xFFFFFFFF):
        output.append(0xFF)
        output.append(0xFE)
        for i in range(4):
            output.append(UInt8(UInt64(aad_bytes) >> UInt64(8 * (3 - i))))
    else:
        output.append(0xFF)
        output.append(0xFF)
        for i in range(8):
            output.append(UInt8(UInt64(aad_bytes) >> UInt64(8 * (7 - i))))
    return output^


def _authenticate[
    nonce_origin: Origin,
    aad_origin: Origin,
    message_origin: Origin,
](
    prepared: _PreparedAES,
    nonce: Span[UInt8, nonce_origin],
    aad: Span[UInt8, aad_origin],
    message: Span[UInt8, message_origin],
    tag_bytes: Int,
    q: Int,
) raises -> List[UInt8]:
    var b0 = List[UInt8](length=16, fill=0)
    b0[0] = UInt8(
        (0x40 if len(aad) != 0 else 0) | ((tag_bytes - 2) // 2 << 3) | (q - 1)
    )
    for i in range(len(nonce)):
        b0[1 + i] = nonce[i]
    var message_length = UInt64(len(message))
    for i in range(q):
        b0[15 - i] = UInt8(message_length >> UInt64(8 * i))

    var state = List[UInt8](length=16, fill=0)
    var combined = List[UInt8](length=16, fill=0)
    _mac_block(prepared, state, Span(b0), combined)
    if len(aad) != 0:
        _mac_aad(prepared, state, aad, combined)
    _mac_bytes(prepared, state, message, combined)
    return state^


def _crypt[
    nonce_origin: Origin, input_origin: Origin
](
    prepared: _PreparedAES,
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
    q: Int,
) raises -> List[UInt8]:
    var output = List[UInt8](length=len(input), fill=0)
    var offset = 0
    var counter = _counter(nonce, q, 1)
    var stream = List[UInt8](length=16, fill=0)
    comptime if CompilationTarget.is_x86():
        var counters = List[UInt8](length=128, fill=0)
        var counter_pointer = Span(counter).unsafe_ptr()
        var counters_pointer = Span(counters).unsafe_ptr()
        while offset + 128 <= len(input):
            comptime for block in range(8):
                counters_pointer.unsafe_store[width=16](
                    block * 16,
                    counter_pointer.unsafe_load[width=16](0),
                )
                _increment_counter(counter, q)
            prepared.encrypt_eight(
                Span(counters),
                0,
                input,
                offset,
                Span(output),
                offset,
            )
            offset += 128
    while offset < len(input):
        prepared.encrypt_into(Span(counter), Span(stream), 0)
        var take = min(16, len(input) - offset)
        for i in range(take):
            output[offset + i] = input[offset + i] ^ stream[i]
        offset += take
        _increment_counter(counter, q)
    return output^


struct _PreparedCCM(Movable):
    """Reusable AES key schedule for independent CCM messages."""

    var key: List[UInt8]
    var prepared: _PreparedAES

    def __init__[
        key_origin: Origin
    ](out self, key: Span[UInt8, key_origin]) raises:
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise Error("AES-CCM key must be 16, 24, or 32 bytes")
        self.key = List[UInt8](capacity=len(key))
        for byte in key:
            self.key.append(byte)
        self.prepared = _PreparedAES(key)

    def encrypt[
        nonce_origin: Origin,
        aad_origin: Origin,
        message_origin: Origin,
    ](
        self,
        nonce: Span[UInt8, nonce_origin],
        aad: Span[UInt8, aad_origin],
        message: Span[UInt8, message_origin],
        tag_bytes: Int = 16,
    ) raises -> Tuple[List[UInt8], List[UInt8]]:
        var q = _validate(Span(self.key), nonce, len(message), tag_bytes)
        var mac = _authenticate(
            self.prepared, nonce, aad, message, tag_bytes, q
        )
        var zero_counter = _counter(nonce, q, 0)
        var s0 = List[UInt8](length=16, fill=0)
        self.prepared.encrypt_into(Span(zero_counter), Span(s0), 0)
        var tag = List[UInt8](capacity=tag_bytes)
        for i in range(tag_bytes):
            tag.append(mac[i] ^ s0[i])
        var ciphertext = _crypt(self.prepared, nonce, message, q)
        return (ciphertext^, tag^)

    def decrypt[
        nonce_origin: Origin,
        aad_origin: Origin,
        cipher_origin: Origin,
        tag_origin: Origin,
    ](
        self,
        nonce: Span[UInt8, nonce_origin],
        aad: Span[UInt8, aad_origin],
        ciphertext: Span[UInt8, cipher_origin],
        tag: Span[UInt8, tag_origin],
    ) raises -> List[UInt8]:
        var q = _validate(Span(self.key), nonce, len(ciphertext), len(tag))
        var message = _crypt(self.prepared, nonce, ciphertext, q)
        var mac = _authenticate(
            self.prepared, nonce, aad, Span(message), len(tag), q
        )
        var zero_counter = _counter(nonce, q, 0)
        var s0 = List[UInt8](length=16, fill=0)
        self.prepared.encrypt_into(Span(zero_counter), Span(s0), 0)
        var expected = List[UInt8](capacity=len(tag))
        for i in range(len(tag)):
            expected.append(mac[i] ^ s0[i])
        if not constant_time_equal(Span(expected), tag):
            raise Error("AES-CCM authentication failed")
        return message^


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
    var prepared = _PreparedCCM(key)
    return prepared.encrypt(nonce, aad, message, tag_bytes)


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
    var prepared = _PreparedCCM(key)
    return prepared.decrypt(nonce, aad, ciphertext, tag)
