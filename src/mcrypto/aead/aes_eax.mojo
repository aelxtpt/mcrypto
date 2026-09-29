"""AES-EAX authenticated encryption (Bellare, Rogaway, and Wagner)."""

from std.sys import CompilationTarget
from ..ciphers.prepared_aes import _PreparedAES
from ..traits import constant_time_equal


@always_inline("nodebug")
def _validate[
    key_origin: Origin
](key: Span[UInt8, key_origin], tag_bytes: Int) raises:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("AES-EAX key must be 16, 24, or 32 bytes")
    if tag_bytes < 1 or tag_bytes > 16:
        raise Error("AES-EAX tag must be between 1 and 16 bytes")


def _double_block[
    block_origin: Origin
](block: Span[UInt8, block_origin]) -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    var carry = UInt8(0)
    for offset in range(16):
        var i = 15 - offset
        var next_carry = block[i] >> 7
        output[i] = (block[i] << 1) | carry
        carry = next_carry
    output[15] ^= (UInt8(0) - carry) & 0x87
    return output^


def _cmac_subkeys(
    prepared: _PreparedAES,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    var zero = List[UInt8](length=16, fill=0)
    var encrypted = List[UInt8](length=16, fill=0)
    prepared.encrypt_into(Span(zero), Span(encrypted), 0)
    var k1 = _double_block(Span(encrypted))
    var k2 = _double_block(Span(k1))
    return (k1^, k2^)


def _omac[
    data_origin: Origin
](
    prepared: _PreparedAES,
    k1: List[UInt8],
    k2: List[UInt8],
    domain: UInt8,
    data: Span[UInt8, data_origin],
) raises -> List[UInt8]:
    # Process the domain block and data as one virtual CMAC message, without
    # materializing their concatenation.
    var domain_block = List[UInt8](length=16, fill=0)
    domain_block[15] = domain
    var output = List[UInt8](length=16, fill=0)
    if len(data) == 0:
        for i in range(16):
            domain_block[i] ^= k1[i]
        prepared.encrypt_into(Span(domain_block), Span(output), 0)
        return output^

    var state = List[UInt8](length=16, fill=0)
    var combined = List[UInt8](length=16, fill=0)
    prepared.encrypt_into(Span(domain_block), Span(state), 0)
    var state_pointer = Span(state).unsafe_ptr()
    var combined_pointer = Span(combined).unsafe_ptr()
    var data_pointer = data.unsafe_ptr()
    var offset = 0
    while offset + 16 < len(data):
        combined_pointer.unsafe_store[width=16](
            0,
            state_pointer.unsafe_load[width=16](0)
            ^ data_pointer.unsafe_load[width=16](offset),
        )
        prepared.encrypt_into(Span(combined), Span(state), 0)
        offset += 16

    var remaining = len(data) - offset
    var final = List[UInt8](length=16, fill=0)
    for i in range(remaining):
        final[i] = data[offset + i]
    if remaining == 16:
        for i in range(16):
            final[i] ^= k1[i]
    else:
        final[remaining] = 0x80
        for i in range(16):
            final[i] ^= k2[i]
    Span(final).unsafe_ptr().unsafe_store[width=16](
        0,
        Span(final).unsafe_ptr().unsafe_load[width=16](0)
        ^ state_pointer.unsafe_load[width=16](0),
    )
    prepared.encrypt_into(Span(final), Span(output), 0)
    return output^


@always_inline("nodebug")
def _increment(mut counter: List[UInt8]):
    var offset = 0
    while offset < 16:
        var i = 15 - offset
        counter[i] += 1
        if counter[i] != 0:
            return
        offset += 1


def _ctr[
    input_origin: Origin
](
    prepared: _PreparedAES,
    initial_counter: List[UInt8],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=len(input), fill=0)
    var counter = initial_counter.copy()
    var offset = 0
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
                _increment(counter)
            prepared.encrypt_eight(
                Span(counters),
                0,
                input,
                offset,
                Span(output),
                offset,
            )
            offset += 128
    while offset + 16 <= len(input):
        prepared.encrypt_into(Span(counter), Span(output), offset)
        comptime for i in range(16):
            output[offset + i] ^= input[offset + i]
        offset += 16
        _increment(counter)
    if offset < len(input):
        var stream = List[UInt8](length=16, fill=0)
        prepared.encrypt_into(Span(counter), Span(stream), 0)
        for i in range(len(input) - offset):
            output[offset + i] = input[offset + i] ^ stream[i]
    return output^


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
    """Encrypt and authenticate, returning detached ciphertext and tag."""
    _validate(key, tag_bytes)
    var prepared = _PreparedAES(key)
    var subkeys = _cmac_subkeys(prepared)
    var nonce_mac = _omac(prepared, subkeys[0], subkeys[1], 0, nonce)
    var header_mac = _omac(prepared, subkeys[0], subkeys[1], 1, aad)
    var ciphertext = _ctr(prepared, nonce_mac, message)
    var message_mac = _omac(
        prepared, subkeys[0], subkeys[1], 2, Span(ciphertext)
    )
    var tag = List[UInt8](capacity=tag_bytes)
    for i in range(tag_bytes):
        tag.append(nonce_mac[i] ^ header_mac[i] ^ message_mac[i])
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
    """Authenticate a detached EAX ciphertext before decrypting it."""
    _validate(key, len(tag))
    var prepared = _PreparedAES(key)
    var subkeys = _cmac_subkeys(prepared)
    var nonce_mac = _omac(prepared, subkeys[0], subkeys[1], 0, nonce)
    var header_mac = _omac(prepared, subkeys[0], subkeys[1], 1, aad)
    var message_mac = _omac(prepared, subkeys[0], subkeys[1], 2, ciphertext)
    var expected = List[UInt8](capacity=len(tag))
    for i in range(len(tag)):
        expected.append(nonce_mac[i] ^ header_mac[i] ^ message_mac[i])
    if not constant_time_equal(Span(expected), tag):
        raise Error("AES-EAX authentication failed")
    return _ctr(prepared, nonce_mac, ciphertext)
