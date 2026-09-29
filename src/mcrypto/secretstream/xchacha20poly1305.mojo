"""Pure-Mojo interop-compatible stateful XChaCha20-Poly1305 secret streams."""


from ..ciphers.stream import _hchacha_inline
from ..internal.bytes import copy_into
from ..random.entropy import system_entropy
from ..internal.secret import secure_zero
from ..traits import constant_time_equal
from ..secretbox._stream_into import (
    chacha20_ietf_state,
    chacha20_ietf_xor_into,
    chacha20_secretstream_material_into,
)
from ._poly1305 import (
    _Poly1305,
    _authenticate_record_prefix,
    _authenticate_record_suffix,
    authenticate_record_into,
)

comptime MESSAGE = UInt8(0)
comptime PUSH = UInt8(1)
comptime REKEY = UInt8(2)
comptime FINAL = UInt8(3)
comptime OVERHEAD = 17


@always_inline("nodebug")
def _increment(mut nonce: InlineArray[UInt8, 12]):
    for i in range(4):
        nonce[i] += 1
        if nonce[i] != 0:
            break


def _rekey_state[
    key_origin: MutOrigin, nonce_origin: MutOrigin
](
    key: Span[mut=True, UInt8, key_origin],
    nonce: Span[mut=True, UInt8, nonce_origin],
) raises:
    var material = InlineArray[UInt8, 40](fill=0)
    copy_into(key, Span(material))
    copy_into(nonce[4:12], Span(material), 32)
    var encrypted = InlineArray[UInt8, 40](fill=0)
    var state = chacha20_ietf_state(key, nonce)
    chacha20_ietf_xor_into(state, Span(material), Span(encrypted), 0)
    copy_into(Span(encrypted)[0:32], key)
    copy_into(Span(encrypted)[32:40], nonce, 4)
    comptime for i in range(4):
        nonce[i] = 0
    nonce[0] = 1


@always_inline("nodebug")
def _derive_key[
    key_origin: Origin, header_origin: Origin
](
    key: Span[UInt8, key_origin], header: Span[UInt8, header_origin]
) raises -> InlineArray[UInt8, 32]:
    return _hchacha_inline(key, header[0:16])


struct PushStream(Movable):
    var _key: InlineArray[UInt8, 32]
    var _nonce: InlineArray[UInt8, 12]
    var _live: Bool
    var header: List[UInt8]

    def __init__[origin: Origin](out self, key: Span[UInt8, origin]) raises:
        if len(key) != 32:
            raise Error("secretstream key must be 32 bytes")
        self.header = system_entropy(24)
        self._key = _derive_key(key, Span(self.header))
        self._nonce = InlineArray[UInt8, 12](fill=0)
        self._nonce[0] = 1
        comptime for i in range(8):
            self._nonce[4 + i] = self.header[16 + i]
        self._live = True

    def __init__[
        key_origin: Origin, header_origin: Origin
    ](
        out self,
        key: Span[UInt8, key_origin],
        header: Span[UInt8, header_origin],
    ) raises:
        """Initialize from a caller-provided unique 24-byte header."""
        if len(key) != 32 or len(header) != 24:
            raise Error(
                "secretstream requires a 32-byte key and 24-byte header"
            )
        self.header = List[UInt8](length=24, fill=0)
        for i in range(24):
            self.header[i] = header[i]
        self._key = _derive_key(key, Span(self.header))
        self._nonce = InlineArray[UInt8, 12](fill=0)
        self._nonce[0] = 1
        comptime for i in range(8):
            self._nonce[4 + i] = self.header[16 + i]
        self._live = True

    def __init__(out self, *, deinit move: Self):
        self._key = move._key^
        self._nonce = move._nonce^
        self._live = move._live
        self.header = move.header^

    def _rekey(mut self) raises:
        _rekey_state(Span(self._key), Span(self._nonce))

    def push_into[
        message_origin: Origin,
        aad_origin: Origin,
        output_origin: MutOrigin,
    ](
        mut self,
        message: Span[UInt8, message_origin],
        aad: Span[UInt8, aad_origin],
        output: Span[mut=True, UInt8, output_origin],
        tag: UInt8 = MESSAGE,
    ) raises:
        if (
            not self._live
            or tag > FINAL
            or len(output) != len(message) + OVERHEAD
        ):
            raise Error("invalid secretstream push state, tag, or output")
        var state = chacha20_ietf_state(Span(self._key), Span(self._nonce))
        var poly_key = InlineArray[UInt8, 32](fill=0)
        var tag_block = InlineArray[UInt8, 64](fill=0)
        var encrypted_tag = chacha20_secretstream_material_into[False](
            state, tag, Span(poly_key), Span(tag_block)
        )
        output[0] = encrypted_tag
        var poly = _Poly1305(Span(poly_key))
        _authenticate_record_prefix(poly, aad, Span(tag_block))
        var offset = 0
        while offset + 4096 <= len(message):
            chacha20_ietf_xor_into(
                state,
                message[offset : offset + 4096],
                output,
                1 + offset,
                128 + offset,
            )
            offset += 4096
        if offset < len(message):
            chacha20_ietf_xor_into(
                state,
                message[offset:],
                output,
                1 + offset,
                128 + offset,
            )
        offset = 0
        while offset + 64 <= len(message):
            poly.update_four(output[1 + offset : 1 + offset + 64])
            offset += 64
        if offset + 32 <= len(message):
            poly.update_pair(output[1 + offset : 1 + offset + 32])
            offset += 32
        var tail_bytes = len(message) - offset
        var ciphertext_tail = InlineArray[UInt8, 32](fill=0)
        for i in range(tail_bytes):
            ciphertext_tail[i] = output[1 + offset + i]
        _authenticate_record_suffix(
            poly,
            Span(ciphertext_tail)[0:tail_bytes],
            len(message),
            len(aad),
            output,
            len(message) + 1,
        )
        comptime for i in range(8):
            self._nonce[4 + i] ^= output[len(message) + 1 + i]
        _increment(self._nonce)
        if tag == REKEY or tag == FINAL:
            self._rekey()
        if tag == FINAL:
            self._live = False
        return

    def push[
        message_origin: Origin, aad_origin: Origin
    ](
        mut self,
        message: Span[UInt8, message_origin],
        aad: Span[UInt8, aad_origin],
        tag: UInt8 = MESSAGE,
    ) raises -> List[UInt8]:
        """Encrypt and authenticate one secretstream record."""
        var output = List[UInt8](unsafe_uninit_length=len(message) + OVERHEAD)
        self.push_into(message, aad, Span(output), tag)
        return output^

    def rekey(mut self) raises:
        if not self._live:
            raise Error("invalid secretstream state")
        self._rekey()


def push_streams_eight[
    origin: Origin
](key: Span[UInt8, origin],) raises -> List[PushStream]:
    """Initialize eight push streams from one batched OS-entropy request."""
    if len(key) != 32:
        raise Error("secretstream key must be 32 bytes")
    var headers = system_entropy(8 * 24)
    var streams = List[PushStream](capacity=8)
    comptime for lane in range(8):
        comptime start = lane * 24
        streams.append(PushStream(key, Span(headers)[start : start + 24]))
    return streams^


struct PullStream(Movable):
    var _key: InlineArray[UInt8, 32]
    var _nonce: InlineArray[UInt8, 12]
    var _live: Bool

    def __init__[
        key_origin: Origin, header_origin: Origin
    ](
        out self,
        key: Span[UInt8, key_origin],
        header: Span[UInt8, header_origin],
    ) raises:
        if len(key) != 32 or len(header) != 24:
            raise Error(
                "secretstream requires a 32-byte key and 24-byte header"
            )
        self._key = _derive_key(key, header)
        self._nonce = InlineArray[UInt8, 12](fill=0)
        self._nonce[0] = 1
        comptime for i in range(8):
            self._nonce[4 + i] = header[16 + i]
        self._live = True

    def __init__(out self, *, deinit move: Self):
        self._key = move._key^
        self._nonce = move._nonce^
        self._live = move._live

    def _rekey(mut self) raises:
        _rekey_state(Span(self._key), Span(self._nonce))

    def pull_into[
        cipher_origin: Origin,
        aad_origin: Origin,
        message_origin: MutOrigin,
    ](
        mut self,
        ciphertext: Span[UInt8, cipher_origin],
        aad: Span[UInt8, aad_origin],
        message: Span[mut=True, UInt8, message_origin],
    ) raises -> UInt8:
        if (
            not self._live
            or len(ciphertext) < OVERHEAD
            or len(message) != len(ciphertext) - OVERHEAD
        ):
            raise Error("invalid secretstream ciphertext, state, or output")
        var mlen = len(message)
        var state = chacha20_ietf_state(Span(self._key), Span(self._nonce))
        var poly_key = InlineArray[UInt8, 32](fill=0)
        var tag_block = InlineArray[UInt8, 64](fill=0)
        var tag = chacha20_secretstream_material_into[True](
            state, ciphertext[0], Span(poly_key), Span(tag_block)
        )
        var expected = InlineArray[UInt8, 16](fill=0)
        authenticate_record_into(
            Span(poly_key),
            aad,
            Span(tag_block),
            ciphertext[1 : 1 + mlen],
            Span(expected),
        )
        chacha20_ietf_xor_into(state, ciphertext[1 : 1 + mlen], message, 0, 128)
        if not constant_time_equal(Span(expected), ciphertext[1 + mlen :]):
            secure_zero(message)
            raise Error("secretstream authentication failed")
        comptime for i in range(8):
            self._nonce[4 + i] ^= expected[i]
        _increment(self._nonce)
        if tag == REKEY or tag == FINAL:
            self._rekey()
        if tag == FINAL:
            self._live = False
        return tag

    def pull[
        cipher_origin: Origin, aad_origin: Origin
    ](
        mut self,
        ciphertext: Span[UInt8, cipher_origin],
        aad: Span[UInt8, aad_origin],
    ) raises -> Tuple[List[UInt8], UInt8]:
        """Authenticate and decrypt one secretstream record."""
        if len(ciphertext) < OVERHEAD:
            raise Error("invalid secretstream ciphertext")
        var message = List[UInt8](
            unsafe_uninit_length=len(ciphertext) - OVERHEAD
        )
        var tag = self.pull_into(ciphertext, aad, Span(message))
        return (message^, tag)

    def rekey(mut self) raises:
        if not self._live:
            raise Error("invalid secretstream state")
        self._rekey()
