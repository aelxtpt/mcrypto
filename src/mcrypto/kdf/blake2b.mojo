"""Pure-Mojo interop-compatible BLAKE2b subkey derivation."""

from ..hashes.blake2 import (
    _blake2b_output_into,
    _compress_b,
    blake2b_keyed_salt_personal_into,
)
from ..internal.bytes import load_le64
from std.collections import InlineArray


struct PreparedBLAKE2bKDF(Movable):
    """Reusable interop BLAKE2b subkey derivation state."""

    var h0: SIMD[DType.uint64, 4]
    var h1: SIMD[DType.uint64, 4]
    var key_block: InlineArray[UInt8, 128]
    var output_bytes: Int

    def __init__[
        context_origin: Origin, key_origin: Origin
    ](
        out self,
        context: Span[UInt8, context_origin],
        key: Span[UInt8, key_origin],
        subkey_id: UInt64,
        output_bytes: Int = 32,
    ) raises:
        if (
            len(context) != 8
            or len(key) != 32
            or output_bytes < 16
            or output_bytes > 64
        ):
            raise Error(
                "BLAKE2b KDF requires 8-byte context, 32-byte key, and"
                " 16..64-byte output"
            )
        self.h0 = SIMD[DType.uint64, 4](
            0x6A09E667F3BCC908,
            0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B,
            0xA54FF53A5F1D36F1,
        )
        self.h1 = SIMD[DType.uint64, 4](
            0x510E527FADE682D1,
            0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B,
            0x5BE0CD19137E2179,
        )
        self.h0[0] ^= UInt64(output_bytes | (32 << 8) | 0x01010000)
        self.h1[0] ^= subkey_id
        self.h1[2] ^= load_le64(context, 0)
        self.key_block = InlineArray[UInt8, 128](fill=0)
        for i in range(32):
            self.key_block[i] = key[i]
        self.output_bytes = output_bytes

    def __init__(out self, *, deinit move: Self):
        self.h0 = move.h0
        self.h1 = move.h1
        self.key_block = move.key_block^
        self.output_bytes = move.output_bytes

    @always_inline("nodebug")
    def derive_into[
        output_origin: MutOrigin
    ](self, output: Span[mut=True, UInt8, output_origin]) raises:
        if len(output) != self.output_bytes:
            raise Error("BLAKE2b KDF prepared output length changed")
        var h0 = self.h0
        var h1 = self.h1
        _compress_b(
            h0,
            h1,
            Span(self.key_block),
            0,
            UInt128(128),
            True,
        )
        _blake2b_output_into(h0, h1, output)


def derive_into[
    context_origin: Origin,
    key_origin: Origin,
    output_origin: MutOrigin,
](
    context: Span[UInt8, context_origin],
    key: Span[UInt8, key_origin],
    subkey_id: UInt64,
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if (
        len(context) != 8
        or len(key) != 32
        or len(output) < 16
        or len(output) > 64
    ):
        raise Error(
            "BLAKE2b KDF requires 8-byte context, 32-byte key, and 16..64-byte"
            " output"
        )
    var salt = InlineArray[UInt8, 16](fill=0)
    for i in range(8):
        salt[i] = UInt8(subkey_id >> UInt64(8 * i))
    var personal = InlineArray[UInt8, 16](fill=0)
    for i in range(8):
        personal[i] = context[i]
    var empty = InlineArray[UInt8, 1](uninitialized=True)
    blake2b_keyed_salt_personal_into(
        Span(empty)[0:0], key, Span(salt), Span(personal), output
    )


def derive[
    context_origin: Origin, key_origin: Origin
](
    context: Span[UInt8, context_origin],
    key: Span[UInt8, key_origin],
    subkey_id: UInt64,
    output_bytes: Int = 32,
) raises -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    derive_into(context, key, subkey_id, Span(output))
    return output^
