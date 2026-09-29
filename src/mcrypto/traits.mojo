"""Zero-cost contracts shared by pure-Mojo cryptographic primitives."""

from std.memory import bitcast


trait Digest:
    comptime block_bytes: Int
    comptime digest_bytes: Int

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        ...

    def finalize(mut self) raises -> List[UInt8]:
        ...


trait ExtendableOutput:
    comptime rate_bytes: Int

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        ...

    def squeeze(mut self, output_bytes: Int) raises -> List[UInt8]:
        ...


trait MessageAuthenticator:
    comptime tag_bytes: Int

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        ...

    def finalize(mut self) raises -> List[UInt8]:
        ...


trait RandomAccessBlockCipher:
    comptime block_bytes: Int

    def encrypt_block[
        input_origin: Origin,
        output_origin: MutOrigin,
    ](
        self,
        input: Span[UInt8, input_origin],
        output: Span[mut=True, UInt8, output_origin],
    ) raises:
        ...

    def decrypt_block[
        input_origin: Origin,
        output_origin: MutOrigin,
    ](
        self,
        input: Span[UInt8, input_origin],
        output: Span[mut=True, UInt8, output_origin],
    ) raises:
        ...


trait StreamCipher:
    def xor[
        input_origin: Origin,
        output_origin: MutOrigin,
    ](
        mut self,
        input: Span[UInt8, input_origin],
        output: Span[mut=True, UInt8, output_origin],
    ) raises:
        ...


trait AuthenticatedCipher:
    comptime tag_bytes: Int

    def seal[
        nonce_origin: Origin,
        aad_origin: Origin,
        message_origin: Origin,
    ](
        self,
        nonce: Span[UInt8, nonce_origin],
        aad: Span[UInt8, aad_origin],
        message: Span[UInt8, message_origin],
    ) raises -> List[UInt8]:
        ...

    def open[
        nonce_origin: Origin,
        aad_origin: Origin,
        ciphertext_origin: Origin,
    ](
        self,
        nonce: Span[UInt8, nonce_origin],
        aad: Span[UInt8, aad_origin],
        ciphertext: Span[UInt8, ciphertext_origin],
    ) raises -> List[UInt8]:
        ...


@always_inline("nodebug")
def constant_time_equal[
    a_origin: Origin, b_origin: Origin
](a: Span[UInt8, a_origin], b: Span[UInt8, b_origin]) -> Bool:
    """Compare equal-length byte strings without data-dependent exits."""
    if len(a) != len(b):
        return False
    var difference = UInt64(0)
    var offset = 0
    while offset + 32 <= len(a):
        var lanes = bitcast[DType.uint64, 4](
            a.unsafe_ptr().unsafe_load[width=32](offset)
            ^ b.unsafe_ptr().unsafe_load[width=32](offset)
        )
        comptime for lane in range(4):
            difference |= UInt64(lanes[lane])
        offset += 32
    if offset + 16 <= len(a):
        var lanes = bitcast[DType.uint64, 2](
            a.unsafe_ptr().unsafe_load[width=16](offset)
            ^ b.unsafe_ptr().unsafe_load[width=16](offset)
        )
        difference |= UInt64(lanes[0]) | UInt64(lanes[1])
        offset += 16
    while offset < len(a):
        difference |= UInt64(a[offset] ^ b[offset])
        offset += 1
    return difference == 0


@always_inline("nodebug")
def constant_time_select(
    condition: UInt8, when_true: UInt8, when_false: UInt8
) -> UInt8:
    """Select a byte using an all-zero or all-one mask."""
    var mask = UInt8(0) - UInt8(condition != 0)
    return (when_true & mask) | (when_false & ~mask)


def wipe[origin: MutOrigin](data: Span[mut=True, UInt8, origin]):
    """Overwrite a mutable byte span before its storage is released."""
    for i in range(len(data)):
        data[i] = 0
