"""PKCS#7 padding as specified in RFC 5652 section 6.3."""

comptime _MAX_BLOCK_BYTES = 255


def _validate_block_size(block_size: Int) raises:
    if block_size < 1 or block_size > _MAX_BLOCK_BYTES:
        raise Error("PKCS#7 block size must be between 1 and 255 bytes")


def pad[
    origin: Origin
](data: Span[UInt8, origin], block_size: Int) raises -> List[UInt8]:
    """Append padding, including a complete block for aligned or empty input."""
    _validate_block_size(block_size)
    var padding_bytes = block_size - len(data) % block_size
    var output = List(data)
    for _ in range(padding_bytes):
        output.append(UInt8(padding_bytes))
    return output^


def unpad[
    origin: Origin
](data: Span[UInt8, origin], block_size: Int) raises -> List[UInt8]:
    """Validate all padding bytes before returning a copy of the message.

    The final-block scan has no padding-dependent early exit. This helper
    does not authenticate ciphertext; authenticate before exposing padding errors.
    """
    _validate_block_size(block_size)
    if len(data) == 0 or len(data) % block_size != 0:
        raise Error("invalid PKCS#7 padding")
    var padding_bytes = Int(data[len(data) - 1])
    var invalid = UInt8(padding_bytes == 0) | UInt8(padding_bytes > block_size)
    # Scan the whole final block. A mask selects only the claimed padding bytes.
    for offset in range(1, block_size + 1):
        var mask = UInt8(0) - UInt8(offset <= padding_bytes)
        invalid |= (data[len(data) - offset] ^ UInt8(padding_bytes)) & mask
    if invalid != 0:
        raise Error("invalid PKCS#7 padding")
    return List(data[0 : len(data) - padding_bytes])
