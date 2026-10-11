"""RFC 5869 HKDF-SHA256 and HKDF-SHA512 in pure Mojo."""

from ..hashes.algorithm import HashAlgorithm
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import _HMACKey, authenticate
from ..internal.secret import secure_zero
from std.collections import InlineArray


def _parameters(
    hash_algorithm: HashAlgorithm,
) raises -> Tuple[Int, HmacAlgorithm]:
    if hash_algorithm == HashAlgorithm.SHA256:
        return (32, HmacAlgorithm.SHA256)
    if hash_algorithm == HashAlgorithm.SHA512:
        return (64, HmacAlgorithm.SHA512)
    raise Error("HKDF requires SHA-256 or SHA-512")


def extract[
    salt_origin: Origin, key_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    salt: Span[UInt8, salt_origin],
    input_key_material: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    """Extract a HashLen-byte PRK; an empty salt means HashLen zero bytes."""
    var parameters = _parameters(hash_algorithm)
    if len(salt) == 0:
        var zero_salt = InlineArray[UInt8, 64](fill=0)
        return authenticate(
            parameters[1],
            Span(zero_salt)[0 : parameters[0]],
            input_key_material,
        )
    return authenticate(parameters[1], salt, input_key_material)


def expand[
    key_origin: Origin, context_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    pseudorandom_key: Span[UInt8, key_origin],
    context: Span[UInt8, context_origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    """Expand an already extracted PRK into 0..255*HashLen bytes."""
    var parameters = _parameters(hash_algorithm)
    var hash_bytes = parameters[0]
    if len(pseudorandom_key) < hash_bytes:
        raise Error("HKDF pseudorandom key must contain at least HashLen bytes")
    if output_bytes < 0 or output_bytes > 255 * hash_bytes:
        raise Error("invalid HKDF output length")
    var prepared = _HMACKey(parameters[1], pseudorandom_key)
    var output = List[UInt8](length=output_bytes, fill=0)
    var previous = InlineArray[UInt8, 64](uninitialized=True)
    var next = InlineArray[UInt8, 64](uninitialized=True)
    var counter_buffer = InlineArray[UInt8, 1](uninitialized=True)
    var output_offset = 0
    var previous_bytes = 0
    var counter = 1
    while output_offset < output_bytes:
        counter_buffer[0] = UInt8(counter)
        if counter & 1:
            prepared.authenticate_parts_into(
                Span(previous)[0:previous_bytes],
                context,
                Span(counter_buffer),
                next,
            )
        else:
            prepared.authenticate_parts_into(
                Span(next)[0:previous_bytes],
                context,
                Span(counter_buffer),
                previous,
            )
        var copy_bytes = min(hash_bytes, output_bytes - output_offset)
        if counter & 1:
            for i in range(copy_bytes):
                output[output_offset + i] = next[i]
        else:
            for i in range(copy_bytes):
                output[output_offset + i] = previous[i]
        previous_bytes = hash_bytes
        output_offset += copy_bytes
        counter += 1
    secure_zero(Span(previous))
    secure_zero(Span(next))
    return output^


def derive[
    salt_origin: Origin, key_origin: Origin, context_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    salt: Span[UInt8, salt_origin],
    key: Span[UInt8, key_origin],
    context: Span[UInt8, context_origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    """Extract then expand, retaining the existing positive-length contract."""
    var parameters = _parameters(hash_algorithm)
    if output_bytes <= 0 or output_bytes > 255 * parameters[0]:
        raise Error("invalid HKDF output length")
    var pseudorandom_key = extract(hash_algorithm, salt, key)
    try:
        var output = expand(
            hash_algorithm, Span(pseudorandom_key), context, output_bytes
        )
        secure_zero(Span(pseudorandom_key))
        return output^
    except error:
        secure_zero(Span(pseudorandom_key))
        raise error^
