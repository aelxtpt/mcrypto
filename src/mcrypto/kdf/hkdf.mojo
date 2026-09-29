"""HKDF-SHA256 and HKDF-SHA512 in pure Mojo."""

from ..hashes.algorithm import HashAlgorithm
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import _HMACKey
from std.collections import InlineArray


def derive[
    salt_origin: Origin, key_origin: Origin, context_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    salt: Span[UInt8, salt_origin],
    key: Span[UInt8, key_origin],
    context: Span[UInt8, context_origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    if (
        hash_algorithm != HashAlgorithm.SHA256
        and hash_algorithm != HashAlgorithm.SHA512
    ):
        raise Error("HKDF requires SHA-256 or SHA-512")
    var hash_bytes = 32 if hash_algorithm == HashAlgorithm.SHA256 else 64
    var hmac_algorithm = (
        HmacAlgorithm.SHA256 if hash_algorithm
        == HashAlgorithm.SHA256 else HmacAlgorithm.SHA512
    )
    if output_bytes <= 0 or output_bytes > 255 * hash_bytes:
        raise Error("invalid HKDF output length")
    var prk = InlineArray[UInt8, 64](uninitialized=True)
    if len(salt) == 0:
        var zero_salt = InlineArray[UInt8, 64](fill=0)
        var extract = _HMACKey(hmac_algorithm, Span(zero_salt))
        extract.authenticate_into(key, prk)
    else:
        var extract = _HMACKey(hmac_algorithm, salt)
        extract.authenticate_into(key, prk)
    var expand = _HMACKey(hmac_algorithm, Span(prk)[0:hash_bytes])
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
            expand.authenticate_parts_into(
                Span(previous)[0:previous_bytes],
                context,
                Span(counter_buffer),
                next,
            )
        else:
            expand.authenticate_parts_into(
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
    return output^
