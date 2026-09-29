"""CSPRNG and NIST DRBG interfaces in pure Mojo."""

from .algorithm import DrbgAlgorithm
from ..hashes.algorithm import HashAlgorithm
from ..macs.algorithm import HmacAlgorithm
from .entropy import system_entropy
from .drbg import hash_drbg, hmac_drbg


def random_bytes(output_bytes: Int) raises -> List[UInt8]:
    if output_bytes <= 0:
        raise Error("random output must be positive")
    return system_entropy(output_bytes)


def drbg[
    entropy_origin: Origin,
    nonce_origin: Origin,
    personalization_origin: Origin,
    additional_origin: Origin,
](
    algorithm: DrbgAlgorithm,
    entropy: Span[UInt8, entropy_origin],
    nonce: Span[UInt8, nonce_origin],
    personalization: Span[UInt8, personalization_origin],
    additional: Span[UInt8, additional_origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    if output_bytes <= 0 or output_bytes > 65536:
        raise Error("DRBG output must be 1..65536 bytes")
    if algorithm == DrbgAlgorithm.HASH_SHA256:
        return hash_drbg(
            HashAlgorithm.SHA256,
            entropy,
            nonce,
            personalization,
            additional,
            output_bytes,
        )
    if algorithm == DrbgAlgorithm.HASH_SHA512:
        return hash_drbg(
            HashAlgorithm.SHA512,
            entropy,
            nonce,
            personalization,
            additional,
            output_bytes,
        )
    if algorithm == DrbgAlgorithm.HMAC_SHA256:
        return hmac_drbg(
            HmacAlgorithm.SHA256,
            entropy,
            nonce,
            personalization,
            additional,
            output_bytes,
        )
    if algorithm == DrbgAlgorithm.HMAC_SHA512:
        return hmac_drbg(
            HmacAlgorithm.SHA512,
            entropy,
            nonce,
            personalization,
            additional,
            output_bytes,
        )
    raise Error("unknown DRBG")
