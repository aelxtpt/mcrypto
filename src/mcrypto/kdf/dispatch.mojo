"""Pure-Mojo KDF dispatcher."""

from .algorithm import KdfAlgorithm
from ..hashes.algorithm import HashAlgorithm
from .hkdf import derive as hkdf
from .pbkdf import pbkdf1, pbkdf2, pkcs12_pbkdf_sha1
from .scrypt import scrypt
from .argon2 import argon2i, argon2id


def derive[
    secret_origin: Origin, salt_origin: Origin, info_origin: Origin
](
    algorithm: KdfAlgorithm,
    secret: Span[UInt8, secret_origin],
    salt: Span[UInt8, salt_origin],
    info: Span[UInt8, info_origin],
    output_bytes: Int,
    iterations: Int = 1,
    purpose: UInt8 = 0,
    cost: UInt64 = 16,
    block_size: UInt64 = 1,
    parallelization: UInt64 = 1,
) raises -> List[UInt8]:
    if algorithm == KdfAlgorithm.HKDF_SHA256:
        return hkdf(HashAlgorithm.SHA256, salt, secret, info, output_bytes)
    if algorithm == KdfAlgorithm.HKDF_SHA512:
        return hkdf(HashAlgorithm.SHA512, salt, secret, info, output_bytes)
    if algorithm == KdfAlgorithm.PBKDF1:
        return pbkdf1(secret, salt, output_bytes, iterations)
    if algorithm == KdfAlgorithm.PBKDF2_HMAC_SHA256:
        return pbkdf2(
            HashAlgorithm.SHA256, secret, salt, output_bytes, iterations
        )
    if algorithm == KdfAlgorithm.PBKDF2_HMAC_SHA1:
        return pbkdf2(
            HashAlgorithm.SHA1, secret, salt, output_bytes, iterations
        )
    if algorithm == KdfAlgorithm.PBKDF2_HMAC_SHA512:
        return pbkdf2(
            HashAlgorithm.SHA512, secret, salt, output_bytes, iterations
        )
    if algorithm == KdfAlgorithm.PKCS12_PBKDF_SHA1:
        return pkcs12_pbkdf_sha1(
            secret, salt, output_bytes, iterations, purpose
        )
    if algorithm == KdfAlgorithm.SCRYPT:
        return scrypt(
            secret,
            salt,
            output_bytes,
            Int(cost),
            Int(block_size),
            Int(parallelization),
        )
    if algorithm == KdfAlgorithm.ARGON2I:
        return argon2i(
            secret,
            salt,
            output_bytes,
            iterations,
            Int(cost),
            Int(parallelization),
        )
    if algorithm == KdfAlgorithm.ARGON2ID:
        return argon2id(
            secret,
            salt,
            output_bytes,
            iterations,
            Int(cost),
            Int(parallelization),
        )
    raise Error("unknown pure-Mojo KDF")
