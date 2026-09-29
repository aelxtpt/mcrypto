"""PBKDF1 and PBKDF2-HMAC-SHA1/SHA256/SHA512 in pure Mojo."""

from ..hashes.algorithm import HashAlgorithm
from ..macs.algorithm import HmacAlgorithm
from ..hashes.sha1 import SHA1
from ..hashes.sha256 import SHA256
from ..macs.hmac import (
    _HMACKey,
    _finalize_sha1_into,
    _finalize_sha256_into,
)
from std.collections import InlineArray


def pbkdf1[
    password_origin: Origin, salt_origin: Origin
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    iterations: Int,
) raises -> List[UInt8]:
    if iterations <= 0 or output_bytes <= 0 or output_bytes > 32:
        raise Error("invalid PBKDF1 parameters")
    var digest = InlineArray[UInt8, 64](uninitialized=True)
    var state = SHA256()
    state.update(password)
    state.update(salt)
    _finalize_sha256_into(state, digest)
    for _ in range(1, iterations):
        var round_state = SHA256()
        round_state.update(Span(digest)[0:32])
        _finalize_sha256_into(round_state, digest)
    var output = List[UInt8](length=output_bytes, fill=0)
    for i in range(output_bytes):
        output[i] = digest[i]
    return output^


def _pbkdf2_prepared[
    salt_origin: Origin
](
    prepared: _HMACKey,
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    iterations: Int,
    hash_bytes: Int,
) raises -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    var accumulator = InlineArray[UInt8, 64](uninitialized=True)
    var u = InlineArray[UInt8, 64](uninitialized=True)
    var next = InlineArray[UInt8, 64](uninitialized=True)
    var block_number = InlineArray[UInt8, 4](uninitialized=True)
    var output_offset = 0
    var block_index = 1
    while output_offset < output_bytes:
        block_number[0] = UInt8(block_index >> 24)
        block_number[1] = UInt8(block_index >> 16)
        block_number[2] = UInt8(block_index >> 8)
        block_number[3] = UInt8(block_index)
        prepared.authenticate_pair_into(salt, Span(block_number), u)
        for i in range(hash_bytes):
            accumulator[i] = u[i]
        for round in range(1, iterations):
            if round & 1:
                prepared.authenticate_into(Span(u)[0:hash_bytes], next)
                for i in range(hash_bytes):
                    accumulator[i] ^= next[i]
            else:
                prepared.authenticate_into(Span(next)[0:hash_bytes], u)
                for i in range(hash_bytes):
                    accumulator[i] ^= u[i]
        var copy_bytes = min(hash_bytes, output_bytes - output_offset)
        for i in range(copy_bytes):
            output[output_offset + i] = accumulator[i]
        output_offset += copy_bytes
        block_index += 1
    return output^


def pbkdf2[
    password_origin: Origin, salt_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    iterations: Int,
) raises -> List[UInt8]:
    if (
        hash_algorithm != HashAlgorithm.SHA1
        and hash_algorithm != HashAlgorithm.SHA256
        and hash_algorithm != HashAlgorithm.SHA512
    ):
        raise Error("PBKDF2 requires SHA-1, SHA-256, or SHA-512")
    var hash_bytes = 20 if hash_algorithm == HashAlgorithm.SHA1 else (
        32 if hash_algorithm == HashAlgorithm.SHA256 else 64
    )
    var hmac_algorithm = (
        HmacAlgorithm.SHA1 if hash_algorithm
        == HashAlgorithm.SHA1 else (
            HmacAlgorithm.SHA256 if hash_algorithm
            == HashAlgorithm.SHA256 else HmacAlgorithm.SHA512
        )
    )
    if iterations <= 0 or output_bytes <= 0:
        raise Error("invalid PBKDF2 parameters")
    var prepared = _HMACKey(hmac_algorithm, password)
    return _pbkdf2_prepared(
        prepared, salt, output_bytes, iterations, hash_bytes
    )


def pkcs12_pbkdf_sha1[
    password_origin: Origin, salt_origin: Origin
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int,
    iterations: Int,
    purpose: UInt8,
) raises -> List[UInt8]:
    if output_bytes <= 0 or iterations <= 0:
        raise Error("invalid PKCS12 PBKDF parameters")
    var block_bytes = 64
    var salt_bytes = (
        (len(salt) + block_bytes - 1) // block_bytes
    ) * block_bytes if len(salt) != 0 else 0
    var password_bytes = (
        (len(password) + block_bytes - 1) // block_bytes
    ) * block_bytes if len(password) != 0 else 0
    var diversifier = InlineArray[UInt8, 64](fill=purpose)
    var input = List[UInt8](length=salt_bytes + password_bytes, fill=0)
    for i in range(salt_bytes):
        input[i] = salt[i % len(salt)]
    for i in range(password_bytes):
        input[salt_bytes + i] = password[i % len(password)]
    var output = List[UInt8](length=output_bytes, fill=0)
    var repeated = InlineArray[UInt8, 64](fill=0)
    var output_offset = 0
    var digest = InlineArray[UInt8, 64](fill=0)
    var next = InlineArray[UInt8, 64](fill=0)
    while output_offset < output_bytes:
        var state = SHA1()
        state.update(Span(diversifier))
        state.update(Span(input))
        _finalize_sha1_into(state, digest)
        for _ in range(1, iterations):
            var round_state = SHA1()
            round_state.update(Span(digest)[0:20])
            _finalize_sha1_into(round_state, next)
            for i in range(20):
                digest[i] = next[i]
        var copy_bytes = min(20, output_bytes - output_offset)
        for i in range(copy_bytes):
            output[output_offset + i] = digest[i]
        output_offset += copy_bytes
        for i in range(block_bytes):
            repeated[i] = digest[i % 20]
        var offset = 0
        while offset < len(input):
            var carry = 1
            for reverse in range(block_bytes):
                var index = offset + block_bytes - 1 - reverse
                var total = (
                    Int(input[index])
                    + Int(repeated[block_bytes - 1 - reverse])
                    + carry
                )
                input[index] = UInt8(total)
                carry = total >> 8
            offset += block_bytes
    return output^
