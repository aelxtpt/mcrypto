"""Unified pure-Mojo one-shot hash dispatcher."""

from .algorithm import HashAlgorithm, parse_hash_algorithm
from .sha1 import SHA1, sha1
from .sha256 import SHA224, SHA256, sha224, sha256
from .sha512 import SHA384, SHA512, sha384, sha512
from .keccak import sha3, keccak
from .blake2 import blake2s, blake2s_into, blake2b, blake2b_into
from .md_legacy import md2, md2_into, md4
from .md5 import md5
from .ripemd import ripemd128, ripemd160, ripemd256, ripemd320
from .checksums import adler32, adler32_into, crc32, crc32_into, crc32c
from .sm3 import sm3
from .panama import panama
from .tiger import tiger
from .whirlpool import whirlpool, whirlpool_into
from .lsh256 import lsh224, lsh256, lsh256_into
from .lsh512 import lsh384, lsh512, lsh512_256, lsh512_into


def digest_size(algorithm: HashAlgorithm) raises -> Int:
    if (
        algorithm == HashAlgorithm.SHA224
        or algorithm == HashAlgorithm.SHA3_224
        or algorithm == HashAlgorithm.KECCAK224
        or algorithm == HashAlgorithm.LSH224
    ):
        return 28
    if (
        algorithm == HashAlgorithm.SHA256
        or algorithm == HashAlgorithm.SHA3_256
        or algorithm == HashAlgorithm.KECCAK256
        or algorithm == HashAlgorithm.LSH256
        or algorithm == HashAlgorithm.LSH512_256
        or algorithm == HashAlgorithm.BLAKE2S
        or algorithm == HashAlgorithm.RIPEMD256
        or algorithm == HashAlgorithm.SM3
        or algorithm == HashAlgorithm.PANAMA_HASH
    ):
        return 32
    if (
        algorithm == HashAlgorithm.SHA384
        or algorithm == HashAlgorithm.SHA3_384
        or algorithm == HashAlgorithm.KECCAK384
        or algorithm == HashAlgorithm.LSH384
    ):
        return 48
    if (
        algorithm == HashAlgorithm.SHA512
        or algorithm == HashAlgorithm.SHA3_512
        or algorithm == HashAlgorithm.KECCAK512
        or algorithm == HashAlgorithm.LSH512
        or algorithm == HashAlgorithm.BLAKE2B
        or algorithm == HashAlgorithm.WHIRLPOOL
    ):
        return 64
    if algorithm == HashAlgorithm.SHA1 or algorithm == HashAlgorithm.RIPEMD160:
        return 20
    if algorithm == HashAlgorithm.TIGER:
        return 24
    if (
        algorithm == HashAlgorithm.MD2
        or algorithm == HashAlgorithm.MD4
        or algorithm == HashAlgorithm.MD5
        or algorithm == HashAlgorithm.RIPEMD128
    ):
        return 16
    if algorithm == HashAlgorithm.RIPEMD320:
        return 40
    if (
        algorithm == HashAlgorithm.ADLER32
        or algorithm == HashAlgorithm.CRC32
        or algorithm == HashAlgorithm.CRC32C
    ):
        return 4
    raise Error("invalid HashAlgorithm value")


def digest_size_by_name(name: String) raises -> Int:
    """Parse a catalog/CLI name and return its fixed digest size."""
    return digest_size(parse_hash_algorithm(name))


def _full[
    origin: Origin
](algorithm: HashAlgorithm, data: Span[UInt8, origin]) raises -> List[UInt8]:
    if algorithm == HashAlgorithm.SHA1:
        return sha1(data)
    if algorithm == HashAlgorithm.SHA224:
        return sha224(data)
    if algorithm == HashAlgorithm.SHA256:
        return sha256(data)
    if algorithm == HashAlgorithm.SHA384:
        return sha384(data)
    if algorithm == HashAlgorithm.SHA512:
        return sha512(data)
    if algorithm == HashAlgorithm.SHA3_224:
        return sha3(224, data)
    if algorithm == HashAlgorithm.SHA3_256:
        return sha3(256, data)
    if algorithm == HashAlgorithm.SHA3_384:
        return sha3(384, data)
    if algorithm == HashAlgorithm.SHA3_512:
        return sha3(512, data)
    if algorithm == HashAlgorithm.SM3:
        return sm3(data)
    if algorithm == HashAlgorithm.KECCAK224:
        return keccak(224, data)
    if algorithm == HashAlgorithm.KECCAK256:
        return keccak(256, data)
    if algorithm == HashAlgorithm.KECCAK384:
        return keccak(384, data)
    if algorithm == HashAlgorithm.KECCAK512:
        return keccak(512, data)
    if algorithm == HashAlgorithm.BLAKE2S:
        return blake2s(data)
    if algorithm == HashAlgorithm.BLAKE2B:
        return blake2b(data)
    if algorithm == HashAlgorithm.MD2:
        return md2(data)
    if algorithm == HashAlgorithm.MD4:
        return md4(data)
    if algorithm == HashAlgorithm.MD5:
        return md5(data)
    if algorithm == HashAlgorithm.RIPEMD128:
        return ripemd128(data)
    if algorithm == HashAlgorithm.RIPEMD160:
        return ripemd160(data)
    if algorithm == HashAlgorithm.RIPEMD256:
        return ripemd256(data)
    if algorithm == HashAlgorithm.RIPEMD320:
        return ripemd320(data)
    if algorithm == HashAlgorithm.CRC32:
        return crc32(data)
    if algorithm == HashAlgorithm.CRC32C:
        return crc32c(data)
    if algorithm == HashAlgorithm.LSH224:
        return lsh224(data)
    if algorithm == HashAlgorithm.LSH256:
        return lsh256(256, data)
    if algorithm == HashAlgorithm.LSH384:
        return lsh384(data)
    if algorithm == HashAlgorithm.LSH512:
        return lsh512(512, data)
    if algorithm == HashAlgorithm.LSH512_256:
        return lsh512_256(data)
    if algorithm == HashAlgorithm.ADLER32:
        return adler32(data)
    if algorithm == HashAlgorithm.PANAMA_HASH:
        return panama(data)
    if algorithm == HashAlgorithm.TIGER:
        return tiger(data)
    if algorithm == HashAlgorithm.WHIRLPOOL:
        return whirlpool(data)
    raise Error("invalid HashAlgorithm value")


def hash_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    algorithm: HashAlgorithm,
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) != digest_size(algorithm):
        raise Error("hash output span has invalid length")
    if algorithm == HashAlgorithm.SHA1:
        var state = SHA1()
        state.update(data)
        state.finalize_into(output)
        return
    if algorithm == HashAlgorithm.SHA224:
        var state = SHA224()
        state.update(data)
        state.finalize_into(output)
        return
    if algorithm == HashAlgorithm.SHA256:
        var state = SHA256()
        state.update(data)
        state.finalize_into(output)
        return
    if algorithm == HashAlgorithm.SHA384:
        var state = SHA384()
        state.update(data)
        state.finalize_into(output)
        return
    if algorithm == HashAlgorithm.SHA512:
        var state = SHA512()
        state.update(data)
        state.finalize_into(output)
        return
    if algorithm == HashAlgorithm.BLAKE2S:
        blake2s_into(data, output)
        return
    if algorithm == HashAlgorithm.BLAKE2B:
        blake2b_into(data, output)
        return
    if algorithm == HashAlgorithm.ADLER32:
        adler32_into(data, output)
        return
    if algorithm == HashAlgorithm.CRC32:
        crc32_into(data, output)
        return
    if algorithm == HashAlgorithm.MD2:
        md2_into(data, output)
        return
    if algorithm == HashAlgorithm.WHIRLPOOL:
        whirlpool_into(data, output)
        return
    if algorithm == HashAlgorithm.LSH224:
        lsh256_into(224, data, output)
        return
    if algorithm == HashAlgorithm.LSH256:
        lsh256_into(256, data, output)
        return
    if algorithm == HashAlgorithm.LSH384:
        lsh512_into(384, data, output)
        return
    if algorithm == HashAlgorithm.LSH512:
        lsh512_into(512, data, output)
        return
    if algorithm == HashAlgorithm.LSH512_256:
        lsh512_into(256, data, output)
        return
    var full = _full(algorithm, data)
    for i in range(len(output)):
        output[i] = full[i]


def hash[
    origin: Origin
](
    algorithm: HashAlgorithm,
    data: Span[UInt8, origin],
    output_bytes: Int = 0,
) raises -> List[UInt8]:
    var full = _full(algorithm, data)
    var size = len(full) if output_bytes == 0 else output_bytes
    if size <= 0 or size > len(full):
        raise Error("invalid hash output length")
    if size == len(full):
        return full^
    var output = List[UInt8](capacity=size)
    for i in range(size):
        output.append(full[i])
    return output^


def hash(
    algorithm: HashAlgorithm, text: String, output_bytes: Int = 0
) raises -> List[UInt8]:
    return hash(algorithm, text.as_bytes(), output_bytes)


def hash_into_by_name[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    name: String,
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    """Parse a catalog/CLI name and hash into caller-owned output."""
    hash_into(parse_hash_algorithm(name), data, output)


def hash_by_name[
    origin: Origin
](
    name: String, data: Span[UInt8, origin], output_bytes: Int = 0
) raises -> List[UInt8]:
    """Parse a catalog/CLI name and return the selected digest."""
    return hash(parse_hash_algorithm(name), data, output_bytes)


def hash_by_name(
    name: String, text: String, output_bytes: Int = 0
) raises -> List[UInt8]:
    """Parse a catalog/CLI name and hash a text value."""
    return hash_by_name(name, text.as_bytes(), output_bytes)
