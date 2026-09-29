from std.testing import TestSuite
from mcrypto.hashes import (
    HashAlgorithm,
    digest_size,
    hash,
)
from mcrypto.hashes.algorithm import parse_hash_algorithm


def test_every_fixed_hash_rejects_wrong_output_size() raises:
    var message = List[UInt8](length=1, fill=0)
    var accepted = False
    for algorithm in [
        HashAlgorithm.ADLER32,
        HashAlgorithm.BLAKE2B,
        HashAlgorithm.BLAKE2S,
        HashAlgorithm.CRC32,
        HashAlgorithm.CRC32C,
        HashAlgorithm.KECCAK224,
        HashAlgorithm.KECCAK256,
        HashAlgorithm.KECCAK384,
        HashAlgorithm.KECCAK512,
        HashAlgorithm.LSH224,
        HashAlgorithm.LSH256,
        HashAlgorithm.LSH384,
        HashAlgorithm.LSH512,
        HashAlgorithm.LSH512_256,
        HashAlgorithm.MD2,
        HashAlgorithm.MD4,
        HashAlgorithm.MD5,
        HashAlgorithm.PANAMA_HASH,
        HashAlgorithm.RIPEMD128,
        HashAlgorithm.RIPEMD160,
        HashAlgorithm.RIPEMD256,
        HashAlgorithm.RIPEMD320,
        HashAlgorithm.SHA1,
        HashAlgorithm.SHA224,
        HashAlgorithm.SHA256,
        HashAlgorithm.SHA384,
        HashAlgorithm.SHA512,
        HashAlgorithm.SHA3_224,
        HashAlgorithm.SHA3_256,
        HashAlgorithm.SHA3_384,
        HashAlgorithm.SHA3_512,
        HashAlgorithm.SM3,
        HashAlgorithm.TIGER,
        HashAlgorithm.WHIRLPOOL,
    ]:
        var rejected = False
        try:
            _ = hash(algorithm, Span(message), digest_size(algorithm) + 1)
        except:
            rejected = True
        if not rejected:
            accepted = True
    for invalid_name in ["SipHash", "SHAKE128", "SHAKE256"]:
        var rejected = False
        try:
            _ = parse_hash_algorithm(invalid_name)
        except:
            rejected = True
        if not rejected:
            accepted = True
    if accepted:
        raise Error("accepted an invalid hash selector or output size")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
