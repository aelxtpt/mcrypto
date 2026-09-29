from std.testing import assert_equal, assert_raises, assert_true, TestSuite
from mcrypto.hashes import (
    HashAlgorithm,
    digest_size,
    hash,
    hash_into,
)
from mcrypto.hashes.algorithm import parse_hash_algorithm
from mcrypto.hashes.dispatch import (
    digest_size_by_name,
    hash_by_name,
    hash_into_by_name,
)
from mcrypto.hashes.lsh256 import lsh256_two_into
from mcrypto.hashes.md_legacy import md2_two_into


def hex_digest(data: List[UInt8]) -> String:
    comptime digits: StaticString = "0123456789abcdef"
    var output = String(capacity=len(data) * 2)
    for byte in data:
        output += digits[byte=Int(byte >> 4)]
        output += digits[byte=Int(byte & 0x0F)]
    return output^


def test_nist_sha3_256_abc() raises:
    assert_equal(
        hex_digest(hash(HashAlgorithm.SHA3_256, "abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    )


def test_rfc7693_blake2b_abc() raises:
    assert_equal(
        hex_digest(hash(HashAlgorithm.BLAKE2B, "abc")),
        (
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        ),
    )


def test_legacy_md5_rfc1321() raises:
    assert_equal(
        hex_digest(hash(HashAlgorithm.MD5, "abc")),
        "900150983cd24fb0d6963f7d28e17f72",
    )


def test_sm3_gbt32905() raises:
    assert_equal(
        hex_digest(hash(HashAlgorithm.SM3, "abc")),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    )


def test_typed_hash_selection() raises:
    assert_equal(digest_size(HashAlgorithm.SHA256), 32)
    assert_equal(
        hex_digest(hash(HashAlgorithm.SHA256, "abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    var output = List[UInt8](length=32, fill=0)
    hash_into(HashAlgorithm.SHA256, "abc".as_bytes(), Span(output))
    assert_equal(output, hash(HashAlgorithm.SHA256, "abc"))


def test_dispatch_boundary_checks() raises:
    assert_true(parse_hash_algorithm("SHA-512") == HashAlgorithm.SHA512)
    with assert_raises():
        _ = parse_hash_algorithm("unknown")
    with assert_raises():
        _ = hash(HashAlgorithm.SHA256, "abc", 33)


def test_text_name_hash_boundaries() raises:
    var expected = hash(HashAlgorithm.SHA256, "abc")
    assert_equal(digest_size_by_name("SHA-256"), 32)
    assert_equal(hash_by_name("SHA-256", "abc"), expected)
    var output = List[UInt8](length=32, fill=0)
    hash_into_by_name("SHA-256", "abc".as_bytes(), Span(output))
    assert_equal(output, expected)
    with assert_raises():
        _ = digest_size_by_name("unknown")
    with assert_raises():
        _ = hash_by_name("unknown", "abc")
    with assert_raises():
        hash_into_by_name("unknown", "abc".as_bytes(), Span(output))


def test_hash_into_reuses_caller_output() raises:
    for algorithm in [
        HashAlgorithm.SHA1,
        HashAlgorithm.SHA224,
        HashAlgorithm.SHA256,
        HashAlgorithm.SHA384,
        HashAlgorithm.SHA512,
        HashAlgorithm.BLAKE2S,
        HashAlgorithm.BLAKE2B,
        HashAlgorithm.ADLER32,
        HashAlgorithm.CRC32,
        HashAlgorithm.MD2,
        HashAlgorithm.WHIRLPOOL,
        HashAlgorithm.LSH224,
        HashAlgorithm.LSH256,
        HashAlgorithm.LSH384,
        HashAlgorithm.LSH512,
        HashAlgorithm.LSH512_256,
    ]:
        var expected = hash(algorithm, "abc")
        var output = List[UInt8](length=digest_size(algorithm), fill=0)
        hash_into(algorithm, "abc".as_bytes(), Span(output))
        assert_equal(output, expected)
    var short_output = List[UInt8](length=31, fill=0)
    with assert_raises():
        hash_into(HashAlgorithm.SHA256, "abc".as_bytes(), Span(short_output))


def test_two_way_lsh256_matches_independent_hashes() raises:
    var first = List[UInt8](length=300, fill=0xA5)
    var second = List[UInt8](length=300, fill=0x5A)
    for bits in [224, 256]:
        var first_output = List[UInt8](length=bits // 8, fill=0)
        var second_output = List[UInt8](length=bits // 8, fill=0)
        lsh256_two_into(
            bits,
            Span(first),
            Span(second),
            Span(first_output),
            Span(second_output),
        )
        assert_equal(
            first_output,
            hash(
                HashAlgorithm.LSH224 if bits == 224 else HashAlgorithm.LSH256,
                Span(first),
            ),
        )
        assert_equal(
            second_output,
            hash(
                HashAlgorithm.LSH224 if bits == 224 else HashAlgorithm.LSH256,
                Span(second),
            ),
        )


def test_two_way_md2_matches_independent_hashes() raises:
    var first = List[UInt8](length=64, fill=0x3C)
    var second = List[UInt8](length=64, fill=0xC3)
    var first_output = List[UInt8](length=16, fill=0)
    var second_output = List[UInt8](length=16, fill=0)
    md2_two_into(
        Span(first),
        Span(second),
        Span(first_output),
        Span(second_output),
    )
    assert_equal(first_output, hash(HashAlgorithm.MD2, Span(first)))
    assert_equal(second_output, hash(HashAlgorithm.MD2, Span(second)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
