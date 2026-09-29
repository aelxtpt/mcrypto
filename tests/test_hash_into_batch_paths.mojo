from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes import HashAlgorithm, hash, hash_into
from mcrypto.hashes.keccak import sha3, sha3_four_into
from mcrypto.hashes.lsh256 import lsh256, lsh256_two_into
from mcrypto.hashes.sha512 import sha512, sha2_64_four_into


def test_hash_into_nonzero_offsets_and_boundaries() raises:
    for size in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129]:
        var message = List[UInt8](length=size, fill=UInt8(size))
        var storage = List[UInt8](length=42, fill=0xA5)
        hash_into(HashAlgorithm.SHA256, Span(message), Span(storage)[5:37])
        assert_equal(
            List(Span(storage)[5:37]),
            hash(HashAlgorithm.SHA256, Span(message)),
        )
        for i in range(5):
            assert_equal(storage[i], UInt8(0xA5))
        for i in range(37, 42):
            assert_equal(storage[i], UInt8(0xA5))
    var message: List[UInt8] = [1, 2, 3]
    var short = List[UInt8](length=31, fill=0)
    with assert_raises():
        hash_into(HashAlgorithm.SHA256, Span(message), Span(short))


def test_hash_batch_paths_match_scalar_with_offset_storage() raises:
    for size in [135, 136, 137, 271, 272, 273]:
        var first = List[UInt8](length=size, fill=0x11)
        var second = List[UInt8](length=size, fill=0x22)
        var third = List[UInt8](length=size, fill=0x33)
        var fourth = List[UInt8](length=size, fill=0x44)
        var first_storage = List[UInt8](length=42, fill=0xA5)
        var second_storage = List[UInt8](length=42, fill=0xA5)
        var third_storage = List[UInt8](length=42, fill=0xA5)
        var fourth_storage = List[UInt8](length=42, fill=0xA5)
        sha3_four_into(
            256,
            Span(first),
            Span(second),
            Span(third),
            Span(fourth),
            Span(first_storage)[5:37],
            Span(second_storage)[5:37],
            Span(third_storage)[5:37],
            Span(fourth_storage)[5:37],
        )
        assert_equal(List(Span(first_storage)[5:37]), sha3(256, Span(first)))
        assert_equal(List(Span(second_storage)[5:37]), sha3(256, Span(second)))
        assert_equal(List(Span(third_storage)[5:37]), sha3(256, Span(third)))
        assert_equal(List(Span(fourth_storage)[5:37]), sha3(256, Span(fourth)))
    var first = List[UInt8](length=255, fill=0x5A)
    var second = List[UInt8](length=255, fill=0xA5)
    var first_output = List[UInt8](length=32, fill=0)
    var second_output = List[UInt8](length=32, fill=0)
    lsh256_two_into(
        256,
        Span(first),
        Span(second),
        Span(first_output),
        Span(second_output),
    )
    assert_equal(first_output, lsh256(256, Span(first)))
    assert_equal(second_output, lsh256(256, Span(second)))


def test_sha512_four_way_thresholds_match_scalar() raises:
    for size in [127, 128, 129, 255, 256, 257]:
        var first = List[UInt8](length=size, fill=1)
        var second = List[UInt8](length=size, fill=2)
        var third = List[UInt8](length=size, fill=3)
        var fourth = List[UInt8](length=size, fill=4)
        var first_output = List[UInt8](length=64, fill=0)
        var second_output = List[UInt8](length=64, fill=0)
        var third_output = List[UInt8](length=64, fill=0)
        var fourth_output = List[UInt8](length=64, fill=0)
        sha2_64_four_into[False](
            Span(first),
            Span(second),
            Span(third),
            Span(fourth),
            Span(first_output),
            Span(second_output),
            Span(third_output),
            Span(fourth_output),
        )
        assert_equal(first_output, sha512(Span(first)))
        assert_equal(second_output, sha512(Span(second)))
        assert_equal(third_output, sha512(Span(third)))
        assert_equal(fourth_output, sha512(Span(fourth)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
