from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes.sha1 import SHA1, sha1


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_fips180_sha1_vectors() raises:
    assert_equal(
        sha1(""), hex_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    )
    assert_equal(
        sha1("abc"), hex_bytes("a9993e364706816aba3e25717850c26c9cd0d89d")
    )
    assert_equal(
        sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        hex_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    )


def test_sha1_incremental_and_single_use() raises:
    var state = SHA1()
    state.update("a".as_bytes())
    state.update("bc".as_bytes())
    assert_equal(state.finalize(), sha1("abc"))
    with assert_raises():
        _ = state.finalize()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
