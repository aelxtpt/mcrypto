from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes.sha256 import SHA224, SHA256, sha224, sha256


def hex_digest(data: List[UInt8]) -> String:
    comptime digits: StaticString = "0123456789abcdef"
    var output = String(capacity=len(data) * 2)
    for byte in data:
        output += digits[byte=Int(byte >> 4)]
        output += digits[byte=Int(byte & 0x0F)]
    return output^


def test_nist_empty() raises:
    assert_equal(
        hex_digest(sha256("")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_nist_abc() raises:
    assert_equal(
        hex_digest(sha256("abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )


def test_nist_sha224_abc() raises:
    assert_equal(
        hex_digest(sha224("abc")),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    )


def test_nist_multiblock() raises:
    assert_equal(
        hex_digest(
            sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        ),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    )


def test_incremental_boundaries() raises:
    var state = SHA256()
    state.update("a".as_bytes())
    state.update("b".as_bytes())
    state.update("c".as_bytes())
    assert_equal(
        hex_digest(state.finalize()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )


def test_finalize_is_single_use() raises:
    var state = SHA256()
    state.update("abc".as_bytes())
    _ = state.finalize()
    with assert_raises():
        _ = state.finalize()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
