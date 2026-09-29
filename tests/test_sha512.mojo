from std.testing import assert_equal, TestSuite
from mcrypto.hashes.sha512 import (
    SHA384,
    SHA512,
    sha384,
    sha512,
    sha2_64_four_into,
)


def hex_digest(data: List[UInt8]) -> String:
    comptime digits: StaticString = "0123456789abcdef"
    var output = String(capacity=len(data) * 2)
    for byte in data:
        output += digits[byte=Int(byte >> 4)]
        output += digits[byte=Int(byte & 0x0F)]
    return output^


def test_nist_sha384_abc() raises:
    assert_equal(
        hex_digest(sha384("abc")),
        (
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        ),
    )


def test_nist_sha512_empty() raises:
    assert_equal(
        hex_digest(sha512("")),
        (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ),
    )


def test_nist_sha512_abc() raises:
    assert_equal(
        hex_digest(sha512("abc")),
        (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ),
    )


def test_sha512_incremental() raises:
    var state = SHA512()
    state.update("a".as_bytes())
    state.update("bc".as_bytes())
    assert_equal(hex_digest(state.finalize()), hex_digest(sha512("abc")))


def test_four_way_sha2_matches_independent_hashes() raises:
    var first = List[UInt8](length=300, fill=0x11)
    var second = List[UInt8](length=300, fill=0x22)
    var third = List[UInt8](length=300, fill=0x33)
    var fourth = List[UInt8](length=300, fill=0x44)
    var first512 = List[UInt8](length=64, fill=0)
    var second512 = List[UInt8](length=64, fill=0)
    var third512 = List[UInt8](length=64, fill=0)
    var fourth512 = List[UInt8](length=64, fill=0)
    sha2_64_four_into[False](
        Span(first),
        Span(second),
        Span(third),
        Span(fourth),
        Span(first512),
        Span(second512),
        Span(third512),
        Span(fourth512),
    )
    assert_equal(first512, sha512(Span(first)))
    assert_equal(second512, sha512(Span(second)))
    assert_equal(third512, sha512(Span(third)))
    assert_equal(fourth512, sha512(Span(fourth)))
    var first384 = List[UInt8](length=48, fill=0)
    var second384 = List[UInt8](length=48, fill=0)
    var third384 = List[UInt8](length=48, fill=0)
    var fourth384 = List[UInt8](length=48, fill=0)
    sha2_64_four_into[True](
        Span(first),
        Span(second),
        Span(third),
        Span(fourth),
        Span(first384),
        Span(second384),
        Span(third384),
        Span(fourth384),
    )
    assert_equal(first384, sha384(Span(first)))
    assert_equal(second384, sha384(Span(second)))
    assert_equal(third384, sha384(Span(third)))
    assert_equal(fourth384, sha384(Span(fourth)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
