from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.internal.bytes import (
    load_be32,
    load_be64,
    load_le32,
    load_le64,
    store_be32,
    store_be64,
    store_le32,
    store_le64,
    xor_into,
)
from mcrypto.internal.secret import SecretBytes


def test_word_load_store_roundtrips() raises:
    var input: List[UInt8] = [0, 1, 2, 3, 4, 5, 6, 7]
    assert_equal(load_le32(Span(input), 0), UInt32(0x03020100))
    assert_equal(load_be32(Span(input), 0), UInt32(0x00010203))
    assert_equal(load_le64(Span(input), 0), UInt64(0x0706050403020100))
    assert_equal(load_be64(Span(input), 0), UInt64(0x0001020304050607))
    var output = List[UInt8](length=32, fill=0)
    var output_span = Span(output)
    store_le32(UInt32(0x03020100), output_span, 0)
    store_be32(UInt32(0x00010203), output_span, 4)
    store_le64(UInt64(0x0706050403020100), output_span, 8)
    store_be64(UInt64(0x0001020304050607), output_span, 16)
    for i in range(4):
        assert_equal(output[i], input[i])
        assert_equal(output[4 + i], input[i])
    for i in range(8):
        assert_equal(output[8 + i], input[i])
        assert_equal(output[16 + i], input[i])


def test_bounds_and_xor() raises:
    var short: List[UInt8] = [1, 2, 3]
    with assert_raises():
        _ = load_le32(Span(short), 0)
    var left: List[UInt8] = [0xAA, 0x55]
    var right: List[UInt8] = [0x0F, 0xF0]
    var output = List[UInt8](length=2, fill=0)
    var output_span = Span(output)
    xor_into(Span(left), Span(right), output_span)
    var expected: List[UInt8] = [0xA5, 0xA5]
    assert_equal(output, expected)


def test_secret_bytes_contract() raises:
    var source: List[UInt8] = [1, 2, 3, 4]
    var secret = SecretBytes(Span(source))
    assert_equal(len(secret), 4)
    assert_equal(secret.expose_copy(), source)
    secret.mut_span()[0] = 9
    assert_equal(secret.expose_copy()[0], UInt8(9))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
