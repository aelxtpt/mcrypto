from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes.checksums import (
    adler32,
    crc32,
    crc32c,
    crc32c_four_into,
)


def test_standard_checksum_vectors() raises:
    var message = "123456789".as_bytes()
    var adler_expected: List[UInt8] = [0x09, 0x1E, 0x01, 0xDE]
    var crc_expected: List[UInt8] = [0xCB, 0xF4, 0x39, 0x26]
    var crc_c_expected: List[UInt8] = [0xE3, 0x06, 0x92, 0x83]
    assert_equal(adler32(message), adler_expected)
    assert_equal(crc32(message), crc_expected)
    assert_equal(crc32c(message), crc_c_expected)


def test_empty_checksums() raises:
    var empty = List[UInt8]()
    var adler_expected: List[UInt8] = [0, 0, 0, 1]
    var crc_expected: List[UInt8] = [0, 0, 0, 0]
    assert_equal(adler32(Span(empty)), adler_expected)
    assert_equal(crc32(Span(empty)), crc_expected)
    assert_equal(crc32c(Span(empty)), crc_expected)


def test_adler32_unrolled_boundaries() raises:
    for size in [127, 128, 129, 5551, 5552, 5553, 32768]:
        var input = List[UInt8](length=size, fill=0)
        var s1 = UInt32(1)
        var s2 = UInt32(0)
        for i in range(size):
            input[i] = UInt8(i * 197 + 31)
            s1 = (s1 + UInt32(input[i])) % 65521
            s2 = (s2 + s1) % 65521
        var expected: List[UInt8] = [
            UInt8(s2 >> 8),
            UInt8(s2),
            UInt8(s1 >> 8),
            UInt8(s1),
        ]
        assert_equal(adler32(Span(input)), expected)


def test_four_way_crc32c_matches_independent_messages() raises:
    var input0 = List[UInt8](length=1025, fill=0)
    var input1 = List[UInt8](length=1025, fill=1)
    var input2 = List[UInt8](length=1025, fill=0)
    var input3 = List[UInt8](length=1025, fill=0)
    for i in range(1025):
        input2[i] = UInt8(i & 255)
        input3[i] = UInt8((i * 197 + 31) & 255)
    var output0 = List[UInt8](length=4, fill=0)
    var output1 = List[UInt8](length=4, fill=0)
    var output2 = List[UInt8](length=4, fill=0)
    var output3 = List[UInt8](length=4, fill=0)
    crc32c_four_into(
        Span(input0),
        Span(input1),
        Span(input2),
        Span(input3),
        Span(output0),
        Span(output1),
        Span(output2),
        Span(output3),
    )
    assert_equal(output0, crc32c(Span(input0)))
    assert_equal(output1, crc32c(Span(input1)))
    assert_equal(output2, crc32c(Span(input2)))
    assert_equal(output3, crc32c(Span(input3)))
    var short_input = List[UInt8](length=1024, fill=0)
    with assert_raises():
        crc32c_four_into(
            Span(input0),
            Span(input1),
            Span(input2),
            Span(short_input),
            Span(output0),
            Span(output1),
            Span(output2),
            Span(output3),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
