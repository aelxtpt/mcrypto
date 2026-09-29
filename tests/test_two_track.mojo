from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.macs.two_track import authenticate, authenticate_four_into


def hex_bytes(text: StaticString) -> List[UInt8]:
    var raw = text.as_bytes()
    var output = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw), 2):
        var high = Int(raw[i])
        var low = Int(raw[i + 1])
        high = high - (48 if high <= 57 else 87)
        low = low - (48 if low <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def check(message: StaticString, expected: StaticString) raises:
    var key = hex_bytes("00112233445566778899aabbccddeeff01234567")
    assert_equal(
        authenticate(Span(key), message.as_bytes()), hex_bytes(expected)
    )


def test_nessie_short_vectors() raises:
    # From the NESSIE Two-Track-MAC submission.
    check("", "2dec8ed4a0fd712ed9fbf2ab466ec2df21215e4a")
    check("a", "5893e3e6e306704dd77ad6e6ed432cde321a7756")
    check("abc", "70bfd1029797a5c16da5b557a1f0b2779b78497e")
    check("message digest", "8289f4f19ffe4f2af737de4bd71c829d93a972fa")
    check(
        "abcdefghijklmnopqrstuvwxyz", "2186ca09c5533198b7371f245273504ca92bae60"
    )
    check(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "8a7bf77aef62a2578497a27c0d6518a429e7c14d",
    )
    check(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "54bac392a886806d169556fcbb6789b54fb364fb",
    )


def test_nessie_repeated_vector() raises:
    var key = hex_bytes("00112233445566778899aabbccddeeff01234567")
    var message = List[UInt8](capacity=80)
    for _ in range(8):
        for byte in "1234567890".as_bytes():
            message.append(byte)
    assert_equal(
        authenticate(Span(key), Span(message)),
        hex_bytes("0ced2c9f8f0d9d03981ab5c8184bac43dd54c484"),
    )


def test_lengths_are_strict() raises:
    var short_key = List[UInt8](length=19, fill=0)
    var key = hex_bytes("00112233445566778899aabbccddeeff01234567")
    var empty = List[UInt8]()
    with assert_raises():
        _ = authenticate(Span(short_key), Span(empty))
    with assert_raises():
        _ = authenticate(Span(key), Span(empty), 10)
    assert_equal(
        authenticate(Span(key), Span(empty), 4),
        hex_bytes("0d7514d9"),
    )
    assert_equal(
        authenticate(Span(key), Span(empty), 8),
        hex_bytes("1358c3e29a1ac324"),
    )
    assert_equal(
        authenticate(Span(key), Span(empty), 12),
        hex_bytes("1358c3e29a1ac3244c564460"),
    )
    assert_equal(
        authenticate(Span(key), Span(empty), 16),
        hex_bytes("1358c3e29a1ac3244c564460078d9258"),
    )
    assert_equal(len(authenticate(Span(key), Span(empty), 4)), 4)
    assert_equal(len(authenticate(Span(key), Span(empty), 8)), 8)
    assert_equal(len(authenticate(Span(key), Span(empty), 12)), 12)
    assert_equal(len(authenticate(Span(key), Span(empty), 16)), 16)


def test_four_way_matches_independent_authentication() raises:
    var key = hex_bytes("00112233445566778899aabbccddeeff01234567")
    var first = List[UInt8](length=130, fill=0x11)
    var second = List[UInt8](length=130, fill=0x22)
    var third = List[UInt8](length=130, fill=0x33)
    var fourth = List[UInt8](length=130, fill=0x44)
    for tag_bytes in [4, 8, 12, 16, 20]:
        var first_output = List[UInt8](length=tag_bytes, fill=0)
        var second_output = List[UInt8](length=tag_bytes, fill=0)
        var third_output = List[UInt8](length=tag_bytes, fill=0)
        var fourth_output = List[UInt8](length=tag_bytes, fill=0)
        authenticate_four_into(
            Span(key),
            Span(first),
            Span(second),
            Span(third),
            Span(fourth),
            Span(first_output),
            Span(second_output),
            Span(third_output),
            Span(fourth_output),
        )
        assert_equal(
            first_output, authenticate(Span(key), Span(first), tag_bytes)
        )
        assert_equal(
            second_output, authenticate(Span(key), Span(second), tag_bytes)
        )
        assert_equal(
            third_output, authenticate(Span(key), Span(third), tag_bytes)
        )
        assert_equal(
            fourth_output, authenticate(Span(key), Span(fourth), tag_bytes)
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
