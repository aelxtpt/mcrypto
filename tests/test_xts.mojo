from std.testing import assert_equal, assert_true, TestSuite
from mcrypto.ciphers.xts import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high -= 48 if high <= 57 else 87
        low -= 48 if low <= 57 else 87
        output.append(UInt8(high * 16 + low))
    return output^


def check_vector(
    key_text: StaticString,
    tweak_text: StaticString,
    plain_text: StaticString,
    cipher_text: StaticString,
) raises:
    var key = hex_bytes(key_text)
    var tweak = hex_bytes(tweak_text)
    var plain = hex_bytes(plain_text)
    var expected = hex_bytes(cipher_text)
    var encrypted = process(
        BlockCipherAlgorithm.AES, True, Span(key), Span(tweak), Span(plain)
    )
    assert_equal(encrypted, expected)
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            False,
            Span(key),
            Span(tweak),
            Span(encrypted),
        ),
        plain,
    )


def test_p1619_vectors_1_to_3() raises:
    check_vector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
    )
    check_vector(
        "1111111111111111111111111111111122222222222222222222222222222222",
        "33333333330000000000000000000000",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
    )
    check_vector(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
        "33333333330000000000000000000000",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
    )


def test_p1619_ciphertext_stealing() raises:
    check_vector(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
        "9a785634120000000000000000000000",
        "000102030405060708090a0b0c0d0e0f10",
        "6c1625db4671522d3d7599601de7ca09ed",
    )


def test_threefish_wide_xts_roundtrip() raises:
    var key = List[UInt8](length=64, fill=0)
    var tweak = List[UInt8](length=32, fill=0)
    var plain = List[UInt8](length=49, fill=0)
    for i in range(len(key)):
        key[i] = UInt8(i)
    for i in range(len(tweak)):
        tweak[i] = UInt8(i * 3)
    for i in range(len(plain)):
        plain[i] = UInt8(i * 5)
    var cipher = process(
        BlockCipherAlgorithm.THREEFISH256,
        True,
        Span(key),
        Span(tweak),
        Span(plain),
    )
    assert_true(cipher != plain)
    assert_equal(
        process(
            BlockCipherAlgorithm.THREEFISH256,
            False,
            Span(key),
            Span(tweak),
            Span(cipher),
        ),
        plain,
    )

    var key512 = List[UInt8](length=128, fill=0)
    var tweak512 = List[UInt8](length=64, fill=0)
    var plain512 = List[UInt8](length=81, fill=0)
    for i in range(len(key512)):
        key512[i] = UInt8(i)
    for i in range(len(tweak512)):
        tweak512[i] = UInt8(i * 2)
    for i in range(len(plain512)):
        plain512[i] = UInt8(i * 3)
    var cipher512 = process(
        BlockCipherAlgorithm.THREEFISH512,
        True,
        Span(key512),
        Span(tweak512),
        Span(plain512),
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.THREEFISH512,
            False,
            Span(key512),
            Span(tweak512),
            Span(cipher512),
        ),
        plain512,
    )

    var key1024 = List[UInt8](length=256, fill=0)
    var tweak1024 = List[UInt8](length=128, fill=0)
    var plain1024 = List[UInt8](length=145, fill=0)
    for i in range(len(key1024)):
        key1024[i] = UInt8(i)
    for i in range(len(tweak1024)):
        tweak1024[i] = UInt8(i)
    for i in range(len(plain1024)):
        plain1024[i] = UInt8(i)
    var cipher1024 = process(
        BlockCipherAlgorithm.THREEFISH1024,
        True,
        Span(key1024),
        Span(tweak1024),
        Span(plain1024),
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.THREEFISH1024,
            False,
            Span(key1024),
            Span(tweak1024),
            Span(cipher1024),
        ),
        plain1024,
    )


def test_invalid_lengths() raises:
    var key = List[UInt8](length=32, fill=0)
    var tweak = List[UInt8](length=16, fill=0)
    var short = List[UInt8](length=15, fill=0)
    var failed = False
    try:
        _ = process(
            BlockCipherAlgorithm.AES,
            True,
            Span(key),
            Span(tweak),
            Span(short),
        )
    except:
        failed = True
    assert_true(failed)

    var bad_key = List[UInt8](length=31, fill=0)
    var block = List[UInt8](length=16, fill=0)
    failed = False
    try:
        _ = process(
            BlockCipherAlgorithm.AES,
            True,
            Span(bad_key),
            Span(tweak),
            Span(block),
        )
    except:
        failed = True
    assert_true(failed)

    var bad_tweak = List[UInt8](length=15, fill=0)
    failed = False
    try:
        _ = process(
            BlockCipherAlgorithm.AES,
            True,
            Span(key),
            Span(bad_tweak),
            Span(block),
        )
    except:
        failed = True
    assert_true(failed)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
