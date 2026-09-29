from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.aria import process
from mcrypto.ciphers.modes import (
    process as mode_process,
    process_aria_cbc_four_into,
)


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else (87 if a >= 97 else 55)
        c -= 48 if c <= 57 else (87 if c >= 97 else 55)
        o.append(UInt8(a * 16 + c))
    return o^


def check(key: StaticString, cipher: StaticString) raises:
    var k = h(key)
    var p = h("00112233445566778899aabbccddeeff")
    var c = h(cipher)
    assert_equal(process(False, Span(k), Span(p)), c)
    assert_equal(process(True, Span(k), Span(c)), p)


def test_aria_rfc5794() raises:
    check(
        "000102030405060708090a0b0c0d0e0f", "d718fbd6ab644c739da95f3be6451778"
    )
    check(
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "26449c1805dbe7aa25a468ce263a9e79",
    )
    check(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "f92bd7c79fb72e2f2b8f80c1972d24fc",
    )


def test_four_block_aria_modes_match_independent_blocks() raises:
    var key = h("000102030405060708090a0b0c0d0e0f")
    var iv = List[UInt8](length=16, fill=0)
    var plaintext = List[UInt8](length=64, fill=0)
    for i in range(64):
        plaintext[i] = UInt8(i)
    var encrypted = mode_process(
        BlockCipherAlgorithm.ARIA,
        CipherMode.ECB,
        True,
        Span(key),
        Span(iv),
        Span(plaintext),
    )
    for block in range(4):
        var expected = process(
            False, Span(key), Span(plaintext)[block * 16 : block * 16 + 16]
        )
        for i in range(16):
            assert_equal(encrypted[block * 16 + i], expected[i])
    assert_equal(
        mode_process(
            BlockCipherAlgorithm.ARIA,
            CipherMode.ECB,
            False,
            Span(key),
            Span(iv),
            Span(encrypted),
        ),
        plaintext,
    )
    var ctr = mode_process(
        BlockCipherAlgorithm.ARIA,
        CipherMode.CTR,
        True,
        Span(key),
        Span(iv),
        Span(plaintext),
    )
    assert_equal(
        mode_process(
            BlockCipherAlgorithm.ARIA,
            CipherMode.CTR,
            False,
            Span(key),
            Span(iv),
            Span(ctr),
        ),
        plaintext,
    )
    var second = plaintext.copy()
    var third = plaintext.copy()
    var fourth = plaintext.copy()
    second[0] = 0x22
    third[0] = 0x33
    fourth[0] = 0x44
    var first_output = List[UInt8](length=64, fill=0)
    var second_output = List[UInt8](length=64, fill=0)
    var third_output = List[UInt8](length=64, fill=0)
    var fourth_output = List[UInt8](length=64, fill=0)
    process_aria_cbc_four_into(
        True,
        Span(key),
        Span(iv),
        Span(plaintext),
        Span(second),
        Span(third),
        Span(fourth),
        Span(first_output),
        Span(second_output),
        Span(third_output),
        Span(fourth_output),
    )
    assert_equal(
        first_output,
        mode_process(
            BlockCipherAlgorithm.ARIA,
            CipherMode.CBC,
            True,
            Span(key),
            Span(iv),
            Span(plaintext),
        ),
    )
    assert_equal(
        second_output,
        mode_process(
            BlockCipherAlgorithm.ARIA,
            CipherMode.CBC,
            True,
            Span(key),
            Span(iv),
            Span(second),
        ),
    )
    assert_equal(
        third_output,
        mode_process(
            BlockCipherAlgorithm.ARIA,
            CipherMode.CBC,
            True,
            Span(key),
            Span(iv),
            Span(third),
        ),
    )
    assert_equal(
        fourth_output,
        mode_process(
            BlockCipherAlgorithm.ARIA,
            CipherMode.CBC,
            True,
            Span(key),
            Span(iv),
            Span(fourth),
        ),
    )
    var first_recovered = List[UInt8](length=64, fill=0)
    var second_recovered = List[UInt8](length=64, fill=0)
    var third_recovered = List[UInt8](length=64, fill=0)
    var fourth_recovered = List[UInt8](length=64, fill=0)
    process_aria_cbc_four_into(
        False,
        Span(key),
        Span(iv),
        Span(first_output),
        Span(second_output),
        Span(third_output),
        Span(fourth_output),
        Span(first_recovered),
        Span(second_recovered),
        Span(third_recovered),
        Span(fourth_recovered),
    )
    assert_equal(first_recovered, plaintext)
    assert_equal(second_recovered, second)
    assert_equal(third_recovered, third)
    assert_equal(fourth_recovered, fourth)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
