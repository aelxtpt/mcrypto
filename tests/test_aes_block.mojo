from std.memory import bitcast
from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.aes_block import (
    _prepare_aesni128,
    decrypt_block,
    encrypt_block,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var h = Int(bytes[i])
        var l = Int(bytes[i + 1])
        h -= 48 if h <= 57 else 87
        l -= 48 if l <= 57 else 87
        output.append(UInt8(h * 16 + l))
    return output^


def test_fips197_aes_vectors() raises:
    var plaintext = hex_bytes("00112233445566778899aabbccddeeff")
    var key128 = hex_bytes("000102030405060708090a0b0c0d0e0f")
    var key192 = hex_bytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    var key256 = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    var c128 = hex_bytes("69c4e0d86a7b0430d8cdb78070b4c55a")
    var c192 = hex_bytes("dda97ca4864cdfe06eaf70a0ec0d7191")
    var c256 = hex_bytes("8ea2b7ca516745bfeafc49904b496089")
    assert_equal(encrypt_block(Span(key128), Span(plaintext)), c128)
    assert_equal(decrypt_block(Span(key128), Span(c128)), plaintext)
    assert_equal(encrypt_block(Span(key192), Span(plaintext)), c192)
    assert_equal(decrypt_block(Span(key192), Span(c192)), plaintext)
    assert_equal(encrypt_block(Span(key256), Span(plaintext)), c256)
    assert_equal(decrypt_block(Span(key256), Span(c256)), plaintext)


def test_prepared_aes128_schedule_matches_fips197() raises:
    var key = hex_bytes("000102030405060708090a0b0c0d0e0f")
    var expected_last = hex_bytes("13111d7fe3944a17f307a78b4d2b30c5")
    var keys = _prepare_aesni128(Span(key))
    assert_equal(len(keys), 11)
    var last = bitcast[DType.uint8, 16](keys[10])
    for i in range(16):
        assert_equal(UInt8(last[i]), expected_last[i])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
