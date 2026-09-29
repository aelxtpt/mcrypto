from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.aead.aes_gcm import decrypt, encrypt


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high -= 48 if high <= 57 else (87 if high >= 97 else 55)
        low -= 48 if low <= 57 else (87 if low >= 97 else 55)
        output.append(UInt8(high * 16 + low))
    return output^


def check_vector(
    key_hex: StaticString,
    nonce_hex: StaticString,
    aad_hex: StaticString,
    message_hex: StaticString,
    ciphertext_hex: StaticString,
    tag_hex: StaticString,
) raises:
    var key = hex_bytes(key_hex)
    var nonce = hex_bytes(nonce_hex)
    var aad = hex_bytes(aad_hex)
    var message = hex_bytes(message_hex)
    var expected_ciphertext = hex_bytes(ciphertext_hex)
    var expected_tag = hex_bytes(tag_hex)
    var sealed = encrypt(
        Span(key), Span(nonce), Span(aad), Span(message), len(expected_tag)
    )
    assert_equal(sealed[0], expected_ciphertext)
    assert_equal(sealed[1], expected_tag)
    assert_equal(
        decrypt(
            Span(key),
            Span(nonce),
            Span(aad),
            Span(expected_ciphertext),
            Span(expected_tag),
        ),
        message,
    )


def test_nist_aes128_96_bit_nonce() raises:
    check_vector(
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf",
    )


def test_nist_aad_and_partial_plaintext() raises:
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47",
    )


def test_nist_arbitrary_iv() raises:
    check_vector(
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbad",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        "3612d2e79e3b0785561be14aaca2fccb",
    )


def test_aes192_and_aes256() raises:
    check_vector(
        "000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "98e7247c07f0fe411c267e4384b0f600",
        "2ff58d80033927ab8ef4d4587514f0fb",
    )
    check_vector(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    )


def test_truncated_tags() raises:
    var key = hex_bytes("00000000000000000000000000000000")
    var nonce = hex_bytes("000000000000000000000000")
    var aad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4, 5, 6, 7, 8]
    var full = encrypt(Span(key), Span(nonce), Span(aad), Span(message))
    for tag_bytes in range(12, 17):
        var sealed = encrypt(
            Span(key), Span(nonce), Span(aad), Span(message), tag_bytes
        )
        assert_equal(sealed[0], full[0])
        for i in range(tag_bytes):
            assert_equal(sealed[1][i], full[1][i])
        var ciphertext = sealed[0].copy()
        var tag = sealed[1].copy()
        assert_equal(
            decrypt(
                Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
            ),
            message,
        )


def test_authentication_and_parameter_rejection() raises:
    var key = hex_bytes("00000000000000000000000000000000")
    var nonce = hex_bytes("000000000000000000000000")
    var aad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4, 5, 6, 7, 8]
    var sealed = encrypt(Span(key), Span(nonce), Span(aad), Span(message))
    var ciphertext = sealed[0].copy()
    var tag = sealed[1].copy()
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    ciphertext[0] ^= 1
    tag[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    tag[0] ^= 1
    nonce[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    nonce[0] ^= 1
    aad[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    var empty_nonce = List[UInt8]()
    with assert_raises():
        _ = encrypt(Span(key), Span(empty_nonce), Span(aad), Span(message))
    with assert_raises():
        _ = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 11)
    with assert_raises():
        _ = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 17)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
