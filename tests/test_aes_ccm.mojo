from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.aead.aes_ccm import decrypt, encrypt


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


def test_reference_basic_vectors() raises:
    # CCM vectors: nonce, AAD, plaintext, and tag sizes all vary.
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "10111213141516",
        "0001020304050607",
        "20212223",
        "7162015b",
        "4dac255d",
    )
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "1011121314151617",
        "000102030405060708090a0b0c0d0e0f",
        "202122232425262728292a2b2c2d2e2f",
        "d2a1f0e051ea5f62081a7792073d593d",
        "1fc64fbfaccd",
    )
    check_vector(
        "404142434445464748494a4b4c4d4e4f",
        "101112131415161718191a1b",
        "000102030405060708090a0b0c0d0e0f10111213",
        "202122232425262728292a2b2c2d2e2f3031323334353637",
        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
        "484392fbc1b09951",
    )
    # The r256 pattern repeats the following 256-byte sequence,
    # exercising CCM's 0xfffe + 32-bit AAD-length encoding.
    var key = hex_bytes("404142434445464748494a4b4c4d4e4f")
    var nonce = hex_bytes("101112131415161718191a1b1c")
    var aad = List[UInt8](capacity=65536)
    for _ in range(256):
        for byte in range(256):
            aad.append(UInt8(byte))
    var message = hex_bytes(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    var expected_ciphertext = hex_bytes(
        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72"
    )
    var expected_tag = hex_bytes("b4ac6bec93e8598e7f0dadbcea5b")
    var sealed = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 14)
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


def test_reference_aes256_empty_inputs() raises:
    check_vector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "c1944044c8e7aa95d2de9513c7f3dd8c",
        "4b0a3e5e51f151eb0ffae7c43d010fdb",
    )
    check_vector(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "",
        "904704e89fb216443cb9d584911fc3c2",
    )


def test_tampering_and_limits() raises:
    var key = hex_bytes("404142434445464748494a4b4c4d4e4f")
    var nonce = hex_bytes("101112131415161718191a1b1c")
    var aad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4, 5, 6, 7, 8]
    var sealed = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 8)
    var ciphertext = sealed[0].copy()
    var tag = sealed[1].copy()
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    ciphertext = sealed[0].copy()
    tag = sealed[1].copy()
    tag[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    tag = sealed[1].copy()
    aad[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )

    var short_nonce = List[UInt8](length=6, fill=0)
    var long_nonce = List[UInt8](length=14, fill=0)
    with assert_raises():
        _ = encrypt(Span(key), Span(short_nonce), Span(aad), Span(message), 8)
    with assert_raises():
        _ = encrypt(Span(key), Span(long_nonce), Span(aad), Span(message), 8)
    with assert_raises():
        _ = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 2)
    with assert_raises():
        _ = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 5)
    with assert_raises():
        _ = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 18)

    # A 13-byte nonce has q=2, so 2^16 bytes cannot be represented in B0.
    var maximum_nonce = List[UInt8](length=13, fill=0)
    var too_long = List[UInt8](length=65536, fill=0)
    with assert_raises():
        _ = encrypt(
            Span(key), Span(maximum_nonce), Span(aad), Span(too_long), 8
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
