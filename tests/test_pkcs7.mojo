from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.padding.pkcs7 import pad, unpad
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.encoding.transforms import transform
from mcrypto.encoding.algorithm import EncodingTransform


def test_all_block_and_padding_sizes() raises:
    for block_size in range(1, 256):
        for padding_bytes in range(1, block_size + 1):
            var message = List[UInt8](
                length=block_size - padding_bytes, fill=0xA5
            )
            var expected = message.copy()
            for _ in range(padding_bytes):
                expected.append(UInt8(padding_bytes))
            var padded = pad(Span(message), block_size)
            assert_equal(padded, expected)
            assert_equal(unpad(Span(expected), block_size), message)
        var aligned = List[UInt8](length=block_size, fill=0xA5)
        var padded = pad(Span(aligned), block_size)
        assert_equal(len(padded), 2 * block_size)
        for i in range(block_size, 2 * block_size):
            assert_equal(padded[i], UInt8(block_size))
        assert_equal(unpad(Span(padded), block_size), aligned)


def test_corruption_of_each_padding_position() raises:
    for padding_bytes in range(1, 17):
        var message = List[UInt8](length=16 - padding_bytes, fill=0xA5)
        var padded = pad(Span(message), 16)
        for position in range(16 - padding_bytes, 16):
            var corrupt = padded.copy()
            # Zero is invalid as the count, and inconsistent in the padding body.
            corrupt[position] = 0
            with assert_raises():
                _ = unpad(Span(corrupt), 16)
    for last in [0, 17, 255]:
        var invalid = List[UInt8](length=16, fill=UInt8(last))
        with assert_raises():
            _ = unpad(Span(invalid), 16)


def test_invalid_lengths_and_block_sizes() raises:
    var empty = List[UInt8]()
    var short = List[UInt8](length=15, fill=1)
    with assert_raises():
        _ = unpad(Span(empty), 16)
    with assert_raises():
        _ = unpad(Span(short), 16)
    for size in [-1, 0, 256]:
        with assert_raises():
            _ = pad(Span(empty), size)
        with assert_raises():
            _ = unpad(Span(short), size)


def test_aes_cbc_openssl_empty_message_vector() raises:
    # OpenSSL AES-128-CBC: zero key/IV, empty plaintext, PKCS#7 enabled.
    var key = List[UInt8](length=16, fill=0)
    var iv = List[UInt8](length=16, fill=0)
    var empty = List[UInt8]()
    var expected = transform(
        EncodingTransform.HEX_DECODE,
        "0143db63ee66b0cdff9f69917680151e".as_bytes(),
    )
    var padded = pad(Span(empty), 16)
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC,
            True,
            Span(key),
            Span(iv),
            Span(padded),
        ),
        expected,
    )
    var decrypted = process(
        BlockCipherAlgorithm.AES,
        CipherMode.CBC,
        False,
        Span(key),
        Span(iv),
        Span(expected),
    )
    assert_equal(unpad(Span(decrypted), 16), empty)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
