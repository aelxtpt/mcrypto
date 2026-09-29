from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.aead.detached import (
    decrypt as aead_decrypt,
    encrypt as aead_encrypt,
)
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.ciphers.aes import aes_cbc_cts
from mcrypto.ciphers.dispatch import process as cipher_process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.macs.dispatch import authenticate
from mcrypto.macs.algorithm import MacAlgorithm


def hex_bytes(text: StaticString) -> List[UInt8]:
    var encoded = text.as_bytes()
    var digits = "0123456789abcdef".as_bytes()
    var output = List[UInt8](capacity=len(encoded) // 2)
    for i in range(0, len(encoded), 2):
        var high: UInt8 = 0
        var low: UInt8 = 0
        for j in range(16):
            if encoded[i] == digits[j]:
                high = UInt8(j)
            if encoded[i + 1] == digits[j]:
                low = UInt8(j)
        output.append((high << 4) | low)
    return output^


def test_nist_aes_ecb_vector() raises:
    var key = hex_bytes("2b7e151628aed2a6abf7158809cf4f3c")
    var iv = List[UInt8]()
    var plaintext = hex_bytes("6bc1bee22e409f96e93d7e117393172a")
    var expected = hex_bytes("3ad77bb40d7a3660a89ecaf32466ef97")
    assert_equal(
        cipher_process(
            BlockCipherAlgorithm.AES,
            CipherMode.ECB,
            True,
            Span(key),
            Span(iv),
            Span(plaintext),
        ),
        expected,
    )


def test_aes_ctr_roundtrip() raises:
    var key = List[UInt8](length=16, fill=0)
    var iv = List[UInt8](length=16, fill=0)
    var plaintext: List[UInt8] = [1, 2, 3, 4, 5]
    var encrypted = cipher_process(
        BlockCipherAlgorithm.AES,
        CipherMode.CTR,
        True,
        Span(key),
        Span(iv),
        Span(plaintext),
    )
    assert_equal(
        cipher_process(
            BlockCipherAlgorithm.AES,
            CipherMode.CTR,
            False,
            Span(key),
            Span(iv),
            Span(encrypted),
        ),
        plaintext,
    )


def test_aes_cbc_cts_roundtrip() raises:
    var key = hex_bytes("603deb1015ca71be2b73aef0857d7781")
    var iv = hex_bytes("000102030405060708090a0b0c0d0e0f")
    var plaintext = List[UInt8](length=47, fill=0xA5)
    var ciphertext = aes_cbc_cts(True, Span(key), Span(iv), Span(plaintext))
    assert_equal(
        aes_cbc_cts(False, Span(key), Span(iv), Span(ciphertext)), plaintext
    )


def test_hmac_sha256() raises:
    var key = List[UInt8](length=16, fill=0)
    var message: List[UInt8] = [1, 2, 3]
    assert_equal(
        len(
            authenticate(MacAlgorithm.HMAC_SHA256, Span(key), Span(message), 32)
        ),
        32,
    )


def test_chachapoly_roundtrip_and_tamper() raises:
    var key = List[UInt8](length=32, fill=0)
    var nonce = List[UInt8](length=8, fill=0)
    var aad: List[UInt8] = [1, 2]
    var message: List[UInt8] = [3, 4, 5]
    var sealed = aead_encrypt(
        AeadAlgorithm.CHACHA20_POLY1305,
        Span(key),
        Span(nonce),
        Span(aad),
        Span(message),
        16,
    )
    var ciphertext = sealed[0].copy()
    var tag = sealed[1].copy()
    assert_equal(
        aead_decrypt(
            AeadAlgorithm.CHACHA20_POLY1305,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
            Span(tag),
        ),
        message,
    )
    tag[0] ^= 1
    with assert_raises():
        _ = aead_decrypt(
            AeadAlgorithm.CHACHA20_POLY1305,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
            Span(tag),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
