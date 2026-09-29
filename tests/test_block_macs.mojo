from std.testing import assert_equal, assert_false, assert_raises, TestSuite
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm
from mcrypto.macs.cbc_mac import authenticate as cbc_mac, verify as verify_cbc
from mcrypto.macs.cbc_mac import authenticate_four_into as cbc_mac_four_into
from mcrypto.macs.cmac import authenticate as cmac, verify as verify_cmac
from mcrypto.macs.dmac import authenticate as dmac, verify as verify_dmac
from mcrypto.macs.gmac import authenticate as gmac, verify as verify_gmac
from mcrypto.macs.poly1305_aes import (
    authenticate as poly1305_aes,
    verify as verify_poly1305_aes,
)
from mcrypto.macs.vmac import (
    authenticate as vmac,
    authenticate_eight as vmac_eight,
    verify as verify_vmac,
)


def h(text: StaticString) -> List[UInt8]:
    var raw = text.as_bytes()
    var output = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw), 2):
        var high = Int(raw[i])
        var low = Int(raw[i + 1])
        high -= 48 if high <= 57 else 87
        low -= 48 if low <= 57 else 87
        output.append(UInt8(high * 16 + low))
    return output^


def ascii(text: StaticString) -> List[UInt8]:
    var output = List[UInt8](capacity=len(text.as_bytes()))
    for byte in text.as_bytes():
        output.append(byte)
    return output^


def test_cbc_mac_aes_and_truncation() raises:
    # AES CBC-MAC independently obtained by CBC encryption with a zero IV.
    var key = h("2b7e151628aed2a6abf7158809cf4f3c")
    var message = h(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    )
    var expected = h("b148c17f309ee692287ae57cf12add49")
    assert_equal(
        cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(message)), expected
    )
    var short = h("b148c17f309ee692")
    assert_equal(
        cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(message), 8), short
    )
    assert_equal(
        verify_cbc(
            BlockCipherAlgorithm.AES, Span(key), Span(message), Span(short)
        ),
        True,
    )
    message[0] ^= 1
    assert_false(
        verify_cbc(
            BlockCipherAlgorithm.AES, Span(key), Span(message), Span(short)
        )
    )


def test_generic_cmac_and_verify() raises:
    var key = h("00010002000300040005000600070008")
    var message = ascii("7654321 Now is the time for ")
    # NIST SP 800-38B generic path exercised with the 64-bit IDEA block cipher.
    var tag = cmac(BlockCipherAlgorithm.IDEA, Span(key), Span(message), 4)
    assert_equal(len(tag), 4)
    assert_equal(
        verify_cmac(
            BlockCipherAlgorithm.IDEA, Span(key), Span(message), Span(tag)
        ),
        True,
    )
    tag[0] ^= 1
    assert_false(
        verify_cmac(
            BlockCipherAlgorithm.IDEA, Span(key), Span(message), Span(tag)
        )
    )


def test_dmac_aes_vector_and_verify() raises:
    # Fixed AES regression vector for the DMAC construction.
    var key = h("2b7e151628aed2a6abf7158809cf4f3c")
    var message = h("6bc1bee22e409f96e93d7e117393172a")
    var expected = h("61a4ca5beef434e447f1310dc519d5d7")
    assert_equal(
        dmac(BlockCipherAlgorithm.AES, Span(key), Span(message)), expected
    )
    assert_equal(
        verify_dmac(
            BlockCipherAlgorithm.AES,
            Span(key),
            Span(message),
            Span(expected),
        ),
        True,
    )


def test_gmac_nist_vector_and_tamper() raises:
    # NIST GCMVS: empty plaintext, 128-bit AAD.
    var key = h("feffe9928665731c6d6a8f9467308308")
    var nonce = h("cafebabefacedbaddecaf888")
    var aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    var expected = h("346434fd51d5cd0c5887ec63e39b907a")
    assert_equal(gmac(Span(key), Span(nonce), Span(aad)), expected)
    assert_equal(
        verify_gmac(Span(key), Span(nonce), Span(aad), Span(expected)), True
    )
    aad[0] ^= 1
    assert_false(verify_gmac(Span(key), Span(nonce), Span(aad), Span(expected)))


def test_poly1305_aes_reference_vectors() raises:
    var key = h(
        "363f690fdaf4ba5754603fc8f336743d9e3f4d0ee44e5a00405bf20d5c6f6002"
    )
    var nonce = h("73f3878da0b86ccdae5c69ea922cbe1b")
    var message = List[UInt8]()
    var expected = h("97402378282344fdd119481631acb1ec")
    assert_equal(poly1305_aes(Span(key), Span(nonce), Span(message)), expected)
    assert_equal(
        poly1305_aes(Span(key), Span(nonce), Span(message), 8),
        h("97402378282344fd"),
    )
    assert_equal(
        verify_poly1305_aes(
            Span(key), Span(nonce), Span(message), Span(expected)
        ),
        True,
    )
    key[0] ^= 1
    assert_false(
        verify_poly1305_aes(
            Span(key), Span(nonce), Span(message), Span(expected)
        )
    )


def test_vmac_rfc4418_vectors() raises:
    var key = ascii("abcdefghijklmnop")
    var nonce = ascii("bcdefghi")
    var empty = List[UInt8]()
    var abc = ascii("abc")
    assert_equal(
        vmac(Span(key), Span(nonce), Span(empty), 8), h("2576be1c56d8b81b")
    )
    assert_equal(
        vmac(Span(key), Span(nonce), Span(abc), 8), h("2d376cf5b1813ce5")
    )
    var expected128 = h("4ee815a06a1d71edd36fc75d51188a42")
    assert_equal(vmac(Span(key), Span(nonce), Span(abc), 16), expected128)
    assert_equal(
        verify_vmac(Span(key), Span(nonce), Span(abc), Span(expected128)), True
    )
    abc[0] ^= 1
    assert_false(
        verify_vmac(Span(key), Span(nonce), Span(abc), Span(expected128))
    )


def test_four_way_cbc_mac_matches_independent_tags() raises:
    var key = h("2b7e151628aed2a6abf7158809cf4f3c")
    var first = List[UInt8](length=130, fill=0x11)
    var second = List[UInt8](length=130, fill=0x22)
    var third = List[UInt8](length=130, fill=0x33)
    var fourth = List[UInt8](length=130, fill=0x44)
    var first_output = List[UInt8](length=16, fill=0)
    var second_output = List[UInt8](length=16, fill=0)
    var third_output = List[UInt8](length=16, fill=0)
    var fourth_output = List[UInt8](length=16, fill=0)
    cbc_mac_four_into(
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
        first_output,
        cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(first)),
    )
    assert_equal(
        second_output,
        cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(second)),
    )
    assert_equal(
        third_output,
        cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(third)),
    )
    assert_equal(
        fourth_output,
        cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(fourth)),
    )


def test_eight_way_vmac_matches_independent_tags() raises:
    var key = h("2b7e151628aed2a6abf7158809cf4f3c")
    for tag_size in [8, 16]:
        var nonces = List[List[UInt8]](capacity=8)
        var messages = List[List[UInt8]](capacity=8)
        for lane in range(8):
            nonces.append(List[UInt8](length=16, fill=UInt8(lane)))
            messages.append(List[UInt8](length=300, fill=UInt8(0x20 + lane)))
        var outputs = vmac_eight(Span(key), nonces, messages, tag_size)
        for lane in range(8):
            assert_equal(
                outputs[lane],
                vmac(
                    Span(key),
                    Span(nonces[lane]),
                    Span(messages[lane]),
                    tag_size,
                ),
            )


def test_invalid_sizes() raises:
    var key = List[UInt8](length=16, fill=0)
    var empty = List[UInt8]()
    var nonce = List[UInt8](length=16, fill=0)
    var message = List[UInt8]()
    with assert_raises():
        _ = cbc_mac(BlockCipherAlgorithm.AES, Span(key), Span(empty), 17)
    with assert_raises():
        _ = cmac(BlockCipherAlgorithm.AES, Span(key), Span(empty), 17)
    with assert_raises():
        _ = gmac(Span(key), Span(empty), Span(message))
    with assert_raises():
        _ = vmac(Span(key), Span(nonce), Span(empty), 12)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
