"""XEd25519 known answers and strict verification boundaries.

The first vector is Signal's xeddsa_fast_test. Additional vectors were produced
and verified with its C reference at commit
3a83a4f4ed2302ff6e68ab569c88793b50c22d28. See the reproduction instructions in
docs/algorithms/xeddsa.md. Fixed random inputs below are only test fixtures.
"""

from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.key_exchange.x25519 import public_key as x25519_public_key
from mcrypto.signatures.xeddsa import sign, sign_with_randomness, verify


def _nibble(value: UInt8) raises -> UInt8:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    raise Error("invalid test hex")


def _hex(value: String) raises -> List[UInt8]:
    var data = value.as_bytes()
    if len(data) % 2 != 0:
        raise Error("odd test hex")
    var output = List[UInt8](capacity=len(data) // 2)
    for i in range(0, len(data), 2):
        output.append((_nibble(data[i]) << 4) | _nibble(data[i + 1]))
    return output^


def test_signal_published_vector() raises:
    var private_key = _hex(
        "0000000000000000bd0000000000000000000000000000000000000000000000"
    )
    var public_key = _hex(
        "5995f464e9d34d5ca56b9905b9a3cc37c456b2d8d313edbcf584b705b5c04955"
    )
    var message = _hex(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000"
    )
    var randomness = _hex(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    var expected = _hex(
        "11c7f3e6c4df9e8a5150e1db3b30f92de3a3b3aa438656545fa7390f4bcc7bb2"
        "6c431d9e90643e4f0eaa0e9c557766fa69ada576d63dcaf2ac326c11d0b97702"
    )
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    assert_equal(signature, expected)
    assert_equal(x25519_public_key(Span(private_key)), public_key)
    assert_true(verify(Span(expected), Span(message), Span(public_key)))


def test_reference_empty_message_sign_zero() raises:
    var private_key = _hex(
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    var public_key = _hex(
        "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
    )
    var message = _hex("")
    var randomness = _hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    var expected = _hex(
        "94f8cc42ccaa4db5cbaad566fb2cd36d6723d0cee19e556e40f7a3502af7155d"
        "b1430f2aa5c44bca287b9f4e86a938c2db6006e7e69d80225651dc4e9640f40e"
    )
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    assert_equal(signature, expected)
    assert_equal(x25519_public_key(Span(private_key)), public_key)
    assert_true(verify(Span(expected), Span(message), Span(public_key)))


def test_reference_abc() raises:
    var private_key = _hex(
        "0202020202020202020202020202020202020202020202020202020202020202"
    )
    var public_key = _hex(
        "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"
    )
    var message = _hex("616263")
    var randomness = _hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    var expected = _hex(
        "d2e47b28e1caef2b9c4982ddf30be5db964a75648e63315ba6c544e95d1052a1"
        "69aed4525c9c3d54497a09815aec1f9998a5ee01d044cb714ada1434ed546006"
    )
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    assert_equal(signature, expected)
    assert_equal(x25519_public_key(Span(private_key)), public_key)
    assert_true(verify(Span(expected), Span(message), Span(public_key)))


def test_reference_binary_message_sign_one() raises:
    var private_key = _hex(
        "0303030303030303030303030303030303030303030303030303030303030303"
    )
    var public_key = _hex(
        "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"
    )
    var message = _hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    var randomness = _hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    var expected = _hex(
        "ca2fdd1b565396b85bcf9b6b0cb0ffd50c08da26e8ae235096989589eefba495"
        "0e185822da65fce5db24b475b3bc7d9ddd6266130f3ad9949ffa55b91f8ec30d"
    )
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    assert_equal(signature, expected)
    assert_equal(x25519_public_key(Span(private_key)), public_key)
    assert_true(verify(Span(expected), Span(message), Span(public_key)))


def test_reference_block_boundary() raises:
    var private_key = _hex(
        "0404040404040404040404040404040404040404040404040404040404040404"
    )
    var public_key = _hex(
        "ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"
    )
    var message = _hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    var randomness = _hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    var expected = _hex(
        "45394e1c6b5fc6809347572d14b6629bd588b61f1dd452e3e937e19a8dcd9026"
        "045f0de7ea8aefaa00b4324b41709c1e2d25f3a3282e02e9d5162f94eded6c0d"
    )
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    assert_equal(signature, expected)
    assert_equal(x25519_public_key(Span(private_key)), public_key)
    assert_true(verify(Span(expected), Span(message), Span(public_key)))


def test_clamping_and_input_preservation() raises:
    var private_key = List[UInt8](length=32, fill=0xFF)
    var original_key = private_key.copy()
    var clamped_key = private_key.copy()
    clamped_key[0] &= 0xF8
    clamped_key[31] = (clamped_key[31] & 0x7F) | 0x40
    var randomness = List[UInt8](length=64, fill=0xA5)
    var original_randomness = randomness.copy()
    var message = List("unchanged input".as_bytes())
    var original_message = message.copy()
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    var clamped_signature = sign_with_randomness(
        Span(message), Span(clamped_key), Span(randomness)
    )
    assert_equal(signature, clamped_signature)
    assert_equal(private_key, original_key)
    assert_equal(randomness, original_randomness)
    assert_equal(message, original_message)
    var public_key = x25519_public_key(Span(private_key))
    assert_true(verify(Span(signature), Span(message), Span(public_key)))


def test_randomness_changes_signature() raises:
    var private_key = List[UInt8](length=32, fill=7)
    var public_key = x25519_public_key(Span(private_key))
    var message = List("randomized signatures".as_bytes())
    var randomness = List[UInt8](length=64, fill=0)
    var first = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    # Include the final byte of Z: catches truncated or ignored randomness.
    randomness[63] = 1
    var second = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    assert_true(first != second)
    assert_true(verify(Span(first), Span(message), Span(public_key)))
    assert_true(verify(Span(second), Span(message), Span(public_key)))


def test_os_randomness_and_long_message() raises:
    var private_key = List[UInt8](length=32, fill=9)
    var public_key = x25519_public_key(Span(private_key))
    var message = List[UInt8](length=4096, fill=0xA5)
    var signature = sign(Span(message), Span(private_key))
    assert_equal(len(signature), 64)
    assert_true(verify(Span(signature), Span(message), Span(public_key)))
    var second = sign(Span(message), Span(private_key))
    assert_true(signature != second)
    assert_true(verify(Span(second), Span(message), Span(public_key)))
    message[4095] ^= 1
    assert_false(verify(Span(signature), Span(message), Span(public_key)))


def test_tampering_and_wrong_key() raises:
    var private_key = List[UInt8](length=32, fill=2)
    var public_key = x25519_public_key(Span(private_key))
    var message = List("abc".as_bytes())
    var randomness = List[UInt8](length=64, fill=0)
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    for i in range(64):
        signature[i] ^= 1
        assert_false(verify(Span(signature), Span(message), Span(public_key)))
        signature[i] ^= 1
    message[0] ^= 1
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    message[0] ^= 1
    private_key[1] ^= 1
    var other_public_key = x25519_public_key(Span(private_key))
    assert_false(verify(Span(signature), Span(message), Span(other_public_key)))
    assert_true(verify(Span(signature), Span(message), Span(public_key)))


def test_invalid_lengths() raises:
    var private_key = List[UInt8](length=32, fill=2)
    var public_key = x25519_public_key(Span(private_key))
    var message = List[UInt8]()
    var randomness = List[UInt8](length=64, fill=0)
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    var bad_key_sizes: List[Int] = [0, 1, 31, 33, 64]
    for size in bad_key_sizes:
        var bad_key = List[UInt8](length=size, fill=0)
        with assert_raises():
            _ = sign(Span(message), Span(bad_key))
        with assert_raises():
            _ = sign_with_randomness(
                Span(message), Span(bad_key), Span(randomness)
            )
        assert_false(verify(Span(signature), Span(message), Span(bad_key)))
    var bad_data_sizes: List[Int] = [0, 1, 32, 63, 65]
    for size in bad_data_sizes:
        var bad = List[UInt8](length=size, fill=0)
        with assert_raises():
            _ = sign_with_randomness(
                Span(message), Span(private_key), Span(bad)
            )
        assert_false(verify(Span(bad), Span(message), Span(public_key)))


def test_noncanonical_and_invalid_public_keys() raises:
    var private_key = List[UInt8](length=32, fill=2)
    var public_key = x25519_public_key(Span(private_key))
    var message = List("abc".as_bytes())
    var randomness = List[UInt8](length=64, fill=0)
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    public_key[31] |= 0x80
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    # p and all greater 255-bit values, p-1 (zero denominator), small-order
    # u=0, u=1, and u=2 (on the twist rather than the Edwards curve).
    var invalid = List[UInt8](length=32, fill=0xFF)
    invalid[31] = 0x7F
    for low_byte in range(0xEC, 0x100):
        invalid[0] = UInt8(low_byte)
        assert_false(verify(Span(signature), Span(message), Span(invalid)))
    invalid = List[UInt8](length=32, fill=0)
    for u in range(3):
        invalid[0] = UInt8(u)
        assert_false(verify(Span(signature), Span(message), Span(invalid)))


def test_scalar_malleability_and_legacy_sign_bit() raises:
    var private_key = List[UInt8](length=32, fill=2)
    var public_key = x25519_public_key(Span(private_key))
    var message = List("abc".as_bytes())
    var randomness = List[UInt8](length=64, fill=0)
    var signature = sign_with_randomness(
        Span(message), Span(private_key), Span(randomness)
    )
    signature[63] |= 0x80
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    signature[63] &= 0x7F
    # s + q satisfies the same verification equation, but is not canonical.
    var order = _hex(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
    )
    var carry = UInt16(0)
    for i in range(32):
        var total = UInt16(signature[32 + i]) + UInt16(order[i]) + carry
        signature[32 + i] = UInt8(total & 0xFF)
        carry = total >> 8
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    # Also reject the exact s=q boundary and noncanonical R=y=p.
    for i in range(32):
        signature[32 + i] = order[i]
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    var noncanonical_r = _hex(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    )
    for i in range(32):
        signature[i] = noncanonical_r[i]
        signature[32 + i] = 0
    assert_false(verify(Span(signature), Span(message), Span(public_key)))


def test_small_order_forgery_and_identity_r() raises:
    # Both equations pass the historical C reference verifier; the library's
    # strict policy rejects these points rather than accepting trivial proofs.
    var public_key = List[UInt8](length=32, fill=0)
    var message = List[UInt8](length=1, fill=0)
    var forged = _hex(
        "58666666666666666666666666666666666666666666666666666666666666660100000000000000000000000000000000000000000000000000000000000000"
    )
    assert_false(verify(Span(forged), Span(message), Span(public_key)))
    var private_key = List[UInt8](length=32, fill=2)
    public_key = x25519_public_key(Span(private_key))
    message = List("abc".as_bytes())
    var identity_r = _hex(
        "0100000000000000000000000000000000000000000000000000000000000000cb9240869e0595ba3518584f1965e1a705261c7d2eb867457fb4b5125fcce90b"
    )
    assert_false(verify(Span(identity_r), Span(message), Span(public_key)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
