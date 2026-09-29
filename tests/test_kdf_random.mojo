from std.testing import assert_equal, assert_false, assert_raises, TestSuite
from mcrypto.kdf.dispatch import derive
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.random.generator import drbg, random_bytes
from mcrypto.random.algorithm import DrbgAlgorithm


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


def test_rfc5869_hkdf_sha256() raises:
    var secret = List[UInt8](length=22, fill=0x0B)
    var salt = hex_bytes("000102030405060708090a0b0c")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    var expected = hex_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert_equal(
        derive(
            KdfAlgorithm.HKDF_SHA256,
            Span(secret),
            Span(salt),
            Span(info),
            42,
        ),
        expected,
    )


def test_pbkdf2_and_pkcs12_vectors() raises:
    var no_info = List[UInt8]()
    var password = hex_bytes("70617373776f7264")
    var salt = hex_bytes("1234567878563412")
    assert_equal(
        derive(
            KdfAlgorithm.PBKDF2_HMAC_SHA1,
            Span(password),
            Span(salt),
            Span(no_info),
            8,
            5,
        ),
        hex_bytes("d1daa78615f287e6"),
    )
    var pkcs_password = hex_bytes("0073006d006500670000")
    var pkcs_salt = hex_bytes("0a58cf64530d823f")
    assert_equal(
        derive(
            KdfAlgorithm.PKCS12_PBKDF_SHA1,
            Span(pkcs_password),
            Span(pkcs_salt),
            Span(no_info),
            24,
            1,
            UInt8(1),
        ),
        hex_bytes("8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"),
    )


def test_rfc7914_scrypt() raises:
    var password = List[UInt8]()
    var salt = List[UInt8]()
    var info = List[UInt8]()
    assert_equal(
        derive(
            KdfAlgorithm.SCRYPT,
            Span(password),
            Span(salt),
            Span(info),
            64,
            cost=16,
            block_size=1,
            parallelization=1,
        ),
        hex_bytes(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        ),
    )


def test_rng_and_drbg_invariants() raises:
    var first = random_bytes(32)
    var second = random_bytes(32)
    assert_false(first == second)
    var entropy = List[UInt8](length=32, fill=1)
    var nonce = List[UInt8](length=16, fill=2)
    var personalization: List[UInt8] = [3, 4]
    var additional: List[UInt8] = [5, 6]
    for algorithm in [
        DrbgAlgorithm.HASH_SHA256,
        DrbgAlgorithm.HMAC_SHA256,
        DrbgAlgorithm.HASH_SHA512,
        DrbgAlgorithm.HMAC_SHA512,
    ]:
        var output = drbg(
            algorithm,
            Span(entropy),
            Span(nonce),
            Span(personalization),
            Span(additional),
            64,
        )
        assert_equal(len(output), 64)
        assert_equal(
            output,
            drbg(
                algorithm,
                Span(entropy),
                Span(nonce),
                Span(personalization),
                Span(additional),
                64,
            ),
        )
    with assert_raises():
        _ = drbg(
            DrbgAlgorithm.HASH_SHA256,
            Span(entropy),
            Span(nonce),
            Span(personalization),
            Span(additional),
            65537,
        )


def test_nist_drbg_sha256_sha512_known_answers() raises:
    var entropy = List[UInt8](capacity=32)
    for i in range(32):
        entropy.append(UInt8(i))
    var nonce = List[UInt8](capacity=16)
    for i in range(16):
        nonce.append(UInt8(0x20 + i))
    var personalization = List("mcrypto-drbg".as_bytes())
    var additional = List("additional".as_bytes())
    assert_equal(
        drbg(
            DrbgAlgorithm.HASH_SHA256,
            Span(entropy),
            Span(nonce),
            Span(personalization),
            Span(additional),
            64,
        ),
        hex_bytes(
            "d51e1d4414c658a3eebce9af6adf8f2bc2cc6c5261e6a4ba2764c77d9890eaf"
            "172ab39551c2e0c2e7dbb16dafb3b23bfedafcf665c687ce15cb190d80ee1f5b1"
        ),
    )
    assert_equal(
        drbg(
            DrbgAlgorithm.HASH_SHA512,
            Span(entropy),
            Span(nonce),
            Span(personalization),
            Span(additional),
            64,
        ),
        hex_bytes(
            "9d57c435f48275b30f20dfaf992984ab66bdc35df73a9c5f6865f9583ff43fcd"
            "8c7206be0b7815ad40385ad0c2c0076582eed09721c5239dce12c75e0a92f0bb"
        ),
    )
    assert_equal(
        drbg(
            DrbgAlgorithm.HMAC_SHA256,
            Span(entropy),
            Span(nonce),
            Span(personalization),
            Span(additional),
            64,
        ),
        hex_bytes(
            "202fe845f2e3fade4a2b3a2f75a7f519d371b440c0f1b6b6abc45f91c8bcc5e8"
            "7780c329b68923968d13b420a647aa039afcd42b02ca0ac9ca8e6a24b0c5eaec"
        ),
    )
    assert_equal(
        drbg(
            DrbgAlgorithm.HMAC_SHA512,
            Span(entropy),
            Span(nonce),
            Span(personalization),
            Span(additional),
            64,
        ),
        hex_bytes(
            "2c444e943a91eeeaa89746f6430e75e0073cbcfae804525e0e7569c93aac6931"
            "6d766fb5c9e859c5f3e588227d6dc39249539879aa6a9eabee2bf07fa044c11c"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
