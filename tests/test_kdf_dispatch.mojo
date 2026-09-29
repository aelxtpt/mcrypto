from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive


def test_dispatch_paths() raises:
    var password = "password".as_bytes()
    var salt = "salt".as_bytes()
    var empty = List[UInt8]()
    assert_equal(
        len(
            derive(
                KdfAlgorithm.PBKDF2_HMAC_SHA256,
                password,
                salt,
                Span(empty),
                32,
                2,
            )
        ),
        32,
    )
    assert_equal(
        len(
            derive(
                KdfAlgorithm.SCRYPT,
                password,
                salt,
                Span(empty),
                32,
                cost=16,
                block_size=1,
                parallelization=1,
            )
        ),
        32,
    )


def test_dispatch_rejects_zero_output_for_every_family() raises:
    var password = "password".as_bytes()
    var salt = "salt".as_bytes()
    var empty = List[UInt8]()
    for algorithm in [
        KdfAlgorithm.PBKDF1,
        KdfAlgorithm.PBKDF2_HMAC_SHA256,
        KdfAlgorithm.PKCS12_PBKDF_SHA1,
        KdfAlgorithm.HKDF_SHA256,
        KdfAlgorithm.SCRYPT,
    ]:
        with assert_raises():
            _ = derive(
                algorithm,
                password,
                salt,
                Span(empty),
                0,
                2,
                cost=16,
                block_size=1,
                parallelization=1,
            )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
