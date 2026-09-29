from std.testing import assert_equal, TestSuite
from mcrypto.kem.algorithm import KemAlgorithm
from mcrypto.kem.dispatch import (
    decapsulate as kem_decapsulate,
    encapsulate as kem_encapsulate,
    keypair as kem_keypair,
)


def test_kem_families() raises:
    for algorithm in [KemAlgorithm.ML_KEM_768, KemAlgorithm.X_WING]:
        var keys = kem_keypair(algorithm)
        var public_key = keys[0].copy()
        var secret_key = keys[1].copy()
        var sealed = kem_encapsulate(algorithm, Span(public_key))
        var ciphertext = sealed[0].copy()
        var sender_shared = sealed[1].copy()
        assert_equal(
            kem_decapsulate(algorithm, Span(ciphertext), Span(secret_key)),
            sender_shared,
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
