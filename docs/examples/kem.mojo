from std.testing import assert_equal, assert_true
from mcrypto.kem.algorithm import KemAlgorithm
from mcrypto.kem.dispatch import keypair, encapsulate, decapsulate


def main() raises:
    # KEMs return (public_key, secret_key).
    var keys = keypair(KemAlgorithm.ML_KEM_768)
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    # Encapsulation returns (ciphertext, shared_secret).
    var encapsulated = encapsulate(KemAlgorithm.ML_KEM_768, Span(public_key))
    var ciphertext = encapsulated[0].copy()
    var sender_secret = encapsulated[1].copy()
    assert_equal(
        decapsulate(
            KemAlgorithm.ML_KEM_768, Span(ciphertext), Span(secret_key)
        ),
        sender_secret,
    )
    ciphertext[0] ^= 1
    var rejected = decapsulate(
        KemAlgorithm.ML_KEM_768, Span(ciphertext), Span(secret_key)
    )
    assert_equal(len(rejected), 32)
    assert_true(rejected != sender_secret)
    print("kem: ok")
