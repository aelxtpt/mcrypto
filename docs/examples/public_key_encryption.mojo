from std.testing import assert_equal, assert_true
from mcrypto.public_key.encryption import generate_keypair, encrypt, decrypt
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm


def main() raises:
    # Generic public-key dispatch returns (private_key, public_key).
    var keys = generate_keypair(PublicKeyEncryptionAlgorithm.RSA, 2048)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("hybrid key material".as_bytes())
    var ciphertext = encrypt(
        PublicKeyEncryptionAlgorithm.RSA, Span(public_key), Span(message)
    )
    assert_true(ciphertext != message)
    assert_equal(
        decrypt(
            PublicKeyEncryptionAlgorithm.RSA,
            Span(private_key),
            Span(ciphertext),
        ),
        message,
    )
    print("public-key-encryption: ok")
