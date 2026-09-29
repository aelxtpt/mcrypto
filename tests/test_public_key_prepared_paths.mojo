from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.key_exchange.agreement import (
    PreparedAgreement,
    agree,
    generate_keypair as generate_agreement_keypair,
    generate_peer as generate_agreement_peer,
    info as agreement_info,
)
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.public_key.encryption import (
    PreparedECIESDecryptor,
    PreparedECIESEncryptor,
    decrypt,
    encrypt,
    generate_keypair as generate_encryption_keypair,
)
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm


def test_prepared_ecies_matches_dispatch_both_directions() raises:
    var message: List[UInt8] = [3, 1, 4, 1, 5, 9, 2, 6]
    var keys = generate_encryption_keypair(
        PublicKeyEncryptionAlgorithm.ECIES, 256
    )
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var prepared_encryptor = PreparedECIESEncryptor(
        PublicKeyEncryptionAlgorithm.ECIES, Span(public_key)
    )
    var prepared_decryptor = PreparedECIESDecryptor(
        PublicKeyEncryptionAlgorithm.ECIES, Span(private_key)
    )
    var prepared_ciphertext = prepared_encryptor.encrypt(Span(message))
    assert_equal(
        decrypt(
            PublicKeyEncryptionAlgorithm.ECIES,
            Span(private_key),
            Span(prepared_ciphertext),
        ),
        message,
    )
    var dispatch_ciphertext = encrypt(
        PublicKeyEncryptionAlgorithm.ECIES, Span(public_key), Span(message)
    )
    assert_equal(prepared_decryptor.decrypt(Span(dispatch_ciphertext)), message)
    prepared_ciphertext[len(prepared_ciphertext) - 1] ^= 1
    with assert_raises():
        _ = prepared_decryptor.decrypt(Span(prepared_ciphertext))


def test_prepared_agreement_matches_scalar_and_rejects_peer_tamper() raises:
    var name = AgreementAlgorithm.ECDH_P256
    var sizes = agreement_info(name, 512)
    var alice = generate_agreement_keypair(name, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_agreement_peer(
        name,
        Span(parameters),
        sizes[0],
        sizes[1],
        False,
    )
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var expected = agree(
        name,
        Span(parameters),
        Span(alice_private),
        Span(bob_public),
        sizes[2],
        True,
    )
    var prepared = PreparedAgreement(
        name,
        Span(parameters),
        Span(alice_private),
        Span(bob_public),
        sizes[2],
        True,
    )
    assert_equal(prepared.agree(), expected)
    assert_equal(
        expected,
        agree(
            name,
            Span(parameters),
            Span(bob_private),
            Span(alice_public),
            sizes[2],
            False,
        ),
    )
    bob_public[0] ^= 1
    with assert_raises():
        _ = PreparedAgreement(
            name,
            Span(parameters),
            Span(alice_private),
            Span(bob_public),
            sizes[2],
            True,
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
