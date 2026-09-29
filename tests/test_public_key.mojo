from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.key_exchange.agreement import (
    PreparedAgreement,
    PreparedLUCDIFKeyGenerator,
    PreparedEllipticKeyGenerator,
    agree,
    info as agreement_info,
    generate_keypair as generate_agreement_keypair,
    generate_peer as generate_agreement_peer,
)
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.public_key.encryption import (
    PreparedECIESEncryptor,
    PreparedECIESDecryptor,
    decrypt,
    encrypt,
    generate_keypair as generate_encryption_keypair,
)
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import (
    generate_keypair as generate_signature_keypair,
    sign,
    verify,
)


def test_rsa_oaep_roundtrip() raises:
    var keys = generate_encryption_keypair(
        PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1, 1024
    )
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(
        PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1,
        Span(public_key),
        Span(message),
    )
    assert_equal(
        decrypt(
            PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1,
            Span(private_key),
            Span(ciphertext),
        ),
        message,
    )


def test_rsa_pss_tamper() raises:
    var keys = generate_signature_keypair(SignatureAlgorithm.RSA_PSS_SHA1, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [5, 4, 3, 2, 1]
    var signature = sign(
        SignatureAlgorithm.RSA_PSS_SHA1,
        Span(private_key),
        Span(message),
    )
    assert_true(
        verify(
            SignatureAlgorithm.RSA_PSS_SHA1,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )
    message[0] ^= 1
    assert_false(
        verify(
            SignatureAlgorithm.RSA_PSS_SHA1,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )


def test_every_encryption_dispatch_branch() raises:
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    for algorithm, bits in [
        (PublicKeyEncryptionAlgorithm.RSA, 1024),
        (PublicKeyEncryptionAlgorithm.RSA_PKCS1, 1024),
        (PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1, 1024),
        (PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256, 1024),
        (PublicKeyEncryptionAlgorithm.ELGAMAL, 512),
        (PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1, 512),
        (PublicKeyEncryptionAlgorithm.LUCELG, 512),
        (PublicKeyEncryptionAlgorithm.DLIES, 512),
        (PublicKeyEncryptionAlgorithm.ECIES, 256),
    ]:
        var keys = generate_encryption_keypair(algorithm, bits)
        var private_key = keys[0].copy()
        var public_key = keys[1].copy()
        var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
        assert_equal(
            decrypt(algorithm, Span(private_key), Span(ciphertext)),
            message,
        )


def _check_raw_encryption_dispatch(
    algorithm: PublicKeyEncryptionAlgorithm,
) raises:
    var keys = generate_encryption_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var rabin = (
        algorithm == PublicKeyEncryptionAlgorithm.RABIN
        or algorithm == PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS
    )
    if rabin:
        assert_equal(private_key[0], UInt8(ord("R")))
        assert_equal(private_key[1], UInt8(ord("B")))
        assert_equal(private_key[2], UInt8(ord("S")))
        assert_equal(private_key[3], UInt8(ord("1")))
        assert_equal(public_key[0], UInt8(ord("R")))
        assert_equal(public_key[1], UInt8(ord("B")))
        assert_equal(public_key[2], UInt8(ord("W")))
        assert_equal(public_key[3], UInt8(ord("1")))
    var value: List[UInt8] = [42]
    for _ in range(8 if rabin else 1):
        var image = encrypt(algorithm, Span(public_key), Span(value))
        var recovered = decrypt(algorithm, Span(private_key), Span(image))
        for i in range(len(recovered) - 1):
            assert_equal(recovered[i], UInt8(0))
        assert_equal(recovered[len(recovered) - 1], UInt8(42))
    if rabin:
        var zero: List[UInt8] = [0]
        var zero_image = encrypt(algorithm, Span(public_key), Span(zero))
        var zero_recovered = decrypt(
            algorithm, Span(private_key), Span(zero_image)
        )
        for byte in zero_recovered:
            assert_equal(byte, UInt8(0))
        var empty = List[UInt8]()
        var empty_image = encrypt(algorithm, Span(public_key), Span(empty))
        var empty_recovered = decrypt(
            algorithm, Span(private_key), Span(empty_image)
        )
        for byte in empty_recovered:
            assert_equal(byte, UInt8(0))


def test_rabin_raw_dispatch_roundtrip() raises:
    _check_raw_encryption_dispatch(PublicKeyEncryptionAlgorithm.RABIN)


def test_rabin_williams_raw_dispatch_roundtrip() raises:
    _check_raw_encryption_dispatch(PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS)


def test_luc_raw_dispatch_roundtrip() raises:
    _check_raw_encryption_dispatch(PublicKeyEncryptionAlgorithm.LUC)


def test_rabin_oaep_dispatch_key_contract() raises:
    var keys = generate_encryption_keypair(
        PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1, 512
    )
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(
        PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1,
        Span(public_key),
        Span(message),
    )
    assert_equal(
        decrypt(
            PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1,
            Span(private_key),
            Span(ciphertext),
        ),
        message,
    )
    ciphertext[len(ciphertext) - 1] ^= 1
    with assert_raises():
        _ = decrypt(
            PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1,
            Span(private_key),
            Span(ciphertext),
        )


def test_rabin_encryption_rejects_bad_frames_and_lengths() raises:
    var keys = generate_encryption_keypair(
        PublicKeyEncryptionAlgorithm.RABIN, 512
    )
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var value: List[UInt8] = [42]
    var bad_public = public_key.copy()
    bad_public[0] ^= 1
    with assert_raises():
        _ = encrypt(
            PublicKeyEncryptionAlgorithm.RABIN, Span(bad_public), Span(value)
        )
    var image = encrypt(
        PublicKeyEncryptionAlgorithm.RABIN, Span(public_key), Span(value)
    )
    var bad_private = private_key.copy()
    bad_private[0] ^= 1
    with assert_raises():
        _ = decrypt(
            PublicKeyEncryptionAlgorithm.RABIN,
            Span(bad_private),
            Span(image),
        )
    var short_image = List[UInt8](capacity=len(image) - 1)
    for i in range(len(image) - 1):
        short_image.append(image[i])
    with assert_raises():
        _ = decrypt(
            PublicKeyEncryptionAlgorithm.RABIN,
            Span(private_key),
            Span(short_image),
        )


def test_every_signature_dispatch_branch() raises:
    var message: List[UInt8] = [9, 8, 7, 6, 5]
    for algorithm, bits in [
        (SignatureAlgorithm.RSA, 1024),
        (SignatureAlgorithm.RSA_PSS_SHA1, 1024),
        (SignatureAlgorithm.RSA_PSS_SHA256, 1024),
        (SignatureAlgorithm.RSA_PKCS1_SHA1, 1024),
        (SignatureAlgorithm.RSA_PKCS1_SHA256, 1024),
        (SignatureAlgorithm.DSA, 512),
        (SignatureAlgorithm.DSA_RFC6979, 512),
        (SignatureAlgorithm.ELGAMAL, 512),
        (SignatureAlgorithm.NR, 512),
        (SignatureAlgorithm.RABIN_WILLIAMS, 512),
        (SignatureAlgorithm.RABIN_PSSR_SHA256, 1024),
        (SignatureAlgorithm.RABIN_EMSA2_SHA256, 512),
        (SignatureAlgorithm.LUC, 512),
        (SignatureAlgorithm.LUC_PKCS1_SHA256, 512),
        (SignatureAlgorithm.LUC_HMP_EMSA1_SHA256, 512),
        (SignatureAlgorithm.ESIGN, 384),
        (SignatureAlgorithm.ECDSA, 256),
        (SignatureAlgorithm.ECDSA_RFC6979, 256),
        (SignatureAlgorithm.ECDSA_P256_SHA256, 256),
        (SignatureAlgorithm.ECDSA_RFC6979_P256_SHA256, 256),
        (SignatureAlgorithm.ECGDSA, 256),
        (SignatureAlgorithm.ECGDSA_P256_SHA256, 256),
        (SignatureAlgorithm.ECGDSA_BRAINPOOL_P256_SHA256, 256),
        (SignatureAlgorithm.ECNR, 256),
        (SignatureAlgorithm.ECNR_P256_SHA256, 256),
        (SignatureAlgorithm.ED25519, 256),
    ]:
        var keys = generate_signature_keypair(algorithm, bits)
        var private_key = keys[0].copy()
        var public_key = keys[1].copy()
        var signature = sign(algorithm, Span(private_key), Span(message))
        assert_true(
            verify(
                algorithm,
                Span(public_key),
                Span(message),
                Span(signature),
            )
        )
        var wrong_message = message.copy()
        wrong_message[0] ^= 1
        assert_false(
            verify(
                algorithm,
                Span(public_key),
                Span(wrong_message),
                Span(signature),
            )
        )
        var short_signature = signature[0 : len(signature) - 1]
        assert_false(
            verify(
                algorithm,
                Span(public_key),
                Span(message),
                short_signature,
            )
        )
        var malformed_public = public_key.copy()
        malformed_public[0] ^= 1
        with assert_raises():
            _ = verify(
                algorithm,
                Span(malformed_public),
                Span(message),
                Span(signature),
            )


def test_all_agreement_families() raises:
    var names: List[AgreementAlgorithm] = [
        AgreementAlgorithm.DH,
        AgreementAlgorithm.DH2,
        AgreementAlgorithm.MQV,
        AgreementAlgorithm.HMQV,
        AgreementAlgorithm.FHMQV,
        AgreementAlgorithm.LUCDIF,
        AgreementAlgorithm.XTR_DH,
        AgreementAlgorithm.ECDH_P256,
        AgreementAlgorithm.ECMQV_P256,
        AgreementAlgorithm.ECHMQV_P256,
        AgreementAlgorithm.ECFHMQV_P256,
        AgreementAlgorithm.X25519,
    ]
    for name in names:
        var sizes = agreement_info(name, 512)
        var alice = generate_agreement_keypair(name, 512)
        var alice_private = alice[0].copy()
        var alice_public = alice[1].copy()
        var parameters = alice[2].copy()
        if name == AgreementAlgorithm.DH:
            for i in range(6, 230):
                assert_equal(alice_private[i], UInt8(0))
            var exponent_nonzero = UInt8(0)
            for i in range(230, 262):
                exponent_nonzero |= alice_private[i]
            assert_true(exponent_nonzero != 0)
        var bob = generate_agreement_peer(
            name,
            Span(parameters),
            sizes[0],
            sizes[1],
            False,
        )
        var bob_private = bob[0].copy()
        var bob_public = bob[1].copy()
        var alice_shared = agree(
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
        assert_equal(prepared.agree(), alice_shared)
        var bob_shared = agree(
            name,
            Span(parameters),
            Span(bob_private),
            Span(alice_public),
            sizes[2],
            False,
        )
        assert_equal(alice_shared, bob_shared)


def test_agreement_rejects_peer_tamper() raises:
    var sizes = agreement_info(AgreementAlgorithm.ECDH_P256, 512)
    var alice = generate_agreement_keypair(AgreementAlgorithm.ECDH_P256, 512)
    var alice_private = alice[0].copy()
    var parameters = alice[2].copy()
    var bob = generate_agreement_peer(
        AgreementAlgorithm.ECDH_P256,
        Span(parameters),
        sizes[0],
        sizes[1],
        False,
    )
    var bob_public = bob[1].copy()
    bob_public[0] ^= 1
    with assert_raises():
        _ = agree(
            AgreementAlgorithm.ECDH_P256,
            Span(parameters),
            Span(alice_private),
            Span(bob_public),
            sizes[2],
            True,
        )


def test_prepared_public_encryptors() raises:
    var message: List[UInt8] = [9, 8, 7, 6]
    var keys = generate_encryption_keypair(
        PublicKeyEncryptionAlgorithm.ECIES, 256
    )
    var ec_encryptor = PreparedECIESEncryptor(
        PublicKeyEncryptionAlgorithm.ECIES, Span(keys[1])
    )
    var ec_decryptor = PreparedECIESDecryptor(
        PublicKeyEncryptionAlgorithm.ECIES, Span(keys[0])
    )
    var ciphertext = ec_encryptor.encrypt(Span(message))
    assert_equal(ec_decryptor.decrypt(Span(ciphertext)), message)


def test_prepared_agreement_key_generators() raises:
    var luc_generator = PreparedLUCDIFKeyGenerator(512)
    var luc_alice = luc_generator.generate()
    var luc_private = luc_alice[0].copy()
    var luc_public = luc_alice[1].copy()
    var luc_parameters = luc_alice[2].copy()
    var luc_sizes = agreement_info(AgreementAlgorithm.LUCDIF, 512)
    var luc_bob = generate_agreement_peer(
        AgreementAlgorithm.LUCDIF,
        Span(luc_parameters),
        luc_sizes[0],
        luc_sizes[1],
        False,
    )
    assert_equal(
        agree(
            AgreementAlgorithm.LUCDIF,
            Span(luc_parameters),
            Span(luc_private),
            Span(luc_bob[1]),
            luc_sizes[2],
            True,
        ),
        agree(
            AgreementAlgorithm.LUCDIF,
            Span(luc_parameters),
            Span(luc_bob[0]),
            Span(luc_public),
            luc_sizes[2],
            False,
        ),
    )
    var ec_generator = PreparedEllipticKeyGenerator(
        AgreementAlgorithm.ECDH_P256, 512
    )
    var ec_alice = ec_generator.generate()
    var ec_private = ec_alice[0].copy()
    var ec_public = ec_alice[1].copy()
    var ec_parameters = ec_alice[2].copy()
    var ec_sizes = agreement_info(AgreementAlgorithm.ECDH_P256, 512)
    var ec_bob = generate_agreement_peer(
        AgreementAlgorithm.ECDH_P256,
        Span(ec_parameters),
        ec_sizes[0],
        ec_sizes[1],
        False,
    )
    assert_equal(
        agree(
            AgreementAlgorithm.ECDH_P256,
            Span(ec_parameters),
            Span(ec_private),
            Span(ec_bob[1]),
            ec_sizes[2],
            True,
        ),
        agree(
            AgreementAlgorithm.ECDH_P256,
            Span(ec_parameters),
            Span(ec_bob[0]),
            Span(ec_public),
            ec_sizes[2],
            False,
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
