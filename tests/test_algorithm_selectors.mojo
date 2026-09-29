from std.testing import assert_raises, assert_true, TestSuite

from mcrypto.aead.algorithm import (
    AeadAlgorithm,
    AegisAlgorithm,
    ChachaAeadAlgorithm,
    as_aegis_algorithm,
    as_chacha_aead_algorithm,
    parse_aead_algorithm,
)
from mcrypto.aead.combined import encrypt as combined_aead_encrypt
from mcrypto.aead.chacha20poly1305 import (
    _counter_algorithm,
    _stream_algorithm,
    encrypt as chacha_aead_encrypt,
)
from mcrypto.ciphers.algorithm import (
    BlockCipherAlgorithm,
    Chacha20Stream,
    CipherMode,
    StreamCipherAlgorithm,
    block_cipher_name,
    chacha20_stream_name,
    cipher_mode_name,
    parse_block_cipher,
    parse_cipher_mode,
    parse_cipher_path,
    parse_stream_cipher,
    stream_cipher_name,
)
from mcrypto.compression.algorithm import (
    CompressionTransform,
    parse_compression_transform,
)
from mcrypto.compression.transforms import (
    transform as compression_transform,
)
from mcrypto.encoding.algorithm import (
    EncodingTransform,
    parse_encoding_transform,
)
from mcrypto.encoding.transforms import transform as encoding_transform
from mcrypto.groups.algorithm import (
    BatchedCoreAlgorithm,
    CoreAlgorithm,
    EdwardsGroupAlgorithm,
    GroupFamily,
    GroupOperation,
    parse_batched_core_algorithm,
    parse_core_algorithm,
    parse_edwards_group_algorithm,
    parse_group_family,
    parse_group_operation,
)
from mcrypto.groups.scalar import core_operation, group_operation
from mcrypto.hashes.algorithm import (
    HashAlgorithm,
    hash_algorithm_name,
    parse_hash_algorithm,
)
from mcrypto.hashes.xof_algorithm import XofAlgorithm, parse_xof_algorithm
from mcrypto.hashes.xof import xof
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm, parse_ipcrypt_algorithm
from mcrypto.kdf.algorithm import (
    Argon2Algorithm,
    KdfAlgorithm,
    parse_argon2_algorithm,
    parse_kdf_algorithm,
)
from mcrypto.kdf.argon2 import derive as argon2_derive
from mcrypto.kem.algorithm import KemAlgorithm, parse_kem_algorithm
from mcrypto.kem.dispatch import keypair as kem_keypair
from mcrypto.key_exchange.algorithm import (
    AgreementAlgorithm,
    parse_agreement_algorithm,
)
from mcrypto.macs.algorithm import (
    HmacAlgorithm,
    MacAlgorithm,
    SipHashAlgorithm,
    as_hmac_algorithm,
    as_siphash_algorithm,
    hmac_algorithm_name,
    parse_mac_algorithm,
    siphash_algorithm_name,
)
from mcrypto.math.curve import CurveAlgorithm, curve_name, parse_curve_algorithm
from mcrypto.public_key.algorithm import (
    PublicKeyEncryptionAlgorithm,
    RsaEncryptionAlgorithm,
    as_rsa_encryption_algorithm,
    parse_public_key_encryption_algorithm,
    public_key_encryption_name,
    rsa_encryption_name,
)
from mcrypto.random.algorithm import (
    DrbgAlgorithm,
    HardwareRandomAlgorithm,
    RandomAlgorithm,
    X917Cipher,
    parse_drbg_algorithm,
    parse_hardware_random_algorithm,
    parse_random_algorithm,
    parse_x917_cipher,
)
from mcrypto.signatures.algorithm import (
    ECSignatureScheme,
    RsaSignatureAlgorithm,
    SignatureAlgorithm,
    as_rsa_signature_algorithm,
    parse_signature_algorithm,
    rsa_signature_name,
    signature_algorithm_name,
)
from mcrypto.signatures.ecdsa import PreparedECSigner


def test_external_names_parse_to_typed_selectors() raises:
    assert_true(parse_aead_algorithm("GCM") == AeadAlgorithm.GCM)
    assert_true(parse_block_cipher("AES") == BlockCipherAlgorithm.AES)
    assert_true(
        parse_stream_cipher("ChaCha20") == StreamCipherAlgorithm.CHACHA20
    )
    assert_true(parse_cipher_mode("CBC") == CipherMode.CBC)
    var cipher_path = parse_cipher_path("AES/CBC")
    assert_true(cipher_path[0] == BlockCipherAlgorithm.AES)
    assert_true(cipher_path[1] == CipherMode.CBC)
    assert_true(
        parse_compression_transform("Deflate") == CompressionTransform.DEFLATE
    )
    assert_true(
        parse_encoding_transform("HexEncode") == EncodingTransform.HEX_ENCODE
    )
    assert_true(parse_core_algorithm("HChaCha20") == CoreAlgorithm.HCHACHA20)
    assert_true(
        parse_batched_core_algorithm("HChaCha20")
        == BatchedCoreAlgorithm.HCHACHA20
    )
    assert_true(
        parse_edwards_group_algorithm("Ed25519")
        == EdwardsGroupAlgorithm.ED25519
    )
    assert_true(parse_group_family("X25519") == GroupFamily.X25519)
    assert_true(parse_group_operation("add") == GroupOperation.ADD)
    assert_true(parse_hash_algorithm("SHA-256") == HashAlgorithm.SHA256)
    assert_true(parse_xof_algorithm("SHAKE128") == XofAlgorithm.SHAKE128)
    assert_true(parse_ipcrypt_algorithm("IPcrypt") == IpcryptAlgorithm.IPCRYPT)
    assert_true(parse_argon2_algorithm("Argon2i") == Argon2Algorithm.ARGON2I)
    assert_true(parse_kdf_algorithm("HKDF-SHA256") == KdfAlgorithm.HKDF_SHA256)
    assert_true(parse_kem_algorithm("ML-KEM-768") == KemAlgorithm.ML_KEM_768)
    assert_true(parse_agreement_algorithm("DH") == AgreementAlgorithm.DH)
    assert_true(parse_mac_algorithm("HMAC-SHA256") == MacAlgorithm.HMAC_SHA256)
    assert_true(parse_curve_algorithm("P-256") == CurveAlgorithm.P256)
    assert_true(
        parse_public_key_encryption_algorithm("RSA")
        == PublicKeyEncryptionAlgorithm.RSA
    )
    assert_true(
        parse_hardware_random_algorithm("RDRAND")
        == HardwareRandomAlgorithm.RDRAND
    )
    assert_true(parse_x917_cipher("AES") == X917Cipher.AES)
    assert_true(
        parse_drbg_algorithm("Hash-DRBG-SHA256") == DrbgAlgorithm.HASH_SHA256
    )
    assert_true(
        parse_random_algorithm("ANSI-X9.31-AES")
        == RandomAlgorithm.ANSI_X931_AES
    )
    assert_true(parse_signature_algorithm("RSA") == SignatureAlgorithm.RSA)


def test_selector_names_and_subfamily_conversions() raises:
    assert_true(
        as_aegis_algorithm(AeadAlgorithm.AEGIS128L) == AegisAlgorithm.AEGIS128L
    )
    assert_true(
        as_chacha_aead_algorithm(AeadAlgorithm.CHACHA20_POLY1305_IETF)
        == ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF
    )
    assert_true(block_cipher_name(BlockCipherAlgorithm.AES) == "AES")
    assert_true(
        stream_cipher_name(StreamCipherAlgorithm.CHACHA20) == "ChaCha20"
    )
    assert_true(
        stream_cipher_name(StreamCipherAlgorithm.XCHACHA20_COUNTER1)
        == "XChaCha20-Counter1"
    )
    assert_true(
        parse_stream_cipher("XChaCha20-Counter1")
        == StreamCipherAlgorithm.XCHACHA20_COUNTER1
    )
    assert_true(chacha20_stream_name(Chacha20Stream.CHACHA20) == "ChaCha20")
    assert_true(cipher_mode_name(CipherMode.CBC) == "CBC")
    assert_true(hash_algorithm_name(HashAlgorithm.SHA256) == "SHA-256")
    assert_true(
        as_hmac_algorithm(MacAlgorithm.HMAC_SHA256) == HmacAlgorithm.SHA256
    )
    assert_true(hmac_algorithm_name(HmacAlgorithm.SHA256) == "HMAC-SHA256")
    assert_true(
        as_siphash_algorithm(MacAlgorithm.SIPHASH_2_4)
        == SipHashAlgorithm.SIPHASH_2_4
    )
    assert_true(
        siphash_algorithm_name(SipHashAlgorithm.SIPHASH_2_4) == "SipHash-2-4"
    )
    assert_true(curve_name(CurveAlgorithm.P256) == "P-256")
    assert_true(
        as_rsa_encryption_algorithm(
            PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256
        )
        == RsaEncryptionAlgorithm.OAEP_SHA256
    )
    assert_true(
        public_key_encryption_name(PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256)
        == "RSA/OAEP-MGF1(SHA-256)"
    )
    assert_true(
        rsa_encryption_name(RsaEncryptionAlgorithm.OAEP_SHA256)
        == "RSA/OAEP-MGF1(SHA-256)"
    )
    assert_true(
        as_rsa_signature_algorithm(SignatureAlgorithm.RSA_PSS_SHA256)
        == RsaSignatureAlgorithm.PSS_SHA256
    )
    assert_true(
        signature_algorithm_name(SignatureAlgorithm.RSA_PSS_SHA256)
        == "RSA/PSS-MGF1(SHA-256)"
    )
    assert_true(
        rsa_signature_name(RsaSignatureAlgorithm.PSS_SHA256)
        == "RSA/PSS-MGF1(SHA-256)"
    )
    assert_true(ECSignatureScheme.ECDSA == ECSignatureScheme.ECDSA)


def test_unknown_external_names_are_rejected() raises:
    with assert_raises():
        _ = parse_aead_algorithm("unknown")
    with assert_raises():
        _ = parse_block_cipher("unknown")
    with assert_raises():
        _ = parse_stream_cipher("unknown")
    with assert_raises():
        _ = parse_cipher_mode("unknown")
    with assert_raises():
        _ = parse_cipher_path("unknown")
    with assert_raises():
        _ = parse_compression_transform("unknown")
    with assert_raises():
        _ = parse_encoding_transform("unknown")
    with assert_raises():
        _ = parse_core_algorithm("unknown")
    with assert_raises():
        _ = parse_batched_core_algorithm("unknown")
    with assert_raises():
        _ = parse_edwards_group_algorithm("unknown")
    with assert_raises():
        _ = parse_group_family("unknown")
    with assert_raises():
        _ = parse_group_operation("unknown")
    with assert_raises():
        _ = parse_hash_algorithm("unknown")
    with assert_raises():
        _ = parse_xof_algorithm("unknown")
    with assert_raises():
        _ = parse_ipcrypt_algorithm("unknown")
    with assert_raises():
        _ = parse_argon2_algorithm("unknown")
    with assert_raises():
        _ = parse_kdf_algorithm("unknown")
    with assert_raises():
        _ = parse_kem_algorithm("unknown")
    with assert_raises():
        _ = parse_agreement_algorithm("unknown")
    with assert_raises():
        _ = parse_mac_algorithm("unknown")
    with assert_raises():
        _ = parse_curve_algorithm("unknown")
    with assert_raises():
        _ = parse_public_key_encryption_algorithm("unknown")
    with assert_raises():
        _ = parse_hardware_random_algorithm("unknown")
    with assert_raises():
        _ = parse_x917_cipher("unknown")
    with assert_raises():
        _ = parse_drbg_algorithm("unknown")
    with assert_raises():
        _ = parse_random_algorithm("unknown")
    with assert_raises():
        _ = parse_signature_algorithm("unknown")


def test_selector_name_helpers_reject_corrupted_values() raises:
    assert_true(chacha20_stream_name(Chacha20Stream.XCHACHA20) == "XChaCha20")
    assert_true(block_cipher_name(BlockCipherAlgorithm.XTEA) == "XTEA")
    assert_true(stream_cipher_name(StreamCipherAlgorithm.HC256) == "HC-256")
    assert_true(cipher_mode_name(CipherMode.XTS) == "XTS")
    assert_true(hash_algorithm_name(HashAlgorithm.WHIRLPOOL) == "Whirlpool")
    assert_true(
        hmac_algorithm_name(HmacAlgorithm.RIPEMD160) == "RIPEMD160-HMAC"
    )
    assert_true(
        siphash_algorithm_name(SipHashAlgorithm.SIPHASH_X_2_4)
        == "SipHash-x-2-4"
    )
    assert_true(
        curve_name(CurveAlgorithm.BRAINPOOL_P256R1) == "brainpoolP256r1"
    )
    assert_true(
        rsa_encryption_name(RsaEncryptionAlgorithm.OAEP_SHA256)
        == "RSA/OAEP-MGF1(SHA-256)"
    )
    assert_true(
        public_key_encryption_name(PublicKeyEncryptionAlgorithm.ECIES)
        == "ECIES"
    )
    assert_true(
        rsa_signature_name(RsaSignatureAlgorithm.PKCS1_SHA256)
        == "RSA/PKCS1-1.5(SHA-256)"
    )
    assert_true(
        signature_algorithm_name(SignatureAlgorithm.ED25519) == "Ed25519"
    )

    var chacha = Chacha20Stream.CHACHA20
    chacha._value = 255
    with assert_raises():
        _ = chacha20_stream_name(chacha)
    var block = BlockCipherAlgorithm.AES
    block._value = 255
    with assert_raises():
        _ = block_cipher_name(block)
    var stream = StreamCipherAlgorithm.CHACHA20
    stream._value = 255
    with assert_raises():
        _ = stream_cipher_name(stream)
    var mode = CipherMode.CBC
    mode._value = 255
    with assert_raises():
        _ = cipher_mode_name(mode)
    var hash = HashAlgorithm.SHA256
    hash._value = 255
    with assert_raises():
        _ = hash_algorithm_name(hash)
    var hmac = HmacAlgorithm.SHA256
    hmac._value = 255
    with assert_raises():
        _ = hmac_algorithm_name(hmac)
    var siphash = SipHashAlgorithm.SIPHASH_2_4
    siphash._value = 255
    with assert_raises():
        _ = siphash_algorithm_name(siphash)
    var curve = CurveAlgorithm.P256
    curve._value = 255
    with assert_raises():
        _ = curve_name(curve)
    var rsa_encryption = RsaEncryptionAlgorithm.OAEP_SHA256
    rsa_encryption._value = 255
    with assert_raises():
        _ = rsa_encryption_name(rsa_encryption)
    var public_key = PublicKeyEncryptionAlgorithm.RSA
    public_key._value = 255
    with assert_raises():
        _ = public_key_encryption_name(public_key)
    var rsa_signature = RsaSignatureAlgorithm.PSS_SHA256
    rsa_signature._value = 255
    with assert_raises():
        _ = rsa_signature_name(rsa_signature)
    var signature = SignatureAlgorithm.RSA
    signature._value = 255
    with assert_raises():
        _ = signature_algorithm_name(signature)


def test_dispatchers_reject_corrupted_selector_values() raises:
    var empty = List[UInt8]()

    var aead = AeadAlgorithm.GCM
    var aead_key = List[UInt8](length=16, fill=0)
    var aead_nonce = List[UInt8](length=12, fill=0)
    var aead_aad = List[UInt8]()
    var aead_message = List[UInt8]()
    _ = combined_aead_encrypt(
        aead,
        Span(aead_key),
        Span(aead_nonce),
        Span(aead_aad),
        Span(aead_message),
    )
    aead._value = 255
    with assert_raises():
        _ = combined_aead_encrypt(
            aead,
            Span(aead_key),
            Span(aead_nonce),
            Span(aead_aad),
            Span(aead_message),
        )

    var chacha_aead = ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF
    var chacha_key = List[UInt8](length=32, fill=0)
    var chacha_nonce = List[UInt8](length=12, fill=0)
    var chacha_aad = List[UInt8]()
    var chacha_message = List[UInt8]()
    _ = chacha_aead_encrypt(
        chacha_aead,
        Span(chacha_key),
        Span(chacha_nonce),
        Span(chacha_aad),
        Span(chacha_message),
    )
    _ = _stream_algorithm(chacha_aead)
    _ = _counter_algorithm(chacha_aead)
    chacha_aead._value = 255
    with assert_raises():
        _ = chacha_aead_encrypt(
            chacha_aead,
            Span(chacha_key),
            Span(chacha_nonce),
            Span(chacha_aad),
            Span(chacha_message),
        )
    with assert_raises():
        _ = _stream_algorithm(chacha_aead)
    with assert_raises():
        _ = _counter_algorithm(chacha_aead)

    var compression = CompressionTransform.GZIP
    var gzip_empty = compression_transform(compression, Span(empty))
    compression._value = 255
    with assert_raises():
        _ = compression_transform(compression, Span(gzip_empty))

    var encoding = EncodingTransform.BASE64URL_DECODE
    var valid_base64url: List[UInt8] = [65, 65, 61, 61]
    _ = encoding_transform(encoding, Span(valid_base64url))
    encoding._value = 255
    with assert_raises():
        _ = encoding_transform(encoding, Span(valid_base64url))

    var xof_algorithm = XofAlgorithm.TURBOSHAKE256
    _ = xof(xof_algorithm, Span(empty), 1)
    xof_algorithm._value = 255
    with assert_raises():
        _ = xof(xof_algorithm, Span(empty), 1)

    var argon2 = Argon2Algorithm.ARGON2ID
    var salt = List[UInt8](length=8, fill=0)
    var password = List[UInt8]()
    var secret = List[UInt8]()
    var associated_data = List[UInt8]()
    _ = argon2_derive(
        argon2,
        Span(password),
        Span(salt),
        Span(secret),
        Span(associated_data),
        4,
        1,
        8,
        1,
    )
    argon2._value = 255
    with assert_raises():
        _ = argon2_derive(
            argon2,
            Span(password),
            Span(salt),
            Span(secret),
            Span(associated_data),
            4,
            1,
            8,
            1,
        )

    var kem = KemAlgorithm.X_WING
    _ = kem_keypair(kem)
    kem._value = 255
    with assert_raises():
        _ = kem_keypair(kem)

    var core = CoreAlgorithm.KECCAK_F1600
    var keccak_state = List[UInt8](length=200, fill=0)
    _ = core_operation(core, Span(keccak_state), Span(empty))
    core._value = 255
    with assert_raises():
        _ = core_operation(core, Span(keccak_state), Span(empty))

    var group = EdwardsGroupAlgorithm.RISTRETTO255
    var group_left = List[UInt8](length=32, fill=0)
    var group_right = List[UInt8](length=32, fill=0)
    _ = group_operation(
        group,
        GroupOperation.SCALAR_MUL,
        Span(group_left),
        Span(group_right),
    )
    group._value = 255
    with assert_raises():
        _ = group_operation(
            group,
            GroupOperation.SCALAR_MUL,
            Span(group_left),
            Span(group_right),
        )

    var scheme = ECSignatureScheme.ECGDSA
    var private_key = List[UInt8](length=32, fill=0)
    private_key[31] = 1
    _ = PreparedECSigner(
        scheme,
        CurveAlgorithm.P256,
        HashAlgorithm.SHA256,
        Span(private_key),
    )
    scheme._value = 255
    with assert_raises():
        _ = PreparedECSigner(
            scheme,
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(private_key),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
