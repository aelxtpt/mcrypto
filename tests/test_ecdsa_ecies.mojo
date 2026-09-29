from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.math.curve import CurveAlgorithm
from mcrypto.signatures.algorithm import ECSignatureScheme
from mcrypto.math.ec import biguint_from_hex, biguint_to_be, named_curve
from mcrypto.signatures.ecdsa import (
    public_key,
    sign,
    verify,
    ecnr_sign,
    ecnr_verify,
    ecgdsa_public_key,
    ecgdsa_sign,
    ecgdsa_verify,
    PreparedECSigner,
)
from mcrypto.public_key.ecies import encrypt_with_ephemeral, decrypt


def _hex(text: String) raises -> List[UInt8]:
    var value = biguint_from_hex(text)
    return biguint_to_be(value, (text.byte_length() + 1) // 2)


def _bytes(text: String) -> List[UInt8]:
    var output = List[UInt8](capacity=text.byte_length())
    for byte in text.as_bytes():
        output.append(byte)
    return output^


def test_rfc6979_p256_sha256_sample() raises:
    # RFC 6979 A.2.5, IEEE P1363 raw signature encoding.
    var private_key = _hex(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
    )
    var message = _bytes("sample")
    var signature = sign(
        CurveAlgorithm.P256,
        HashAlgorithm.SHA256,
        Span(message),
        Span(private_key),
    )
    var expected = _hex(
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
    )
    assert_equal(signature, expected)
    var prepared = PreparedECSigner(
        ECSignatureScheme.ECDSA,
        CurveAlgorithm.P256,
        HashAlgorithm.SHA256,
        Span(private_key),
    )
    assert_equal(prepared.sign(Span(message)), expected)
    var pub = public_key(CurveAlgorithm.P256, Span(private_key))
    assert_true(
        verify(
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(message),
            Span(signature),
            Span(pub),
        )
    )
    message[0] ^= 1
    assert_false(
        verify(
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(message),
            Span(signature),
            Span(pub),
        )
    )


def test_reference_ecnr_and_ecgdsa_families() raises:
    var private_key = List[UInt8](length=32, fill=0)
    private_key[31] = 9
    var message = _bytes("ECNR and ECGDSA family message")
    var pub = public_key(CurveAlgorithm.P256, Span(private_key))
    var nr = ecnr_sign(
        CurveAlgorithm.P256,
        HashAlgorithm.SHA256,
        Span(message),
        Span(private_key),
    )
    assert_true(
        ecnr_verify(
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(message),
            Span(nr),
            Span(pub),
        )
    )
    nr[0] ^= 1
    assert_false(
        ecnr_verify(
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(message),
            Span(nr),
            Span(pub),
        )
    )
    var gpub = ecgdsa_public_key(CurveAlgorithm.P256, Span(private_key))
    var gs = ecgdsa_sign(
        CurveAlgorithm.P256,
        HashAlgorithm.SHA256,
        Span(message),
        Span(private_key),
    )
    assert_true(
        ecgdsa_verify(
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(message),
            Span(gs),
            Span(gpub),
        )
    )
    gs[len(gs) - 1] ^= 1
    assert_false(
        ecgdsa_verify(
            CurveAlgorithm.P256,
            HashAlgorithm.SHA256,
            Span(message),
            Span(gs),
            Span(gpub),
        )
    )


def test_named_curves_and_sec1_validation() raises:
    for curve in [
        CurveAlgorithm.P256,
        CurveAlgorithm.P384,
        CurveAlgorithm.P521,
    ]:
        var domain = named_curve(curve)
        var encoded = domain.encode_point(domain.generator, True)
        var decoded = domain.decode_point(Span(encoded))
        assert_equal(decoded.x.to_hex(), domain.generator.x.to_hex())
    var domain = named_curve(CurveAlgorithm.P256)
    var malformed = List[UInt8](length=65, fill=0)
    malformed[0] = 4
    with assert_raises():
        _ = domain.decode_point(Span(malformed))


def test_ecies_roundtrip_tamper_and_invalid_point() raises:
    # Fixed private/ephemeral scalars make this a stable ECIES construction KAT.
    var recipient_private = List[UInt8](length=32, fill=0)
    recipient_private[31] = 7
    var recipient_public = public_key(
        CurveAlgorithm.P256, Span(recipient_private)
    )
    var ephemeral = List[UInt8](length=32, fill=0)
    ephemeral[31] = 11
    var message = _bytes("interoperable ECIES message")
    var label = _bytes("label")
    var params = _bytes("kdf")
    var ciphertext = encrypt_with_ephemeral(
        CurveAlgorithm.P256,
        Span(message),
        Span(recipient_public),
        Span(ephemeral),
        Span(label),
        Span(params),
    )
    assert_equal(
        ciphertext,
        _hex(
            "043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21"
            "d19099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a37"
            "40287f9445da3a457608e327af9cf15ea5efb6a60b625ff328f7b3beacd67cb3"
            "224dcb1a3deaf3312a7c566e239d16ba"
        ),
    )
    var plaintext = decrypt(
        CurveAlgorithm.P256,
        Span(ciphertext),
        Span(recipient_private),
        Span(label),
        Span(params),
    )
    assert_equal(plaintext, message)
    ciphertext[len(ciphertext) - 1] ^= 1
    with assert_raises():
        _ = decrypt(
            CurveAlgorithm.P256,
            Span(ciphertext),
            Span(recipient_private),
            Span(label),
            Span(params),
        )
    var invalid_public = List[UInt8](length=65, fill=0)
    invalid_public[0] = 4
    with assert_raises():
        _ = encrypt_with_ephemeral(
            CurveAlgorithm.P256,
            Span(message),
            Span(invalid_public),
            Span(ephemeral),
            Span(label),
            Span(params),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
