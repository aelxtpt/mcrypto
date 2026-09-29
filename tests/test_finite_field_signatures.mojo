from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.signatures.finite_field import (
    PrimeGroup,
    encode_parameters,
    from_be,
)
from mcrypto.signatures.dsa import (
    generate_keypair as dsa_keypair,
    sign as dsa_sign,
    verify as dsa_verify,
)
from mcrypto.signatures.elgamal import (
    decrypt as elgamal_decrypt,
    encrypt as elgamal_encrypt,
    generate_keypair as elgamal_keypair,
    sign as elgamal_sign,
    verify as elgamal_verify,
)
from mcrypto.signatures.nr import (
    generate_keypair as nr_keypair,
    sign as nr_sign,
    verify as nr_verify,
)


def hex_bytes(text: String) raises -> List[UInt8]:
    var output = List[UInt8]()
    var high = -1
    for codepoint in text.codepoints():
        var code = Int(codepoint)
        var value: Int
        if code >= 48 and code <= 57:
            value = code - 48
        elif code >= 65 and code <= 70:
            value = code - 55
        elif code >= 97 and code <= 102:
            value = code - 87
        else:
            continue
        if high < 0:
            high = value
        else:
            output.append(UInt8(high * 16 + value))
            high = -1
    if high >= 0:
        raise Error("odd hex string")
    return output^


def rfc_group() raises -> List[UInt8]:
    var p = hex_bytes(
        "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779"
    )
    var q = hex_bytes("996F967F6C8E388D9E28D01E205FBA957A5698B1")
    var g = hex_bytes(
        "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD"
    )
    return encode_parameters(
        PrimeGroup(from_be(Span(p)), from_be(Span(q)), from_be(Span(g)))
    )


def nr_group() raises -> List[UInt8]:
    var q = hex_bytes("09b2940496d6d9a43bb7ec642c57b302e59b3a5155")
    var g = hex_bytes(
        "a1c379ba91fe1f9d5283807b809c698bce4aee6f405f4de8c46becf33c08a63bc5f8088f75b5b6bcfb0847ccbdee700e4e698652317bbd7a3056404c541136d7332c2b835ef0d1508ef57b437de60675f20f75df0483f242ddeb57efacd180418790f4dec0a8250593ba36f17316580d50db1383ea93a21247650a2e04af904d"
    )
    var p = hex_bytes(
        "bd670f79b0cde98a84fd97e54d5d5c81525a016d222a3986dd7af3f32cde8a9f6564e43a559a0c9f8bad36cc25330548b347ac158a345631fa90f7b873c36effae2f7823227a3f580b5dd18304d5932751e743e922eebfbb4289c389d9019c36f96c6b81fffbf20be062182104e3c4b7d02b872d9a21e0fb5f10ded64420951b"
    )
    return encode_parameters(
        PrimeGroup(from_be(Span(p)), from_be(Span(q)), from_be(Span(g)))
    )


def test_rfc6979_dsa_sha256_vector_and_tamper() raises:
    var parameters = rfc_group()
    var private_key = hex_bytes("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7")
    var public_key = hex_bytes(
        "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F65392195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E682F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B"
    )
    var message = hex_bytes("73616D706C65")
    var expected = hex_bytes(
        "81F2F5850BE5BC123C43F71A3033E9384611C5454CDD914B65EB6C66A8AAAD27299BEE6B035F5E89"
    )
    var signature = dsa_sign(
        HashAlgorithm.SHA256,
        Span(parameters),
        Span(private_key),
        Span(message),
    )
    assert_equal(signature, expected)
    assert_true(
        dsa_verify(
            HashAlgorithm.SHA256,
            Span(parameters),
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )
    message[0] ^= 1
    assert_false(
        dsa_verify(
            HashAlgorithm.SHA256,
            Span(parameters),
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )


def test_elgamal_encrypt_sign_roundtrip_and_tamper() raises:
    var parameters = rfc_group()
    var keys = elgamal_keypair(Span(parameters))
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = elgamal_encrypt(
        Span(parameters), Span(public_key), Span(message)
    )
    assert_equal(
        elgamal_decrypt(Span(parameters), Span(private_key), Span(ciphertext)),
        message,
    )
    var signature = elgamal_sign(
        Span(parameters), Span(private_key), Span(message)
    )
    assert_true(
        elgamal_verify(
            Span(parameters), Span(public_key), Span(message), Span(signature)
        )
    )
    signature[0] ^= 1
    assert_false(
        elgamal_verify(
            Span(parameters), Span(public_key), Span(message), Span(signature)
        )
    )


def test_reference_nr_vector_and_roundtrip() raises:
    var parameters = nr_group()
    var public_key = hex_bytes(
        "255cf6b0a33f80cab614eafd5f7b2a6d83b3eafe27cd97b77ae70c7b966707d823f0e6aaaa41dc005aaefd3a0c269e60a665d2642f5d631ff1a3b8701bc06be9c44ab7367f77fefeec4c5959cd07e50d74a05af60b059ad3fc75249ecf44774b88b46860d9c3fa35d033bcfc7b0b2d48dc180d192d4918cddff4f7ebcdaaa198"
    )
    var private_key = hex_bytes("0355dc884345c08fb399b23b161831e94dbe61571e")
    var message = hex_bytes("66B92E1E2C44B80F7BFA")
    var vector_signature = hex_bytes(
        "06e7586b76d5a8270155cce2d3ff4495237eed29a101eb1341fce0b43d95397b053d93772b0a9cf3117b"
    )
    assert_true(
        nr_verify(
            Span(parameters),
            Span(public_key),
            Span(message),
            Span(vector_signature),
        )
    )
    var signature = nr_sign(Span(parameters), Span(private_key), Span(message))
    assert_true(
        nr_verify(
            Span(parameters), Span(public_key), Span(message), Span(signature)
        )
    )
    message[0] ^= 1
    assert_false(
        nr_verify(
            Span(parameters), Span(public_key), Span(message), Span(signature)
        )
    )


def test_dsa_and_nr_generated_key_roundtrips() raises:
    var parameters = rfc_group()
    var dsa_keys = dsa_keypair(Span(parameters))
    var dsa_private = dsa_keys[0].copy()
    var dsa_public = dsa_keys[1].copy()
    var message: List[UInt8] = [10, 20, 30]
    var dsa_signature = dsa_sign(
        HashAlgorithm.SHA256,
        Span(parameters),
        Span(dsa_private),
        Span(message),
    )
    assert_true(
        dsa_verify(
            HashAlgorithm.SHA256,
            Span(parameters),
            Span(dsa_public),
            Span(message),
            Span(dsa_signature),
        )
    )
    var nr_parameters = nr_group()
    var nr_keys = nr_keypair(Span(nr_parameters))
    var nr_private = nr_keys[0].copy()
    var nr_public = nr_keys[1].copy()
    var nr_signature = nr_sign(
        Span(nr_parameters), Span(nr_private), Span(message)
    )
    assert_true(
        nr_verify(
            Span(nr_parameters),
            Span(nr_public),
            Span(message),
            Span(nr_signature),
        )
    )


def test_rejects_malformed_parameters_and_keys() raises:
    var malformed: List[UInt8] = [0, 1, 0]
    with assert_raises():
        _ = elgamal_keypair(Span(malformed))
    var parameters = rfc_group()
    var empty = List[UInt8]()
    var message: List[UInt8] = [1]
    with assert_raises():
        _ = dsa_sign(
            HashAlgorithm.SHA256,
            Span(parameters),
            Span(empty),
            Span(message),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
