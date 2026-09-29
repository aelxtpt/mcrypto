from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.public_key.algorithm import RsaEncryptionAlgorithm
from mcrypto.signatures.algorithm import RsaSignatureAlgorithm
from mcrypto.public_key.rsa import (
    decrypt,
    encrypt,
    generate_keypair,
    i2osp,
    os2ip,
    private_key_from_components,
    public_key_from_components,
    sign,
    verify,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high -= 48 if high <= 57 else (55 if high <= 70 else 87)
        low -= 48 if low <= 57 else (55 if low <= 70 else 87)
        output.append(UInt8(high * 16 + low))
    return output^


def oaep_private_key() raises -> List[UInt8]:
    # PKCS #1 RSAES-OAEP example 1.
    var n = hex_bytes(
        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab"
        "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72"
        "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514"
        "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb"
    )
    var e = hex_bytes("010001")
    var d = hex_bytes(
        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd"
        "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55"
        "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf"
        "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1"
    )
    return private_key_from_components(Span(n), Span(e), Span(d))


def test_os2ip_i2osp() raises:
    var bytes = hex_bytes("00010203040506070809")
    var integer = os2ip(Span(bytes))
    assert_equal(i2osp(integer, 10), bytes)
    with assert_raises():
        _ = i2osp(integer, 8)


def test_reference_oaep_sha1_decrypt_kat() raises:
    var key = oaep_private_key()
    var ciphertext = hex_bytes(
        "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb"
        "21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535f"
        "a9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426"
        "d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a"
    )
    var expected = hex_bytes(
        "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34"
    )
    assert_equal(
        decrypt(
            RsaEncryptionAlgorithm.OAEP_SHA1,
            Span(key),
            Span(ciphertext),
        ),
        expected,
    )
    ciphertext[17] ^= 1
    with assert_raises():
        _ = decrypt(
            RsaEncryptionAlgorithm.OAEP_SHA1,
            Span(key),
            Span(ciphertext),
        )


def test_reference_pss_sha1_verify_kat() raises:
    # PKCS #1 RSASSA-PSS example 1.1.
    var n = hex_bytes(
        "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991"
        "d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1df"
        "d5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f1"
        "05acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137"
    )
    var e = hex_bytes("010001")
    var public_key = public_key_from_components(Span(n), Span(e))
    var message = hex_bytes(
        "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b6"
        "2371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb76"
        "9757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb0"
        "61a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d61"
        "93c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c"
        "296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16"
        "be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0"
    )
    var signature = hex_bytes(
        "9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887"
        "e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5051215"
        "df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65"
        "984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c"
    )
    assert_true(
        verify(
            RsaSignatureAlgorithm.PSS_SHA1,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )
    signature[0] ^= 1
    assert_false(
        verify(
            RsaSignatureAlgorithm.PSS_SHA1,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )


def test_reference_pkcs1_sha1_verify_kat() raises:
    # PKCS #1 v1.5 component-key SHA-1 vector.
    var n = hex_bytes(
        "A885B6F851A8079AB8A281DB0297148511EE0D8C07C0D4AE6D6FED461488E0D4"
        "1E3FF8F281B06A3240B5007A5C2AB4FB6BE8AF88F119DB998368DDDC9710ABED"
    )
    var e = hex_bytes("010001")
    var public_key = public_key_from_components(Span(n), Span(e))
    var message = hex_bytes("74657374")
    var signature = hex_bytes(
        "A7E00CE4391F914D82158D9B732759808E25A1C6383FE87A5199157650D4296C"
        "F612E9FF809E686A0AF328238306E79965F6D0138138829D9A1A22764306F6CE"
    )
    assert_true(
        verify(
            RsaSignatureAlgorithm.PKCS1_SHA1,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )
    message[0] ^= 1
    assert_false(
        verify(
            RsaSignatureAlgorithm.PKCS1_SHA1,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )


def test_generated_key_roundtrips_and_tamper() raises:
    var keys = generate_keypair(512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 3, 3, 7]
    var ciphertext = encrypt(
        RsaEncryptionAlgorithm.PKCS1, Span(public_key), Span(message)
    )
    assert_equal(
        decrypt(
            RsaEncryptionAlgorithm.PKCS1,
            Span(private_key),
            Span(ciphertext),
        ),
        message,
    )
    var oaep = encrypt(
        RsaEncryptionAlgorithm.OAEP_SHA1, Span(public_key), Span(message)
    )
    assert_equal(
        decrypt(
            RsaEncryptionAlgorithm.OAEP_SHA1,
            Span(private_key),
            Span(oaep),
        ),
        message,
    )
    var pss = sign(
        RsaSignatureAlgorithm.PSS_SHA1, Span(private_key), Span(message)
    )
    assert_true(
        verify(
            RsaSignatureAlgorithm.PSS_SHA1,
            Span(public_key),
            Span(message),
            Span(pss),
        )
    )
    pss[3] ^= 1
    assert_false(
        verify(
            RsaSignatureAlgorithm.PSS_SHA1,
            Span(public_key),
            Span(message),
            Span(pss),
        )
    )
    var signature = sign(
        RsaSignatureAlgorithm.PKCS1_SHA256,
        Span(private_key),
        Span(message),
    )
    assert_true(
        verify(
            RsaSignatureAlgorithm.PKCS1_SHA256,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )
    signature[len(signature) - 1] ^= 1
    assert_false(
        verify(
            RsaSignatureAlgorithm.PKCS1_SHA256,
            Span(public_key),
            Span(message),
            Span(signature),
        )
    )
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(
            RsaEncryptionAlgorithm.PKCS1,
            Span(private_key),
            Span(ciphertext),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
