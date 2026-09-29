from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.legacy_stream import arc4, wake


def h(text: StaticString) -> List[UInt8]:
    var b = text.as_bytes()
    var output = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var high = Int(b[i])
        var low = Int(b[i + 1])
        high -= 48 if high <= 57 else (87 if high >= 97 else 55)
        low -= 48 if low <= 57 else (87 if low >= 97 else 55)
        output.append(UInt8(high * 16 + low))
    return output^


def test_arc4_known_vector() raises:
    # "Key" is the intentionally weak published ARC4 compatibility fixture,
    # never production key material.
    var key = "Key".as_bytes()
    var plain = "Plaintext".as_bytes()
    var cipher = h("BBF316E8D940AF0AD3")
    assert_equal(arc4(key, plain), cipher)
    assert_equal(arc4(key, Span(cipher)), List(plain))


def test_wake_generated_vector_prefix() raises:
    # This deterministic WAKE vector key is test material, not a generated
    # production secret.
    var key = h(
        "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
    )
    var input = List[UInt8](length=160, fill=0)
    for i in range(80, 160):
        input[i] = 1
    var expected_le = h(
        "FFEEDDCCDF42B9D4939C351568AB4888BD9264CA66CF7F7885141F6934F3F390"
        "F1987B8609B733919DC5F73F7BED93ECDCD4F35FF32828553B8AFAD113DDA656"
        "5932553D9143AA886AE859167327F3C260434E6C90A0895FD33E6B6412526521"
        "FA0B12F4ECEE3E8F4F96DCF70907AAFB5E29C40FC10EB70A4970736E98DF98C"
        "615AC844A46FB8E4AEBBBF599DF7B73930B94776C6C8757BE51B34E71E9B514"
        "AE"
    )
    var expected_be = h(
        "CCDDEEFFD4B942DF15359C938848AB68CA6492BD787FCF66691F148590F3F334"
        "867B98F19133B7093FF7C59DEC93ED7B5FF3D4DC552828F3D1FA8A3B56A6DD1"
        "33D55325988AA43911659E86AC2F327736C4E43605F89A090646B3ED32165521"
        "2F4120BFA8F3EEEECF7DC964FFBAA07090FC4295E0AB70EC16E737049C698DF9"
        "84A84AC154A8EFB4699F5BBEB93737BDF6C77940BBE57876C714EB351AE14B5E9"
    )
    assert_equal(wake(False, Span(key), Span(input)), expected_be)
    assert_equal(wake(True, Span(key), Span(input)), expected_le)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
