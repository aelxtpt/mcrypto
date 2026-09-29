from std.testing import assert_equal, TestSuite
from mcrypto.aead.combined import encrypt, encrypt_chacha_eight, decrypt
from mcrypto.aead.algorithm import AeadAlgorithm, ChachaAeadAlgorithm


def hex_bytes(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var h = Int(b[i])
        var l = Int(b[i + 1])
        h -= 48 if h <= 57 else 87
        l -= 48 if l <= 57 else 87
        o.append(UInt8(h * 16 + l))
    return o^


def test_rfc8439_aead() raises:
    var key = hex_bytes(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    var nonce = hex_bytes("070000004041424344454647")
    var aad = hex_bytes("50515253c0c1c2c3c4c5c6c7")
    var message = (
        "Ladies and Gentlemen of the class of '99: If I could offer you only"
        " one tip for the future, sunscreen would be it.".as_bytes()
    )
    var expected = hex_bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    )
    var ciphertext = encrypt(
        AeadAlgorithm.CHACHA20_POLY1305_IETF,
        Span(key),
        Span(nonce),
        Span(aad),
        message,
    )
    assert_equal(ciphertext, expected)
    assert_equal(
        decrypt(
            AeadAlgorithm.CHACHA20_POLY1305_IETF,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
        ),
        List(message),
    )


def test_eight_way_chacha_aead_matches_independent_messages() raises:
    var key = List[UInt8](length=32, fill=0xA5)
    for batch_algorithm, algorithm, nonce_size in [
        (
            ChachaAeadAlgorithm.CHACHA20_POLY1305,
            AeadAlgorithm.CHACHA20_POLY1305,
            8,
        ),
        (
            ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF,
            AeadAlgorithm.CHACHA20_POLY1305_IETF,
            12,
        ),
        (
            ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF,
            AeadAlgorithm.XCHACHA20_POLY1305_IETF,
            24,
        ),
    ]:
        var nonces = List[List[UInt8]](capacity=8)
        var aads = List[List[UInt8]](capacity=8)
        var messages = List[List[UInt8]](capacity=8)
        for lane in range(8):
            nonces.append(List[UInt8](length=nonce_size, fill=UInt8(lane)))
            aads.append(List[UInt8](length=17, fill=UInt8(0x10 + lane)))
            messages.append(List[UInt8](length=300, fill=UInt8(0x20 + lane)))
        var outputs = encrypt_chacha_eight(
            batch_algorithm, Span(key), nonces, aads, messages
        )
        for lane in range(8):
            assert_equal(
                outputs[lane],
                encrypt(
                    algorithm,
                    Span(key),
                    Span(nonces[lane]),
                    Span(aads[lane]),
                    Span(messages[lane]),
                ),
            )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
