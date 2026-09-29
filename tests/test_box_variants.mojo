from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.key_exchange.x25519 import public_key
from mcrypto.public_key.box_variants import (
    xsalsa20poly1305_encrypt_easy,
    xsalsa20poly1305_encrypt_eight,
    xsalsa20poly1305_decrypt_easy,
    xsalsa20poly1305_decrypt_eight,
    xsalsa20poly1305_encrypt_detached,
    xsalsa20poly1305_decrypt_detached,
    xchacha20poly1305_encrypt_easy,
    xchacha20poly1305_decrypt_easy,
    xchacha20poly1305_encrypt_eight,
    xchacha20poly1305_decrypt_eight,
    xchacha20poly1305_encrypt_detached,
    xchacha20poly1305_decrypt_detached,
    seal_deterministic,
    seal_open,
    xchacha20poly1305_seal_deterministic,
    xchacha20poly1305_seal_open,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_xsalsa_interop_vector_and_detached() raises:
    var alice_secret = hex_bytes(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    var bob_public = hex_bytes(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    var nonce = hex_bytes("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
    var message = hex_bytes(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"
    )
    var expected = hex_bytes(
        "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"
    )
    var combined = xsalsa20poly1305_encrypt_easy(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(combined, expected)
    var parts = xsalsa20poly1305_encrypt_detached(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    var body = parts[0].copy()
    var tag = parts[1].copy()
    var expected_tag = List[UInt8](capacity=16)
    for i in range(16):
        expected_tag.append(expected[i])
    assert_equal(tag, expected_tag)
    assert_equal(
        xsalsa20poly1305_decrypt_detached(
            Span(body),
            Span(tag),
            Span(nonce),
            Span(bob_public),
            Span(alice_secret),
        ),
        message,
    )


def test_two_party_variants_and_rejection() raises:
    var alice_secret = List[UInt8](length=32, fill=7)
    var bob_secret = List[UInt8](length=32, fill=9)
    var wrong_secret = List[UInt8](length=32, fill=11)
    var alice_public = public_key(Span(alice_secret))
    var bob_public = public_key(Span(bob_secret))
    var nonce = List[UInt8](length=24, fill=3)
    var message: List[UInt8] = [1, 2, 3, 4, 5, 6, 7]
    var xs = xsalsa20poly1305_encrypt_easy(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(
        xsalsa20poly1305_decrypt_easy(
            Span(xs), Span(nonce), Span(alice_public), Span(bob_secret)
        ),
        message,
    )
    with assert_raises():
        _ = xsalsa20poly1305_decrypt_easy(
            Span(xs), Span(nonce), Span(alice_public), Span(wrong_secret)
        )
    var xc = xchacha20poly1305_encrypt_easy(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(
        xchacha20poly1305_decrypt_easy(
            Span(xc), Span(nonce), Span(alice_public), Span(bob_secret)
        ),
        message,
    )
    var parts = xchacha20poly1305_encrypt_detached(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    var body = parts[0].copy()
    var tag = parts[1].copy()
    assert_equal(
        xchacha20poly1305_decrypt_detached(
            Span(body),
            Span(tag),
            Span(nonce),
            Span(alice_public),
            Span(bob_secret),
        ),
        message,
    )
    tag[0] ^= 1
    with assert_raises():
        _ = xchacha20poly1305_decrypt_detached(
            Span(body),
            Span(tag),
            Span(nonce),
            Span(alice_public),
            Span(bob_secret),
        )


def test_eight_way_boxes_match_independent_messages() raises:
    var alice_secret = List[UInt8](length=32, fill=7)
    var bob_secret = List[UInt8](length=32, fill=9)
    var bob_public = public_key(Span(bob_secret))
    var alice_public = public_key(Span(alice_secret))
    var nonces = List[List[UInt8]](capacity=8)
    var messages = List[List[UInt8]](capacity=8)
    for lane in range(8):
        nonces.append(List[UInt8](length=24, fill=UInt8(lane)))
        messages.append(List[UInt8](length=300, fill=UInt8(0x20 + lane)))
    var xsalsa_outputs = xsalsa20poly1305_encrypt_eight(
        messages, nonces, Span(bob_public), Span(alice_secret)
    )
    var xchacha_outputs = xchacha20poly1305_encrypt_eight(
        messages, nonces, Span(bob_public), Span(alice_secret)
    )
    for lane in range(8):
        assert_equal(
            xsalsa_outputs[lane],
            xsalsa20poly1305_encrypt_easy(
                Span(messages[lane]),
                Span(nonces[lane]),
                Span(bob_public),
                Span(alice_secret),
            ),
        )
        assert_equal(
            xchacha_outputs[lane],
            xchacha20poly1305_encrypt_easy(
                Span(messages[lane]),
                Span(nonces[lane]),
                Span(bob_public),
                Span(alice_secret),
            ),
        )
    var xsalsa_recovered = xsalsa20poly1305_decrypt_eight(
        xsalsa_outputs, nonces, Span(alice_public), Span(bob_secret)
    )
    var xchacha_recovered = xchacha20poly1305_decrypt_eight(
        xchacha_outputs, nonces, Span(alice_public), Span(bob_secret)
    )
    for lane in range(8):
        assert_equal(xsalsa_recovered[lane], messages[lane])
        assert_equal(xchacha_recovered[lane], messages[lane])


def test_sealed_boxes_roundtrip_tamper_and_wrong_key() raises:
    var recipient_secret = List[UInt8](length=32, fill=17)
    var recipient_public = public_key(Span(recipient_secret))
    var wrong_secret = List[UInt8](length=32, fill=19)
    var ephemeral_secret = List[UInt8](length=32, fill=23)
    var message: List[UInt8] = [10, 20, 30, 40, 50]
    var classic = seal_deterministic(
        Span(message), Span(recipient_public), Span(ephemeral_secret)
    )
    assert_equal(
        classic,
        hex_bytes(
            "f13fef3efa9598a2a23fc756bf688fe8bbd7f6cf9528bbaef3b4442688f0ab316a4eb3c7cd2f34a077538ad3eb895b62bb98270d36"
        ),
    )
    assert_equal(len(classic), len(message) + 48)
    assert_equal(
        seal_open(
            Span(classic), Span(recipient_public), Span(recipient_secret)
        ),
        message,
    )
    with assert_raises():
        _ = seal_open(Span(classic), Span(recipient_public), Span(wrong_secret))
    classic[32] ^= 1
    with assert_raises():
        _ = seal_open(
            Span(classic), Span(recipient_public), Span(recipient_secret)
        )
    var modern = xchacha20poly1305_seal_deterministic(
        Span(message), Span(recipient_public), Span(ephemeral_secret)
    )
    assert_equal(
        modern,
        hex_bytes(
            "f13fef3efa9598a2a23fc756bf688fe8bbd7f6cf9528bbaef3b4442688f0ab3113cd7d068683aa76f9518e7c204d6212ce73b1150f"
        ),
    )
    assert_equal(
        xchacha20poly1305_seal_open(
            Span(modern), Span(recipient_public), Span(recipient_secret)
        ),
        message,
    )
    modern[0] ^= 1
    with assert_raises():
        _ = xchacha20poly1305_seal_open(
            Span(modern), Span(recipient_public), Span(recipient_secret)
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
