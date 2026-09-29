from std.testing import assert_equal, TestSuite
from mcrypto.key_exchange.x25519 import public_key, agree


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else 87
        c -= 48 if c <= 57 else 87
        o.append(UInt8(a * 16 + c))
    return o^


def test_rfc7748_alice_bob() raises:
    var alice_secret = h(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    var bob_secret = h(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    var alice_public = h(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    var bob_public = h(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    var shared = h(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )
    assert_equal(public_key(Span(alice_secret)), alice_public)
    assert_equal(public_key(Span(bob_secret)), bob_public)
    assert_equal(agree(Span(alice_secret), Span(bob_public)), shared)
    assert_equal(agree(Span(bob_secret), Span(alice_public)), shared)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
