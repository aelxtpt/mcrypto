from std.testing import assert_false, assert_true
from mcrypto.signatures.ed25519 import keypair, sign, verify, sign_ph, verify_ph


def main() raises:
    # Direct Ed25519 returns (public_key, secret_key).
    var keys = keypair()
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var message = List("signed documentation example".as_bytes())
    var signature = sign(Span(message), Span(secret_key))
    assert_true(verify(Span(signature), Span(message), Span(public_key)))
    message[0] ^= 1
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    message[0] ^= 1
    var prehashed = sign_ph(Span(message), Span(secret_key))
    assert_true(verify_ph(Span(prehashed), Span(message), Span(public_key)))
    print("signatures: ok")
