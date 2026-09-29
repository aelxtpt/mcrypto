from std.testing import assert_equal
from mcrypto.public_key.box import keypair, encrypt, decrypt
from mcrypto.public_key.box_variants import seal, seal_open


def main() raises:
    var alice = keypair()
    var alice_public = alice[0].copy()
    var alice_secret = alice[1].copy()
    var bob = keypair()
    var bob_public = bob[0].copy()
    var bob_secret = bob[1].copy()
    var nonce = List[UInt8](length=24, fill=0xB4)
    var message = List("authenticated box message".as_bytes())
    var boxed = encrypt(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(
        decrypt(Span(boxed), Span(nonce), Span(alice_public), Span(bob_secret)),
        message,
    )
    var anonymous = seal(Span(message), Span(bob_public))
    assert_equal(
        seal_open(Span(anonymous), Span(bob_public), Span(bob_secret)), message
    )
    print("boxes: ok")
