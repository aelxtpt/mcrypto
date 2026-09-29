from std.testing import assert_equal
from mcrypto.groups.algorithm import GroupFamily
from mcrypto.key_exchange.kx import keypair, session_keys
from mcrypto.groups.scalar import scalar_base


def main() raises:
    var alice = keypair()
    var alice_public = alice[0].copy()
    var alice_secret = alice[1].copy()
    var bob = keypair()
    var bob_public = bob[0].copy()
    var bob_secret = bob[1].copy()
    assert_equal(
        scalar_base(GroupFamily.X25519, Span(alice_secret)), alice_public
    )

    var client = session_keys(
        True, Span(alice_public), Span(alice_secret), Span(bob_public)
    )
    var server = session_keys(
        False, Span(bob_public), Span(bob_secret), Span(alice_public)
    )
    assert_equal(client[0], server[1])
    assert_equal(client[1], server[0])
    print("kx-scalarmult: ok")
