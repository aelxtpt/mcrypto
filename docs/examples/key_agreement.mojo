from std.testing import assert_equal
from mcrypto.key_exchange.agreement import (
    info,
    generate_keypair,
    generate_peer,
    agree,
)
from mcrypto.key_exchange.algorithm import AgreementAlgorithm


def main() raises:
    var sizes = info(AgreementAlgorithm.X25519, 512)
    var alice = generate_keypair(AgreementAlgorithm.X25519, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(
        AgreementAlgorithm.X25519,
        Span(parameters),
        sizes[0],
        sizes[1],
        False,
    )
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(
        AgreementAlgorithm.X25519,
        Span(parameters),
        Span(alice_private),
        Span(bob_public),
        sizes[2],
        True,
    )
    var bob_shared = agree(
        AgreementAlgorithm.X25519,
        Span(parameters),
        Span(bob_private),
        Span(alice_public),
        sizes[2],
        False,
    )
    assert_equal(alice_shared, bob_shared)
    print("key-agreement: ok")
