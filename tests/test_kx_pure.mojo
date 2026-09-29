from std.testing import assert_equal, TestSuite
from mcrypto.key_exchange.x25519 import public_key
from mcrypto.key_exchange.kx import session_keys


def test_kx_session_direction() raises:
    var alice_secret = List[UInt8](length=32, fill=7)
    var bob_secret = List[UInt8](length=32, fill=9)
    var alice_public = public_key(Span(alice_secret))
    var bob_public = public_key(Span(bob_secret))
    var client = session_keys(
        True, Span(alice_public), Span(alice_secret), Span(bob_public)
    )
    var server = session_keys(
        False, Span(bob_public), Span(bob_secret), Span(alice_public)
    )
    assert_equal(client[0], server[1])
    assert_equal(client[1], server[0])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
