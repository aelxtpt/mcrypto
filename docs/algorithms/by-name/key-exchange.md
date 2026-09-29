---
title: Session key exchange
---

# Session key exchange

This API combines X25519 agreement with BLAKE2b key derivation and assigns distinct receive/transmit keys by endpoint role. Authenticate the long-term or ephemeral public keys through the surrounding protocol.

<!-- algorithm: key-exchange/x25519-blake2b -->
<a id="key-exchange-x25519-blake2b"></a>
## X25519-BLAKE2b

The client and server derive the same two keys in opposite order: the client's receive key is the server's transmit key, and vice versa. The role boolean is therefore a protocol input, not a local preference.

<a id="example-key-exchange-x25519-blake2b"></a>
<!-- runnable-example: key-exchange-x25519-blake2b -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.kx import keypair, session_keys

def main() raises:
    var client = keypair()
    var server = keypair()
    var client_public = client[0].copy()
    var client_secret = client[1].copy()
    var server_public = server[0].copy()
    var server_secret = server[1].copy()
    var client_keys = session_keys(True, Span(client_public), Span(client_secret), Span(server_public))
    var server_keys = session_keys(False, Span(server_public), Span(server_secret), Span(client_public))
    assert_equal(client_keys[0], server_keys[1])
    assert_equal(client_keys[1], server_keys[0])
    print("key-exchange-x25519-blake2b: ok")
```
