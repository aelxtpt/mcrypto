---
title: Key agreement
---

# Key agreement

Key agreement produces shared secret material; it does not by itself authenticate identities or produce application traffic keys. Validate peer keys, preserve endpoint roles, and feed the result plus the transcript into a domain-separated KDF.

<!-- algorithm: key-agreement/dh -->
<a id="key-agreement-dh"></a>
## DH

Finite-field Diffie–Hellman derives a shared secret from one private exponent and the peer public value. Authenticate both public values and the domain parameters before deriving session keys.

<a id="example-key-agreement-dh"></a>
<!-- runnable-example: key-agreement-dh -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.DH
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-dh: ok")
```

<!-- algorithm: key-agreement/dh2 -->
<a id="key-agreement-dh2"></a>
## DH2

DH2 performs the two-key finite-field agreement variant. Static and ephemeral roles are part of the protocol and must not be silently exchanged.

<a id="example-key-agreement-dh2"></a>
<!-- runnable-example: key-agreement-dh2 -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.DH2
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-dh2: ok")
```

<!-- algorithm: key-agreement/mqv -->
<a id="key-agreement-mqv"></a>
## MQV

MQV combines static and ephemeral finite-field keys to authenticate the agreement implicitly. Peer identities and transcript context still need explicit binding in the KDF.

<a id="example-key-agreement-mqv"></a>
<!-- runnable-example: key-agreement-mqv -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.MQV
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-mqv: ok")
```

<!-- algorithm: key-agreement/hmqv -->
<a id="key-agreement-hmqv"></a>
## HMQV

HMQV hashes static and ephemeral values into the MQV computation. Use the complete public-key validation and role rules required by the protocol.

<a id="example-key-agreement-hmqv"></a>
<!-- runnable-example: key-agreement-hmqv -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.HMQV
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-hmqv: ok")
```

<!-- algorithm: key-agreement/fhmqv -->
<a id="key-agreement-fhmqv"></a>
## FHMQV

FHMQV is a fully hashed MQV variant. It remains a key-agreement primitive; derive purpose-specific traffic keys from its shared output.

<a id="example-key-agreement-fhmqv"></a>
<!-- runnable-example: key-agreement-fhmqv -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.FHMQV
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-fhmqv: ok")
```

<!-- algorithm: key-agreement/lucdif -->
<a id="key-agreement-lucdif"></a>
## LUCDIF

LUCDIF performs Diffie–Hellman-style agreement through Lucas sequences. It is provided for compatible protocols with fixed parameters.

<a id="example-key-agreement-lucdif"></a>
<!-- runnable-example: key-agreement-lucdif -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.LUCDIF
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-lucdif: ok")
```

<!-- algorithm: key-agreement/xtr-dh -->
<a id="key-agreement-xtr-dh"></a>
## XTR-DH

XTR-DH represents subgroup elements through traces in an extension field. Preserve the generated parameter frame and validate the peer value before agreement.

<a id="example-key-agreement-xtr-dh"></a>
<!-- runnable-example: key-agreement-xtr-dh -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.XTR_DH
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-xtr-dh: ok")
```

<!-- algorithm: key-agreement/ecdh -->
<a id="key-agreement-ecdh"></a>
## ECDH P-256

ECDH P-256 multiplies a peer point by a private scalar. Public-point validation and a transcript-bound KDF are required before using the shared bytes as keys.

<a id="example-key-agreement-ecdh"></a>
<!-- runnable-example: key-agreement-ecdh -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.ECDH_P256
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-ecdh: ok")
```

<!-- algorithm: key-agreement/ecmqv -->
<a id="key-agreement-ecmqv"></a>
## ECMQV P-256

ECMQV combines static and ephemeral P-256 keys. The initiator/responder role affects the computation and must match on both endpoints.

<a id="example-key-agreement-ecmqv"></a>
<!-- runnable-example: key-agreement-ecmqv -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.ECMQV_P256
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-ecmqv: ok")
```

<!-- algorithm: key-agreement/echmqv -->
<a id="key-agreement-echmqv"></a>
## ECHMQV P-256

ECHMQV hashes P-256 MQV inputs before combining them. Authenticate identities and bind all public values into subsequent key derivation.

<a id="example-key-agreement-echmqv"></a>
<!-- runnable-example: key-agreement-echmqv -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.ECHMQV_P256
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-echmqv: ok")
```

<!-- algorithm: key-agreement/ecfhmqv -->
<a id="key-agreement-ecfhmqv"></a>
## ECFHMQV P-256

ECFHMQV is the fully hashed elliptic MQV variant. Treat its output as input key material, not directly as a multi-purpose session key.

<a id="example-key-agreement-ecfhmqv"></a>
<!-- runnable-example: key-agreement-ecfhmqv -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.ECFHMQV_P256
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-ecfhmqv: ok")
```

<!-- algorithm: key-agreement/x25519 -->
<a id="key-agreement-x25519"></a>
## X25519

X25519 provides a compact Montgomery-curve agreement. Reject invalid all-zero shared results and bind both public keys and roles into a KDF.

<a id="example-key-agreement-x25519"></a>
<!-- runnable-example: key-agreement-x25519 -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.agreement import agree, generate_keypair, generate_peer, info

def main() raises:
    var algorithm = AgreementAlgorithm.X25519
    var sizes = info(algorithm, 512)
    var alice = generate_keypair(algorithm, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(algorithm, Span(parameters), sizes[0], sizes[1], False)
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(algorithm, Span(parameters), Span(alice_private), Span(bob_public), sizes[2], True)
    var bob_shared = agree(algorithm, Span(parameters), Span(bob_private), Span(alice_public), sizes[2], False)
    assert_equal(alice_shared, bob_shared)
    print("key-agreement-x25519: ok")
```

