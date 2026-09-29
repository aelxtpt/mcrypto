---
title: Key encapsulation
---

# Key-encapsulation mechanisms

A KEM transports shared secret material to a public key. Use the shared output as input to a protocol KDF, bind the encapsulation ciphertext and identities to the transcript, and treat decapsulation failures according to the protocol's side-channel rules.

<!-- algorithm: kem/ml-kem-768 -->
<a id="kem-ml-kem-768"></a>
## ML-KEM-768

ML-KEM-768 is a lattice-based key-encapsulation mechanism. Encapsulation returns a ciphertext and shared secret; decapsulation must run on the complete secret key and should feed the shared result into protocol key derivation.

<a id="example-kem-ml-kem-768"></a>
<!-- runnable-example: kem-ml-kem-768 -->
```mojo
from std.testing import assert_equal
from mcrypto.kem.algorithm import KemAlgorithm
from mcrypto.kem.dispatch import decapsulate, encapsulate, keypair

def main() raises:
    var algorithm = KemAlgorithm.ML_KEM_768
    var keys = keypair(algorithm)
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var sealed = encapsulate(algorithm, Span(public_key))
    var ciphertext = sealed[0].copy()
    var sender_shared = sealed[1].copy()
    assert_equal(decapsulate(algorithm, Span(ciphertext), Span(secret_key)), sender_shared)
    print("kem-ml-kem-768: ok")
```

<!-- algorithm: kem/x-wing -->
<a id="kem-x-wing"></a>
## X-Wing

X-Wing combines ML-KEM-768 with X25519 so the shared secret depends on both components. Keep the hybrid ciphertext and key formats intact rather than negotiating the components independently.

<a id="example-kem-x-wing"></a>
<!-- runnable-example: kem-x-wing -->
```mojo
from std.testing import assert_equal
from mcrypto.kem.algorithm import KemAlgorithm
from mcrypto.kem.dispatch import decapsulate, encapsulate, keypair

def main() raises:
    var algorithm = KemAlgorithm.X_WING
    var keys = keypair(algorithm)
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var sealed = encapsulate(algorithm, Span(public_key))
    var ciphertext = sealed[0].copy()
    var sender_shared = sealed[1].copy()
    assert_equal(decapsulate(algorithm, Span(ciphertext), Span(secret_key)), sender_shared)
    print("kem-x-wing: ok")
```

