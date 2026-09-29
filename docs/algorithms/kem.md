---
title: KEMs
---

# KEMs

## What this family does

A KEM creates a shared secret for a recipient public key and a ciphertext the recipient decapsulates. It does not encrypt application data by itself.

## Safe selection and legacy warning

Use the KEM selected by a reviewed hybrid protocol, derive context-bound keys from the shared secret, and protect data with AEAD. ML-KEM-768 and X-Wing have different wire formats and cannot be substituted silently.

## Public imports and signatures

```mojo
from mcrypto.kem.algorithm import KemAlgorithm
from mcrypto.kem.dispatch import keypair, encapsulate, decapsulate

def keypair(algorithm: KemAlgorithm) raises -> Tuple[List[UInt8], List[UInt8]]
def encapsulate[origin: Origin](algorithm: KemAlgorithm, public_key: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]
def decapsulate[cipher_origin: Origin, key_origin: Origin](algorithm: KemAlgorithm, ciphertext: Span[UInt8, cipher_origin], secret_key: Span[UInt8, key_origin]) raises -> List[UInt8]
```

## Inventory names and invocation spellings

The dispatcher accepts `KemAlgorithm.ML_KEM_768` and `KemAlgorithm.X_WING`; external strings are parsed only at the external-name boundary.

## Dimensions

ML-KEM-768: public key 1184, secret key 2400, ciphertext 1088, shared secret 32 bytes. X-Wing: public key 1216, secret key 32, ciphertext 1120, shared secret 32 bytes.

## Return and wire layout

KEM keypair order is `(public_key, secret_key)`. Encapsulation order is `(ciphertext, shared_secret)`. These orders differ from generic public encryption/signature key generation. Copy tuple elements before retaining them independently.

## Executable examples

<a id="example-kem"></a>
### Encapsulation and implicit rejection
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.kem.algorithm import KemAlgorithm
from mcrypto.kem.dispatch import keypair, encapsulate, decapsulate


def main() raises:
    # KEMs return (public_key, secret_key).
    var keys = keypair(KemAlgorithm.ML_KEM_768)
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    # Encapsulation returns (ciphertext, shared_secret).
    var encapsulated = encapsulate(KemAlgorithm.ML_KEM_768, Span(public_key))
    var ciphertext = encapsulated[0].copy()
    var sender_secret = encapsulated[1].copy()
    assert_equal(
        decapsulate(
            KemAlgorithm.ML_KEM_768, Span(ciphertext), Span(secret_key)
        ),
        sender_secret,
    )
    ciphertext[0] ^= 1
    var rejected = decapsulate(
        KemAlgorithm.ML_KEM_768, Span(ciphertext), Span(secret_key)
    )
    assert_equal(len(rejected), 32)
    assert_true(rejected != sender_secret)
    print("kem: ok")
```

## Authentication, errors, and state

Malformed lengths raise. A same-size modified ciphertext uses implicit rejection: decapsulation returns a deterministic replacement secret rather than an exception and it must not equal the sender's secret. Protocols must not branch on a hidden decapsulation-validity signal.

## Prepared, into, and batch APIs

Direct modules expose deterministic seed-based keypair/encapsulation helpers for vectors. They are not production entropy substitutes. The public dispatcher has no batch contract.

## Inventory and test evidence

See [`ML-KEM-768`](../reference/algorithms.md#kem-ml-kem-768) and [`X-Wing`](../reference/algorithms.md#kem-x-wing). Representative tests: `tests/test_kem.mojo` and `tests/test_public_key_prepared_paths.mojo`.