---
title: Signatures and padding
---

# Signatures and padding

## What this family does

A signature binds a message to a private signing key and is checked with a public key. Padding/encoding labels describe scheme internals; they are not independent authentication algorithms.

## Safe selection and legacy warning

Use Ed25519 or a protocol-required modern scheme. Prefer deterministic DSA/ECDSA spellings where supported. PKCS#1 v1.5, SHA-1 encodings, Rabin-Williams, LUC, ESIGN, NR, ECGDSA, and ECNR remain compatibility surfaces.

## Public imports and signatures

```mojo
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify
from mcrypto.signatures.ed25519 import sign_ph, verify_ph

def generate_keypair(algorithm: SignatureAlgorithm, key_bits: Int = 2048) raises -> Tuple[List[UInt8], List[UInt8]]
def sign[private_origin: Origin, message_origin: Origin](algorithm: SignatureAlgorithm, private_key: Span[UInt8, private_origin], message: Span[UInt8, message_origin]) raises -> List[UInt8]
def verify[public_origin: Origin, message_origin: Origin, signature_origin: Origin](algorithm: SignatureAlgorithm, public_key: Span[UInt8, public_origin], message: Span[UInt8, message_origin], signature: Span[UInt8, signature_origin]) -> Bool
```

`Ed25519ph` is direct-only through `sign_ph`/`verify_ph`; it has no generic dispatcher spelling.

## Inventory names and invocation spellings

Application code passes a `SignatureAlgorithm` constant for RSA, DSA, NR, Rabin-Williams, LUC, ESIGN, ECDSA, ECGDSA, ECNR, or Ed25519. Catalog and protocol strings map to those constants at their boundary. Padding inventory rows such as PKCS#1, OAEP, PSS, PSSR, and IEEE P1363 encodings are represented only through a complete scheme constant.

## Dimensions

Finite-field/trapdoor `key_bits` defaults to 2048; EC families use their named curve framing. Direct Ed25519 uses 32-byte public keys, 32-byte seed/secret material according to the direct API, and 64-byte signatures. Scheme verifiers validate exact signature length.

## Return and wire layout

The generic keypair order is `(private_key, public_key)`. `sign` returns scheme signature bytes. Direct Ed25519 keypair order is `(public_key, secret_key)`. Signature framing varies by scheme; do not transcode it without a protocol specification.

## Executable examples

<a id="example-signatures"></a>
### Signing and failed verification

```mojo
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
```

<a id="example-public-key-encryption"></a>
### Encryption schemes using padding

```mojo
from std.testing import assert_equal, assert_true
from mcrypto.public_key.encryption import generate_keypair, encrypt, decrypt
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm


def main() raises:
    # Generic public-key dispatch returns (private_key, public_key).
    var keys = generate_keypair(PublicKeyEncryptionAlgorithm.RSA, 2048)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("hybrid key material".as_bytes())
    var ciphertext = encrypt(
        PublicKeyEncryptionAlgorithm.RSA, Span(public_key), Span(message)
    )
    assert_true(ciphertext != message)
    assert_equal(
        decrypt(
            PublicKeyEncryptionAlgorithm.RSA,
            Span(private_key),
            Span(ciphertext),
        ),
        message,
    )
    print("public-key-encryption: ok")
```

## Authentication, errors, and state

`verify` catches malformed input and returns `False`; it does not raise. Signing and key generation can raise. Always branch on the Boolean. A signature does not encrypt the message or establish freshness.

## Prepared, into, and batch APIs

Prepared DSA/NR and public-key math helpers amortize domain/key work. The generic signature front door has no equal-width batch API. Direct Ed25519 prehash is a distinct state/semantic choice, not a flag on generic signing.

## Inventory and test evidence

See [`ECDSA-RFC6979`](../reference/algorithms.md#signature-ecdsa-rfc6979), [`Ed25519ph`](../reference/algorithms.md#signature-ed25519ph), and [`IEEE-P1363-EMSA5`](../reference/algorithms.md#scheme-ieee-p1363-emsa5). Representative tests: `tests/test_public_key.mojo`, `tests/test_ed25519.mojo`, and `tests/test_legacy_public_key.mojo`.