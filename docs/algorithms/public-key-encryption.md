---
title: Public-key encryption
---

# Public-key encryption

## What this family does

Public-key encryption encrypts to a public key and decrypts with the matching private key. It is distinct from signatures and KEM encapsulation.

## Safe selection and legacy warning

Prefer a protocol-defined KEM plus AEAD for new hybrid encryption. RSA and ECIES must use the exact padding/framing expected by peers. Raw Rabin/LUC and legacy ElGamal/LUCELG/DLIES paths are compatibility surfaces; do not invent message encoding around them.

## Public imports and signatures

```mojo
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import generate_keypair, encrypt, decrypt

def generate_keypair(algorithm: PublicKeyEncryptionAlgorithm, key_bits: Int = 2048) raises -> Tuple[List[UInt8], List[UInt8]]
def encrypt[public_origin: Origin, message_origin: Origin](algorithm: PublicKeyEncryptionAlgorithm, public_key: Span[UInt8, public_origin], message: Span[UInt8, message_origin]) raises -> List[UInt8]
def decrypt[private_origin: Origin, ciphertext_origin: Origin](algorithm: PublicKeyEncryptionAlgorithm, private_key: Span[UInt8, private_origin], ciphertext: Span[UInt8, ciphertext_origin]) raises -> List[UInt8]
```

## Inventory names and invocation spellings

`PublicKeyEncryptionAlgorithm.RSA` selects OAEP-SHA-256 by default. Explicit constants cover RSA PKCS#1/OAEP variants, ElGamal, Rabin, Rabin-Williams, LUC, LUCELG, DLIES, and ECIES; textual inventory labels are parsed only at external boundaries.

## Dimensions

`key_bits` defaults to 2048 for finite-field/trapdoor families. Message limits depend on modulus and encoding; OAEP overhead reduces usable plaintext. ECIES uses its fixed curve framing. Key and ciphertext lengths are validated by each scheme.

## Return and wire layout

The generic keypair order is `(private_key, public_key)`. This is intentionally different from direct Ed25519, box, KX, and KEM APIs. Keys include mcrypto framing where the dispatcher needs type/domain metadata. Encryption returns scheme ciphertext only.

## Executable examples

<a id="example-public-key-encryption"></a>
### Encryption round trip

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

Malformed keys/ciphertexts, oversized plaintext, invalid padding, and unsupported names raise. Do not use a successful raw decryption as proof of sender authenticity. Rabin/Rabin-Williams generic dispatch has retained round-trip failures.

## Direct ECIES leaf API

The dispatcher is not a substitute for the direct ECIES contract. Import direct ECIES from `mcrypto.public_key.ecies`:

```mojo
from mcrypto.math.curve import CurveAlgorithm
from mcrypto.public_key.ecies import (
    ECIESDecryptor,
    ECIESEncryptor,
    ECIESKeyGenerator,
    decrypt,
    encrypt,
    keypair,
)

def keypair(curve: CurveAlgorithm = CurveAlgorithm.P256, compressed: Bool = False) raises -> Tuple[List[UInt8], List[UInt8]]
def encrypt(curve: CurveAlgorithm, message: Span[UInt8], encoded_public_key: Span[UInt8], label: Span[UInt8], derivation_parameters: Span[UInt8]) raises -> List[UInt8]
def decrypt(curve: CurveAlgorithm, ciphertext: Span[UInt8], private_key: Span[UInt8], label: Span[UInt8], derivation_parameters: Span[UInt8]) raises -> List[UInt8]
```

Direct `keypair` and `ECIESKeyGenerator.generate()` return `(public_key, private_key)`. The generic dispatcher and `PreparedECIESKeyGenerator.generate()` return framed `(private_key, public_key)`. Do not interchange raw direct keys with framed dispatcher keys.

For P-256 with the default uncompressed ephemeral point, ciphertext is `65-byte ephemeral point || encrypted message || 20-byte HMAC-SHA1 tag`, an 85-byte fixed overhead. `label` is authenticated and `derivation_parameters` changes the KDF; both must match at decryption. `ECIESEncryptor` and `ECIESDecryptor` validate and retain a direct raw key for repeated operations. `PreparedECIESEncryptor` and `PreparedECIESDecryptor` in `mcrypto.public_key.encryption` instead accept framed dispatcher keys and fixed empty label/derivation parameters. Invalid points, invalid private scalars, truncated ciphertext, or tag mismatch raise before plaintext is returned.

## Direct LUC and LUC-IES leaf APIs

Import LUC compatibility primitives from `mcrypto.public_key.luc`:

```mojo
from mcrypto.public_key.luc import (
    LUCELGDecryptor,
    LUCELGEncryptor,
    apply,
    invert,
    keypair,
    lucelg_decrypt,
    lucelg_encrypt,
    lucelg_keypair,
)

def keypair(bits: Int = 512, public_exponent: UInt64 = 17) raises -> Tuple[List[UInt8], List[UInt8]]
def apply(public_key: Span[UInt8], input: Span[UInt8]) raises -> List[UInt8]
def invert(private_key: Span[UInt8], input: Span[UInt8]) raises -> List[UInt8]
def lucelg_keypair(bits: Int = 512) raises -> Tuple[List[UInt8], List[UInt8]]
def lucelg_encrypt(public_key: Span[UInt8], message: Span[UInt8], label: Span[UInt8]) raises -> List[UInt8]
def lucelg_decrypt(private_key: Span[UInt8], ciphertext: Span[UInt8], label: Span[UInt8]) raises -> List[UInt8]
```

Both direct key generators return `(public_key, private_key)`; the generic dispatcher reverses them to `(private_key, public_key)`. Raw `apply`/`invert` is a trapdoor permutation, not authenticated encryption and not a message-encoding API. LUC-IES is authenticated: its ciphertext is `modulus-width ephemeral value || encrypted message || 20-byte HMAC-SHA1 tag`. The same label is required on both sides. `LUCELGEncryptor` and `LUCELGDecryptor` validate and retain decoded keys for repeated operations. Invalid frames, representatives outside the modulus or subgroup, truncated ciphertext, and authentication mismatch raise.

## Prepared and repeated-use APIs

`ECIESKeyGenerator`, `ECIESEncryptor`, `ECIESDecryptor`, `LUCELGEncryptor`, and `LUCELGDecryptor` cache validated key material or fixed-base work; they do not change output framing or authentication rules. The framed `PreparedECIESKeyGenerator`, `PreparedECIESEncryptor`, and `PreparedECIESDecryptor` mirror the generic dispatcher. The agreement dispatcher separately exposes `PreparedAgreement`, `PreparedLUCDIFKeyGenerator`, and `PreparedEllipticKeyGenerator`; those are key-agreement APIs, not public-key encryption.

## Inventory and test evidence

See [`RSA`](../reference/algorithms.md#public-key-encryption-rsa), [`ECIES`](../reference/algorithms.md#public-key-encryption-ecies), and [`Rabin-Williams`](../reference/algorithms.md#signature-rabin-williams). Representative tests: `tests/test_public_key.mojo`, `tests/test_legacy_public_key.mojo`, and `tests/test_public_key_prepared_paths.mojo`.