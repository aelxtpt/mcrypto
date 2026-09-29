---
title: Authenticated encryption
---

# Authenticated encryption

## What this family does

AEAD encrypts a message and authenticates both ciphertext and associated data (AAD). AAD is authenticated but not encrypted.

## Safe selection and legacy warning

Use XChaCha20-Poly1305-IETF when a 24-byte nonce simplifies safe uniqueness, ChaCha20-Poly1305-IETF for 12-byte protocol nonces, or AES-GCM/AEGIS when the protocol and platform call for them. Nonce reuse under one key can destroy confidentiality and authenticity.

## Public imports and signatures

```mojo
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt
from mcrypto.aead.detached import encrypt as encrypt_detached, decrypt as decrypt_detached

def encrypt[key_origin: Origin, nonce_origin: Origin, aad_origin: Origin, message_origin: Origin](algorithm: AeadAlgorithm, key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin], aad: Span[UInt8, aad_origin], message: Span[UInt8, message_origin], tag_bytes: Int = 0) raises -> List[UInt8]
def decrypt[key_origin: Origin, nonce_origin: Origin, aad_origin: Origin, cipher_origin: Origin](algorithm: AeadAlgorithm, key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin], aad: Span[UInt8, aad_origin], ciphertext: Span[UInt8, cipher_origin], tag_bytes: Int = 0) raises -> List[UInt8]
def encrypt_detached[key_origin: Origin, nonce_origin: Origin, aad_origin: Origin, message_origin: Origin](algorithm: AeadAlgorithm, key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin], aad: Span[UInt8, aad_origin], message: Span[UInt8, message_origin], tag_bytes: Int = 16) raises -> Tuple[List[UInt8], List[UInt8]]
```

## Inventory names and invocation spellings

Catalog and protocol names map explicitly to `AeadAlgorithm` constants. Application code uses values such as `AeadAlgorithm.GCM`, `AeadAlgorithm.CCM`, `AeadAlgorithm.EAX`, `AeadAlgorithm.AEGIS128L`, `AeadAlgorithm.AEGIS256`, `AeadAlgorithm.CHACHA20_POLY1305_IETF`, or `AeadAlgorithm.XCHACHA20_POLY1305_IETF`.

## Dimensions

ChaCha AEAD uses a 32-byte key and 16-byte tag; nonce length is 8 for the legacy form, 12 for IETF, and 24 for XChaCha. AES accepts 16/24/32-byte keys except `AES-256-GCM`, which requires 32. GCM normally uses 12-byte nonces but supports its validated variable-IV path. AEGIS validates algorithm-specific keys/nonces and defaults to a 32-byte combined tag; other combined forms default to 16.

## Return and wire layout

Combined encryption returns `ciphertext || tag`. Combined decryption splits the final `tag_bytes`. Detached encryption returns `(ciphertext, tag)`; copy tuple-owned lists before retaining them independently. No API prepends the nonce or AAD.

## Executable examples

<a id="example-aead-combined"></a>
### Combined ciphertext and tag
```mojo
from std.testing import assert_equal, assert_raises, assert_true
from mcrypto.aead.combined import encrypt, decrypt
from mcrypto.aead.algorithm import AeadAlgorithm


def main() raises:
    var key = List[UInt8](length=32, fill=0x35)
    var nonce = List[UInt8](length=24, fill=0x46)
    var aad = List("record header".as_bytes())
    var message = List("authenticated plaintext".as_bytes())
    var combined = encrypt(
        AeadAlgorithm.XCHACHA20_POLY1305_IETF,
        Span(key),
        Span(nonce),
        Span(aad),
        Span(message),
    )
    assert_equal(len(combined), len(message) + 16)
    assert_equal(
        decrypt(
            AeadAlgorithm.XCHACHA20_POLY1305_IETF,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(combined),
        ),
        message,
    )
    combined[len(combined) - 1] ^= 1
    with assert_raises():
        _ = decrypt(
            AeadAlgorithm.XCHACHA20_POLY1305_IETF,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(combined),
        )
    print("aead-combined: ok")
```

<a id="example-aead-detached"></a>
### Detached tuple
```mojo
from std.testing import assert_equal, assert_raises
from mcrypto.aead.detached import encrypt, decrypt
from mcrypto.aead.algorithm import AeadAlgorithm


def main() raises:
    var key = List[UInt8](length=16, fill=0x57)
    var nonce = List[UInt8](length=12, fill=0x68)
    var aad = List("detached header".as_bytes())
    var message = List("detached payload".as_bytes())
    var parts = encrypt(
        AeadAlgorithm.GCM, Span(key), Span(nonce), Span(aad), Span(message)
    )
    var ciphertext = parts[0].copy()
    var tag = parts[1].copy()
    assert_equal(len(tag), 16)
    assert_equal(
        decrypt(
            AeadAlgorithm.GCM,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
            Span(tag),
        ),
        message,
    )
    tag[0] ^= 1
    with assert_raises():
        _ = decrypt(
            AeadAlgorithm.GCM,
            Span(key),
            Span(nonce),
            Span(aad),
            Span(ciphertext),
            Span(tag),
        )
    print("aead-detached: ok")
```

## Authentication, errors, and state

Wrong key/nonce/tag lengths, unknown names, and authentication failure raise. Decryption authenticates before producing or returning plaintext; failed authentication yields no plaintext. Treat AAD and nonce framing as protocol inputs, not optional metadata.

## Prepared, into, and batch APIs

Selected implementations expose `encrypt_into` and eight-way functions. Eight-way ChaCha-family calls require eight equal-width message lanes with corresponding unique nonces. Combined and detached batching preserve their respective wire layouts.

## Inventory and test evidence

See [`XChaCha20-Poly1305-IETF`](../reference/algorithms.md#aead-xchacha20-poly1305-ietf) and [`GCM`](../reference/algorithms.md#aead-gcm). Representative tests: `tests/test_aead_combined.mojo`, `tests/test_chacha_aead.mojo`, and `tests/test_aegis.mojo`.