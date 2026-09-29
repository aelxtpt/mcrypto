---
title: Boxes, secretbox, and secretstream
---

# Boxes, secretbox, and secretstream

## What this family does

Boxes authenticate encryption between public-key peers; sealed boxes provide recipient-only anonymous encryption. Secretbox authenticates one shared-key message. Secretstream authenticates ordered records with evolving state.

## Safe selection and legacy warning

Use XChaCha20-Poly1305 variants when protocol-compatible. Never reuse a secretbox nonce with one key. A box authenticates possession of peer key material but does not replace identity/key validation. Preserve secretstream order and terminate with `FINAL`.

## Public imports and signatures

```mojo
from mcrypto.public_key.box import keypair, encrypt, decrypt
from mcrypto.public_key.box_variants import (
    seal,
    seal_open,
    xchacha20poly1305_encrypt_easy,
    xchacha20poly1305_decrypt_easy,
)
from mcrypto.secretbox.xchacha20poly1305 import encrypt as secretbox_encrypt, decrypt as secretbox_decrypt
from mcrypto.secretstream.xchacha20poly1305 import PushStream, PullStream, FINAL

def keypair() raises -> Tuple[List[UInt8], List[UInt8]]
def encrypt(message: Span[UInt8], nonce: Span[UInt8], peer_public_key: Span[UInt8], secret_key: Span[UInt8]) raises -> List[UInt8]
def decrypt(ciphertext: Span[UInt8], nonce: Span[UInt8], peer_public_key: Span[UInt8], secret_key: Span[UInt8]) raises -> List[UInt8]
```

`PushStream.push(message, aad, tag)` and `PullStream.pull(ciphertext, aad)` are mutating state methods.

## Inventory names and invocation spellings

Box inventory rows are `Curve25519-XSalsa20-Poly1305`, `Curve25519-XChaCha20-Poly1305`, and `sealed-box`; they use direct functions rather than a name dispatcher. Secret rows are `XSalsa20-Poly1305`, `XChaCha20-Poly1305`, and `XChaCha20-Poly1305-secretstream`.

## Dimensions

Box/KX public and secret keys are 32 bytes. XSalsa/XChaCha nonces are 24 bytes. Easy box and secretbox ciphertext adds a fixed 16-byte authenticator. A sealed box adds 48 bytes: a 32-byte ephemeral public key and 16-byte authenticator. Secretstream uses a 32-byte key, 24-byte header, and 17 bytes of overhead per record.

## Return and wire layout

Direct box keypair order is `(public_key, secret_key)`. Box encryption takes the recipient public key and sender secret key; decryption takes the sender public key and recipient secret key. Easy box forms return `16-byte tag || ciphertext`. XChaCha secretbox combined output uses the same tag prefix, unlike combined AEAD's suffix. Secretstream carries a separate 24-byte header, then each ordered record contains 1 encrypted tag byte, ciphertext, and 16 authentication bytes.

## Executable examples

<a id="example-boxes"></a>
### Public-key and sealed boxes
```mojo
from std.testing import assert_equal
from mcrypto.public_key.box import keypair, encrypt, decrypt
from mcrypto.public_key.box_variants import seal, seal_open


def main() raises:
    var alice = keypair()
    var alice_public = alice[0].copy()
    var alice_secret = alice[1].copy()
    var bob = keypair()
    var bob_public = bob[0].copy()
    var bob_secret = bob[1].copy()
    var nonce = List[UInt8](length=24, fill=0xB4)
    var message = List("authenticated box message".as_bytes())
    var boxed = encrypt(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(
        decrypt(Span(boxed), Span(nonce), Span(alice_public), Span(bob_secret)),
        message,
    )
    var anonymous = seal(Span(message), Span(bob_public))
    assert_equal(
        seal_open(Span(anonymous), Span(bob_public), Span(bob_secret)), message
    )
    print("boxes: ok")
```

<a id="example-secretbox"></a>
### Shared-key secretbox
```mojo
from std.testing import assert_equal, assert_raises
from mcrypto.secretbox.xchacha20poly1305 import encrypt, decrypt


def main() raises:
    var key = List[UInt8](length=32, fill=0xB5)
    var nonce = List[UInt8](length=24, fill=0xC6)
    var message = List("secretbox plaintext".as_bytes())
    var ciphertext = encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(len(ciphertext), len(message) + 16)
    assert_equal(decrypt(Span(ciphertext), Span(nonce), Span(key)), message)
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(Span(ciphertext), Span(nonce), Span(key))
    print("secretbox: ok")
```

<a id="example-secretstream"></a>
### Ordered secretstream records
```mojo
from std.testing import assert_equal, assert_raises
from mcrypto.secretstream.xchacha20poly1305 import (
    MESSAGE,
    FINAL,
    PushStream,
    PullStream,
)


def main() raises:
    var key = List[UInt8](length=32, fill=0xC7)
    var header = List[UInt8](length=24, fill=0)
    for i in range(len(header)):
        header[i] = UInt8(i + 1)
    var aad = List("stream header".as_bytes())
    var first_message = List("first ordered record".as_bytes())
    var final_message = List("final ordered record".as_bytes())
    var push = PushStream(Span(key), Span(header))
    var pull = PullStream(Span(key), Span(header))
    var first_cipher = push.push(Span(first_message), Span(aad), MESSAGE)
    var final_cipher = push.push(Span(final_message), Span(aad), FINAL)
    assert_equal(len(first_cipher), len(first_message) + 17)
    var first = pull.pull(Span(first_cipher), Span(aad))
    assert_equal(first[0], first_message)
    assert_equal(first[1], MESSAGE)
    var final = pull.pull(Span(final_cipher), Span(aad))
    assert_equal(final[0], final_message)
    assert_equal(final[1], FINAL)
    with assert_raises():
        _ = push.push(Span(first_message), Span(aad), MESSAGE)
    with assert_raises():
        _ = pull.pull(Span(first_cipher), Span(aad))
    print("secretstream: ok")
```

## Authentication, errors, and state

All open/decrypt calls authenticate before returning plaintext. Wrong key widths, wrong nonce widths, undersized ciphertext, low-order peer keys, and tampering raise. Tampering and undersized secretstream records do not advance `PullStream`. Records are ordered: replay or reordering fails. `FINAL` rekeys and closes both push and pull states; further use raises.

## Prepared, into, and batch APIs

Secretbox exposes detached, `encrypt_into`, and eight-way forms. Box variants expose easy, detached, and eight-way paths. Secretstream exposes `push_into`, `pull_into`, explicit `rekey`, and eight-stream initialization; lane order and per-stream state remain independent.

## Inventory and test evidence

See [`sealed-box`](../reference/algorithms.md#box-sealed-box), [`XChaCha20-Poly1305 secretbox`](../reference/algorithms.md#secretbox-xchacha20-poly1305), and [`XChaCha20-Poly1305 secretstream`](../reference/algorithms.md#secretstream-xchacha20-poly1305-secretstream). Representative tests: `tests/test_box_variants.mojo`, `tests/test_secretbox_pure.mojo`, and `tests/test_secretstream_pure.mojo`.