---
title: Public-key boxes
---

# Public-key boxes

A box combines X25519 agreement with authenticated symmetric encryption. It authenticates possession of the sender secret key to the recipient but does not attach a human identity; bind public keys through the surrounding protocol and never repeat a nonce for one key pair.

<!-- algorithm: box/curve25519-xsalsa20-poly1305 -->
<a id="box-curve25519-xsalsa20-poly1305"></a>
## Curve25519-XSalsa20-Poly1305

This box derives a shared key from X25519 and authenticates XSalsa20-encrypted data with Poly1305. Sender and recipient use opposite public/secret key pairs for decryption.

<a id="example-box-curve25519-xsalsa20-poly1305"></a>
<!-- runnable-example: box-curve25519-xsalsa20-poly1305 -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.box import decrypt, encrypt, keypair

def main() raises:
    var alice = keypair()
    var bob = keypair()
    var alice_public = alice[0].copy()
    var alice_secret = alice[1].copy()
    var bob_public = bob[0].copy()
    var bob_secret = bob[1].copy()
    var nonce = List[UInt8](length=24, fill=0x51)
    var message = List("boxed message".as_bytes())
    var ciphertext = encrypt(Span(message), Span(nonce), Span(bob_public), Span(alice_secret))
    assert_equal(decrypt(Span(ciphertext), Span(nonce), Span(alice_public), Span(bob_secret)), message)
    print("box-curve25519-xsalsa20-poly1305: ok")
```

<!-- algorithm: box/curve25519-xchacha20-poly1305 -->
<a id="box-curve25519-xchacha20-poly1305"></a>
## Curve25519-XChaCha20-Poly1305

This variant derives the box key through HChaCha20 and uses XChaCha20-Poly1305 with a 24-byte nonce. Nonce uniqueness remains required even though random nonces have a large collision margin.

<a id="example-box-curve25519-xchacha20-poly1305"></a>
<!-- runnable-example: box-curve25519-xchacha20-poly1305 -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.x25519 import public_key
from mcrypto.public_key.box_variants import xchacha20poly1305_decrypt_easy, xchacha20poly1305_encrypt_easy

def main() raises:
    var alice_secret = List[UInt8](length=32, fill=0x37)
    var bob_secret = List[UInt8](length=32, fill=0x59)
    var alice_public = public_key(Span(alice_secret))
    var bob_public = public_key(Span(bob_secret))
    var nonce = List[UInt8](length=24, fill=0x7B)
    var message = List("modern boxed message".as_bytes())
    var ciphertext = xchacha20poly1305_encrypt_easy(Span(message), Span(nonce), Span(bob_public), Span(alice_secret))
    assert_equal(xchacha20poly1305_decrypt_easy(Span(ciphertext), Span(nonce), Span(alice_public), Span(bob_secret)), message)
    print("box-curve25519-xchacha20-poly1305: ok")
```

<!-- algorithm: box/sealed-box -->
<a id="box-sealed-box"></a>
## Sealed box

A sealed box generates an ephemeral sender key and lets only the recipient open the ciphertext. It hides the sender key rather than authenticating a sender identity.

<a id="example-box-sealed-box"></a>
<!-- runnable-example: box-sealed-box -->
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.x25519 import public_key
from mcrypto.public_key.box_variants import seal, seal_open

def main() raises:
    var recipient_secret = List[UInt8](length=32, fill=0x41)
    var recipient_public = public_key(Span(recipient_secret))
    var message = List("anonymous sealed message".as_bytes())
    var ciphertext = seal(Span(message), Span(recipient_public))
    assert_equal(seal_open(Span(ciphertext), Span(recipient_public), Span(recipient_secret)), message)
    print("box-sealed-box: ok")
```
