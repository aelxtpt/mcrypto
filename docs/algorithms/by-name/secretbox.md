---
title: Secret-key boxes
---

# Secret-key boxes

A secretbox provides authenticated encryption under a shared 32-byte key. It does not identify which key holder created a ciphertext. Allocate every 24-byte nonce exactly once per key and treat authentication failure as one generic error.

<!-- algorithm: secretbox/xsalsa20-poly1305 -->
<a id="secretbox-xsalsa20-poly1305"></a>
## XSalsa20-Poly1305

XSalsa20-Poly1305 uses a 24-byte nonce and authenticates the ciphertext with Poly1305. The combined output places the authentication data with the ciphertext and rejects modification before returning plaintext.

<a id="example-secretbox-xsalsa20-poly1305"></a>
<!-- runnable-example: secretbox-xsalsa20-poly1305 -->
```mojo
from std.testing import assert_equal
from mcrypto.secretbox.xsalsa20poly1305 import decrypt, encrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x41)
    var nonce = List[UInt8](length=24, fill=0x62)
    var message = List("authenticated secret message".as_bytes())
    var ciphertext = encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(decrypt(Span(ciphertext), Span(nonce), Span(key)), message)
    print("secretbox-xsalsa20-poly1305: ok")
```

<!-- algorithm: secretbox/xchacha20-poly1305 -->
<a id="secretbox-xchacha20-poly1305"></a>
## XChaCha20-Poly1305

XChaCha20-Poly1305 uses HChaCha20 subkey derivation and a 24-byte nonce. Nonces may be generated randomly at large scale but must still never repeat under one key.

<a id="example-secretbox-xchacha20-poly1305"></a>
<!-- runnable-example: secretbox-xchacha20-poly1305 -->
```mojo
from std.testing import assert_equal
from mcrypto.secretbox.xchacha20poly1305 import decrypt, encrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x42)
    var nonce = List[UInt8](length=24, fill=0x63)
    var message = List("authenticated secret message".as_bytes())
    var ciphertext = encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(decrypt(Span(ciphertext), Span(nonce), Span(key)), message)
    print("secretbox-xchacha20-poly1305: ok")
```

