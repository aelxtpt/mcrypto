---
title: AEAD algorithms
---

# AEAD algorithms

Authenticated encryption with associated data produces ciphertext plus an authentication tag. Associated data is authenticated but not encrypted. Decryption must be treated as a single operation: never release plaintext after a tag failure, never reuse a nonce with the same key, and bind protocol metadata through the associated-data input.

<!-- algorithm: aead/gcm -->
<a id="aead-gcm"></a>
## GCM

GCM combines AES counter-mode encryption with a polynomial authenticator. It is a strong fit for protocols that already standardize AES and can guarantee unique nonces. mcrypto accepts 16-, 24-, or 32-byte AES keys; a 12-byte nonce uses the conventional fast path. A repeated key/nonce pair destroys the security bound, so allocate nonces centrally rather than deriving them from timestamps.

Use `AeadAlgorithm.GCM` with `mcrypto.aead.combined.encrypt` and `decrypt`. The combined ciphertext appends a 16-byte tag by default.

<a id="example-aead-gcm"></a>
<!-- runnable-example: aead-gcm -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=16, fill=0x11)
    var nonce = List[UInt8](length=12, fill=0x22)
    var header: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [10, 20, 30, 40]
    var sealed = encrypt(AeadAlgorithm.GCM, Span(key), Span(nonce), Span(header), Span(message))
    assert_equal(decrypt(AeadAlgorithm.GCM, Span(key), Span(nonce), Span(header), Span(sealed)), message)
    print("aead-gcm: ok")
```

<!-- algorithm: aead/ccm -->
<a id="aead-ccm"></a>
## CCM

CCM combines AES counter mode with CBC-MAC. It suits constrained or established protocols that require CCM, but it needs the plaintext length before encryption and is less naturally streaming than GCM. This example uses a 16-byte AES key and a 12-byte nonce. The nonce length controls the maximum encodable message size; follow the surrounding protocol rather than choosing it ad hoc.

<a id="example-aead-ccm"></a>
<!-- runnable-example: aead-ccm -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=16, fill=0x31)
    var nonce = List[UInt8](length=12, fill=0x41)
    var aad: List[UInt8] = [7, 8]
    var message: List[UInt8] = [1, 3, 5, 7, 9]
    var sealed = encrypt(AeadAlgorithm.CCM, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.CCM, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-ccm: ok")
```

<!-- algorithm: aead/eax -->
<a id="aead-eax"></a>
## EAX

EAX is an AES-based encrypt-then-authenticate construction that accepts arbitrary nonce lengths and does not require message length up front. Choose it for compatibility with an EAX protocol; for new designs, prefer the construction already standardized by the surrounding system. Nonces must still be unique per key. The default mcrypto tag is 16 bytes.

<a id="example-aead-eax"></a>
<!-- runnable-example: aead-eax -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=16, fill=0x51)
    var nonce = List[UInt8](length=16, fill=0x61)
    var aad: List[UInt8] = [0xA0, 0xA1]
    var message: List[UInt8] = [0xB0, 0xB1, 0xB2]
    var sealed = encrypt(AeadAlgorithm.EAX, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.EAX, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-eax: ok")
```

<!-- algorithm: aead/chacha20-poly1305-ietf -->
<a id="aead-chacha20-poly1305-ietf"></a>
## ChaCha20-Poly1305-IETF

This construction combines the IETF ChaCha20 layout with a one-time Poly1305 authenticator. It uses a 32-byte key and a 12-byte nonce and is a practical default when AES acceleration cannot be assumed. A nonce may be public but must never repeat under one key. Put sequence numbers, content types, and other unencrypted protocol fields in associated data.

<a id="example-aead-chacha20-poly1305-ietf"></a>
<!-- runnable-example: aead-chacha20-poly1305-ietf -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x17)
    var nonce = List[UInt8](length=12, fill=0x27)
    var aad: List[UInt8] = [4, 2]
    var message: List[UInt8] = [8, 6, 7, 5, 3, 0, 9]
    var sealed = encrypt(AeadAlgorithm.CHACHA20_POLY1305_IETF, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.CHACHA20_POLY1305_IETF, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-chacha20-poly1305-ietf: ok")
```

<!-- algorithm: aead/xchacha20-poly1305-ietf -->
<a id="aead-xchacha20-poly1305-ietf"></a>
## XChaCha20-Poly1305-IETF

XChaCha20-Poly1305 extends the nonce to 24 bytes and derives a per-message subkey before using the IETF construction. The larger nonce makes randomly generated nonces practical for applications without a durable sequence counter. It still requires a 32-byte key and authenticated decryption. Prefer this variant when the protocol permits 24-byte nonces and decentralised nonce allocation matters.

<a id="example-aead-xchacha20-poly1305-ietf"></a>
<!-- runnable-example: aead-xchacha20-poly1305-ietf -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x19)
    var nonce = List[UInt8](length=24, fill=0x29)
    var aad: List[UInt8] = [1, 0, 1]
    var message: List[UInt8] = [2, 4, 6, 8]
    var sealed = encrypt(AeadAlgorithm.XCHACHA20_POLY1305_IETF, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.XCHACHA20_POLY1305_IETF, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-xchacha20-poly1305-ietf: ok")
```

<!-- algorithm: aead/aegis-128l -->
<a id="aead-aegis-128l"></a>
## AEGIS-128L

AEGIS-128L is a high-throughput authenticated cipher built from AES round operations. It uses a 16-byte key and a 16-byte nonce; mcrypto emits a 32-byte tag by default. Choose it only when both endpoints specify AEGIS-128L. Hardware support affects speed, not the API contract. As with every nonce-based AEAD, never repeat a nonce under one key.

<a id="example-aead-aegis-128l"></a>
<!-- runnable-example: aead-aegis-128l -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=16, fill=0x35)
    var nonce = List[UInt8](length=16, fill=0x45)
    var aad: List[UInt8] = [5, 5]
    var message: List[UInt8] = [9, 9, 9]
    var sealed = encrypt(AeadAlgorithm.AEGIS128L, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.AEGIS128L, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-aegis-128l: ok")
```

<!-- algorithm: aead/aegis-256 -->
<a id="aead-aegis-256"></a>
## AEGIS-256

AEGIS-256 uses 32-byte keys and 32-byte nonces and targets high-throughput authenticated encryption. Its nonce size and wire format differ from AEGIS-128L, so the variants are not interchangeable. mcrypto's combined API appends a 32-byte tag by default. Select it from a negotiated protocol identifier, not by guessing from key length.

<a id="example-aead-aegis-256"></a>
<!-- runnable-example: aead-aegis-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x36)
    var nonce = List[UInt8](length=32, fill=0x46)
    var aad: List[UInt8] = [6, 6]
    var message: List[UInt8] = [1, 4, 9, 16]
    var sealed = encrypt(AeadAlgorithm.AEGIS256, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.AEGIS256, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-aegis-256: ok")
```

<!-- algorithm: aead/aes-256-gcm -->
<a id="aead-aes-256-gcm"></a>
## AES-256-GCM

AES-256-GCM fixes the GCM key size at 32 bytes while retaining the 12-byte nonce fast path and 16-byte default tag. Use this selector when the protocol requires AES-256 specifically; use generic GCM when key size is negotiated separately. Nonce reuse remains catastrophic even with a larger key.

<a id="example-aead-aes-256-gcm"></a>
<!-- runnable-example: aead-aes-256-gcm -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x57)
    var nonce = List[UInt8](length=12, fill=0x67)
    var aad: List[UInt8] = [0, 1, 2, 3]
    var message: List[UInt8] = [3, 2, 1, 0]
    var sealed = encrypt(AeadAlgorithm.AES256_GCM, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.AES256_GCM, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-aes-256-gcm: ok")
```

<!-- algorithm: aead/chacha20-poly1305 -->
<a id="aead-chacha20-poly1305"></a>
## ChaCha20-Poly1305

This is the original construction with an 8-byte nonce and a 64-bit block counter. Its wire format is not compatible with the 12-byte-nonce IETF variant. Use it only when an existing protocol explicitly requires this layout. The key is 32 bytes, the default tag is 16 bytes, and nonce reuse under one key is forbidden.

<a id="example-aead-chacha20-poly1305"></a>
<!-- runnable-example: aead-chacha20-poly1305 -->
```mojo
from std.testing import assert_equal
from mcrypto.aead.algorithm import AeadAlgorithm
from mcrypto.aead.combined import encrypt, decrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x71)
    var nonce = List[UInt8](length=8, fill=0x81)
    var aad: List[UInt8] = [0x10]
    var message: List[UInt8] = [0x20, 0x21, 0x22]
    var sealed = encrypt(AeadAlgorithm.CHACHA20_POLY1305, Span(key), Span(nonce), Span(aad), Span(message))
    assert_equal(decrypt(AeadAlgorithm.CHACHA20_POLY1305, Span(key), Span(nonce), Span(aad), Span(sealed)), message)
    print("aead-chacha20-poly1305: ok")
```
