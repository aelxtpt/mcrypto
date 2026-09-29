---
title: MACs and short keyed hashes
---

# MACs and short keyed hashes

A MAC detects modification by parties that do not know the secret key. It does not hide the message. Compare tags through the matching verification API or constant-time comparison, and keep keys separate from encryption and KDF keys. Example bytes are deterministic only to show the API.

<!-- algorithm: mac/blake2s-mac -->
<a id="mac-blake2s-mac"></a>
## BLAKE2s-MAC

BLAKE2s keyed mode is a compact MAC for software-oriented protocols. Keys may be at most 32 bytes; choose the tag length explicitly and keep domain separation outside the raw primitive.

<a id="example-mac-blake2s-mac"></a>
<!-- runnable-example: mac-blake2s-mac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x31)
    var message = List[UInt8](length=16, fill=0x61)
    var first = authenticate(MacAlgorithm.BLAKE2S_MAC, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.BLAKE2S_MAC, Span(key), Span(message), 16), first)
    print("mac-blake2s-mac: ok")
```

<!-- algorithm: mac/blake2b-mac -->
<a id="mac-blake2b-mac"></a>
## BLAKE2b-MAC

BLAKE2b keyed mode provides tags up to 64 bytes and is efficient on 64-bit CPUs. It is a keyed hash mode, not an interchangeable spelling of HMAC-BLAKE2.

<a id="example-mac-blake2b-mac"></a>
<!-- runnable-example: mac-blake2b-mac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x32)
    var message = List[UInt8](length=16, fill=0x62)
    var first = authenticate(MacAlgorithm.BLAKE2B_MAC, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.BLAKE2B_MAC, Span(key), Span(message), 16), first)
    print("mac-blake2b-mac: ok")
```

<!-- algorithm: mac/cbc-mac -->
<a id="mac-cbc-mac"></a>
## CBC-MAC

CBC-MAC is secure only for fixed-length message domains under one key. Variable-length protocols need an unambiguous length construction or, preferably, CMAC.

<a id="example-mac-cbc-mac"></a>
<!-- runnable-example: mac-cbc-mac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x33)
    var message = List[UInt8](length=32, fill=0x63)
    var first = authenticate(MacAlgorithm.CBC_MAC, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.CBC_MAC, Span(key), Span(message), 16), first)
    print("mac-cbc-mac: ok")
```

<!-- algorithm: mac/cmac -->
<a id="mac-cmac"></a>
## CMAC

CMAC is the standardized block-cipher MAC for variable-length messages. This API uses AES; use a dedicated key rather than reusing an encryption key.

<a id="example-mac-cmac"></a>
<!-- runnable-example: mac-cmac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x34)
    var message = List[UInt8](length=23, fill=0x64)
    var first = authenticate(MacAlgorithm.CMAC, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.CMAC, Span(key), Span(message), 16), first)
    print("mac-cmac: ok")
```

<!-- algorithm: mac/dmac -->
<a id="mac-dmac"></a>
## DMAC

DMAC is a two-key-derived block-cipher authenticator retained for compatible formats. Prefer CMAC for new designs and never reuse its key in another primitive.

<a id="example-mac-dmac"></a>
<!-- runnable-example: mac-dmac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x35)
    var message = List[UInt8](length=23, fill=0x65)
    var first = authenticate(MacAlgorithm.DMAC, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.DMAC, Span(key), Span(message), 16), first)
    print("mac-dmac: ok")
```

<!-- algorithm: mac/gmac -->
<a id="mac-gmac"></a>
## GMAC

GMAC is the authentication-only form of GCM. A nonce must never repeat under a key; repetition can expose the authentication key and enable forgeries.

<a id="example-mac-gmac"></a>
<!-- runnable-example: mac-gmac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.gmac import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x46)
    var nonce = List[UInt8](length=12, fill=0x67)
    var message = List[UInt8](length=23, fill=0x88)
    var first = authenticate(Span(key), Span(nonce), Span(message), 16)
    assert_equal(authenticate(Span(key), Span(nonce), Span(message), 16), first)
    print("mac-gmac: ok")
```

<!-- algorithm: mac/hmac -->
<a id="mac-hmac"></a>
## HMAC

HMAC wraps an explicitly selected digest. Choose the digest token in code and size the key and tag for the protocol; HMAC-SHA-256 is the default example.

<a id="example-mac-hmac"></a>
<!-- runnable-example: mac-hmac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x37)
    var message = List[UInt8](length=23, fill=0x67)
    var first = authenticate(MacAlgorithm.HMAC_SHA256, Span(key), Span(message), 32)
    assert_equal(authenticate(MacAlgorithm.HMAC_SHA256, Span(key), Span(message), 32), first)
    print("mac-hmac: ok")
```

<!-- algorithm: mac/panamamac -->
<a id="mac-panamamac"></a>
## PanamaMAC

PanamaMAC is a legacy keyed Panama construction provided for compatibility. It is not a recommendation for a new protocol.

<a id="example-mac-panamamac"></a>
<!-- runnable-example: mac-panamamac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x38)
    var message = List[UInt8](length=23, fill=0x68)
    var first = authenticate(MacAlgorithm.PANAMA_MAC, Span(key), Span(message), 32)
    assert_equal(authenticate(MacAlgorithm.PANAMA_MAC, Span(key), Span(message), 32), first)
    print("mac-panamamac: ok")
```

<!-- algorithm: mac/poly1305-aes -->
<a id="mac-poly1305-aes"></a>
## Poly1305-AES

Poly1305-AES derives a one-time Poly1305 key from AES and a 16-byte nonce. The nonce must be unique for every message under the 32-byte key.

<a id="example-mac-poly1305-aes"></a>
<!-- runnable-example: mac-poly1305-aes -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.poly1305_aes import authenticate

def main() raises:
    var key = List[UInt8](length=32, fill=0x49)
    var nonce = List[UInt8](length=16, fill=0x6A)
    var message = List[UInt8](length=23, fill=0x8B)
    var first = authenticate(Span(key), Span(nonce), Span(message), 16)
    assert_equal(authenticate(Span(key), Span(nonce), Span(message), 16), first)
    print("mac-poly1305-aes: ok")
```

<!-- algorithm: mac/poly1305 -->
<a id="mac-poly1305"></a>
## Poly1305

Poly1305 authenticates one message with a 32-byte one-time key. Reusing that key invalidates the security bound; protocols normally derive it from a nonce-based cipher.

<a id="example-mac-poly1305"></a>
<!-- runnable-example: mac-poly1305 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=32, fill=0x3A)
    var message = List[UInt8](length=23, fill=0x6A)
    var first = authenticate(MacAlgorithm.POLY1305, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.POLY1305, Span(key), Span(message), 16), first)
    print("mac-poly1305: ok")
```

<!-- algorithm: mac/ripemd160-hmac -->
<a id="mac-ripemd160-hmac"></a>
## RIPEMD160-HMAC

RIPEMD-160 HMAC exists for compatibility with deployed formats. Prefer HMAC-SHA-256 when designing a new protocol.

<a id="example-mac-ripemd160-hmac"></a>
<!-- runnable-example: mac-ripemd160-hmac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x3B)
    var message = List[UInt8](length=23, fill=0x6B)
    var first = authenticate(MacAlgorithm.RIPEMD160_HMAC, Span(key), Span(message), 20)
    assert_equal(authenticate(MacAlgorithm.RIPEMD160_HMAC, Span(key), Span(message), 20), first)
    print("mac-ripemd160-hmac: ok")
```

<!-- algorithm: mac/siphash-2-4 -->
<a id="mac-siphash-2-4"></a>
## SipHash-2-4

SipHash-2-4 is a 64-bit keyed hash for hash-table and short-input denial-of-service resistance. Its short tag is not a general replacement for a 128-bit message authenticator.

<a id="example-mac-siphash-2-4"></a>
<!-- runnable-example: mac-siphash-2-4 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x3C)
    var message = List[UInt8](length=23, fill=0x6C)
    var first = authenticate(MacAlgorithm.SIPHASH_2_4, Span(key), Span(message), 8)
    assert_equal(authenticate(MacAlgorithm.SIPHASH_2_4, Span(key), Span(message), 8), first)
    print("mac-siphash-2-4: ok")
```

<!-- algorithm: mac/siphash-4-8 -->
<a id="mac-siphash-4-8"></a>
## SipHash-4-8

SipHash-4-8 spends more rounds than SipHash-2-4 for conservative short-input authentication. It still emits a 64-bit tag.

<a id="example-mac-siphash-4-8"></a>
<!-- runnable-example: mac-siphash-4-8 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x3D)
    var message = List[UInt8](length=23, fill=0x6D)
    var first = authenticate(MacAlgorithm.SIPHASH_4_8, Span(key), Span(message), 8)
    assert_equal(authenticate(MacAlgorithm.SIPHASH_4_8, Span(key), Span(message), 8), first)
    print("mac-siphash-4-8: ok")
```

<!-- algorithm: mac/two-track-mac -->
<a id="mac-two-track-mac"></a>
## Two-Track-MAC

Two-Track-MAC is a legacy RIPEMD-family authenticator retained for format compatibility. Prefer HMAC-SHA-256 or CMAC for new designs.

<a id="example-mac-two-track-mac"></a>
<!-- runnable-example: mac-two-track-mac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x3E)
    var message = List[UInt8](length=23, fill=0x6E)
    var first = authenticate(MacAlgorithm.TWO_TRACK_MAC, Span(key), Span(message), 20)
    assert_equal(authenticate(MacAlgorithm.TWO_TRACK_MAC, Span(key), Span(message), 20), first)
    print("mac-two-track-mac: ok")
```

<!-- algorithm: mac/vmac -->
<a id="mac-vmac"></a>
## VMAC

VMAC is a high-throughput AES-based universal hash with 64- or 128-bit tags. Its nonce must be unique for every message under a key.

<a id="example-mac-vmac"></a>
<!-- runnable-example: mac-vmac -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.vmac import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x4F)
    var nonce = List[UInt8](length=8, fill=0x70)
    var message = List[UInt8](length=23, fill=0x91)
    var first = authenticate(Span(key), Span(nonce), Span(message), 16)
    assert_equal(authenticate(Span(key), Span(nonce), Span(message), 16), first)
    print("mac-vmac: ok")
```

<!-- algorithm: mac/siphash -->
<a id="mac-siphash"></a>
## Parameterized SipHash

The parameterized SipHash API makes the compression/finalization variant explicit through `SipHashAlgorithm`. Use it when a protocol negotiates among the supported SipHash variants.

<a id="example-mac-siphash"></a>
<!-- runnable-example: mac-siphash -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x40)
    var message = List[UInt8](length=23, fill=0x70)
    var first = authenticate(MacAlgorithm.SIPHASH_2_4, Span(key), Span(message), 8)
    assert_equal(authenticate(MacAlgorithm.SIPHASH_2_4, Span(key), Span(message), 8), first)
    print("mac-siphash: ok")
```

<!-- algorithm: mac/hmac-sha256 -->
<a id="mac-hmac-sha256"></a>
## HMAC-SHA-256

HMAC-SHA-256 is the usual general-purpose HMAC choice. It accepts arbitrary message lengths and separates authentication from encryption.

<a id="example-mac-hmac-sha256"></a>
<!-- runnable-example: mac-hmac-sha256 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x41)
    var message = List[UInt8](length=23, fill=0x71)
    var first = authenticate(MacAlgorithm.HMAC_SHA256, Span(key), Span(message), 32)
    assert_equal(authenticate(MacAlgorithm.HMAC_SHA256, Span(key), Span(message), 32), first)
    print("mac-hmac-sha256: ok")
```

<!-- algorithm: mac/hmac-sha512 -->
<a id="mac-hmac-sha512"></a>
## HMAC-SHA-512

HMAC-SHA-512 uses SHA-512 and emits up to 64 tag bytes. It is useful where the protocol specifically standardizes SHA-512.

<a id="example-mac-hmac-sha512"></a>
<!-- runnable-example: mac-hmac-sha512 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x42)
    var message = List[UInt8](length=23, fill=0x72)
    var first = authenticate(MacAlgorithm.HMAC_SHA512, Span(key), Span(message), 64)
    assert_equal(authenticate(MacAlgorithm.HMAC_SHA512, Span(key), Span(message), 64), first)
    print("mac-hmac-sha512: ok")
```

<!-- algorithm: mac/hmac-sha512-256 -->
<a id="mac-hmac-sha512-256"></a>
## HMAC-SHA-512/256

HMAC-SHA-512/256 uses the SHA-512/256 digest construction, not simple truncation of HMAC-SHA-512. Select its dedicated token.

<a id="example-mac-hmac-sha512-256"></a>
<!-- runnable-example: mac-hmac-sha512-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=20, fill=0x43)
    var message = List[UInt8](length=23, fill=0x73)
    var first = authenticate(MacAlgorithm.HMAC_SHA512_256, Span(key), Span(message), 32)
    assert_equal(authenticate(MacAlgorithm.HMAC_SHA512_256, Span(key), Span(message), 32), first)
    print("mac-hmac-sha512-256: ok")
```

<!-- algorithm: mac/siphash-x-2-4 -->
<a id="mac-siphash-x-2-4"></a>
## SipHash-x-2-4

SipHash-x-2-4 extends the SipHash-2-4 output to 128 bits. It keeps the same 16-byte key requirement.

<a id="example-mac-siphash-x-2-4"></a>
<!-- runnable-example: mac-siphash-x-2-4 -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate

def main() raises:
    var key = List[UInt8](length=16, fill=0x44)
    var message = List[UInt8](length=23, fill=0x74)
    var first = authenticate(MacAlgorithm.SIPHASH_X_2_4, Span(key), Span(message), 16)
    assert_equal(authenticate(MacAlgorithm.SIPHASH_X_2_4, Span(key), Span(message), 16), first)
    print("mac-siphash-x-2-4: ok")
```

