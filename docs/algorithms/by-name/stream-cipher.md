---
title: Stream cipher algorithms
---

# Stream cipher algorithms

A stream cipher XORs a keystream with input bytes; applying the same operation again with the same key and nonce recovers the input. It does not authenticate. Use an AEAD for new protocols. If a stream cipher is required, authenticate the ciphertext separately and never reuse a key/nonce pair.

<!-- algorithm: stream-cipher/chacha8 -->
<a id="stream-cipher-chacha8"></a>
## ChaCha8

ChaCha8 is the eight-round member of the ChaCha family. It uses a 32-byte key and an 8-byte nonce. Its reduced round count trades security margin for speed, so use it only where the protocol explicitly names ChaCha8; ChaCha20 is the conservative general choice.

<a id="example-stream-cipher-chacha8"></a>
<!-- runnable-example: stream-cipher-chacha8 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=8)
    var nonce = List[UInt8](length=8, fill=1)
    var message: List[UInt8] = [1, 2, 3, 4]
    var cipher = xor(StreamCipherAlgorithm.CHACHA8, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.CHACHA8, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-chacha8: ok")
```

<!-- algorithm: stream-cipher/chacha12 -->
<a id="stream-cipher-chacha12"></a>
## ChaCha12

ChaCha12 uses twelve rounds, a 32-byte key, and an 8-byte nonce. It provides more margin than ChaCha8 but is not wire-compatible with ChaCha20. Select it only from an explicit protocol parameter and keep nonces unique per key.

<a id="example-stream-cipher-chacha12"></a>
<!-- runnable-example: stream-cipher-chacha12 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=12)
    var nonce = List[UInt8](length=8, fill=2)
    var message: List[UInt8] = [12, 24, 36]
    var cipher = xor(StreamCipherAlgorithm.CHACHA12, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.CHACHA12, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-chacha12: ok")
```

<!-- algorithm: stream-cipher/chacha20 -->
<a id="stream-cipher-chacha20"></a>
## ChaCha20

This selector is the original ChaCha20 layout with a 32-byte key and an 8-byte nonce. It differs from the 12-byte-nonce IETF layout. Prefer authenticated ChaCha20-Poly1305 unless a protocol requires raw stream output.

<a id="example-stream-cipher-chacha20"></a>
<!-- runnable-example: stream-cipher-chacha20 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=20)
    var nonce = List[UInt8](length=8, fill=3)
    var message: List[UInt8] = [2, 7, 1, 8]
    var cipher = xor(StreamCipherAlgorithm.CHACHA20, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.CHACHA20, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-chacha20: ok")
```

<!-- algorithm: stream-cipher/xchacha20 -->
<a id="stream-cipher-xchacha20"></a>
## XChaCha20

XChaCha20 expands the nonce to 24 bytes and derives a subkey before running ChaCha20. The larger nonce supports random nonce allocation with negligible collision risk. It still provides confidentiality only; pair it with authentication or use XChaCha20-Poly1305.

<a id="example-stream-cipher-xchacha20"></a>
<!-- runnable-example: stream-cipher-xchacha20 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x21)
    var nonce = List[UInt8](length=24, fill=0x31)
    var message: List[UInt8] = [5, 10, 15, 20]
    var cipher = xor(StreamCipherAlgorithm.XCHACHA20, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.XCHACHA20, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-xchacha20: ok")
```

<!-- algorithm: stream-cipher/xchacha20-counter-1 -->
<a id="stream-cipher-xchacha20-counter-1"></a>
## XChaCha20 (counter 1)

This XChaCha20 variant starts the IETF block counter at one rather than zero. It exists for formats whose first keystream block is reserved for another construction. It is not interchangeable with `StreamCipherAlgorithm.XCHACHA20`; select it with `XCHACHA20_COUNTER1`, a 32-byte key, and a 24-byte nonce.

<a id="example-stream-cipher-xchacha20-counter-1"></a>
<!-- runnable-example: stream-cipher-xchacha20-counter-1 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x22)
    var nonce = List[UInt8](length=24, fill=0x32)
    var message: List[UInt8] = [6, 12, 18, 24]
    var cipher = xor(StreamCipherAlgorithm.XCHACHA20_COUNTER1, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.XCHACHA20_COUNTER1, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-xchacha20-counter-1: ok")
```

<!-- algorithm: stream-cipher/panama -->
<a id="stream-cipher-panama"></a>
## Panama

Panama is a legacy word-oriented stream construction with 32-byte keys and 32-byte nonces. mcrypto also exposes a byte-order variant through its parser. Use Panama only for compatibility with an existing format, and authenticate the result separately.

<a id="example-stream-cipher-panama"></a>
<!-- runnable-example: stream-cipher-panama -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x23)
    var nonce = List[UInt8](length=32, fill=0x33)
    var message: List[UInt8] = [7, 14, 21, 28]
    var cipher = xor(StreamCipherAlgorithm.PANAMA, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.PANAMA, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-panama: ok")
```

<!-- algorithm: stream-cipher/salsa20 -->
<a id="stream-cipher-salsa20"></a>
## Salsa20

Salsa20 uses a 32-byte key, an 8-byte nonce, and twenty rounds. It is a mature stream cipher but supplies no authentication. Keep a monotonic nonce allocation per key or choose an authenticated construction with a larger nonce.

<a id="example-stream-cipher-salsa20"></a>
<!-- runnable-example: stream-cipher-salsa20 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x24)
    var nonce = List[UInt8](length=8, fill=0x34)
    var message: List[UInt8] = [8, 16, 24, 32]
    var cipher = xor(StreamCipherAlgorithm.SALSA20, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.SALSA20, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-salsa20: ok")
```

<!-- algorithm: stream-cipher/xsalsa20 -->
<a id="stream-cipher-xsalsa20"></a>
## XSalsa20

XSalsa20 extends Salsa20 to a 24-byte nonce while retaining the 32-byte key. That nonce size is convenient when independent senders generate nonces randomly. For authenticated messages, prefer XSalsa20-Poly1305 rather than composing a MAC manually.

<a id="example-stream-cipher-xsalsa20"></a>
<!-- runnable-example: stream-cipher-xsalsa20 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x25)
    var nonce = List[UInt8](length=24, fill=0x35)
    var message: List[UInt8] = [9, 18, 27, 36]
    var cipher = xor(StreamCipherAlgorithm.XSALSA20, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.XSALSA20, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-xsalsa20: ok")
```

<!-- algorithm: stream-cipher/sosemanuk -->
<a id="stream-cipher-sosemanuk"></a>
## Sosemanuk

Sosemanuk accepts a key up to 32 bytes and a 16-byte nonce. It is provided for interoperability with existing data, not as a default for a new protocol. The nonce is not secret but must not repeat with the same key, and ciphertext must be authenticated.

<a id="example-stream-cipher-sosemanuk"></a>
<!-- runnable-example: stream-cipher-sosemanuk -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x26)
    var nonce = List[UInt8](length=16, fill=0x36)
    var message: List[UInt8] = [10, 20, 30, 40]
    var cipher = xor(StreamCipherAlgorithm.SOSEMANUK, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.SOSEMANUK, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-sosemanuk: ok")
```

<!-- algorithm: stream-cipher/arc4 -->
<a id="stream-cipher-arc4"></a>
## ARC4

ARC4 is a legacy byte-oriented cipher with severe keystream biases. Do not use it for new encryption or protocol design. This API remains only for decoding or reproducing legacy formats; the nonce parameter is empty because ARC4 itself has no nonce input.

<a id="example-stream-cipher-arc4"></a>
<!-- runnable-example: stream-cipher-arc4 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key: List[UInt8] = [75, 101, 121]
    var nonce = List[UInt8]()
    var message: List[UInt8] = [80, 108, 97, 105, 110]
    var cipher = xor(StreamCipherAlgorithm.ARC4, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.ARC4, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-arc4: ok")
```

<!-- algorithm: stream-cipher/seal -->
<a id="stream-cipher-seal"></a>
## SEAL

SEAL is a legacy stream cipher with a 20-byte key and a 4-byte nonce. mcrypto preserves byte-order variants for format compatibility. Do not select it for new systems; when reading old data, match the exact variant and authenticate any newly produced ciphertext separately.

<a id="example-stream-cipher-seal"></a>
<!-- runnable-example: stream-cipher-seal -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=20, fill=0x27)
    var nonce = List[UInt8](length=4, fill=0x37)
    var message: List[UInt8] = [11, 22, 33, 44]
    var cipher = xor(StreamCipherAlgorithm.SEAL, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.SEAL, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-seal: ok")
```

<!-- algorithm: stream-cipher/wake-ofb -->
<a id="stream-cipher-wake-ofb"></a>
## WAKE-OFB

WAKE-OFB is a legacy keystream construction driven by a 32-byte key and no nonce in this API. Reusing the same key therefore reuses the keystream, making it unsuitable for ordinary multi-message encryption. Keep it only for deterministic compatibility work on trusted legacy data.

<a id="example-stream-cipher-wake-ofb"></a>
<!-- runnable-example: stream-cipher-wake-ofb -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x28)
    var nonce = List[UInt8]()
    var message: List[UInt8] = [12, 24, 36, 48]
    var cipher = xor(StreamCipherAlgorithm.WAKE_OFB, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.WAKE_OFB, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-wake-ofb: ok")
```

<!-- algorithm: stream-cipher/rabbit -->
<a id="stream-cipher-rabbit"></a>
## Rabbit

Rabbit uses a 16-byte key and accepts an 8-byte nonce. It is included for compatibility with systems that already specify Rabbit. It does not authenticate output, and the nonce must be unique for every message encrypted under one key.

<a id="example-stream-cipher-rabbit"></a>
<!-- runnable-example: stream-cipher-rabbit -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=16, fill=0x29)
    var nonce = List[UInt8](length=8, fill=0x39)
    var message: List[UInt8] = [13, 26, 39, 52]
    var cipher = xor(StreamCipherAlgorithm.RABBIT, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.RABBIT, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-rabbit: ok")
```

<!-- algorithm: stream-cipher/hc-128 -->
<a id="stream-cipher-hc-128"></a>
## HC-128

HC-128 uses a 16-byte key and a 16-byte nonce. Its large internal state is initialized from both values, so nonce reuse repeats a keystream. Use it only when a protocol requires HC-128 and add independent authentication.

<a id="example-stream-cipher-hc-128"></a>
<!-- runnable-example: stream-cipher-hc-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=16, fill=0x2A)
    var nonce = List[UInt8](length=16, fill=0x3A)
    var message: List[UInt8] = [14, 28, 42, 56]
    var cipher = xor(StreamCipherAlgorithm.HC128, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.HC128, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-hc-128: ok")
```

<!-- algorithm: stream-cipher/hc-256 -->
<a id="stream-cipher-hc-256"></a>
## HC-256

HC-256 uses a 32-byte key and a 32-byte nonce and has a larger state than HC-128. It is not a drop-in encoding substitute for HC-128. Reserve it for protocols that identify HC-256 explicitly, keep nonces unique, and authenticate ciphertext.

<a id="example-stream-cipher-hc-256"></a>
<!-- runnable-example: stream-cipher-hc-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x2B)
    var nonce = List[UInt8](length=32, fill=0x3B)
    var message: List[UInt8] = [15, 30, 45, 60]
    var cipher = xor(StreamCipherAlgorithm.HC256, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.HC256, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-hc-256: ok")
```

<!-- algorithm: stream-cipher/chacha20-ietf -->
<a id="stream-cipher-chacha20-ietf"></a>
## ChaCha20-IETF

ChaCha20-IETF uses a 32-byte key, a 12-byte nonce, and a 32-bit block counter. It is distinct from the original 8-byte-nonce selector. Prefer the authenticated ChaCha20-Poly1305-IETF construction; use raw stream output only when the protocol supplies a separate authenticator.

<a id="example-stream-cipher-chacha20-ietf"></a>
<!-- runnable-example: stream-cipher-chacha20-ietf -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x2C)
    var nonce = List[UInt8](length=12, fill=0x3C)
    var message: List[UInt8] = [16, 32, 48, 64]
    var cipher = xor(StreamCipherAlgorithm.CHACHA20_IETF, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.CHACHA20_IETF, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-chacha20-ietf: ok")
```

<!-- algorithm: stream-cipher/salsa20-12 -->
<a id="stream-cipher-salsa20-12"></a>
## Salsa20-12

Salsa20-12 reduces Salsa20 to twelve rounds. It uses a 32-byte key and an 8-byte nonce. The lower round count is a deliberate compatibility or performance choice, not an automatic optimization; prefer Salsa20's full-round selector when the format leaves the choice open.

<a id="example-stream-cipher-salsa20-12"></a>
<!-- runnable-example: stream-cipher-salsa20-12 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x2D)
    var nonce = List[UInt8](length=8, fill=0x3D)
    var message: List[UInt8] = [17, 34, 51, 68]
    var cipher = xor(StreamCipherAlgorithm.SALSA20_12, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.SALSA20_12, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-salsa20-12: ok")
```

<!-- algorithm: stream-cipher/salsa20-8 -->
<a id="stream-cipher-salsa20-8"></a>
## Salsa20-8

Salsa20-8 is the eight-round reduced variant with a 32-byte key and an 8-byte nonce. It has less security margin than Salsa20 and should appear only where a protocol explicitly requires it. Never reuse nonces, and do not mistake encryption for authentication.

<a id="example-stream-cipher-salsa20-8"></a>
<!-- runnable-example: stream-cipher-salsa20-8 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor

def main() raises:
    var key = List[UInt8](length=32, fill=0x2E)
    var nonce = List[UInt8](length=8, fill=0x3E)
    var message: List[UInt8] = [18, 36, 54, 72]
    var cipher = xor(StreamCipherAlgorithm.SALSA20_8, Span(key), Span(nonce), Span(message))
    assert_equal(xor(StreamCipherAlgorithm.SALSA20_8, Span(key), Span(nonce), Span(cipher)), message)
    print("stream-cipher-salsa20-8: ok")
```
