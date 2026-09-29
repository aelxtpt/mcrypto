---
title: Block cipher modes
---

# Block cipher modes

A mode defines how fixed-size block-cipher calls cover a message. None of these modes authenticates ciphertext; prefer an AEAD for files, messages, and network records. Example bytes are deterministic only to show the API.

<!-- algorithm: cipher-mode/ecb -->
<a id="cipher-mode-ecb"></a>
## ECB

ECB transforms each 16-byte AES block independently. Equal plaintext blocks produce equal ciphertext blocks, so it leaks structure and should not encrypt ordinary data.

Use `CipherMode.ECB` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-ecb"></a>
<!-- runnable-example: cipher-mode-ecb -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x31)
    var iv = List[UInt8](length=16, fill=0x51)
    var message = List[UInt8](length=32, fill=0x71)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.ECB, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.ECB, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-ecb: ok")
```

<!-- algorithm: cipher-mode/cbc -->
<a id="cipher-mode-cbc"></a>
## CBC

CBC chains each plaintext block to the previous ciphertext block. It requires an unpredictable, unique 16-byte IV and padding for non-block-aligned messages; it does not authenticate.

Use `CipherMode.CBC` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-cbc"></a>
<!-- runnable-example: cipher-mode-cbc -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x32)
    var iv = List[UInt8](length=16, fill=0x52)
    var message = List[UInt8](length=32, fill=0x72)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.CBC, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.CBC, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-cbc: ok")
```

<!-- algorithm: cipher-mode/cbc-cts -->
<a id="cipher-mode-cbc-cts"></a>
## CBC-CTS

CBC ciphertext stealing handles a final partial block without expanding the ciphertext. Both endpoints must use the same CTS convention, and the IV must be unique and unpredictable.

Use `CipherMode.CBC_CTS` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-cbc-cts"></a>
<!-- runnable-example: cipher-mode-cbc-cts -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x33)
    var iv = List[UInt8](length=16, fill=0x53)
    var message = List[UInt8](length=31, fill=0x73)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.CBC_CTS, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.CBC_CTS, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-cbc-cts: ok")
```

<!-- algorithm: cipher-mode/cfb -->
<a id="cipher-mode-cfb"></a>
## CFB

CFB converts a block cipher into a self-synchronizing stream mode. It accepts partial final data, needs a unique unpredictable IV, and remains malleable without a MAC.

Use `CipherMode.CFB` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-cfb"></a>
<!-- runnable-example: cipher-mode-cfb -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x34)
    var iv = List[UInt8](length=16, fill=0x54)
    var message = List[UInt8](length=37, fill=0x74)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.CFB, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.CFB, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-cfb: ok")
```

<!-- algorithm: cipher-mode/ofb -->
<a id="cipher-mode-ofb"></a>
## OFB

OFB generates a keystream independent of plaintext. Reusing an IV with the same key repeats that keystream, so the IV must be unique; authentication is separate.

Use `CipherMode.OFB` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-ofb"></a>
<!-- runnable-example: cipher-mode-ofb -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x35)
    var iv = List[UInt8](length=16, fill=0x55)
    var message = List[UInt8](length=37, fill=0x75)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.OFB, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.OFB, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-ofb: ok")
```

<!-- algorithm: cipher-mode/ctr -->
<a id="cipher-mode-ctr"></a>
## CTR

CTR encrypts counters to produce a parallelizable keystream. A counter block must never repeat under the same key. Allocate nonces and counters as one protocol field.

Use `CipherMode.CTR` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-ctr"></a>
<!-- runnable-example: cipher-mode-ctr -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x36)
    var iv = List[UInt8](length=16, fill=0x56)
    var message = List[UInt8](length=37, fill=0x76)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.CTR, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.CTR, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-ctr: ok")
```

<!-- algorithm: cipher-mode/xts -->
<a id="cipher-mode-xts"></a>
## XTS

XTS is a tweakable storage mode for fixed-size sectors. It uses two AES keys and a 16-byte sector tweak. It is not an authenticated transport mode.

Use `CipherMode.XTS` with `mcrypto.ciphers.dispatch.process`. Decryption must receive the same IV or tweak and key.

<a id="example-cipher-mode-xts"></a>
<!-- runnable-example: cipher-mode-xts -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x37)
    var iv = List[UInt8](length=16, fill=0x57)
    var message = List[UInt8](length=32, fill=0x77)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.XTS, True, Span(key), Span(iv), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.XTS, False, Span(key), Span(iv), Span(cipher)), message)
    print("cipher-mode-xts: ok")
```

