---
title: Block cipher algorithms
---

# Block cipher algorithms

A block cipher transforms one fixed-size block under a secret key. Applications normally need a mode; prefer AEAD for new designs. ECB leaks repeated blocks, CBC/CFB/OFB/CTR need unique IV or counter handling, and XTS is only for fixed-sector storage. The examples use CTR to demonstrate reversible dispatcher usage, not authentication.

<!-- algorithm: block-cipher/aes -->
<a id="block-cipher-aes"></a>
## AES

AES is the standard 128-bit block cipher. It accepts 16-, 24-, or 32-byte keys and benefits from hardware acceleration on many CPUs. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.AES` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-aes"></a>
<!-- runnable-example: block-cipher-aes -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x20)
    var counter = List[UInt8](length=16, fill=0x40)
    var message = List[UInt8](length=19, fill=0x60)
    var cipher = process(BlockCipherAlgorithm.AES, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.AES, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-aes: ok")
```

<!-- algorithm: block-cipher/rc2 -->
<a id="block-cipher-rc2"></a>
## RC2

RC2 is a legacy 64-bit-block cipher with variable key size. Its small block creates collision risk in long streams; use only for old formats. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.RC2` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-rc2"></a>
<!-- runnable-example: block-cipher-rc2 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x21)
    var counter = List[UInt8](length=8, fill=0x41)
    var message = List[UInt8](length=11, fill=0x61)
    var cipher = process(BlockCipherAlgorithm.RC2, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.RC2, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-rc2: ok")
```

<!-- algorithm: block-cipher/rc5 -->
<a id="block-cipher-rc5"></a>
## RC5

RC5 is a parameterized legacy cipher; this selector uses the mcrypto-compatible word and round profile. Match the format exactly. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.RC5` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-rc5"></a>
<!-- runnable-example: block-cipher-rc5 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x22)
    var counter = List[UInt8](length=8, fill=0x42)
    var message = List[UInt8](length=11, fill=0x62)
    var cipher = process(BlockCipherAlgorithm.RC5, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.RC5, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-rc5: ok")
```

<!-- algorithm: block-cipher/rc6 -->
<a id="block-cipher-rc6"></a>
## RC6

RC6 is an AES-era 128-bit-block design. It is retained for interoperability, not as a preferred new protocol cipher. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.RC6` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-rc6"></a>
<!-- runnable-example: block-cipher-rc6 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x23)
    var counter = List[UInt8](length=16, fill=0x43)
    var message = List[UInt8](length=19, fill=0x63)
    var cipher = process(BlockCipherAlgorithm.RC6, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.RC6, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-rc6: ok")
```

<!-- algorithm: block-cipher/mars -->
<a id="block-cipher-mars"></a>
## MARS

MARS is an AES-era 128-bit-block cipher with variable-length keys. Use it only when an established format identifies MARS. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.MARS` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-mars"></a>
<!-- runnable-example: block-cipher-mars -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x24)
    var counter = List[UInt8](length=16, fill=0x44)
    var message = List[UInt8](length=19, fill=0x64)
    var cipher = process(BlockCipherAlgorithm.MARS, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.MARS, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-mars: ok")
```

<!-- algorithm: block-cipher/twofish -->
<a id="block-cipher-twofish"></a>
## Twofish

Twofish is a 128-bit-block AES finalist accepting 16-, 24-, or 32-byte keys. Prefer AEAD unless compatibility requires a raw mode. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.TWOFISH` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-twofish"></a>
<!-- runnable-example: block-cipher-twofish -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x25)
    var counter = List[UInt8](length=16, fill=0x45)
    var message = List[UInt8](length=19, fill=0x65)
    var cipher = process(BlockCipherAlgorithm.TWOFISH, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.TWOFISH, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-twofish: ok")
```

<!-- algorithm: block-cipher/serpent -->
<a id="block-cipher-serpent"></a>
## Serpent

Serpent is a conservative 128-bit-block AES finalist with 16-, 24-, or 32-byte keys. It still needs a secure mode and authentication. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.SERPENT` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-serpent"></a>
<!-- runnable-example: block-cipher-serpent -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x26)
    var counter = List[UInt8](length=16, fill=0x46)
    var message = List[UInt8](length=19, fill=0x66)
    var cipher = process(BlockCipherAlgorithm.SERPENT, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SERPENT, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-serpent: ok")
```

<!-- algorithm: block-cipher/cast-128 -->
<a id="block-cipher-cast-128"></a>
## CAST-128

CAST-128 uses a 64-bit block and variable key sizes. The small block limits safe data volume; reserve it for legacy protocols. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.CAST128` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-cast-128"></a>
<!-- runnable-example: block-cipher-cast-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x27)
    var counter = List[UInt8](length=8, fill=0x47)
    var message = List[UInt8](length=11, fill=0x67)
    var cipher = process(BlockCipherAlgorithm.CAST128, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.CAST128, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-cast-128: ok")
```

<!-- algorithm: block-cipher/cast-256 -->
<a id="block-cipher-cast-256"></a>
## CAST-256

CAST-256 is a 128-bit-block extension of the CAST family. It is primarily an interoperability algorithm. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.CAST256` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-cast-256"></a>
<!-- runnable-example: block-cipher-cast-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x28)
    var counter = List[UInt8](length=16, fill=0x48)
    var message = List[UInt8](length=19, fill=0x68)
    var cipher = process(BlockCipherAlgorithm.CAST256, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.CAST256, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-cast-256: ok")
```

<!-- algorithm: block-cipher/aria -->
<a id="block-cipher-aria"></a>
## ARIA

ARIA is a standardized 128-bit-block cipher accepting 16-, 24-, or 32-byte keys. Choose it when the surrounding standard requires ARIA. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.ARIA` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-aria"></a>
<!-- runnable-example: block-cipher-aria -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x29)
    var counter = List[UInt8](length=16, fill=0x49)
    var message = List[UInt8](length=19, fill=0x69)
    var cipher = process(BlockCipherAlgorithm.ARIA, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.ARIA, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-aria: ok")
```

<!-- algorithm: block-cipher/blowfish -->
<a id="block-cipher-blowfish"></a>
## Blowfish

Blowfish has a 64-bit block and variable key length. Its small block makes it unsuitable for large modern data sets. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.BLOWFISH` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-blowfish"></a>
<!-- runnable-example: block-cipher-blowfish -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x2A)
    var counter = List[UInt8](length=8, fill=0x4A)
    var message = List[UInt8](length=11, fill=0x6A)
    var cipher = process(BlockCipherAlgorithm.BLOWFISH, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.BLOWFISH, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-blowfish: ok")
```

<!-- algorithm: block-cipher/camellia -->
<a id="block-cipher-camellia"></a>
## Camellia

Camellia is a standardized 128-bit-block cipher with 16-, 24-, or 32-byte keys and broad protocol use. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.CAMELLIA` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-camellia"></a>
<!-- runnable-example: block-cipher-camellia -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x2B)
    var counter = List[UInt8](length=16, fill=0x4B)
    var message = List[UInt8](length=19, fill=0x6B)
    var cipher = process(BlockCipherAlgorithm.CAMELLIA, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.CAMELLIA, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-camellia: ok")
```

<!-- algorithm: block-cipher/cham-64 -->
<a id="block-cipher-cham-64"></a>
## CHAM-64

CHAM-64 targets constrained implementations but has a 64-bit block. Use it only where the exact CHAM-64 profile is specified. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.CHAM64` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-cham-64"></a>
<!-- runnable-example: block-cipher-cham-64 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x2C)
    var counter = List[UInt8](length=8, fill=0x4C)
    var message = List[UInt8](length=11, fill=0x6C)
    var cipher = process(BlockCipherAlgorithm.CHAM64, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.CHAM64, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-cham-64: ok")
```

<!-- algorithm: block-cipher/cham-128 -->
<a id="block-cipher-cham-128"></a>
## CHAM-128

CHAM-128 is the 128-bit-block CHAM profile. It is not wire-compatible with CHAM-64 and should be explicitly negotiated. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.CHAM128` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-cham-128"></a>
<!-- runnable-example: block-cipher-cham-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x2D)
    var counter = List[UInt8](length=16, fill=0x4D)
    var message = List[UInt8](length=19, fill=0x6D)
    var cipher = process(BlockCipherAlgorithm.CHAM128, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.CHAM128, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-cham-128: ok")
```

<!-- algorithm: block-cipher/des -->
<a id="block-cipher-des"></a>
## DES

DES has a 56-bit effective key and is exhaustively breakable. Keep it only for decoding legacy data. This algorithm is cryptographically obsolete.

Use `BlockCipherAlgorithm.DES` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-des"></a>
<!-- runnable-example: block-cipher-des -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=8, fill=0x2E)
    var counter = List[UInt8](length=8, fill=0x4E)
    var message = List[UInt8](length=11, fill=0x6E)
    var cipher = process(BlockCipherAlgorithm.DES, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.DES, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-des: ok")
```

<!-- algorithm: block-cipher/des-xex3 -->
<a id="block-cipher-des-xex3"></a>
## DES-XEX3

DES-XEX3 applies a three-key transform around DES. It remains a legacy compatibility construction with a 64-bit block. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.DES_XEX3` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-des-xex3"></a>
<!-- runnable-example: block-cipher-des-xex3 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=24, fill=0x2F)
    var counter = List[UInt8](length=8, fill=0x4F)
    var message = List[UInt8](length=11, fill=0x6F)
    var cipher = process(BlockCipherAlgorithm.DES_XEX3, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.DES_XEX3, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-des-xex3: ok")
```

<!-- algorithm: block-cipher/des-ede2 -->
<a id="block-cipher-des-ede2"></a>
## DES-EDE2

Two-key Triple DES has a 64-bit block and reduced effective security. It is deprecated for new encryption. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.DES_EDE2` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-des-ede2"></a>
<!-- runnable-example: block-cipher-des-ede2 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x30)
    var counter = List[UInt8](length=8, fill=0x50)
    var message = List[UInt8](length=11, fill=0x70)
    var cipher = process(BlockCipherAlgorithm.DES_EDE2, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.DES_EDE2, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-des-ede2: ok")
```

<!-- algorithm: block-cipher/des-ede3 -->
<a id="block-cipher-des-ede3"></a>
## DES-EDE3

Three-key Triple DES has a 64-bit block and strict data-volume limits. Use it only where legacy interoperability requires it. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.DES_EDE3` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-des-ede3"></a>
<!-- runnable-example: block-cipher-des-ede3 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=24, fill=0x31)
    var counter = List[UInt8](length=8, fill=0x51)
    var message = List[UInt8](length=11, fill=0x71)
    var cipher = process(BlockCipherAlgorithm.DES_EDE3, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.DES_EDE3, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-des-ede3: ok")
```

<!-- algorithm: block-cipher/3-way -->
<a id="block-cipher-3-way"></a>
## 3-WAY

3-WAY uses an unusual 96-bit block and a 96-bit key. It exists for exact-format compatibility only. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.THREE_WAY` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 12-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-3-way"></a>
<!-- runnable-example: block-cipher-3-way -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=12, fill=0x32)
    var counter = List[UInt8](length=12, fill=0x52)
    var message = List[UInt8](length=15, fill=0x72)
    var cipher = process(BlockCipherAlgorithm.THREE_WAY, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.THREE_WAY, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-3-way: ok")
```

<!-- algorithm: block-cipher/gost -->
<a id="block-cipher-gost"></a>
## GOST

This GOST block cipher profile uses a 64-bit block and 256-bit key. Parameters must match the protocol; the name alone may be insufficient elsewhere. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.GOST` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-gost"></a>
<!-- runnable-example: block-cipher-gost -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x33)
    var counter = List[UInt8](length=8, fill=0x53)
    var message = List[UInt8](length=11, fill=0x73)
    var cipher = process(BlockCipherAlgorithm.GOST, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.GOST, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-gost: ok")
```

<!-- algorithm: block-cipher/hight -->
<a id="block-cipher-hight"></a>
## HIGHT

HIGHT is a lightweight 64-bit-block cipher with a 128-bit key. Its block size limits safe bulk encryption. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.HIGHT` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-hight"></a>
<!-- runnable-example: block-cipher-hight -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x34)
    var counter = List[UInt8](length=8, fill=0x54)
    var message = List[UInt8](length=11, fill=0x74)
    var cipher = process(BlockCipherAlgorithm.HIGHT, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.HIGHT, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-hight: ok")
```

<!-- algorithm: block-cipher/idea -->
<a id="block-cipher-idea"></a>
## IDEA

IDEA uses a 64-bit block and 128-bit key. It remains for established formats and should not anchor a new protocol. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.IDEA` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-idea"></a>
<!-- runnable-example: block-cipher-idea -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x35)
    var counter = List[UInt8](length=8, fill=0x55)
    var message = List[UInt8](length=11, fill=0x75)
    var cipher = process(BlockCipherAlgorithm.IDEA, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.IDEA, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-idea: ok")
```

<!-- algorithm: block-cipher/kalyna-128 -->
<a id="block-cipher-kalyna-128"></a>
## Kalyna-128

Kalyna-128 uses a 128-bit block. Match its key and block profile to the protocol and choose a nonce-safe mode. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.KALYNA128` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-kalyna-128"></a>
<!-- runnable-example: block-cipher-kalyna-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x36)
    var counter = List[UInt8](length=16, fill=0x56)
    var message = List[UInt8](length=19, fill=0x76)
    var cipher = process(BlockCipherAlgorithm.KALYNA128, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.KALYNA128, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-kalyna-128: ok")
```

<!-- algorithm: block-cipher/kalyna-256 -->
<a id="block-cipher-kalyna-256"></a>
## Kalyna-256

Kalyna-256 uses a 256-bit block and distinct schedule. It is not interchangeable with Kalyna-128. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.KALYNA256` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 32-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-kalyna-256"></a>
<!-- runnable-example: block-cipher-kalyna-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x37)
    var counter = List[UInt8](length=32, fill=0x57)
    var message = List[UInt8](length=35, fill=0x77)
    var cipher = process(BlockCipherAlgorithm.KALYNA256, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.KALYNA256, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-kalyna-256: ok")
```

<!-- algorithm: block-cipher/kalyna-512 -->
<a id="block-cipher-kalyna-512"></a>
## Kalyna-512

Kalyna-512 uses a 512-bit block and key profile. Its wide block changes mode sizing and serialized ciphertext expectations. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.KALYNA512` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 64-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-kalyna-512"></a>
<!-- runnable-example: block-cipher-kalyna-512 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=64, fill=0x38)
    var counter = List[UInt8](length=64, fill=0x58)
    var message = List[UInt8](length=67, fill=0x78)
    var cipher = process(BlockCipherAlgorithm.KALYNA512, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.KALYNA512, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-kalyna-512: ok")
```

<!-- algorithm: block-cipher/lea -->
<a id="block-cipher-lea"></a>
## LEA

LEA is a 128-bit-block cipher accepting 16-, 24-, or 32-byte keys. Use it when required by an interoperable specification. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.LEA` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-lea"></a>
<!-- runnable-example: block-cipher-lea -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x39)
    var counter = List[UInt8](length=16, fill=0x59)
    var message = List[UInt8](length=19, fill=0x79)
    var cipher = process(BlockCipherAlgorithm.LEA, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.LEA, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-lea: ok")
```

<!-- algorithm: block-cipher/safer -->
<a id="block-cipher-safer"></a>
## SAFER

SAFER is a legacy family with a 64-bit block. The selector fixes the implementation profile; do not infer another SAFER variant. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SAFER` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-safer"></a>
<!-- runnable-example: block-cipher-safer -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x3A)
    var counter = List[UInt8](length=8, fill=0x5A)
    var message = List[UInt8](length=11, fill=0x7A)
    var cipher = process(BlockCipherAlgorithm.SAFER, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SAFER, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-safer: ok")
```

<!-- algorithm: block-cipher/seed -->
<a id="block-cipher-seed"></a>
## SEED

SEED is a standardized 128-bit-block cipher with a 128-bit key. It is used mainly by existing regional protocols. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.SEED` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-seed"></a>
<!-- runnable-example: block-cipher-seed -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x3B)
    var counter = List[UInt8](length=16, fill=0x5B)
    var message = List[UInt8](length=19, fill=0x7B)
    var cipher = process(BlockCipherAlgorithm.SEED, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SEED, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-seed: ok")
```

<!-- algorithm: block-cipher/shacal-2 -->
<a id="block-cipher-shacal-2"></a>
## SHACAL-2

SHACAL-2 exposes a 256-bit block derived from the SHA-256 compression design. Use only where SHACAL-2 is explicit. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SHACAL2` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 32-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-shacal-2"></a>
<!-- runnable-example: block-cipher-shacal-2 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x3C)
    var counter = List[UInt8](length=32, fill=0x5C)
    var message = List[UInt8](length=35, fill=0x7C)
    var cipher = process(BlockCipherAlgorithm.SHACAL2, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SHACAL2, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-shacal-2: ok")
```

<!-- algorithm: block-cipher/shark -->
<a id="block-cipher-shark"></a>
## SHARK

SHARK is a predecessor to Rijndael with a 64-bit block. It is a historical interoperability cipher, not a new-system choice. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SHARK` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-shark"></a>
<!-- runnable-example: block-cipher-shark -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x3D)
    var counter = List[UInt8](length=8, fill=0x5D)
    var message = List[UInt8](length=11, fill=0x7D)
    var cipher = process(BlockCipherAlgorithm.SHARK, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SHARK, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-shark: ok")
```

<!-- algorithm: block-cipher/simeck-32 -->
<a id="block-cipher-simeck-32"></a>
## SIMECK-32

SIMECK-32 has a 32-bit block and is unsuitable for ordinary bulk data. Use only in a tightly specified constrained protocol. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SIMECK32` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 4-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-simeck-32"></a>
<!-- runnable-example: block-cipher-simeck-32 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=8, fill=0x3E)
    var counter = List[UInt8](length=4, fill=0x5E)
    var message = List[UInt8](length=7, fill=0x7E)
    var cipher = process(BlockCipherAlgorithm.SIMECK32, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SIMECK32, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-simeck-32: ok")
```

<!-- algorithm: block-cipher/simeck-64 -->
<a id="block-cipher-simeck-64"></a>
## SIMECK-64

SIMECK-64 has a 64-bit block and should be limited to protocols that explicitly require this lightweight profile. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SIMECK64` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-simeck-64"></a>
<!-- runnable-example: block-cipher-simeck-64 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x3F)
    var counter = List[UInt8](length=8, fill=0x5F)
    var message = List[UInt8](length=11, fill=0x7F)
    var cipher = process(BlockCipherAlgorithm.SIMECK64, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SIMECK64, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-simeck-64: ok")
```

<!-- algorithm: block-cipher/simon-64 -->
<a id="block-cipher-simon-64"></a>
## SIMON-64

SIMON-64 has a 64-bit block. Match the protocol key profile and enforce conservative data-volume limits. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SIMON64` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-simon-64"></a>
<!-- runnable-example: block-cipher-simon-64 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x40)
    var counter = List[UInt8](length=8, fill=0x60)
    var message = List[UInt8](length=11, fill=0x80)
    var cipher = process(BlockCipherAlgorithm.SIMON64, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SIMON64, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-simon-64: ok")
```

<!-- algorithm: block-cipher/simon-128 -->
<a id="block-cipher-simon-128"></a>
## SIMON-128

SIMON-128 uses a 128-bit block and is distinct from SIMON-64. Select it only through an explicit algorithm identifier. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SIMON128` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-simon-128"></a>
<!-- runnable-example: block-cipher-simon-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x41)
    var counter = List[UInt8](length=16, fill=0x61)
    var message = List[UInt8](length=19, fill=0x81)
    var cipher = process(BlockCipherAlgorithm.SIMON128, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SIMON128, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-simon-128: ok")
```

<!-- algorithm: block-cipher/skipjack -->
<a id="block-cipher-skipjack"></a>
## Skipjack

Skipjack uses an 80-bit key and 64-bit block. Its security margin is obsolete; keep it only for legacy decoding. This algorithm is cryptographically obsolete.

Use `BlockCipherAlgorithm.SKIPJACK` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-skipjack"></a>
<!-- runnable-example: block-cipher-skipjack -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=10, fill=0x42)
    var counter = List[UInt8](length=8, fill=0x62)
    var message = List[UInt8](length=11, fill=0x82)
    var cipher = process(BlockCipherAlgorithm.SKIPJACK, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SKIPJACK, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-skipjack: ok")
```

<!-- algorithm: block-cipher/speck-64 -->
<a id="block-cipher-speck-64"></a>
## SPECK-64

SPECK-64 is the 64-bit-block profile. It is not compatible with SPECK-128 and should only follow an explicit specification. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SPECK64` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-speck-64"></a>
<!-- runnable-example: block-cipher-speck-64 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=12, fill=0x43)
    var counter = List[UInt8](length=8, fill=0x63)
    var message = List[UInt8](length=11, fill=0x83)
    var cipher = process(BlockCipherAlgorithm.SPECK64, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SPECK64, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-speck-64: ok")
```

<!-- algorithm: block-cipher/speck-128 -->
<a id="block-cipher-speck-128"></a>
## SPECK-128

SPECK-128 is the 128-bit-block profile. Treat its use as a compatibility decision rather than a default. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SPECK128` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-speck-128"></a>
<!-- runnable-example: block-cipher-speck-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x44)
    var counter = List[UInt8](length=16, fill=0x64)
    var message = List[UInt8](length=19, fill=0x84)
    var cipher = process(BlockCipherAlgorithm.SPECK128, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SPECK128, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-speck-128: ok")
```

<!-- algorithm: block-cipher/sm4 -->
<a id="block-cipher-sm4"></a>
## SM4

SM4 is a standardized 128-bit-block cipher with a 128-bit key. Use it when the surrounding protocol specifies SM4. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.SM4` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-sm4"></a>
<!-- runnable-example: block-cipher-sm4 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x45)
    var counter = List[UInt8](length=16, fill=0x65)
    var message = List[UInt8](length=19, fill=0x85)
    var cipher = process(BlockCipherAlgorithm.SM4, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SM4, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-sm4: ok")
```

<!-- algorithm: block-cipher/square -->
<a id="block-cipher-square"></a>
## Square

Square is a 128-bit-block predecessor to Rijndael. It is retained for historical formats, not new designs. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.SQUARE` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 16-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-square"></a>
<!-- runnable-example: block-cipher-square -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x46)
    var counter = List[UInt8](length=16, fill=0x66)
    var message = List[UInt8](length=19, fill=0x86)
    var cipher = process(BlockCipherAlgorithm.SQUARE, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.SQUARE, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-square: ok")
```

<!-- algorithm: block-cipher/tea -->
<a id="block-cipher-tea"></a>
## TEA

TEA has a 64-bit block and known related-key weaknesses. Use only for compatibility with an existing data format. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.TEA` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-tea"></a>
<!-- runnable-example: block-cipher-tea -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x47)
    var counter = List[UInt8](length=8, fill=0x67)
    var message = List[UInt8](length=11, fill=0x87)
    var cipher = process(BlockCipherAlgorithm.TEA, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.TEA, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-tea: ok")
```

<!-- algorithm: block-cipher/threefish-256 -->
<a id="block-cipher-threefish-256"></a>
## Threefish-256

Threefish-256 uses a 256-bit block, key, and tweakable design. The mode API supplies the tweak through its IV parameter. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.THREEFISH256` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 32-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-threefish-256"></a>
<!-- runnable-example: block-cipher-threefish-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=32, fill=0x48)
    var counter = List[UInt8](length=32, fill=0x68)
    var message = List[UInt8](length=35, fill=0x88)
    var cipher = process(BlockCipherAlgorithm.THREEFISH256, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.THREEFISH256, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-threefish-256: ok")
```

<!-- algorithm: block-cipher/threefish-512 -->
<a id="block-cipher-threefish-512"></a>
## Threefish-512

Threefish-512 uses a 512-bit block and key. Its wide block makes ciphertext incompatible with other Threefish sizes. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.THREEFISH512` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 64-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-threefish-512"></a>
<!-- runnable-example: block-cipher-threefish-512 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=64, fill=0x49)
    var counter = List[UInt8](length=64, fill=0x69)
    var message = List[UInt8](length=67, fill=0x89)
    var cipher = process(BlockCipherAlgorithm.THREEFISH512, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.THREEFISH512, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-threefish-512: ok")
```

<!-- algorithm: block-cipher/threefish-1024 -->
<a id="block-cipher-threefish-1024"></a>
## Threefish-1024

Threefish-1024 uses a 1024-bit block and key. Allocate mode buffers from this 128-byte block size. The block cipher still requires a secure mode and independent authentication unless an AEAD wraps it.

Use `BlockCipherAlgorithm.THREEFISH1024` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 128-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-threefish-1024"></a>
<!-- runnable-example: block-cipher-threefish-1024 -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=128, fill=0x4A)
    var counter = List[UInt8](length=128, fill=0x6A)
    var message = List[UInt8](length=131, fill=0x8A)
    var cipher = process(BlockCipherAlgorithm.THREEFISH1024, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.THREEFISH1024, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-threefish-1024: ok")
```

<!-- algorithm: block-cipher/xtea -->
<a id="block-cipher-xtea"></a>
## XTEA

XTEA is a TEA-family cipher with a 64-bit block and 128-bit key. It is a legacy compatibility option. Prefer a modern AEAD for new data.

Use `BlockCipherAlgorithm.XTEA` with `mcrypto.ciphers.dispatch.process`; the IV length for this example is the 8-byte block size. Never reuse a CTR counter with the same key.

<a id="example-block-cipher-xtea"></a>
<!-- runnable-example: block-cipher-xtea -->
```mojo
from std.testing import assert_equal
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def main() raises:
    var key = List[UInt8](length=16, fill=0x4B)
    var counter = List[UInt8](length=8, fill=0x6B)
    var message = List[UInt8](length=11, fill=0x8B)
    var cipher = process(BlockCipherAlgorithm.XTEA, CipherMode.CTR, True, Span(key), Span(counter), Span(message))
    assert_equal(process(BlockCipherAlgorithm.XTEA, CipherMode.CTR, False, Span(key), Span(counter), Span(cipher)), message)
    print("block-cipher-xtea: ok")
```

