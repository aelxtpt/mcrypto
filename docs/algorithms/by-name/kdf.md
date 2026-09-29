---
title: KDFs
---

# Key-derivation functions

KDFs turn secret material into purpose-specific keys. They do not add entropy. Use a fresh salt where the construction expects one, encode protocol context in `info` or the dedicated context field, and never derive unrelated keys with an identical parameter tuple. The examples use small work factors for documentation runtime; production password work factors must be calibrated.

<!-- algorithm: kdf/pbkdf1 -->
<a id="kdf-pbkdf1"></a>
## PBKDF1

PBKDF1 is a legacy password derivation with a digest-sized output ceiling. Use it only when an existing format requires it; Argon2id or scrypt is appropriate for new password storage.

<a id="example-kdf-pbkdf1"></a>
<!-- runnable-example: kdf-pbkdf1 -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x51)
    var info = List[UInt8]()
    var output = derive(KdfAlgorithm.PBKDF1, Span(secret), Span(salt), Span(info), 16, iterations=1000)
    assert_equal(len(output), 16)
    print("kdf-pbkdf1: ok")
```

<!-- algorithm: kdf/pbkdf2 -->
<a id="kdf-pbkdf2"></a>
## PBKDF2

PBKDF2 repeatedly applies HMAC. Select the digest variant explicitly, store the salt and iteration count with the result, and calibrate iterations on deployment hardware.

<a id="example-kdf-pbkdf2"></a>
<!-- runnable-example: kdf-pbkdf2 -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x52)
    var info = List[UInt8]()
    var output = derive(KdfAlgorithm.PBKDF2_HMAC_SHA256, Span(secret), Span(salt), Span(info), 32, iterations=1000)
    assert_equal(len(output), 32)
    print("kdf-pbkdf2: ok")
```

<!-- algorithm: kdf/pkcs12-pbkdf -->
<a id="kdf-pkcs12-pbkdf"></a>
## PKCS#12 PBKDF

The PKCS#12 derivation supports legacy key, IV, and MAC material generation through a purpose byte. Use it only for PKCS#12 compatibility.

<a id="example-kdf-pkcs12-pbkdf"></a>
<!-- runnable-example: kdf-pkcs12-pbkdf -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x53)
    var info = List[UInt8]()
    var output = derive(KdfAlgorithm.PKCS12_PBKDF_SHA1, Span(secret), Span(salt), Span(info), 24, iterations=1000, purpose=UInt8(1))
    assert_equal(len(output), 24)
    print("kdf-pkcs12-pbkdf: ok")
```

<!-- algorithm: kdf/hkdf -->
<a id="kdf-hkdf"></a>
## HKDF

HKDF extracts and expands high-entropy input key material. Salt may be public; `info` binds the derived key to a protocol, role, and purpose.

<a id="example-kdf-hkdf"></a>
<!-- runnable-example: kdf-hkdf -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x54)
    var info = List("mcrypto docs/hkdf".as_bytes())
    var output = derive(KdfAlgorithm.HKDF_SHA256, Span(secret), Span(salt), Span(info), 32)
    assert_equal(len(output), 32)
    print("kdf-hkdf: ok")
```

<!-- algorithm: kdf/scrypt -->
<a id="kdf-scrypt"></a>
## scrypt

scrypt is a memory-hard password derivation. `cost` must be a power of two; choose cost, block size, and parallelization through deployment measurements.

<a id="example-kdf-scrypt"></a>
<!-- runnable-example: kdf-scrypt -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x55)
    var info = List[UInt8]()
    var output = derive(KdfAlgorithm.SCRYPT, Span(secret), Span(salt), Span(info), 32, cost=UInt64(16), block_size=UInt64(1), parallelization=UInt64(1))
    assert_equal(len(output), 32)
    print("kdf-scrypt: ok")
```

<!-- algorithm: kdf/blake2b-kdf -->
<a id="kdf-blake2b-kdf"></a>
## BLAKE2b KDF

The BLAKE2b KDF derives independently numbered subkeys from a 32-byte master key and an exact 8-byte context. Assign a stable context per protocol subsystem.

<a id="example-kdf-blake2b-kdf"></a>
<!-- runnable-example: kdf-blake2b-kdf -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.blake2b import derive

def main() raises:
    var context = List("doc-key1".as_bytes())
    var master_key = List[UInt8](length=32, fill=0x47)
    var subkey = derive(Span(context), Span(master_key), UInt64(1), 32)
    assert_equal(len(subkey), 32)
    print("kdf-blake2b-kdf: ok")
```

<!-- algorithm: kdf/hkdf-sha256 -->
<a id="kdf-hkdf-sha256"></a>
## HKDF-SHA-256

HKDF-SHA-256 is the usual HKDF choice. Give each output purpose a distinct `info` value and request only the key bytes the target primitive needs.

<a id="example-kdf-hkdf-sha256"></a>
<!-- runnable-example: kdf-hkdf-sha256 -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x57)
    var info = List("mcrypto docs/hkdf-sha256".as_bytes())
    var output = derive(KdfAlgorithm.HKDF_SHA256, Span(secret), Span(salt), Span(info), 32)
    assert_equal(len(output), 32)
    print("kdf-hkdf-sha256: ok")
```

<!-- algorithm: kdf/hkdf-sha512 -->
<a id="kdf-hkdf-sha512"></a>
## HKDF-SHA-512

HKDF-SHA-512 uses SHA-512 for extraction and expansion. Select it when the protocol specifies SHA-512 rather than as an automatic upgrade.

<a id="example-kdf-hkdf-sha512"></a>
<!-- runnable-example: kdf-hkdf-sha512 -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive

def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List[UInt8](length=16, fill=0x58)
    var info = List("mcrypto docs/hkdf-sha512".as_bytes())
    var output = derive(KdfAlgorithm.HKDF_SHA512, Span(secret), Span(salt), Span(info), 32)
    assert_equal(len(output), 32)
    print("kdf-hkdf-sha512: ok")
```

