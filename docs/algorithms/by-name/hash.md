---
title: Hash algorithms
---

# Hash algorithms

A fixed-output hash maps bytes to a digest of a defined size. It does not hide low-entropy inputs or authenticate without a keyed construction. Match established protocols exactly; for new general hashing, prefer SHA-256, SHA-512, SHA3-256, or BLAKE2.

<!-- algorithm: hash/adler32 -->
<a id="hash-adler32"></a>
## Adler32

Adler32 is a 32-bit error-detecting checksum, not a cryptographic hash. Use it for accidental-corruption checks where compatibility requires it. Never use it for signatures, passwords, adversarial integrity, or content identity.

<a id="example-hash-adler32"></a>
<!-- runnable-example: hash-adler32 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.ADLER32, "payload")
    assert_equal(len(digest), 4)
    print("hash-adler32: ok")
```

<!-- algorithm: hash/crc32 -->
<a id="hash-crc32"></a>
## CRC32

CRC32 is a 32-bit cyclic redundancy check for transmission errors. Its polynomial and byte conventions must match the file or wire format. It is linear and forgeable, so it is not an authenticator.

<a id="example-hash-crc32"></a>
<!-- runnable-example: hash-crc32 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.CRC32, "record")
    assert_equal(len(digest), 4)
    print("hash-crc32: ok")
```

<!-- algorithm: hash/crc32c -->
<a id="hash-crc32c"></a>
## CRC32C

CRC32C uses a polynomial different from CRC32. Select it only when the format names CRC32C; the results are not interchangeable. It detects accidental errors but provides no protection against an attacker.

<a id="example-hash-crc32c"></a>
<!-- runnable-example: hash-crc32c -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.CRC32C, "record")
    assert_equal(len(digest), 4)
    print("hash-crc32c: ok")
```

<!-- algorithm: hash/md2 -->
<a id="hash-md2"></a>
## MD2

MD2 produces 16 bytes and remains only for compatibility with old formats. Its collision resistance is broken and its design is obsolete. Do not use it for new signatures, certificates, integrity checks, or identifiers.

<a id="example-hash-md2"></a>
<!-- runnable-example: hash-md2 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.MD2, "legacy")
    assert_equal(len(digest), 16)
    print("hash-md2: ok")
```

<!-- algorithm: hash/md4 -->
<a id="hash-md4"></a>
## MD4

MD4 produces 16 bytes and has practical collision attacks. It exists to reproduce legacy data, not as a security primitive. A matching MD4 digest is a compatibility fact, never proof of integrity.

<a id="example-hash-md4"></a>
<!-- runnable-example: hash-md4 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.MD4, "legacy")
    assert_equal(len(digest), 16)
    print("hash-md4: ok")
```

<!-- algorithm: hash/md5 -->
<a id="hash-md5"></a>
## MD5

MD5 produces 16 bytes and is collision-broken. It may identify accidental corruption in a non-adversarial legacy workflow, but it must not protect signatures, downloads, certificates, or chosen content. Prefer a modern hash for every new format.

<a id="example-hash-md5"></a>
<!-- runnable-example: hash-md5 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.MD5, "legacy")
    assert_equal(len(digest), 16)
    print("hash-md5: ok")
```

<!-- algorithm: hash/blake2s -->
<a id="hash-blake2s"></a>
## BLAKE2s

BLAKE2s is optimized for 32-bit platforms; the dispatcher returns its full 32-byte digest. It suits general hashing. Use the MAC interface for keyed authentication and a password-hashing API for credentials.

<a id="example-hash-blake2s"></a>
<!-- runnable-example: hash-blake2s -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.BLAKE2S, "payload")
    assert_equal(len(digest), 32)
    print("hash-blake2s: ok")
```

<!-- algorithm: hash/blake2b -->
<a id="hash-blake2b"></a>
## BLAKE2b

BLAKE2b is optimized for 64-bit platforms; the dispatcher returns 64 bytes. It is a strong general-purpose hash for content identifiers and transcript hashing. Use an explicit MAC or KDF when a secret key is involved.

<a id="example-hash-blake2b"></a>
<!-- runnable-example: hash-blake2b -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.BLAKE2B, "payload")
    assert_equal(len(digest), 64)
    print("hash-blake2b: ok")
```

<!-- algorithm: hash/keccak-224 -->
<a id="hash-keccak-224"></a>
## Keccak-224

Keccak-224 is the 224-bit original Keccak padding variant. It is not byte-compatible with SHA3-224 although both use the same permutation and output size. Select it only when the protocol says Keccak.

<a id="example-hash-keccak-224"></a>
<!-- runnable-example: hash-keccak-224 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.KECCAK224, "message")
    assert_equal(len(digest), 28)
    print("hash-keccak-224: ok")
```

<!-- algorithm: hash/keccak-256 -->
<a id="hash-keccak-256"></a>
## Keccak-256

Keccak-256 returns 32 bytes using original Keccak domain padding. It differs from SHA3-256 and their digests must not be substituted. Use it for protocols that explicitly name Keccak-256.

<a id="example-hash-keccak-256"></a>
<!-- runnable-example: hash-keccak-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.KECCAK256, "message")
    assert_equal(len(digest), 32)
    print("hash-keccak-256: ok")
```

<!-- algorithm: hash/keccak-384 -->
<a id="hash-keccak-384"></a>
## Keccak-384

Keccak-384 returns 48 bytes with original Keccak padding. It is a compatibility choice for protocols naming this exact variant. Use SHA3-384 when the protocol names SHA-3.

<a id="example-hash-keccak-384"></a>
<!-- runnable-example: hash-keccak-384 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.KECCAK384, "message")
    assert_equal(len(digest), 48)
    print("hash-keccak-384: ok")
```

<!-- algorithm: hash/keccak-512 -->
<a id="hash-keccak-512"></a>
## Keccak-512

Keccak-512 returns 64 bytes with original Keccak padding rather than SHA-3 domain separation. Its output is distinct from SHA3-512. Match the selector to the serialized protocol identifier.

<a id="example-hash-keccak-512"></a>
<!-- runnable-example: hash-keccak-512 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.KECCAK512, "message")
    assert_equal(len(digest), 64)
    print("hash-keccak-512: ok")
```

<!-- algorithm: hash/lsh-224 -->
<a id="hash-lsh-224"></a>
## LSH-224

LSH-224 returns 28 bytes from the 32-bit LSH family. Use it where an interoperable format requires this exact output. For new protocols, prefer an algorithm already supported across all participants.

<a id="example-hash-lsh-224"></a>
<!-- runnable-example: hash-lsh-224 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.LSH224, "message")
    assert_equal(len(digest), 28)
    print("hash-lsh-224: ok")
```

<!-- algorithm: hash/lsh-256 -->
<a id="hash-lsh-256"></a>
## LSH-256

LSH-256 is the 32-byte output of the 32-bit LSH family. Use it for protocols that explicitly select LSH-256. Store or negotiate the algorithm identifier because digest length alone is ambiguous.

<a id="example-hash-lsh-256"></a>
<!-- runnable-example: hash-lsh-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.LSH256, "message")
    assert_equal(len(digest), 32)
    print("hash-lsh-256: ok")
```

<!-- algorithm: hash/lsh-384 -->
<a id="hash-lsh-384"></a>
## LSH-384

LSH-384 returns 48 bytes from the 64-bit LSH family. It has its own selector and is not a truncation request for LSH-512. Keep the algorithm identity in protocol metadata.

<a id="example-hash-lsh-384"></a>
<!-- runnable-example: hash-lsh-384 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.LSH384, "message")
    assert_equal(len(digest), 48)
    print("hash-lsh-384: ok")
```

<!-- algorithm: hash/lsh-512 -->
<a id="hash-lsh-512"></a>
## LSH-512

LSH-512 is the 64-byte output of the 64-bit LSH family. It is not interchangeable with SHA-512 or SHA3-512. Use it only when both sides explicitly agree on LSH-512.

<a id="example-hash-lsh-512"></a>
<!-- runnable-example: hash-lsh-512 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.LSH512, "message")
    assert_equal(len(digest), 64)
    print("hash-lsh-512: ok")
```

<!-- algorithm: hash/lsh-512-256 -->
<a id="hash-lsh-512-256"></a>
## LSH-512-256

LSH-512-256 uses the 64-bit LSH family but returns 32 bytes. It is a distinct parameter set, not the first half of an LSH-512 digest. Use the dedicated selector whenever the protocol names it.

<a id="example-hash-lsh-512-256"></a>
<!-- runnable-example: hash-lsh-512-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.LSH512_256, "message")
    assert_equal(len(digest), 32)
    print("hash-lsh-512-256: ok")
```

<!-- algorithm: hash/panamahash -->
<a id="hash-panamahash"></a>
## PanamaHash

PanamaHash is the 32-byte hash mode of the Panama construction. It is retained for format compatibility and should not be chosen for new designs. Do not confuse it with the Panama stream cipher.

<a id="example-hash-panamahash"></a>
<!-- runnable-example: hash-panamahash -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.PANAMA_HASH, "legacy")
    assert_equal(len(digest), 32)
    print("hash-panamahash: ok")
```

<!-- algorithm: hash/ripemd-128 -->
<a id="hash-ripemd-128"></a>
## RIPEMD-128

RIPEMD-128 returns 16 bytes and has a limited collision-security margin. Use it only to reproduce an existing format. Do not introduce it for signatures or adversarial content identity.

<a id="example-hash-ripemd-128"></a>
<!-- runnable-example: hash-ripemd-128 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.RIPEMD128, "legacy")
    assert_equal(len(digest), 16)
    print("hash-ripemd-128: ok")
```

<!-- algorithm: hash/ripemd-160 -->
<a id="hash-ripemd-160"></a>
## RIPEMD-160

RIPEMD-160 returns 20 bytes and remains in established formats. Its 80-bit collision bound is below modern targets, so avoid it for new designs. It is not interchangeable with SHA-1 despite the same output length.

<a id="example-hash-ripemd-160"></a>
<!-- runnable-example: hash-ripemd-160 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.RIPEMD160, "record")
    assert_equal(len(digest), 20)
    print("hash-ripemd-160: ok")
```

<!-- algorithm: hash/ripemd-256 -->
<a id="hash-ripemd-256"></a>
## RIPEMD-256

RIPEMD-256 returns 32 bytes but is not a substitute for SHA-256. Use it only where a protocol identifies RIPEMD-256. The common output length does not imply a common construction or security analysis.

<a id="example-hash-ripemd-256"></a>
<!-- runnable-example: hash-ripemd-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.RIPEMD256, "record")
    assert_equal(len(digest), 32)
    print("hash-ripemd-256: ok")
```

<!-- algorithm: hash/ripemd-320 -->
<a id="hash-ripemd-320"></a>
## RIPEMD-320

RIPEMD-320 returns 40 bytes and is a distinct member of the RIPEMD family. It is mainly an interoperability option. Use an explicit identifier because no RIPEMD variant can be inferred from a name prefix alone.

<a id="example-hash-ripemd-320"></a>
<!-- runnable-example: hash-ripemd-320 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.RIPEMD320, "record")
    assert_equal(len(digest), 40)
    print("hash-ripemd-320: ok")
```

<!-- algorithm: hash/sha-1 -->
<a id="hash-sha-1"></a>
## SHA-1

SHA-1 returns 20 bytes and has practical collision attacks. It remains only for old protocols that fix SHA-1. Never select it for new signatures, certificates, or content-addressed storage.

<a id="example-hash-sha-1"></a>
<!-- runnable-example: hash-sha-1 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA1, "legacy")
    assert_equal(len(digest), 20)
    print("hash-sha-1: ok")
```

<!-- algorithm: hash/sha-224 -->
<a id="hash-sha-224"></a>
## SHA-224

SHA-224 is the 28-byte SHA-2 member. Its shorter digest fits protocols with a 224-bit field. For general new work, SHA-256 usually provides wider support and a larger collision bound at little extra cost.

<a id="example-hash-sha-224"></a>
<!-- runnable-example: hash-sha-224 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA224, "payload")
    assert_equal(len(digest), 28)
    print("hash-sha-224: ok")
```

<!-- algorithm: hash/sha-256 -->
<a id="hash-sha-256"></a>
## SHA-256

SHA-256 is a widely interoperable 32-byte SHA-2 digest and a sound default for general hashing. It is not a password hash and does not authenticate by itself. Use HMAC-SHA256 for keyed authentication.

<a id="example-hash-sha-256"></a>
<!-- runnable-example: hash-sha-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA256, "payload")
    assert_equal(len(digest), 32)
    print("hash-sha-256: ok")
```

<!-- algorithm: hash/sha-384 -->
<a id="hash-sha-384"></a>
## SHA-384

SHA-384 returns 48 bytes from the SHA-512 internal family. It suits profiles requiring a 384-bit digest. It is not the same as naively truncating SHA-512 because it uses distinct initialization constants.

<a id="example-hash-sha-384"></a>
<!-- runnable-example: hash-sha-384 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA384, "payload")
    assert_equal(len(digest), 48)
    print("hash-sha-384: ok")
```

<!-- algorithm: hash/sha-512 -->
<a id="hash-sha-512"></a>
## SHA-512

SHA-512 returns 64 bytes and is efficient on 64-bit processors. It is a strong general-purpose digest when the larger output is acceptable. Use HMAC when authenticity rather than only hashing is required.

<a id="example-hash-sha-512"></a>
<!-- runnable-example: hash-sha-512 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA512, "payload")
    assert_equal(len(digest), 64)
    print("hash-sha-512: ok")
```

<!-- algorithm: hash/sha3-224 -->
<a id="hash-sha3-224"></a>
## SHA3-224

SHA3-224 is the 28-byte standardized SHA-3 digest. Its domain padding differs from Keccak-224. Use it when a 224-bit SHA-3 result is an explicit protocol parameter.

<a id="example-hash-sha3-224"></a>
<!-- runnable-example: hash-sha3-224 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA3_224, "payload")
    assert_equal(len(digest), 28)
    print("hash-sha3-224: ok")
```

<!-- algorithm: hash/sha3-256 -->
<a id="hash-sha3-256"></a>
## SHA3-256

SHA3-256 returns 32 bytes from a sponge construction and is a strong general-purpose digest. It is not byte-compatible with Keccak-256 or SHA-256. Store the algorithm identifier with persisted digests.

<a id="example-hash-sha3-256"></a>
<!-- runnable-example: hash-sha3-256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA3_256, "payload")
    assert_equal(len(digest), 32)
    print("hash-sha3-256: ok")
```

<!-- algorithm: hash/sha3-384 -->
<a id="hash-sha3-384"></a>
## SHA3-384

SHA3-384 returns 48 bytes and uses SHA-3 domain separation. Choose it when the protocol specifies SHA3-384. It is not a wire-compatible replacement for SHA-384.

<a id="example-hash-sha3-384"></a>
<!-- runnable-example: hash-sha3-384 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA3_384, "payload")
    assert_equal(len(digest), 48)
    print("hash-sha3-384: ok")
```

<!-- algorithm: hash/sha3-512 -->
<a id="hash-sha3-512"></a>
## SHA3-512

SHA3-512 is the 64-byte standardized SHA-3 digest. It gives the largest fixed SHA-3 output in mcrypto. Do not confuse it with Keccak-512, whose padding produces different digests.

<a id="example-hash-sha3-512"></a>
<!-- runnable-example: hash-sha3-512 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SHA3_512, "payload")
    assert_equal(len(digest), 64)
    print("hash-sha3-512: ok")
```

<!-- algorithm: hash/sm3 -->
<a id="hash-sm3"></a>
## SM3

SM3 returns 32 bytes and is used by protocols that standardize the SM family. Select it for interoperability with those protocols. Output length does not make it interchangeable with SHA-256 or BLAKE2s.

<a id="example-hash-sm3"></a>
<!-- runnable-example: hash-sm3 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.SM3, "payload")
    assert_equal(len(digest), 32)
    print("hash-sm3: ok")
```

<!-- algorithm: hash/tiger -->
<a id="hash-tiger"></a>
## Tiger

Tiger returns 24 bytes and was designed for 64-bit software. It is now mainly a legacy interoperability algorithm. Do not choose it for a new signature or content-addressing format.

<a id="example-hash-tiger"></a>
<!-- runnable-example: hash-tiger -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.TIGER, "legacy")
    assert_equal(len(digest), 24)
    print("hash-tiger: ok")
```

<!-- algorithm: hash/whirlpool -->
<a id="hash-whirlpool"></a>
## Whirlpool

Whirlpool returns 64 bytes from a wide block-cipher-style permutation. It is an interoperability option rather than a default. Its output is not compatible with SHA-512, SHA3-512, or BLAKE2b.

<a id="example-hash-whirlpool"></a>
<!-- runnable-example: hash-whirlpool -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash

def main() raises:
    var digest = hash(HashAlgorithm.WHIRLPOOL, "payload")
    assert_equal(len(digest), 64)
    print("hash-whirlpool: ok")
```
