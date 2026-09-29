---
title: KDFs and passwords
---

# KDFs and passwords

## What this family does

KDFs derive purpose-specific key material from secrets. Password hashing adds deliberately expensive work to low-entropy passwords.

## Safe selection and legacy warning

Use HKDF after a high-entropy shared secret. Use the high-level Argon2id wrapper for stored passwords or password-derived keys. PBKDF1, PKCS#12 PBKDF, Argon2i, and legacy scrypt profiles exist for protocol compatibility. Tiny costs in vector tests are fixtures, never deployment recommendations.

## Public imports and signatures

```mojo
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive
from mcrypto.passwords.argon2id import derive as derive_password

def derive[secret_origin: Origin, salt_origin: Origin, info_origin: Origin](algorithm: KdfAlgorithm, secret: Span[UInt8, secret_origin], salt: Span[UInt8, salt_origin], info: Span[UInt8, info_origin], output_bytes: Int, iterations: Int = 1, purpose: UInt8 = 0, cost: UInt64 = 16, block_size: UInt64 = 1, parallelization: UInt64 = 1) raises -> List[UInt8]
def derive_password[password_origin: Origin, salt_origin: Origin](password: Span[UInt8, password_origin], salt: Span[UInt8, salt_origin], output_bytes: Int = 32, operations: UInt64 = 2, memory_bytes: Int = 67108864) raises -> List[UInt8]
```

## Inventory names and invocation spellings

Text boundaries map inventory labels to `KdfAlgorithm`. Application code passes constants such as `KdfAlgorithm.HKDF_SHA256`, `KdfAlgorithm.PBKDF2_HMAC_SHA256`, `KdfAlgorithm.SCRYPT`, or `KdfAlgorithm.ARGON2ID`; the catalog-only `HKDF` umbrella is not an algorithm constant.

## Dimensions

The dispatcher requires a positive algorithm-valid output length. HKDF limits expansion according to its digest. The high-level Argon2id wrapper requires exactly a 16-byte salt, at least 16 output bytes, at least one operation, and at least 8 KiB; defaults are 32 bytes, 2 operations, and 64 MiB with one lane.

## Return and wire layout

All calls return raw derived bytes only. They do not encode parameters, salt, algorithm identifier, or version. Store those parameters in protocol framing. Equal password, salt, and parameters deterministically produce equal output.

## Executable examples

<a id="example-kdf"></a>
### HKDF and dispatcher models
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive


def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List("documented salt".as_bytes())
    var info = List("mcrypto docs example".as_bytes())
    var first = derive(
        KdfAlgorithm.HKDF_SHA256,
        Span(secret),
        Span(salt),
        Span(info),
        32,
    )
    var second = derive(
        KdfAlgorithm.HKDF_SHA256,
        Span(secret),
        Span(salt),
        Span(info),
        32,
    )
    assert_equal(first, second)
    assert_equal(len(first), 32)
    info[0] ^= 1
    var separated = derive(
        KdfAlgorithm.HKDF_SHA256,
        Span(secret),
        Span(salt),
        Span(info),
        32,
    )
    assert_true(separated != first)
    print("kdf: ok")
```

<a id="example-password-hashing"></a>
### High-level Argon2id
```mojo
from std.testing import assert_equal
from mcrypto.passwords.argon2id import derive


def main() raises:
    var password = List("correct horse battery staple".as_bytes())
    var salt = List[UInt8](length=16, fill=0)
    for i in range(len(salt)):
        salt[i] = UInt8(i + 1)
    # Uses the high-level defaults: 2 operations, 64 MiB, one lane, 32 bytes.
    var derived = derive(Span(password), Span(salt))
    assert_equal(len(derived), 32)
    print("password-hashing: ok")
```

## Authentication, errors, and state

A KDF does not verify a password by itself; recompute with stored parameters and compare safely. Invalid costs, salt sizes, output lengths, or names raise. Never silently downgrade cost after an allocation or latency failure.

## Prepared, into, and batch APIs

BLAKE2b-KDF exposes `PreparedBLAKE2bKDF` and `derive_into`; other calls return owned lists. Password KDFs are intentionally not described as a low-cost batch shortcut.

## Inventory and test evidence

See [`HKDF`](../reference/algorithms.md#kdf-hkdf), [`Argon2id`](../reference/algorithms.md#password-hash-argon2id), and [`Scrypt-Salsa20-8-SHA256`](../reference/algorithms.md#password-hash-scrypt-salsa20-8-sha256). Representative tests: `tests/test_kdf_dispatch.mojo`, `tests/test_argon2.mojo`, and `tests/test_scrypt.mojo`.