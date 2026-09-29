---
title: Password hashing
---

# Password hashing

Password hashes must be salted and deliberately expensive. The examples use minimum or very small work factors only so the documentation is runnable; do not copy those work factors into production. Calibrate on the deployment class, enforce resource ceilings, and store every parameter needed for verification.

<!-- algorithm: password-hash/argon2i -->
<a id="password-hash-argon2i"></a>
## Argon2i

Argon2i uses data-independent memory access. It is retained for protocols that require the i variant; Argon2id is the default choice for password hashing.

<a id="example-password-hash-argon2i"></a>
<!-- runnable-example: password-hash-argon2i -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.argon2 import argon2i

def main() raises:
    var password = List("correct horse battery staple".as_bytes())
    var salt = List[UInt8](length=16, fill=0x62)
    var output = argon2i(Span(password), Span(salt), 32, 1, 8, 1)
    assert_equal(len(output), 32)
    print("password-hash-argon2i: ok")
```

<!-- algorithm: password-hash/argon2id -->
<a id="password-hash-argon2id"></a>
## Argon2id

Argon2id combines data-independent and data-dependent passes and is the default password-hashing variant. Store its salt, operations, memory setting, and version beside the result.

<a id="example-password-hash-argon2id"></a>
<!-- runnable-example: password-hash-argon2id -->
```mojo
from std.testing import assert_equal
from mcrypto.passwords.argon2id import derive

def main() raises:
    var password = List("correct horse battery staple".as_bytes())
    var salt = List[UInt8](length=16, fill=0x63)
    var output = derive(Span(password), Span(salt), 32, UInt64(1), 8192)
    assert_equal(len(output), 32)
    print("password-hash-argon2id: ok")
```

<!-- algorithm: password-hash/scrypt-salsa20-8-sha256 -->
<a id="password-hash-scrypt-salsa20-8-sha256"></a>
## scrypt-Salsa20/8-SHA-256

scrypt uses Salsa20/8 mixing and PBKDF2-HMAC-SHA-256. Raise `cost`, block size, and parallelization after measuring memory and latency limits.

<a id="example-password-hash-scrypt-salsa20-8-sha256"></a>
<!-- runnable-example: password-hash-scrypt-salsa20-8-sha256 -->
```mojo
from std.testing import assert_equal
from mcrypto.kdf.scrypt import scrypt

def main() raises:
    var password = List("correct horse battery staple".as_bytes())
    var salt = List[UInt8](length=16, fill=0x64)
    var output = scrypt(Span(password), Span(salt), 32, 16, 1, 1)
    assert_equal(len(output), 32)
    print("password-hash-scrypt-salsa20-8-sha256: ok")
```

