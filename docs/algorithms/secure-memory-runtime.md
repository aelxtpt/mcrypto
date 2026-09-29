---
title: Secure memory and runtime
---

# Secure memory and runtime

## What this family does

Secure-memory helpers minimize secret lifetime, wipe buffers, and optionally lock pages. Runtime initialization and constant-time helpers support cryptographic call paths.

## Safe selection and legacy warning

Memory locking is a defense in depth, not proof that a secret never reached a register, copy, core dump, swap file, or log. Check availability and fail according to application policy. Never print keys, derived secrets, or unprotected copies.

## Public imports and signatures

```mojo
from mcrypto.secure_memory import (
    page_locking_available,
    LockedSecretBytes,
    SecretBytes,
    secure_zero,
)
from mcrypto.traits import constant_time_equal

def page_locking_available() -> Bool
def constant_time_equal[first_origin: Origin, second_origin: Origin](first: Span[UInt8, first_origin], second: Span[UInt8, second_origin]) -> Bool
```

`SecretBytes` owns wipe-on-destruction bytes. `LockedSecretBytes` exposes borrowed `span()`/`mut_span()`, `clear()`, and `expose_copy()`.

## Inventory names and invocation spellings

`secure-memory` and `constant-time-verify` are direct APIs. `system-CSPRNG` is documented under [randomness](randomness.md). Runtime helpers have no algorithm-name dispatcher.

## Dimensions

Secure buffers use caller-selected positive lengths. Constant-time equality accepts any two lengths and returns false on mismatch. Page locking is bounded by OS policy and process limits.

## Return and wire layout

Borrowed spans do not copy. `expose_copy()` deliberately returns an owned pageable `List[UInt8]`; its protection no longer matches locked storage. `secure_zero` mutates caller storage in place.

## Executable examples

<a id="example-secure-memory"></a>
### Wiping and optional page locking

```mojo
from std.testing import assert_equal
from mcrypto.secure_memory import (
    SecretBytes,
    LockedSecretBytes,
    page_locking_available,
    secure_zero,
)


def main() raises:
    var caller: List[UInt8] = [1, 2, 3, 4, 5]
    secure_zero(Span(caller)[1:4])
    var expected: List[UInt8] = [1, 0, 0, 0, 5]
    assert_equal(caller, expected)

    var input: List[UInt8] = [6, 7, 8, 9]
    var secret = SecretBytes(Span(input))
    secret.clear()
    assert_equal(secret.expose_copy(), List[UInt8](length=4, fill=0))

    if page_locking_available():
        var locked = LockedSecretBytes(Span(input))
        locked.clear()
        assert_equal(locked.expose_copy(), List[UInt8](length=4, fill=0))
    print("secure-memory: ok")
```

## Authentication, errors, and state

Lock construction can fail when page locking is unavailable or denied. The example guards it with `page_locking_available()`. Cleared or destroyed secret containers must not be reused as if they still held key material.

## Prepared, into, and batch APIs

Secure memory is caller-owned state rather than a batch primitive. Use mutable spans with `*_into` APIs to avoid extra owned outputs, then wipe complete buffers. Do not call `expose_copy()` merely to satisfy an avoidable API mismatch.

## Inventory and test evidence

See [`secure memory`](../reference/algorithms.md#utility-secure-memory) and [`constant-time verify`](../reference/algorithms.md#utility-constant-time-verify). Representative tests: `tests/test_runtime_security_paths.mojo` and `tests/test_traits.mojo`.