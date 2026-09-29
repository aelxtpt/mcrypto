---
title: Cryptographic utilities
---

# Cryptographic utilities

These APIs handle byte comparison, secret storage, and system randomness. They support complete protocols but do not replace algorithm-specific nonce, key-separation, or lifecycle rules.

<!-- algorithm: utility/constant-time-verify -->
<a id="utility-constant-time-verify"></a>
## Constant-time byte comparison

`constant_time_equal` compares equal-length byte strings without data-dependent early exits. A length mismatch returns false; protocol framing may still reveal public lengths.

<a id="example-utility-constant-time-verify"></a>
<!-- runnable-example: utility-constant-time-verify -->
```mojo
from std.testing import assert_false, assert_true
from mcrypto.traits import constant_time_equal

def main() raises:
    var expected: List[UInt8] = [1, 2, 3, 4]
    var same: List[UInt8] = [1, 2, 3, 4]
    var different: List[UInt8] = [1, 2, 3, 5]
    assert_true(constant_time_equal(Span(expected), Span(same)))
    assert_false(constant_time_equal(Span(expected), Span(different)))
    print("utility-constant-time-verify: ok")
```

<!-- algorithm: utility/secure-memory -->
<a id="utility-secure-memory"></a>
## Locked secret memory

`LockedSecretBytes` page-locks its owned allocation, wipes it before release, and reports locking failures instead of silently degrading. `expose_copy` intentionally creates ordinary pageable memory, so keep such copies short-lived.

<a id="example-utility-secure-memory"></a>
<!-- runnable-example: utility-secure-memory -->
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.secure_memory import LockedSecretBytes, page_locking_available

def main() raises:
    assert_true(page_locking_available())
    var input: List[UInt8] = [5, 6, 7, 8]
    var secret = LockedSecretBytes(Span(input))
    assert_equal(secret.expose_copy(), input)
    secret.clear()
    assert_equal(secret.expose_copy(), List[UInt8](length=4, fill=0))
    print("utility-secure-memory: ok")
```

<!-- algorithm: utility/system-csprng -->
<a id="utility-system-csprng"></a>
## System CSPRNG

`random_bytes` obtains positive-length output from the operating-system entropy interface. Use it for keys, nonces that may be random, and seeds; do not substitute a deterministic documentation value in production.

<a id="example-utility-system-csprng"></a>
<!-- runnable-example: utility-system-csprng -->
```mojo
from std.testing import assert_equal
from mcrypto.random.generator import random_bytes

def main() raises:
    var output = random_bytes(32)
    assert_equal(len(output), 32)
    print("utility-system-csprng: ok")
```
