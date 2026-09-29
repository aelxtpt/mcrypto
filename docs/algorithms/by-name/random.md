---
title: Random generators
---

# Random generators

A deterministic generator is only as strong as its entropy input and state handling. Use `mcrypto.random.entropy.system_entropy` or the system CSPRNG for ordinary key generation. The deterministic examples below prove the API shape; their fixed entropy, seed, and time-vector bytes are not production inputs.

<!-- algorithm: random/ansi-x9-17 -->
<a id="random-ansi-x9-17"></a>
## ANSI X9.17 / X9.31

`X917RNG` implements the older block-cipher generator with either 3DES or AES. It is provided for compatible systems. Protect and refresh its state, and prefer the operating-system CSPRNG in a new design.

<a id="example-random-ansi-x9-17"></a>
<!-- runnable-example: random-ansi-x9-17 -->
```mojo
from std.testing import assert_equal
from mcrypto.random.algorithm import X917Cipher
from mcrypto.random.legacy import X917RNG

def main() raises:
    var key = List[UInt8](length=16, fill=0x31)
    var seed = List[UInt8](length=16, fill=0x52)
    var time_vector = List[UInt8](length=16, fill=0x73)
    var generator = X917RNG(X917Cipher.AES, Span(key), Span(seed), Span(time_vector))
    assert_equal(len(generator.random_bytes(32)), 32)
    print("random-ansi-x9-17: ok")
```

<!-- algorithm: random/randompool -->
<a id="random-randompool"></a>
## RandomPool

`RandomPool` mixes seed material through SHA-256 and generates bytes with AES-256. It is a stateful compatibility generator, not a substitute for obtaining fresh system entropy at process startup.

<a id="example-random-randompool"></a>
<!-- runnable-example: random-randompool -->
```mojo
from std.testing import assert_equal
from mcrypto.random.legacy import RandomPool

def main() raises:
    var seed = List[UInt8](length=32, fill=0x42)
    var generator = RandomPool(Span(seed))
    assert_equal(len(generator.random_bytes(32)), 32)
    print("random-randompool: ok")
```

<!-- algorithm: random/nist-hash-drbg -->
<a id="random-nist-hash-drbg"></a>
## Hash_DRBG

Hash_DRBG expands entropy with SHA-256 or SHA-512. Entropy, nonce, personalization, and per-request additional input are separate inputs; preserve that separation in the surrounding protocol.

<a id="example-random-nist-hash-drbg"></a>
<!-- runnable-example: random-nist-hash-drbg -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.random.drbg import hash_drbg

def main() raises:
    var entropy = List[UInt8](length=32, fill=0x53)
    var nonce = List[UInt8](length=16, fill=0x74)
    var personalization = List("mcrypto docs".as_bytes())
    var additional = List[UInt8]()
    var output = hash_drbg(HashAlgorithm.SHA256, Span(entropy), Span(nonce), Span(personalization), Span(additional), 32)
    assert_equal(len(output), 32)
    print("random-nist-hash-drbg: ok")
```

<!-- algorithm: random/nist-hmac-drbg -->
<a id="random-nist-hmac-drbg"></a>
## HMAC_DRBG

HMAC_DRBG expands entropy through HMAC-SHA-256 or HMAC-SHA-512. Supply independent entropy and nonce inputs and reseed according to the lifecycle defined by the caller.

<a id="example-random-nist-hmac-drbg"></a>
<!-- runnable-example: random-nist-hmac-drbg -->
```mojo
from std.testing import assert_equal
from mcrypto.macs.algorithm import HmacAlgorithm
from mcrypto.random.drbg import hmac_drbg

def main() raises:
    var entropy = List[UInt8](length=32, fill=0x54)
    var nonce = List[UInt8](length=16, fill=0x75)
    var personalization = List("mcrypto docs".as_bytes())
    var additional = List[UInt8]()
    var output = hmac_drbg(HmacAlgorithm.SHA256, Span(entropy), Span(nonce), Span(personalization), Span(additional), 32)
    assert_equal(len(output), 32)
    print("random-nist-hmac-drbg: ok")
```

<!-- algorithm: random/rdrand -->
<a id="random-rdrand"></a>
## RDRAND

RDRAND reads the x86 hardware generator and checks its success flag. It is available only on supported x86 targets. Combine platform policy, feature evidence, and the application threat model before using it directly.

<a id="example-random-rdrand"></a>
<!-- runnable-example: random-rdrand -->
```mojo
from std.testing import assert_equal, assert_true
from std.sys import CompilationTarget
from mcrypto.random.algorithm import HardwareRandomAlgorithm
from mcrypto.random.legacy import hardware_random

def main() raises:
    comptime if CompilationTarget.is_x86():
        var output = hardware_random(HardwareRandomAlgorithm.RDRAND, 32)
        assert_equal(len(output), 32)
    else:
        assert_true(not CompilationTarget.is_x86())
    print("random-rdrand: ok")
```

<!-- algorithm: random/rdseed -->
<a id="random-rdseed"></a>
## RDSEED

RDSEED exposes the x86 seed-generation instruction and checks its success flag. It is target-specific and intended as seed material rather than an unexamined cross-platform default.

<a id="example-random-rdseed"></a>
<!-- runnable-example: random-rdseed -->
```mojo
from std.testing import assert_equal, assert_true
from std.sys import CompilationTarget
from mcrypto.random.algorithm import HardwareRandomAlgorithm
from mcrypto.random.legacy import hardware_random

def main() raises:
    comptime if CompilationTarget.is_x86():
        var output = hardware_random(HardwareRandomAlgorithm.RDSEED, 32)
        assert_equal(len(output), 32)
    else:
        assert_true(not CompilationTarget.is_x86())
    print("random-rdseed: ok")
```
