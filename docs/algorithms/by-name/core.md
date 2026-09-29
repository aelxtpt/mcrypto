---
title: Permutation and stream cores
---

# Permutation and stream cores

Core operations expose low-level permutations and subkey functions. They do not supply nonces, framing, authentication, or sponge domain separation. Prefer the complete stream, AEAD, hash, or box API unless a specification requires the raw core.

<!-- algorithm: core/hchacha20 -->
<a id="core-hchacha20"></a>
## HChaCha20

HChaCha20 maps a 32-byte key and 16-byte input to a 32-byte subkey. It is a building block for XChaCha constructions, not an encryption function by itself.

<a id="example-core-hchacha20"></a>
<!-- runnable-example: core-hchacha20 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm
from mcrypto.groups.scalar import core_operation

def main() raises:
    var key = List[UInt8](length=32, fill=0x42)
    var input = List[UInt8](length=16, fill=0x63)
    var output = core_operation(CoreAlgorithm.HCHACHA20, Span(key), Span(input))
    assert_equal(len(output), 32)
    print("core-hchacha20: ok")
```

<!-- algorithm: core/hsalsa20 -->
<a id="core-hsalsa20"></a>
## HSalsa20

HSalsa20 maps a 32-byte key and 16-byte input to a 32-byte subkey. It is the subkey core used by XSalsa constructions.

<a id="example-core-hsalsa20"></a>
<!-- runnable-example: core-hsalsa20 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm
from mcrypto.groups.scalar import core_operation

def main() raises:
    var key = List[UInt8](length=32, fill=0x42)
    var input = List[UInt8](length=16, fill=0x63)
    var output = core_operation(CoreAlgorithm.HSALSA20, Span(key), Span(input))
    assert_equal(len(output), 32)
    print("core-hsalsa20: ok")
```

<!-- algorithm: core/keccak-f1600 -->
<a id="core-keccak-f1600"></a>
## Keccak-f1600

Keccak-f1600 permutes a complete 200-byte state. Sponge rate, capacity, padding, and domain bits are intentionally outside this raw operation.

<a id="example-core-keccak-f1600"></a>
<!-- runnable-example: core-keccak-f1600 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm
from mcrypto.groups.scalar import core_operation

def main() raises:
    var state = List[UInt8](length=200, fill=0x33)
    var empty = List[UInt8]()
    var output = core_operation(CoreAlgorithm.KECCAK_F1600, Span(state), Span(empty))
    assert_equal(len(output), 200)
    print("core-keccak-f1600: ok")
```

<!-- algorithm: core/salsa20 -->
<a id="core-salsa20"></a>
## Salsa20 core

The Salsa20 core applies 20 rounds to a key/input state and returns a 64-byte block. Use the stream-cipher API when encrypting messages.

<a id="example-core-salsa20"></a>
<!-- runnable-example: core-salsa20 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm
from mcrypto.groups.scalar import core_operation

def main() raises:
    var key = List[UInt8](length=32, fill=0x42)
    var input = List[UInt8](length=16, fill=0x63)
    var output = core_operation(CoreAlgorithm.SALSA20, Span(key), Span(input))
    assert_equal(len(output), 64)
    print("core-salsa20: ok")
```

<!-- algorithm: core/salsa20-12 -->
<a id="core-salsa20-12"></a>
## Salsa20/12 core

Salsa20/12 applies twelve rounds and returns a 64-byte core block. The reduced-round choice is a protocol-level algorithm selection.

<a id="example-core-salsa20-12"></a>
<!-- runnable-example: core-salsa20-12 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm
from mcrypto.groups.scalar import core_operation

def main() raises:
    var key = List[UInt8](length=32, fill=0x42)
    var input = List[UInt8](length=16, fill=0x63)
    var output = core_operation(CoreAlgorithm.SALSA20_12, Span(key), Span(input))
    assert_equal(len(output), 64)
    print("core-salsa20-12: ok")
```

<!-- algorithm: core/salsa20-8 -->
<a id="core-salsa20-8"></a>
## Salsa20/8 core

Salsa20/8 applies eight rounds and returns a 64-byte core block. It is commonly used as an internal mixing function rather than direct encryption.

<a id="example-core-salsa20-8"></a>
<!-- runnable-example: core-salsa20-8 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm
from mcrypto.groups.scalar import core_operation

def main() raises:
    var key = List[UInt8](length=32, fill=0x42)
    var input = List[UInt8](length=16, fill=0x63)
    var output = core_operation(CoreAlgorithm.SALSA20_8, Span(key), Span(input))
    assert_equal(len(output), 64)
    print("core-salsa20-8: ok")
```

