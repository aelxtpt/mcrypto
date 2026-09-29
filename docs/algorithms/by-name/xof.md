---
title: Extendable-output functions
---

# Extendable-output functions

An XOF accepts a message and an explicit positive output length. The same input with different requested lengths produces related prefixes, so the length is part of the protocol contract. XOF output is not a MAC and does not safely hash passwords.

<!-- algorithm: xof/shake128 -->
<a id="xof-shake128"></a>
## SHAKE128

SHAKE128 provides flexible-length output with a 128-bit generic security target. Use it for domain-separated hashing, deterministic expansion, or protocols that name SHAKE128. Fix and validate the output length at the protocol boundary instead of accepting an attacker-controlled allocation.

<a id="example-xof-shake128"></a>
<!-- runnable-example: xof-shake128 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes.xof import xof
from mcrypto.hashes.xof_algorithm import XofAlgorithm

def main() raises:
    var message = "context".as_bytes()
    var output = xof(XofAlgorithm.SHAKE128, message, 32)
    assert_equal(len(output), 32)
    print("xof-shake128: ok")
```

<!-- algorithm: xof/shake256 -->
<a id="xof-shake256"></a>
## SHAKE256

SHAKE256 raises the generic security target while retaining arbitrary output length. It is appropriate for wide derived values and protocols that explicitly select SHAKE256. Add a unique domain tag when one application uses it for several independent purposes.

<a id="example-xof-shake256"></a>
<!-- runnable-example: xof-shake256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes.xof import xof
from mcrypto.hashes.xof_algorithm import XofAlgorithm

def main() raises:
    var message = "signature transcript".as_bytes()
    var output = xof(XofAlgorithm.SHAKE256, message, 64)
    assert_equal(len(output), 64)
    print("xof-shake256: ok")
```

<!-- algorithm: xof/turboshake128 -->
<a id="xof-turboshake128"></a>
## TurboSHAKE128

TurboSHAKE128 uses fewer permutation rounds than SHAKE128 for higher throughput. It is a distinct algorithm and does not produce SHAKE128 output. Select it only when the protocol names TurboSHAKE128 and preserve explicit domain separation.

<a id="example-xof-turboshake128"></a>
<!-- runnable-example: xof-turboshake128 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes.turboshake import turboshake128

def main() raises:
    var message = "tree leaf".as_bytes()
    var output = turboshake128(message, 32)
    assert_equal(len(output), 32)
    print("xof-turboshake128: ok")
```

<!-- algorithm: xof/turboshake256 -->
<a id="xof-turboshake256"></a>
## TurboSHAKE256

TurboSHAKE256 is the wider-capacity TurboSHAKE variant. It trades the full-round SHAKE margin for throughput and has its own protocol identity. Choose output length and domain bytes as fixed application parameters.

<a id="example-xof-turboshake256"></a>
<!-- runnable-example: xof-turboshake256 -->
```mojo
from std.testing import assert_equal
from mcrypto.hashes.turboshake import turboshake256

def main() raises:
    var message = "tree root".as_bytes()
    var output = turboshake256(message, 64)
    assert_equal(len(output), 64)
    print("xof-turboshake256: ok")
```
