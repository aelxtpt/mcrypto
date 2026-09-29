---
title: Scalar multiplication groups
---

# Scalar multiplication groups

These are low-level group operations, not complete signatures or key exchanges. Point encoding, subgroup rules, scalar reduction, and domain separation belong to the protocol and must match the selected family.

<!-- algorithm: group/ed25519 -->
<a id="group-ed25519"></a>
## Ed25519 group

The Ed25519 group API exposes scalar multiplication and base-point multiplication on encoded Edwards points. Validate external points and keep signature-domain scalars separate.

<a id="example-group-ed25519"></a>
<!-- runnable-example: group-ed25519 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import GroupFamily
from mcrypto.groups.scalar import scalar_base, scalar_mult

def main() raises:
    var scalar = List[UInt8](length=32, fill=0)
    scalar[0] = 8
    var point = scalar_base(GroupFamily.ED25519, Span(scalar))
    assert_equal(len(point), 32)
    assert_equal(len(scalar_mult(GroupFamily.ED25519, Span(scalar), Span(point))), 32)
    print("group-ed25519: ok")
```

<!-- algorithm: group/ristretto255 -->
<a id="group-ristretto255"></a>
## Ristretto255 group

Ristretto255 gives a prime-order abstraction over the Edwards curve and rejects noncanonical encodings. It is suited to protocols that need complete group operations without a cofactor.

<a id="example-group-ristretto255"></a>
<!-- runnable-example: group-ristretto255 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import GroupFamily
from mcrypto.groups.scalar import scalar_base, scalar_mult

def main() raises:
    var scalar = List[UInt8](length=32, fill=0)
    scalar[0] = 8
    var point = scalar_base(GroupFamily.RISTRETTO255, Span(scalar))
    assert_equal(len(point), 32)
    assert_equal(len(scalar_mult(GroupFamily.RISTRETTO255, Span(scalar), Span(point))), 32)
    print("group-ristretto255: ok")
```

<!-- algorithm: group/x25519 -->
<a id="group-x25519"></a>
## X25519 group

The X25519 group path performs Montgomery scalar multiplication and base-point multiplication. Check protocol-level public-key validation and reject an all-zero agreement result.

<a id="example-group-x25519"></a>
<!-- runnable-example: group-x25519 -->
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import GroupFamily
from mcrypto.groups.scalar import scalar_base, scalar_mult

def main() raises:
    var scalar = List[UInt8](length=32, fill=0)
    scalar[0] = 8
    var point = scalar_base(GroupFamily.X25519, Span(scalar))
    assert_equal(len(point), 32)
    assert_equal(len(scalar_mult(GroupFamily.X25519, Span(scalar), Span(point))), 32)
    print("group-x25519: ok")
```

