---
title: Groups and core operations
---

# Groups and core operations

## What this family does

Group/scalar APIs expose X25519, Ed25519, and Ristretto255 operations. Core APIs expose HChaCha20, HSalsa20, Salsa rounds, and Keccak-f1600 permutations for protocol construction.

## Safe selection and legacy warning

These are low-level building blocks. Prefer box, KX, signature, hash, or AEAD front doors unless a protocol specifies exact point encodings, clamping, domain separation, and transcript rules.

## Public imports and signatures

```mojo
from mcrypto.groups.algorithm import CoreAlgorithm, GroupFamily
from mcrypto.groups.scalar import scalar_mult, scalar_base, core_operation

def scalar_mult[scalar_origin: Origin, point_origin: Origin](family: GroupFamily, scalar: Span[UInt8, scalar_origin], point: Span[UInt8, point_origin]) raises -> List[UInt8]
def core_operation[left_origin: Origin, right_origin: Origin](algorithm: CoreAlgorithm, left: Span[UInt8, left_origin], right: Span[UInt8, right_origin]) raises -> List[UInt8]
```

## Inventory names and invocation spellings

Application code uses `GroupFamily.X25519`, `GroupFamily.ED25519`, or `GroupFamily.RISTRETTO255`. Core selectors include `CoreAlgorithm.HCHACHA20`, `CoreAlgorithm.HSALSA20`, `CoreAlgorithm.KECCAK_F1600`, and the Salsa variants. Ed25519 group operations are distinct from Ed25519 signature dispatch.

## Dimensions

X25519, Ed25519, and Ristretto scalar/point encodings are 32 bytes. HChaCha/HSalsa use protocol-sized 32-byte keys and 16-byte inputs. Keccak-f1600 state is 200 bytes. Salsa core state/output is 64 bytes. Each operation validates its exact family dimensions.

## Return and wire layout

Calls return canonical raw point/scalar/core bytes for the chosen family. They do not attach a family identifier. Keep the family in protocol context and never reinterpret one group's bytes as another's.

## Executable examples

<a id="example-groups-core"></a>
### Scalar and core operations
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm, GroupFamily
from mcrypto.groups.scalar import scalar_base, scalar_mult, core_operation


def main() raises:
    var scalar = List[UInt8](length=32, fill=0x11)
    var basepoint = List[UInt8](length=32, fill=0)
    basepoint[0] = 9
    assert_equal(
        scalar_mult(GroupFamily.X25519, Span(scalar), Span(basepoint)),
        scalar_base(GroupFamily.X25519, Span(scalar)),
    )
    var key = List[UInt8](length=32, fill=0x22)
    var input = List[UInt8](length=16, fill=0x33)
    var core = core_operation(CoreAlgorithm.HCHACHA20, Span(key), Span(input))
    assert_equal(len(core), 32)
    print("groups-core: ok")
```

## Authentication, errors, and state

Malformed points, zero/low-order results where rejected, and wrong lengths raise. A successful scalar multiplication does not authenticate a peer or hash a transcript.

## Prepared, into, and batch APIs

`core_operation_eight`, `core_operation_eight_into`, and scalar batch helpers require exactly eight lanes and equal-width flattened buffers. `*_into` output must have the exact computed size.

## Inventory and test evidence

See [`Keccak-f1600`](../reference/algorithms.md#core-keccak-f1600), [`X25519`](../reference/algorithms.md#group-x25519), and [`Ristretto255`](../reference/algorithms.md#group-ristretto255). Representative tests: `tests/test_groups_ipcrypt_secretstream.mojo` and `tests/test_group_core_batch_paths.mojo`.