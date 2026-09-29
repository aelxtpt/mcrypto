---
title: Agreement, KX, and scalar multiplication
---

# Agreement, KX, and scalar multiplication

## What this family does

Agreement derives a shared secret from local private and peer public material. KX additionally derives directional session keys. Scalar multiplication exposes lower-level group operations.

## Safe selection and legacy warning

Use X25519 or a protocol-specified authenticated agreement. Bare agreement does not authenticate peer identity and is vulnerable to active substitution. DH2/MQV/HMQV/FHMQV, LUC, XTR, and legacy EC variants exist for compatibility.

## Public imports and signatures

```mojo
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.groups.algorithm import GroupFamily
from mcrypto.key_exchange.agreement import generate_keypair, agree
from mcrypto.key_exchange.kx import keypair, session_keys
from mcrypto.groups.scalar import scalar_mult, scalar_base

def generate_keypair(algorithm: AgreementAlgorithm, key_bits: Int = 2048) raises -> Tuple[List[UInt8], List[UInt8], List[UInt8]]
def agree[parameters_origin: Origin, private_origin: Origin, public_origin: Origin](algorithm: AgreementAlgorithm, parameters: Span[UInt8, parameters_origin], private_key: Span[UInt8, private_origin], peer_public_key: Span[UInt8, public_origin], shared_bytes: Int, client_role: Bool) raises -> List[UInt8]
def session_keys[public_origin: Origin, secret_origin: Origin, peer_origin: Origin](client: Bool, public_key: Span[UInt8, public_origin], secret_key: Span[UInt8, secret_origin], peer_public_key: Span[UInt8, peer_origin]) raises -> Tuple[List[UInt8], List[UInt8]]
```

## Inventory names and invocation spellings

Text boundaries map inventory labels to `AgreementAlgorithm`; application code passes constants such as `AgreementAlgorithm.DH`, `AgreementAlgorithm.HMQV`, `AgreementAlgorithm.ECDH_P256`, or `AgreementAlgorithm.X25519`. KX is fixed to X25519-BLAKE2b. Scalar APIs use `GroupFamily.X25519`, `GroupFamily.ED25519`, or `GroupFamily.RISTRETTO255`.

## Dimensions

X25519/KX keys are 32 bytes; KX returns two 32-byte session keys. `generate_keypair` frames sizes according to `info` and returns a 32-byte default shared size. Dual-key agreement families encode two private/public components. `shared_bytes` must be positive and algorithm-valid.

## Return and wire layout

Generic agreement returns `(private_key, public_key, parameters)`. `agree` consumes the same parameters and a `client_role` so dual/role-aware families agree on ordering. Direct KX keypair returns `(public_key, secret_key)`; `session_keys` returns `(receive_key, transmit_key)` in caller-role order.

## Executable examples

<a id="example-key-agreement"></a>
### Role-aware agreement
```mojo
from std.testing import assert_equal
from mcrypto.key_exchange.agreement import (
    info,
    generate_keypair,
    generate_peer,
    agree,
)
from mcrypto.key_exchange.algorithm import AgreementAlgorithm


def main() raises:
    var sizes = info(AgreementAlgorithm.X25519, 512)
    var alice = generate_keypair(AgreementAlgorithm.X25519, 512)
    var alice_private = alice[0].copy()
    var alice_public = alice[1].copy()
    var parameters = alice[2].copy()
    var bob = generate_peer(
        AgreementAlgorithm.X25519,
        Span(parameters),
        sizes[0],
        sizes[1],
        False,
    )
    var bob_private = bob[0].copy()
    var bob_public = bob[1].copy()
    var alice_shared = agree(
        AgreementAlgorithm.X25519,
        Span(parameters),
        Span(alice_private),
        Span(bob_public),
        sizes[2],
        True,
    )
    var bob_shared = agree(
        AgreementAlgorithm.X25519,
        Span(parameters),
        Span(bob_private),
        Span(alice_public),
        sizes[2],
        False,
    )
    assert_equal(alice_shared, bob_shared)
    print("key-agreement: ok")
```

<a id="example-kx-scalarmult"></a>
### KX and scalar multiplication
```mojo
from std.testing import assert_equal
from mcrypto.groups.algorithm import GroupFamily
from mcrypto.key_exchange.kx import keypair, session_keys
from mcrypto.groups.scalar import scalar_base


def main() raises:
    var alice = keypair()
    var alice_public = alice[0].copy()
    var alice_secret = alice[1].copy()
    var bob = keypair()
    var bob_public = bob[0].copy()
    var bob_secret = bob[1].copy()
    assert_equal(
        scalar_base(GroupFamily.X25519, Span(alice_secret)), alice_public
    )

    var client = session_keys(
        True, Span(alice_public), Span(alice_secret), Span(bob_public)
    )
    var server = session_keys(
        False, Span(bob_public), Span(bob_secret), Span(alice_public)
    )
    assert_equal(client[0], server[1])
    assert_equal(client[1], server[0])
    print("kx-scalarmult: ok")
```

## Authentication, errors, and state

Malformed frames, wrong roles, invalid points, low-order material, and size mismatch raise. Matching shared bytes do not authenticate the peer; bind the transcript and identities in a higher-level protocol.

## Prepared, into, and batch APIs

Prepared agreement generators reuse fixed-base tables. Scalar/core modules expose `*_eight` and `*_eight_into` forms for exactly eight lanes. Equal-width flat buffers and valid points remain required.

## Inventory and test evidence

See [`ECDH`](../reference/algorithms.md#key-agreement-ecdh), [`X25519-BLAKE2b`](../reference/algorithms.md#key-exchange-x25519-blake2b), and [`Ristretto255`](../reference/algorithms.md#group-ristretto255). Representative tests: `tests/test_key_exchange.mojo`, `tests/test_kx.mojo`, and `tests/test_group_core_batch_paths.mojo`.