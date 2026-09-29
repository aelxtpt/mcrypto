---
title: Randomness
---

# Randomness

## What this family does

The runtime CSPRNG obtains operating-system entropy. DRBG helpers deterministically expand explicit entropy, nonce, personalization, and additional input. Legacy RNG types exist only for narrow interoperability.

## Safe selection and legacy warning

Use `random_bytes` for keys and nonces unless a protocol requires a specific DRBG. Do not treat deterministic DRBG test entropy as production entropy. ANSI X9.17 and RandomPool are compatibility APIs. RDRAND and RDSEED are x86-only hardware routes.

## Public imports and signatures

```mojo
from mcrypto.random.algorithm import DrbgAlgorithm
from mcrypto.random.generator import random_bytes, drbg

def random_bytes(output_bytes: Int) raises -> List[UInt8]
def drbg[entropy_origin: Origin, nonce_origin: Origin, personalization_origin: Origin, additional_origin: Origin](algorithm: DrbgAlgorithm, entropy: Span[UInt8, entropy_origin], nonce: Span[UInt8, nonce_origin], personalization: Span[UInt8, personalization_origin], additional: Span[UInt8, additional_origin], output_bytes: Int) raises -> List[UInt8]
```

Direct `hash_drbg` and `hmac_drbg` live in `mcrypto.random.drbg`; hardware `RDRAND`/`RDSEED` lives in `mcrypto.random.legacy.hardware_random`.

## Inventory names and invocation spellings

Application code passes `DrbgAlgorithm.HASH_SHA256`, `DrbgAlgorithm.HASH_SHA512`, `DrbgAlgorithm.HMAC_SHA256`, or `DrbgAlgorithm.HMAC_SHA512`. Catalog names map to those constants at the external-name boundary. Legacy RNG and hardware routes use their own typed selectors.

## Dimensions

`random_bytes` requires a positive length. `drbg` permits 1..65536 output bytes and validates the selected digest. Entropy, nonce, personalization, and additional input are separate byte strings; strength depends on supplied entropy. Hardware words are expanded to the requested length only after the carry/success flag passes.

## Return and wire layout

Calls return raw random bytes without metadata. A deterministic DRBG call is one-shot and does not expose a persisted reseed counter. Stateful `RandomPool` and `X917RNG` own mutable generator state.

## Executable examples

<a id="example-randomness-drbg"></a>
### OS entropy and deterministic DRBG

```mojo
from std.testing import assert_equal
from mcrypto.random.algorithm import DrbgAlgorithm
from mcrypto.random.generator import random_bytes, drbg


def main() raises:
    var generated = random_bytes(32)
    assert_equal(len(generated), 32)

    var entropy = List[UInt8](length=48, fill=0x91)
    var nonce = List[UInt8](length=16, fill=0xA2)
    var personalization = List("docs".as_bytes())
    var additional = List("request".as_bytes())
    var first = drbg(
        DrbgAlgorithm.HMAC_SHA256,
        Span(entropy),
        Span(nonce),
        Span(personalization),
        Span(additional),
        64,
    )
    var second = drbg(
        DrbgAlgorithm.HMAC_SHA256,
        Span(entropy),
        Span(nonce),
        Span(personalization),
        Span(additional),
        64,
    )
    assert_equal(first, second)
    print("randomness-drbg: ok")
```

## Authentication, errors, and state

Linux `getrandom` retries `EINTR`, accepts valid partial reads, and continues until the requested output is full. macOS `getentropy` uses chunks of at most 256 bytes and raises on any failed call. Other targets fail at compile time; there is no Windows backend. Never continue with zero bytes or deterministic fallback material after an entropy error.

## Prepared, into, and batch APIs

The ordinary public path returns owned bytes. `push_streams_eight` batches one OS-entropy request for eight secretstream headers, but remains an authenticated-stream API, not a generic random batch. Hardware-specific branches are never presented as portable fallbacks.

## Inventory and test evidence

See [`NIST Hash-DRBG`](../reference/algorithms.md#random-nist-hash-drbg), [`RDRAND`](../reference/algorithms.md#random-rdrand), and [`system CSPRNG`](../reference/algorithms.md#utility-system-csprng). Representative tests: `tests/test_kdf_random.mojo` and `tests/test_runtime_security_paths.mojo`.