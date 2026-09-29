---
title: Prepared, into, and batch APIs
---

# Prepared, into, and batch APIs

## What this family does

Prepared objects amortize key schedules or fixed-base tables. `*_into` writes caller storage. CPU batches process fixed lane counts.

## Safe selection and legacy warning

Choose these APIs only after scalar semantics are correct. Reuse prepared secret state only within its algorithm/key lifetime, validate every offset and dimension, and preserve independent nonces per lane.

## Public imports and signatures

Representative public paths include `mcrypto.ciphers.aes_block.expand_key`, prepared cipher/MAC structs, and family `*_into` functions. Exact signatures differ by family and are indexed per catalog row.

## Inventory names and invocation spellings

Prepared/into/batch are execution forms, not additional catalog algorithms. The underlying scalar algorithm spelling stays unchanged.

## Dimensions

CPU four/eight-way APIs require exactly their lane count. Inputs are equal-width unless the function explicitly accepts per-lane lists. Flattened buffers are lane-major at the documented fixed width. Output spans include offsets and must cover every produced byte.

## Return and wire layout

Prepared calls must be byte-identical to scalar calls. `*_into` writes only its documented output range. Batch result order matches input lane order.

## Executable examples

<a id="example-prepared-into-batch"></a>
### CPU prepared, into, and batch paths

```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash, hash_into
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.modes import PreparedCipher
from mcrypto.ciphers.algorithm import (
    BlockCipherAlgorithm,
    StreamCipherAlgorithm,
    CipherMode,
)
from mcrypto.ciphers.stream import xor, xor_eight


def main() raises:
    var data = List("caller-owned hash output".as_bytes())
    var digest_output = List[UInt8](length=32, fill=0)
    hash_into(HashAlgorithm.SHA256, Span(data), Span(digest_output))
    assert_equal(digest_output, hash(HashAlgorithm.SHA256, Span(data)))

    var aes_key = List[UInt8](length=16, fill=0x78)
    var iv = List[UInt8](length=16, fill=0x89)
    var block_message = List[UInt8](length=32, fill=0x9A)
    var prepared = PreparedCipher(
        BlockCipherAlgorithm.AES, CipherMode.CBC, True, Span(aes_key)
    )
    assert_equal(
        prepared.process(Span(iv), Span(block_message)),
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC,
            True,
            Span(aes_key),
            Span(iv),
            Span(block_message),
        ),
    )

    var stream_key = List[UInt8](length=32, fill=0xAB)
    var nonces = List[List[UInt8]](capacity=8)
    var messages = List[List[UInt8]](capacity=8)
    for lane in range(8):
        var nonce = List[UInt8](length=8, fill=0)
        nonce[0] = UInt8(lane + 1)
        nonces.append(nonce^)
        var message = List[UInt8](length=32, fill=UInt8(lane + 3))
        messages.append(message^)
    var outputs = xor_eight(
        StreamCipherAlgorithm.CHACHA20, Span(stream_key), nonces, messages
    )
    for lane in range(8):
        assert_equal(
            outputs[lane],
            xor(
                StreamCipherAlgorithm.CHACHA20,
                Span(stream_key),
                Span(nonces[lane]),
                Span(messages[lane]),
            ),
        )
    print("prepared-into-batch: ok")
```

## Authentication, errors, and state

Wrong offsets, output lengths, lane counts, or unequal widths raise before returning partial semantic success. Authentication failures retain the scalar no-plaintext guarantee. Prepared objects containing key material are sensitive state.

## Prepared, into, and batch APIs

Prepared objects and fixed-lane batches use the same CPU compilation path as their scalar counterparts.

## Inventory and test evidence

Use the [algorithm inventory](../reference/algorithms.md) for underlying routes. Representative tests: `tests/test_hash_into_batch_paths.mojo`, `tests/test_cipher_prepared_batch_paths.mojo`, `tests/test_aead_mac_into_batch_paths.mojo`, and `tests/test_group_core_batch_paths.mojo`.