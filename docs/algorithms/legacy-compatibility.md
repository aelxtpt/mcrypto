---
title: Legacy compatibility
---

# Legacy compatibility

## What this family does

Legacy modules preserve algorithms and wire behavior needed to read or interoperate with older systems.

## Safe selection and legacy warning

Do not choose these primitives for a new protocol merely because they are implemented. Migration code should isolate legacy parsing/decryption, authenticate the replacement format, and remove the old key path after conversion.

## Public imports and signatures

Legacy source is explicit: `mcrypto.hashes.md_legacy`, `mcrypto.ciphers.legacy_stream`, `mcrypto.random.legacy`, and public-key legacy math/schemes. Use their direct signatures or the documented front-door dispatcher; no "legacy safe mode" changes the primitive.

## Inventory names and invocation spellings

Examples include MD2/MD4/MD5, SHA-1, ARC4, WAKE-OFB, old block ciphers/modes, ANSI-X9.17, Rabin-Williams, LUC, ESIGN, and old padding encodings. Exact accepted spellings and availability annotations are in the generated inventory.

## Dimensions

Legacy dimensions are algorithm-specific and strictly validated. Compatibility does not justify empty keys, zero-length tags, reused IVs, or relaxed framing.

## Return and wire layout

Legacy dispatch returns raw algorithm-native bytes. It does not wrap them in a new authenticated envelope. Preserve exact historical framing only long enough to verify/decrypt and migrate.

## Executable examples

<a id="example-hashes"></a>
### Working compatibility hash path

```mojo
from std.testing import assert_equal, assert_true
from mcrypto.hashes import HashAlgorithm, digest_size, hash
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var message = List("abc".as_bytes())
    var sha256 = hash(HashAlgorithm.SHA256, Span(message))
    var md5 = hash(HashAlgorithm.MD5, Span(message))
    assert_equal(
        sha256,
        transform(
            EncodingTransform.HEX_DECODE,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            .as_bytes(),
        ),
    )
    assert_equal(
        md5,
        transform(
            EncodingTransform.HEX_DECODE,
            "900150983cd24fb0d6963f7d28e17f72".as_bytes(),
        ),
    )
    assert_equal(
        len(hash(HashAlgorithm.BLAKE2B, Span(message))),
        digest_size(HashAlgorithm.BLAKE2B),
    )
    assert_true(sha256 != md5)
    print("hashes: ok")
```

## Authentication, errors, and state

Weakness is a property of the primitive, not only error handling. A round trip does not establish security. Fail closed on malformed legacy data, and authenticate any migrated representation.

## Prepared, into, and batch APIs

Optimized legacy paths remain semantically legacy. Batching or prepared tables improve throughput only; they do not repair collision, key-size, mode, or construction weaknesses.

## Inventory and test evidence

Start with [`MD5`](../reference/algorithms.md#hash-md5), [`ARC4`](../reference/algorithms.md#stream-cipher-arc4), and [`Rabin-Williams`](../reference/algorithms.md#signature-rabin-williams). Representative tests: `tests/test_legacy_stream.mojo`, `tests/test_legacy_public_key.mojo`, and `tests/test_hashes.mojo`.