---
title: Hashes and XOFs
---

# Hashes and XOFs

## What this family does

Fixed hashes map any message to a fixed-size digest. XOFs accept an explicit positive output length. SipHash is a keyed short hash and is not part of the unkeyed fixed-digest dispatcher.

## Safe selection and legacy warning

Use SHA-256/SHA-512, SHA-3, BLAKE2, SHAKE, or TurboSHAKE where the protocol specifies them. CRC, Adler32, MD2, MD4, MD5, SHA-1, RIPEMD, PanamaHash, Tiger, and Whirlpool remain for checksums or compatibility, not new collision-resistant designs. SipHash is suitable for keyed hash-table or short-input use, not as a general unkeyed digest.

## Public imports and signatures

```mojo
from mcrypto.hashes import HashAlgorithm, digest_size, hash, hash_into
from mcrypto.hashes.xof_algorithm import XofAlgorithm
from mcrypto.macs.algorithm import SipHashAlgorithm
from mcrypto.hashes.xof import xof
from mcrypto.macs.siphash import hash as siphash

def hash[origin: Origin](algorithm: HashAlgorithm, data: Span[UInt8, origin], output_bytes: Int = 0) raises -> List[UInt8]
def hash_into[input_origin: Origin, output_origin: MutOrigin](algorithm: HashAlgorithm, data: Span[UInt8, input_origin], output: Span[mut=True, UInt8, output_origin]) raises
def xof[origin: Origin](algorithm: XofAlgorithm, data: Span[UInt8, origin], output_bytes: Int) raises -> List[UInt8]
def siphash[key_origin: Origin, message_origin: Origin](algorithm: SipHashAlgorithm, key: Span[UInt8, key_origin], message: Span[UInt8, message_origin]) raises -> List[UInt8]
```

Incremental SHA-256 uses `from mcrypto.hashes.sha256 import SHA256`, then `update(...)` and `finalize()`.

## Typed selectors and external names

`hash`, `hash_into`, and `digest_size` accept `HashAlgorithm` constants such as `HashAlgorithm.SHA256`, `HashAlgorithm.SHA3_256`, `HashAlgorithm.KECCAK256`, and `HashAlgorithm.BLAKE2B`. This is the normal application API: misspelled algorithm names cannot compile.

Only boundaries that genuinely receive text—manifests, command-line arguments, or protocols—should call `parse_hash_algorithm(name)` or the explicit boundary helpers in `mcrypto.hashes.dispatch`: `hash_by_name`, `hash_into_by_name`, and `digest_size_by_name`. Those parsers accept the fixed names shown in the hash catalog. They reject XOF and SipHash names. Application code passes `XofAlgorithm.SHAKE128`, `XofAlgorithm.SHAKE256`, `XofAlgorithm.TURBOSHAKE128`, or `XofAlgorithm.TURBOSHAKE256`.

## Dimensions

`digest_size(algorithm)` returns 4 bytes for CRC/Adler, 16 for MD2/MD4/MD5/RIPEMD-128, 20 for SHA-1/RIPEMD-160, 24 for Tiger, 28 for 224-bit hashes, 32 for 256-bit hashes, 40 for RIPEMD-320, 48 for 384-bit hashes, and 64 for 512-bit hashes/Whirlpool. XOF output must be greater than zero. SipHash requires a 16-byte key and returns 8 bytes; `SipHash-x-2-4` returns 16.

## Return and wire layout

One-shot APIs return digest bytes in each algorithm's standard byte order. `hash_into` writes exactly `digest_size(algorithm)` bytes into caller storage. Incremental finalization closes that state. XOF output is the requested prefix of the algorithm stream.

## Executable examples

<a id="example-hashes"></a>
### Fixed hashes
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

<a id="example-incremental-hash"></a>
### Incremental hashing
```mojo
from std.testing import assert_equal
from mcrypto.hashes.sha256 import SHA256, sha256


def main() raises:
    var state = SHA256()
    state.update("a".as_bytes())
    state.update("b".as_bytes())
    state.update("c".as_bytes())
    assert_equal(state.finalize(), sha256("abc".as_bytes()))
    print("incremental-hash: ok")
```

<a id="example-xof"></a>
### XOF output
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.hashes.xof_algorithm import XofAlgorithm
from mcrypto.hashes.xof import xof
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var shake = xof(XofAlgorithm.SHAKE128, "abc".as_bytes(), 32)
    assert_equal(
        shake,
        transform(
            EncodingTransform.HEX_DECODE,
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
            .as_bytes(),
        ),
    )
    var turbo = xof(XofAlgorithm.TURBOSHAKE256, "abc".as_bytes(), 48)
    assert_equal(len(turbo), 48)
    assert_true(turbo[0] != shake[0] or turbo[1] != shake[1])
    print("xof: ok")
```

<a id="example-siphash"></a>
### Keyed SipHash
```mojo
from std.testing import assert_equal
from mcrypto.macs.siphash import hash, hash_into
from mcrypto.macs.algorithm import SipHashAlgorithm
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var key = List[UInt8](capacity=16)
    for i in range(16):
        key.append(UInt8(i))
    var empty = List[UInt8]()
    var expected = transform(
        EncodingTransform.HEX_DECODE, "310e0edd47db6f72".as_bytes()
    )
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_2_4, Span(key), Span(empty)), expected
    )
    var output = List[UInt8](length=8, fill=0)
    hash_into(
        SipHashAlgorithm.SIPHASH_2_4,
        Span(key),
        Span(empty),
        Span(output),
    )
    assert_equal(output, expected)
    assert_equal(
        len(hash(SipHashAlgorithm.SIPHASH_X_2_4, Span(key), Span(empty))),
        16,
    )
    print("siphash: ok")
```

## Authentication, errors, and state

Hashes do not authenticate data. External-name parsers reject unknown names; typed and external-name calls reject invalid output lengths and output spans of the wrong size. Incremental states reject update/finalize misuse after finalization. Compare secrets or authentication values with constant-time helpers rather than ordinary early-exit comparisons.

## Prepared, into, and batch APIs

Use `hash_into` to avoid a returned-list allocation. SHA and selected hash modules expose prepared or multi-lane routines; the common batch contract uses equal-width flattened inputs and caller-sized outputs. See [prepared and batch APIs](prepared-into-batch.md).

## Inventory and test evidence

Start at [`SHA-256`](../reference/algorithms.md#hash-sha-256), [`TurboSHAKE256`](../reference/algorithms.md#xof-turboshake256), and [`SipHash`](../reference/algorithms.md#mac-siphash). Representative source tests: `tests/test_hashes.mojo`, `tests/test_xof.mojo`, and `tests/test_siphash.mojo`.