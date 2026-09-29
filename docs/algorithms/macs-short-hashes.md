---
title: MACs and short hashes
---

# MACs and short hashes

## What this family does

A MAC authenticates a message with a shared secret key. SipHash is a keyed short hash. Neither encrypts its input.

## Safe selection and legacy warning

Use HMAC-SHA-256/512, CMAC when required, or Poly1305 only in a protocol that derives one-time keys correctly. Never reuse a Poly1305 one-time key. CBC-MAC is safe only for a fixed-length domain; truncation reduces forgery resistance. Review known CBC-MAC/DMAC verifier defects before use.

## Public imports and signatures

```mojo
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.dispatch import authenticate
from mcrypto.macs.cmac import verify
from mcrypto.macs.gmac import authenticate as gmac
from mcrypto.macs.poly1305_aes import authenticate as poly1305_aes
from mcrypto.macs.vmac import authenticate as vmac

def authenticate[key_origin: Origin, input_origin: Origin](algorithm: MacAlgorithm, key: Span[UInt8, key_origin], input: Span[UInt8, input_origin], tag_bytes: Int) raises -> List[UInt8]
```

The generic dispatcher has no generic verifier. Use the matching direct module's `verify` where it exists and treat the returned `Bool` as authoritative.

## Inventory names and invocation spellings

Text boundaries map generic names to `MacAlgorithm` constants such as `MacAlgorithm.HMAC_SHA256`, `MacAlgorithm.BLAKE2B_MAC`, `MacAlgorithm.CMAC`, or `MacAlgorithm.SIPHASH_2_4`. `MacAlgorithm.GMAC`, `MacAlgorithm.POLY1305_AES`, and `MacAlgorithm.VMAC` are not valid for generic `authenticate`; use their nonce-bearing direct APIs.

## Dimensions

HMAC accepts protocol-selected keys and returns its underlying digest length before truncation. Poly1305 uses a 32-byte one-time key and 16-byte tag. SipHash uses a 16-byte key and returns 8 bytes; SipHash-x returns 16. GMAC/Poly1305-AES/VMAC enforce their algorithm-specific key and nonce sizes. `tag_bytes` must be positive and no larger than the full tag.

## Return and wire layout

Authentication returns only tag bytes. The nonce-bearing APIs do not prepend their nonce. Store or transmit message framing, nonce, and tag separately according to the protocol.

## Executable examples

<a id="example-macs"></a>
### Generic MAC and direct verification

```mojo
from std.testing import assert_false, assert_true
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm
from mcrypto.macs.dispatch import authenticate
from mcrypto.macs.algorithm import MacAlgorithm
from mcrypto.macs.cmac import verify


def main() raises:
    var key = List[UInt8](length=16, fill=0x71)
    var message = List("authenticate this message".as_bytes())
    var tag = authenticate(MacAlgorithm.CMAC, Span(key), Span(message), 16)
    assert_true(
        verify(BlockCipherAlgorithm.AES, Span(key), Span(message), Span(tag))
    )
    message[0] ^= 1
    assert_false(
        verify(BlockCipherAlgorithm.AES, Span(key), Span(message), Span(tag))
    )
    print("macs: ok")
```

<a id="example-nonce-macs"></a>
### Nonce-bearing MACs

```mojo
from std.testing import assert_false, assert_true
from mcrypto.macs.gmac import authenticate, verify


def main() raises:
    var key = List[UInt8](length=16, fill=0x72)
    var nonce = List[UInt8](length=12, fill=0x83)
    var message = List("nonce-bearing MAC input".as_bytes())
    var tag = authenticate(Span(key), Span(nonce), Span(message), 16)
    assert_true(verify(Span(key), Span(nonce), Span(message), Span(tag)))
    nonce[0] ^= 1
    assert_false(verify(Span(key), Span(nonce), Span(message), Span(tag)))
    print("nonce-macs: ok")
```

<a id="example-siphash"></a>
### SipHash

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

A direct verifier returns `False` for a bad tag. Generation is not verification. Unknown names, invalid sizes, or nonce-bearing names sent to the generic dispatcher raise. CBC-MAC and DMAC currently accept a zero-length verification tag.

## Prepared, into, and batch APIs

Selected MAC modules expose prepared key objects, `authenticate_into`, and four/eight-way paths. Caller output must fit the complete requested tag and batch inputs must satisfy lane-width contracts.

## Inventory and test evidence

See [`HMAC`](../reference/algorithms.md#mac-hmac), [`GMAC`](../reference/algorithms.md#mac-gmac), and [`SipHash-x-2-4`](../reference/algorithms.md#mac-siphash-x-2-4). Representative tests: `tests/test_mac_dispatch.mojo`, `tests/test_block_macs.mojo`, and `tests/test_siphash.mojo`.