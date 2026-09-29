---
title: Bytes, ownership, and errors
---

# Bytes, ownership, and errors

## Import explicit modules

Only a small SHA and trait surface is re-exported by `mcrypto`. Prefer the documented implementation module:

```mojo
from mcrypto.hashes import HashAlgorithm, hash
from mcrypto.encoding.transforms import transform
```

## Own bytes with `List[UInt8]`

Most returned byte strings are owned `List[UInt8]` values. Functions accept a borrowed contiguous view:

```mojo
var message: List[UInt8] = [UInt8(0x61), UInt8(0x62), UInt8(0x63)]
var digest = hash(HashAlgorithm.SHA256, Span(message))
```

`Span` does not copy or own the backing bytes. Keep its source alive for the entire call. Mutable `*_into` APIs receive a mutable `Span` over caller-owned output storage and reject the wrong length.

Tuple elements that own lists are borrowed when indexed. Copy an element you need to retain independently:

```mojo
var pair = some_operation()
var first = pair[0].copy()
var second = pair[1].copy()
```

## Propagate failures

Cryptographic operations validate key, nonce, tag, output, and framing lengths. A caller that invokes a raising API normally declares:

```mojo
def main() raises:
    # calls that can raise
    pass
```

Verification APIs return `Bool`: a bad signature or direct MAC check returns `False`. Authenticated decryption and authenticated stream opening raise on a bad tag and do not return unauthenticated plaintext. KEM decapsulation treats a same-size modified ciphertext differently: it returns an implicit-rejection shared secret rather than raising; malformed ciphertext length still raises.

> **Security:**
> Never turn a verification `False` or an authenticated-decryption exception into usable plaintext, a trusted signature, or a success result.

## Decode test vectors

The tested hexadecimal helper is the `HexDecode` operation of `mcrypto.encoding.transforms.transform`:

```mojo
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform

var bytes = transform(
    EncodingTransform.HEX_DECODE, "001122ff".as_bytes()
)
```

Odd-length or non-hexadecimal input raises. Use this helper for documentation and vector material rather than maintaining a second decoder.

Continue to [algorithm guides](../algorithms/index.md).