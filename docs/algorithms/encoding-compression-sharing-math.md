---
title: Encoding, compression, sharing, and math
---

# Encoding, compression, sharing, and math

## What this family does

Encoding converts bytes to textual alphabets; compression transforms byte streams; Shamir splits a secret by threshold; IDA disperses data for recovery; finite-field and prime helpers support cryptographic constructions.

## Safe selection and legacy warning

Encoding and compression provide no confidentiality or authenticity. Never decompress untrusted data without resource limits. Shamir shares protect secrecy below threshold; IDA shares do not. Public math primitives are not complete protocols.

## Public imports and signatures

```mojo
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.encoding.transforms import transform as encode_transform
from mcrypto.compression.transforms import transform as compress_transform
from mcrypto.utilities.secret_sharing import shamir_split, shamir_recover, ida_split, ida_recover

def encode_transform[origin: Origin](algorithm: EncodingTransform, input: Span[UInt8, origin]) raises -> List[UInt8]
def compress_transform[origin: Origin](algorithm: CompressionTransform, input: Span[UInt8, origin]) raises -> List[UInt8]
```

Sharing functions accept the source bytes plus share/threshold parameters and return self-describing share lists; recovery consumes enough compatible shares.

## Inventory names and invocation spellings

Text boundaries map encoding labels to constants such as `EncodingTransform.HEX_DECODE` and compression labels to constants such as `CompressionTransform.ZLIB_DECOMPRESS`. Inventory math/sharing labels are direct APIs, not one common dispatcher.

## Dimensions

Hex output is twice input length. Base32/Base64 expand according to their standards. Compression output is data-dependent. Shamir/IDA require valid `threshold <= shares`; reconstruction needs at least the threshold and matching metadata. GF(2^n) and GF(p) values enforce field/domain widths.

## Return and wire layout

Transform calls return encoded/compressed bytes. Sharing returns self-describing shares in mcrypto's native format. Do not mix shares from different splits, algorithms, or external encodings.

## Executable examples

<a id="example-encoding-compression"></a>
### Encoding and compression
```mojo
from std.testing import assert_equal
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.encoding.transforms import transform as encoding_transform
from mcrypto.compression.transforms import transform as compression_transform


def main() raises:
    var message = List(
        "encode and compress this repeated repeated message".as_bytes()
    )
    for encoder, decoder in [
        (EncodingTransform.HEX_ENCODE, EncodingTransform.HEX_DECODE),
        (EncodingTransform.BASE32_ENCODE, EncodingTransform.BASE32_DECODE),
        (EncodingTransform.BASE64_ENCODE, EncodingTransform.BASE64_DECODE),
        (
            EncodingTransform.BASE64URL_ENCODE,
            EncodingTransform.BASE64URL_DECODE,
        ),
    ]:
        var encoded = encoding_transform(encoder, Span(message))
        assert_equal(encoding_transform(decoder, Span(encoded)), message)
    var gzip = compression_transform(CompressionTransform.GZIP, Span(message))
    assert_equal(
        compression_transform(CompressionTransform.GUNZIP, Span(gzip)), message
    )
    var zlib = compression_transform(
        CompressionTransform.ZLIB_COMPRESS, Span(message)
    )
    assert_equal(
        compression_transform(CompressionTransform.ZLIB_DECOMPRESS, Span(zlib)),
        message,
    )
    print("encoding-compression: ok")
```

<a id="example-sharing-math-primes"></a>
### Sharing, fields, and primes
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.utilities.secret_sharing import (
    shamir_split,
    shamir_recover,
    ida_split,
    ida_recover,
)
from mcrypto.math.biguint import BigUInt
from mcrypto.math.fields import PrimeField64
from mcrypto.math.primes import is_probable_prime


def first_three(shares: List[List[UInt8]]) -> List[List[UInt8]]:
    var selected = List[List[UInt8]](capacity=3)
    selected.append(shares[0].copy())
    selected.append(shares[1].copy())
    selected.append(shares[2].copy())
    return selected^


def main() raises:
    var message = List("threshold data".as_bytes())
    var ids: List[UInt8] = [1, 2, 3, 7, 11]
    var shamir = shamir_split(Span(message), 3, Span(ids))
    assert_equal(shamir_recover(first_three(shamir)), message)
    var ida = ida_split(Span(message), 3, Span(ids))
    assert_equal(ida_recover(first_three(ida)), message)

    var field = PrimeField64(17)
    assert_equal(field.multiply(9, 11), UInt64(14))
    assert_true(is_probable_prime(BigUInt(UInt64(65537))))
    print("sharing-math-primes: ok")
```

## Authentication, errors, and state

Invalid alphabet characters, malformed/truncated compression, bad share headers, duplicate/incompatible shares, and invalid field operations raise. Authenticate compressed/encoded/share framing separately when the protocol requires integrity.

## Prepared, into, and batch APIs

Some field/prime objects retain prepared arithmetic state; transforms and sharing return owned lists.

## Inventory and test evidence

See [`Hex`](../reference/algorithms.md#encoding-hex), [`Shamir secret sharing`](../reference/algorithms.md#secret-sharing-shamir-secret-sharing), and [`Rabin IDA`](../reference/algorithms.md#secret-sharing-rabin-ida). Representative tests: `tests/test_encoding_pure.mojo`, `tests/test_transforms.mojo`, and `tests/test_secret_sharing.mojo`.