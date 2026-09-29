---
title: Binary-to-text encodings
---

# Binary-to-text encodings

Encodings make bytes fit a text channel. They provide no confidentiality, integrity, or authenticity. Decode before cryptographic verification only when the protocol defines one canonical representation.

<!-- algorithm: encoding/hex -->
<a id="encoding-hex"></a>
## Hex

Hex maps each byte to two lowercase hexadecimal digits. It is easy to inspect but doubles the byte length; decoding rejects malformed digits and odd lengths.

<a id="example-encoding-hex"></a>
<!-- runnable-example: encoding-hex -->
```mojo
from std.testing import assert_equal
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform

def main() raises:
    var message: List[UInt8] = [0, 1, 2, 3, 254, 255]
    var encoded = transform(EncodingTransform.HEX_ENCODE, Span(message))
    assert_equal(transform(EncodingTransform.HEX_DECODE, Span(encoded)), message)
    print("encoding-hex: ok")
```

<!-- algorithm: encoding/base32 -->
<a id="encoding-base32"></a>
## Base32

Base32 uses an uppercase alphabet and padding suitable for case-insensitive text channels. Preserve canonical padding when the protocol requires canonical encodings.

<a id="example-encoding-base32"></a>
<!-- runnable-example: encoding-base32 -->
```mojo
from std.testing import assert_equal
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform

def main() raises:
    var message: List[UInt8] = [0, 1, 2, 3, 254, 255]
    var encoded = transform(EncodingTransform.BASE32_ENCODE, Span(message))
    assert_equal(transform(EncodingTransform.BASE32_DECODE, Span(encoded)), message)
    print("encoding-base32: ok")
```

<!-- algorithm: encoding/base64 -->
<a id="encoding-base64"></a>
## Base64

Base64 packs three input bytes into four text bytes using the standard `+` and `/` alphabet. It is transport encoding, not secrecy or integrity.

<a id="example-encoding-base64"></a>
<!-- runnable-example: encoding-base64 -->
```mojo
from std.testing import assert_equal
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform

def main() raises:
    var message: List[UInt8] = [0, 1, 2, 3, 254, 255]
    var encoded = transform(EncodingTransform.BASE64_ENCODE, Span(message))
    assert_equal(transform(EncodingTransform.BASE64_DECODE, Span(encoded)), message)
    print("encoding-base64: ok")
```

<!-- algorithm: encoding/base64url -->
<a id="encoding-base64url"></a>
## Base64URL

Base64URL replaces `+` and `/` with URL-safe characters while retaining the transform API padding rules. Do not silently mix padded and unpadded protocol variants.

<a id="example-encoding-base64url"></a>
<!-- runnable-example: encoding-base64url -->
```mojo
from std.testing import assert_equal
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform

def main() raises:
    var message: List[UInt8] = [0, 1, 2, 3, 254, 255]
    var encoded = transform(EncodingTransform.BASE64URL_ENCODE, Span(message))
    assert_equal(transform(EncodingTransform.BASE64URL_DECODE, Span(encoded)), message)
    print("encoding-base64url: ok")
```

