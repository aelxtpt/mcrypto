---
title: Compression transforms
---

# Compression transforms

Compression is not encryption and must be ordered carefully around secret and attacker-controlled data. Compressing both in one context can leak information through output length. Apply resource limits before decompressing untrusted input.

<!-- algorithm: compression/deflate -->
<a id="compression-deflate"></a>
## DEFLATE

DEFLATE compresses a byte stream without a container header or integrity checksum. Pair it with the matching inflater and define framing outside the compressed bytes.

<a id="example-compression-deflate"></a>
<!-- runnable-example: compression-deflate -->
```mojo
from std.testing import assert_equal
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.compression.transforms import transform

def main() raises:
    var message = List[UInt8](length=4096, fill=0x38)
    var compressed = transform(CompressionTransform.DEFLATE, Span(message))
    assert_equal(transform(CompressionTransform.INFLATE, Span(compressed)), message)
    print("compression-deflate: ok")
```

<!-- algorithm: compression/gzip -->
<a id="compression-gzip"></a>
## gzip

gzip wraps DEFLATE with a header and CRC-32 trailer. Decompression validates the container before returning the original bytes.

<a id="example-compression-gzip"></a>
<!-- runnable-example: compression-gzip -->
```mojo
from std.testing import assert_equal
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.compression.transforms import transform

def main() raises:
    var message = List[UInt8](length=4096, fill=0x35)
    var compressed = transform(CompressionTransform.GZIP, Span(message))
    assert_equal(transform(CompressionTransform.GUNZIP, Span(compressed)), message)
    print("compression-gzip: ok")
```

<!-- algorithm: compression/zlib -->
<a id="compression-zlib"></a>
## zlib

zlib wraps DEFLATE with a compact header and Adler-32 trailer. Use its dedicated compressor and decompressor tokens rather than raw DEFLATE tokens.

<a id="example-compression-zlib"></a>
<!-- runnable-example: compression-zlib -->
```mojo
from std.testing import assert_equal
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.compression.transforms import transform

def main() raises:
    var message = List[UInt8](length=4096, fill=0x35)
    var compressed = transform(CompressionTransform.ZLIB_COMPRESS, Span(message))
    assert_equal(transform(CompressionTransform.ZLIB_DECOMPRESS, Span(compressed)), message)
    print("compression-zlib: ok")
```

