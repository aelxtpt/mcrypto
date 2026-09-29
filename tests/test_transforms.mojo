from std.testing import assert_equal, TestSuite
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.encoding.transforms import transform as encoding_transform
from mcrypto.compression.transforms import transform as compression_transform


def test_encodings_roundtrip() raises:
    var message: List[UInt8] = [0, 1, 2, 3, 254, 255]
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


def test_compression_roundtrip() raises:
    var message = List[UInt8](length=4096, fill=7)
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
