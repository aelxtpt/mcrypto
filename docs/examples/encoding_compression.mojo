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
