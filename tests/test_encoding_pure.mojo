from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.encoding.algorithm import (
    EncodingTransform,
    parse_encoding_transform,
)
from mcrypto.encoding.transforms import transform


def test_encoding_roundtrips() raises:
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
        var encoded = transform(encoder, Span(message))
        assert_equal(transform(decoder, Span(encoded)), message)
    assert_equal(
        transform(EncodingTransform.BASE64_ENCODE, "foobar".as_bytes()),
        List("Zm9vYmFy".as_bytes()),
    )
    assert_equal(
        transform(EncodingTransform.BASE32_ENCODE, "foobar".as_bytes()),
        List("MZXW6YTBOI======".as_bytes()),
    )


def test_malformed_and_noncanonical_encodings_are_rejected() raises:
    with assert_raises():
        _ = transform(EncodingTransform.HEX_DECODE, "0".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.HEX_DECODE, "gg".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE64_DECODE, "A".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE64_DECODE, "=AAA".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE64_DECODE, "AA=A".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE64_DECODE, "AB==".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE64URL_DECODE, "AA+/".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE32_DECODE, "A".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE32_DECODE, "A=======".as_bytes())
    with assert_raises():
        _ = transform(EncodingTransform.BASE32_DECODE, "AB======".as_bytes())
    with assert_raises():
        _ = parse_encoding_transform("Unknown")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
