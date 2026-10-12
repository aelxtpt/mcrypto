from std.testing import assert_equal
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.kdf.hkdf import extract, expand
from mcrypto.padding.pkcs7 import pad, unpad
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform
from mcrypto.compression.transforms import zlib_compress, zlib_decompress
from mcrypto.kem import mlkem512


def main() raises:
    var message = List("example data".as_bytes())
    var prk = extract(
        HashAlgorithm.SHA256, "example salt".as_bytes(), Span(message)
    )
    var derived = expand(
        HashAlgorithm.SHA256, Span(prk), "example context".as_bytes(), 32
    )
    assert_equal(len(derived), 32)
    var padded = pad(Span(message), 16)
    assert_equal(unpad(Span(padded), 16), message)
    var encoded = transform(
        EncodingTransform.BASE64URL_NOPAD_ENCODE, Span(message)
    )
    assert_equal(
        transform(EncodingTransform.BASE64URL_NOPAD_DECODE, Span(encoded)),
        message,
    )
    var compressed = zlib_compress(Span(message))
    assert_equal(
        zlib_decompress(Span(compressed), max_output_bytes=len(message)),
        message,
    )
    var keys = mlkem512.keypair()
    var sealed = mlkem512.encapsulate(Span(keys[0]))
    assert_equal(
        mlkem512.decapsulate(Span(sealed[0]), Span(keys[1])), sealed[1]
    )
    print("standard building blocks: ok")
