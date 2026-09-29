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
