from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var digest = hash(HashAlgorithm.SHA256, "abc".as_bytes())
    var expected = transform(
        EncodingTransform.HEX_DECODE,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        .as_bytes(),
    )
    assert_equal(digest, expected)
    print("quickstart-hash: ok")
