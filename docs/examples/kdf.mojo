from std.testing import assert_equal, assert_true
from mcrypto.kdf.algorithm import KdfAlgorithm
from mcrypto.kdf.dispatch import derive


def main() raises:
    var secret = List("input key material".as_bytes())
    var salt = List("documented salt".as_bytes())
    var info = List("mcrypto docs example".as_bytes())
    var first = derive(
        KdfAlgorithm.HKDF_SHA256,
        Span(secret),
        Span(salt),
        Span(info),
        32,
    )
    var second = derive(
        KdfAlgorithm.HKDF_SHA256,
        Span(secret),
        Span(salt),
        Span(info),
        32,
    )
    assert_equal(first, second)
    assert_equal(len(first), 32)
    info[0] ^= 1
    var separated = derive(
        KdfAlgorithm.HKDF_SHA256,
        Span(secret),
        Span(salt),
        Span(info),
        32,
    )
    assert_true(separated != first)
    print("kdf: ok")
