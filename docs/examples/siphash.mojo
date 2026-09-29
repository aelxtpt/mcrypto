from std.testing import assert_equal
from mcrypto.macs.siphash import hash, hash_into
from mcrypto.macs.algorithm import SipHashAlgorithm
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var key = List[UInt8](capacity=16)
    for i in range(16):
        key.append(UInt8(i))
    var empty = List[UInt8]()
    var expected = transform(
        EncodingTransform.HEX_DECODE, "310e0edd47db6f72".as_bytes()
    )
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_2_4, Span(key), Span(empty)), expected
    )
    var output = List[UInt8](length=8, fill=0)
    hash_into(
        SipHashAlgorithm.SIPHASH_2_4,
        Span(key),
        Span(empty),
        Span(output),
    )
    assert_equal(output, expected)
    assert_equal(
        len(hash(SipHashAlgorithm.SIPHASH_X_2_4, Span(key), Span(empty))),
        16,
    )
    print("siphash: ok")
