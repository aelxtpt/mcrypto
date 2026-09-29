from std.testing import assert_equal, assert_true
from mcrypto.hashes.xof_algorithm import XofAlgorithm
from mcrypto.hashes.xof import xof
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var shake = xof(XofAlgorithm.SHAKE128, "abc".as_bytes(), 32)
    assert_equal(
        shake,
        transform(
            EncodingTransform.HEX_DECODE,
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
            .as_bytes(),
        ),
    )
    var turbo = xof(XofAlgorithm.TURBOSHAKE256, "abc".as_bytes(), 48)
    assert_equal(len(turbo), 48)
    assert_true(turbo[0] != shake[0] or turbo[1] != shake[1])
    print("xof: ok")
