from std.testing import assert_equal, TestSuite
from mcrypto.macs.siphash import hash, hash_into
from mcrypto.macs.algorithm import SipHashAlgorithm


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high = high - (48 if high <= 57 else 87)
        low = low - (48 if low <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_reference_vectors() raises:
    var key = List[UInt8](capacity=16)
    for i in range(16):
        key.append(UInt8(i))
    var empty = List[UInt8]()
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_2_4, Span(key), Span(empty)),
        hex_bytes("310e0edd47db6f72"),
    )
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_4_8, Span(key), Span(empty)),
        hex_bytes("41da38992b0579c8"),
    )
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_X_2_4, Span(key), Span(empty)),
        hex_bytes("a3817f04ba25a8e66df67214c7550293"),
    )
    var one: List[UInt8] = [0]
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_2_4, Span(key), Span(one)),
        hex_bytes("fd67dc93c539f874"),
    )
    assert_equal(
        hash(SipHashAlgorithm.SIPHASH_X_2_4, Span(key), Span(one)),
        hex_bytes("da87c1d86b99af44347659119b22fc45"),
    )
    var output8 = List[UInt8](length=8, fill=0)
    hash_into(SipHashAlgorithm.SIPHASH_2_4, Span(key), Span(one), Span(output8))
    assert_equal(output8, hex_bytes("fd67dc93c539f874"))
    hash_into(
        SipHashAlgorithm.SIPHASH_4_8, Span(key), Span(empty), Span(output8)
    )
    assert_equal(output8, hex_bytes("41da38992b0579c8"))
    var output16 = List[UInt8](length=16, fill=0)
    hash_into(
        SipHashAlgorithm.SIPHASH_X_2_4,
        Span(key),
        Span(one),
        Span(output16),
    )
    assert_equal(output16, hex_bytes("da87c1d86b99af44347659119b22fc45"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
