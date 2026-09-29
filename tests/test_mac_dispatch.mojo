from std.testing import assert_equal, TestSuite
from mcrypto.macs.dispatch import authenticate
from mcrypto.macs.algorithm import MacAlgorithm


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


def test_hmac_and_blake_dispatch() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    assert_equal(
        authenticate(
            MacAlgorithm.HMAC_SHA256, Span(key), "Hi There".as_bytes(), 32
        ),
        hex_bytes(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        ),
    )
    assert_equal(
        authenticate(MacAlgorithm.BLAKE2B_MAC, Span(key), "abc".as_bytes(), 24),
        hex_bytes("08ca9aed7aa592d18549d5657e5d32f04a7ba7d415ac8df2"),
    )
    assert_equal(
        authenticate(MacAlgorithm.BLAKE2S_MAC, Span(key), "abc".as_bytes(), 24),
        hex_bytes("56a6e925bef3680b5cbc4945bce53ed3bf7ca2744afede51"),
    )
    var empty_key = List[UInt8]()
    var empty_message = List[UInt8]()
    assert_equal(
        authenticate(
            MacAlgorithm.PANAMA_MAC,
            Span(empty_key),
            Span(empty_message),
            32,
        ),
        hex_bytes(
            "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b"
        ),
    )
    var panama_key = List("The ".as_bytes())
    assert_equal(
        authenticate(
            MacAlgorithm.PANAMA_MAC,
            Span(panama_key),
            "quick brown fox jumps over the lazy dog".as_bytes(),
            32,
        ),
        hex_bytes(
            "5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
