from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.panama_stream import xor


def h(text: StaticString) -> List[UInt8]:
    var b = text.as_bytes()
    var output = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var high = Int(b[i])
        var low = Int(b[i + 1])
        high -= 48 if high <= 57 else (87 if high >= 97 else 55)
        low -= 48 if low <= 57 else (87 if low >= 97 else 55)
        output.append(UInt8(high * 16 + low))
    return output^


def test_panama_stream_vectors() raises:
    var key = h(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    var nonce = key.copy()
    var plain = key.copy()
    var expected_le = h(
        "F07F5FF2CCD01A0A7D44ACD6D239C2AF0DA1FF35275BAF5DFA6E09411B79D8B9"
    )
    var expected_be = h(
        "E12E2F6BA41AE832D888DA9FA6863BC37C0E996F190A1711330322D37BD98CA4"
    )
    assert_equal(xor(False, Span(key), Span(nonce), Span(plain)), expected_le)
    assert_equal(xor(True, Span(key), Span(nonce), Span(plain)), expected_be)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
