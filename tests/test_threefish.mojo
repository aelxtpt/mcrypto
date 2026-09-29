from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.threefish import process


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else (87 if a >= 97 else 55)
        c -= 48 if c <= 57 else (87 if c >= 97 else 55)
        o.append(UInt8(a * 16 + c))
    return o^


def test_threefish_zero_vectors() raises:
    var tweak = List[UInt8](length=16, fill=0)
    var k256 = List[UInt8](length=32, fill=0)
    var p256 = k256.copy()
    var c256 = h(
        "84DA2A1F8BEAEE947066AE3E3103F1AD536DB1F4A1192495116B9F3CE6133FD8"
    )
    assert_equal(process(False, Span(k256), Span(tweak), Span(p256)), c256)
    assert_equal(process(True, Span(k256), Span(tweak), Span(c256)), k256)
    var k512 = List[UInt8](length=64, fill=0)
    var p512 = k512.copy()
    var c512 = h(
        "B1A2BBC6EF6025BC40EB3822161F36E375D1BB0AEE3186FBD19E47C5D479947B7BC2F8586E35F0CFF7E7F03084B0B7B1F1AB3961A580A3E97EB41EA14A6D7BBE"
    )
    assert_equal(process(False, Span(k512), Span(tweak), Span(p512)), c512)
    assert_equal(process(True, Span(k512), Span(tweak), Span(c512)), k512)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
