from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.hc128 import xor


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


def test_hc128_vector() raises:
    var key = h("2923be84e16cd6ae529049f1f1bbe9eb")
    var iv = h("b3a6db3c870c3e99245e0d1c06b747de")
    var plain = h("b3")
    var cipher = h("1f")
    assert_equal(xor(Span(key), Span(iv), Span(plain)), cipher)
    assert_equal(xor(Span(key), Span(iv), Span(cipher)), plain)
    var zero_key = List[UInt8](length=16, fill=0)
    var zero_iv = List[UInt8](length=16, fill=0)
    var zero_plain = List[UInt8](length=64, fill=0)
    assert_equal(
        xor(Span(zero_key), Span(zero_iv), Span(zero_plain)),
        h(
            "82001573a003fd3b7fd72ffb0eaf63aa"
            "c62f12deb629dca72785a66268ec758b"
            "1edb36900560898178e0ad009abf1f49"
            "1330dc1c246e3d6cb264f6900271d59c"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
