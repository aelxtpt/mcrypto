from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.hc256 import xor


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


def test_hc256_vector() raises:
    var key = List[UInt8](length=32, fill=0)
    var iv = List[UInt8](length=32, fill=0)
    var plain = List[UInt8](length=32, fill=0)
    var cipher = h(
        "5b078985d8f6f30d42c5c02fa6b6795153f06534801f89f24e74248b720b4818"
    )
    assert_equal(xor(Span(key), Span(iv), Span(plain)), cipher)
    assert_equal(xor(Span(key), Span(iv), Span(cipher)), plain)


def test_hc256_random_key_vector() raises:
    var key = h(
        "8799a76a3a4391bb45729a026cf8f6d1cdbb40d3e77887cd42a9734cba58eada"
    )
    var iv = h(
        "673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f6429b91c815f"
    )
    var plain = List[UInt8](length=32, fill=0)
    assert_equal(
        xor(Span(key), Span(iv), Span(plain)),
        h("9f6af6902ebc3110829937427eff0169b4d2d773555e4c3cfa9784ee60029a6f"),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
