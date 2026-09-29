from std.testing import assert_equal, TestSuite
from mcrypto.hashes.ripemd import ripemd128, ripemd160, ripemd256, ripemd320


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_ripemd_empty_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        ripemd128(Span(empty)), hex_bytes("cdf26213a150dc3ecb610f18f6b38b46")
    )
    assert_equal(
        ripemd160(Span(empty)),
        hex_bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    )
    assert_equal(
        ripemd256(Span(empty)),
        hex_bytes(
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"
        ),
    )
    assert_equal(
        ripemd320(Span(empty)),
        hex_bytes(
            "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"
        ),
    )


def test_ripemd_abc_vectors() raises:
    var message = "abc".as_bytes()
    assert_equal(
        ripemd128(message), hex_bytes("c14a12199c66e4ba84636b0f69144c77")
    )
    assert_equal(
        ripemd160(message),
        hex_bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    )
    assert_equal(
        ripemd256(message),
        hex_bytes(
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"
        ),
    )
    assert_equal(
        ripemd320(message),
        hex_bytes(
            "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
