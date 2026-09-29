from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.seal import xor


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


def assert_slice[
    actual_origin: Origin, expected_origin: Origin
](
    actual: Span[UInt8, actual_origin],
    offset: Int,
    expected: Span[UInt8, expected_origin],
) raises:
    for i in range(len(expected)):
        assert_equal(actual[offset + i], expected[i])


def test_seal_30_vector_prefix() raises:
    var key = h("67452301efcdab8998badcfe10325476c3d2e1f0")
    var nonce = h("013577af")
    var zero = List[UInt8](length=64, fill=0)
    var expected = h(
        "37a005959b84c49ca4be1e050673530f5fb097fdf6a13fbd6c2cdecd81fdee7c2abdc3e764209aff00a12283ef675085c1634b53289059e6a7ab5ed9480c01eb"
    )
    assert_equal(xor(False, Span(key), Span(nonce), Span(zero)), expected)


def test_seal_30_position_index_transitions() raises:
    var key = h("000102030405060708090a0b0c0d0e0f10111213")
    var nonce = h("12345678")
    var zero = List[UInt8](length=4112, fill=0)
    var output = xor(False, Span(key), Span(nonce), Span(zero))
    assert_slice(Span(output), 0, Span(h("4ca7b753398c75850876f3efea89611b")))
    assert_slice(
        Span(output), 1024, Span(h("c22867dfe14099b54bf9fb5d14d30cf5"))
    )
    assert_slice(
        Span(output), 2048, Span(h("9c6a2dfb12ac8548ae980bea6c49f1ae"))
    )
    assert_slice(
        Span(output), 3072, Span(h("1c23b0654ce2fcd6387bf4ad4f726dea"))
    )
    assert_slice(
        Span(output), 4096, Span(h("c217692b702bbd6ce1164c858b155cd5"))
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
