from std.testing import assert_equal, assert_false, assert_raises, TestSuite
from mcrypto.random.entropy import ChaChaRNG, system_entropy


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


def test_rfc8439_chacha20_block() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32):
        key.append(UInt8(i))
    var nonce: List[UInt8] = [0, 0, 0, 9, 0, 0, 0, 0x4A, 0, 0, 0, 0]
    var rng = ChaChaRNG(Span(key), Span(nonce), 1)
    var block = rng.random_bytes(64)
    var expected = hex_bytes(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert_equal(block, expected)


def test_chunked_generation_matches_one_shot() raises:
    var key = List[UInt8](length=32, fill=7)
    var nonce = List[UInt8](length=12, fill=9)
    var one = ChaChaRNG(Span(key), Span(nonce))
    var two = ChaChaRNG(Span(key), Span(nonce))
    var expected = one.random_bytes(129)
    var actual = List[UInt8](capacity=129)
    var first = two.random_bytes(17)
    var second = two.random_bytes(112)
    for byte in first:
        actual.append(byte)
    for byte in second:
        actual.append(byte)
    assert_equal(actual, expected)
    with assert_raises():
        _ = two.random_bytes(-1)


def test_system_entropy_source() raises:
    with assert_raises():
        _ = system_entropy(-1)
    assert_equal(len(system_entropy(0)), 0)
    assert_equal(len(system_entropy(257)), 257)
    var first = system_entropy(32)
    var second = system_entropy(32)
    assert_equal(len(first), 32)
    assert_equal(len(second), 32)
    assert_false(first == second)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
