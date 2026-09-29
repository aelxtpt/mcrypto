from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from std.sys import CompilationTarget
from mcrypto.random.algorithm import RandomAlgorithm, X917Cipher
from mcrypto.random.legacy import X917RNG, RandomPool, supported, generate


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


def test_x917_reference_kat() raises:
    var key = hex_bytes("2b7e151628aed2a6abf7158809cf4f3c")
    var seed = hex_bytes("000102030405060708090a0b0c0d0e0f")
    var dt = hex_bytes("00000000000000000000000000000001")
    var expected = hex_bytes(
        "d176edd27493b0395f4d10546232b0693dc7061c03c3a554f09cecf6f6b46d94"
    )
    var rng = X917RNG(X917Cipher.AES, Span(key), Span(seed), Span(dt))
    assert_equal(rng.random_bytes(32), expected)


def test_x917_3des_kat() raises:
    var key = hex_bytes("385d7189a5c3d485e1370aa5d408082b5ccccb5e19f2d90e")
    var seed = hex_bytes("c141b5fccd28dc8a")
    var dt = hex_bytes("0000000000000001")
    var expected = hex_bytes("b45998666986e8667f29c5411538c44f")
    var rng = X917RNG(X917Cipher.TDES, Span(key), Span(seed), Span(dt))
    assert_equal(rng.random_bytes(16), expected)


def test_x917_chunking_and_reseed() raises:
    var key = List[UInt8](length=16, fill=7)
    var seed = List[UInt8](length=16, fill=9)
    var dt = List[UInt8](length=16, fill=11)
    var one = X917RNG(X917Cipher.AES, Span(key), Span(seed), Span(dt))
    var two = X917RNG(X917Cipher.AES, Span(key), Span(seed), Span(dt))
    var expected = one.random_bytes(41)
    var actual = two.random_bytes(7)
    var rest = two.random_bytes(34)
    for byte in rest:
        actual.append(byte)
    assert_equal(actual, expected)
    two.reseed(Span(seed), Span(dt))
    var reset = X917RNG(X917Cipher.AES, Span(key), Span(seed), Span(dt))
    assert_equal(two.random_bytes(41), reset.random_bytes(41))


def test_random_pool_kat_and_reseed() raises:
    var entropy: List[UInt8] = [1, 2, 3, 4]
    var expected = hex_bytes(
        "7872d8ed23ab354b856986485a370936"
        "0614f7c33bb764ba15412518063eb56b"
        "bf873c349c236dae"
    )
    var pool = RandomPool(Span(entropy))
    assert_equal(pool.random_bytes(40), expected)
    var first = RandomPool(Span(entropy))
    var second = RandomPool(Span(entropy))
    assert_equal(first.random_bytes(32), second.random_bytes(32))
    var extra: List[UInt8] = [5, 6, 7]
    first.reseed(Span(extra))
    assert_false(first.random_bytes(32) == second.random_bytes(32))


def test_dispatch_and_hardware_contract() raises:
    assert_true(supported(RandomAlgorithm.ANSI_X931_AES))
    assert_true(supported(RandomAlgorithm.ANSI_X917_3DES))
    assert_true(supported(RandomAlgorithm.RANDOM_POOL))
    var seed = List[UInt8](length=48, fill=1)
    assert_equal(
        len(generate(RandomAlgorithm.ANSI_X931_AES, Span(seed), 33)), 33
    )
    var des_seed = List[UInt8](length=40, fill=2)
    assert_equal(
        len(generate(RandomAlgorithm.ANSI_X917_3DES, Span(des_seed), 17)), 17
    )
    comptime if CompilationTarget.is_x86():
        assert_true(supported(RandomAlgorithm.RDRAND))
        assert_true(supported(RandomAlgorithm.RDSEED))
        assert_equal(len(generate(RandomAlgorithm.RDRAND, Span(seed), 31)), 31)
        assert_equal(len(generate(RandomAlgorithm.RDSEED, Span(seed), 31)), 31)
    else:
        assert_false(supported(RandomAlgorithm.RDRAND))
        assert_false(supported(RandomAlgorithm.RDSEED))
        with assert_raises():
            _ = generate(RandomAlgorithm.RDRAND, Span(seed), 31)
        with assert_raises():
            _ = generate(RandomAlgorithm.RDSEED, Span(seed), 31)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
