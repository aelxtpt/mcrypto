from std.testing import assert_equal, TestSuite
from mcrypto.hashes.blake2 import blake2b, blake2b_keyed, blake2s, blake2s_keyed


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_rfc7693_unkeyed_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        blake2b(Span(empty)),
        hex_bytes(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        ),
    )
    assert_equal(
        blake2s(Span(empty)),
        hex_bytes(
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        ),
    )
    assert_equal(
        blake2b("abc".as_bytes()),
        hex_bytes(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        ),
    )
    assert_equal(
        blake2s("abc".as_bytes()),
        hex_bytes(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        ),
    )


def test_keyed_and_variable_output() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32):
        key.append(UInt8(i))
    assert_equal(
        blake2s_keyed("abc".as_bytes(), Span(key), 16),
        hex_bytes("61ba5f165c194692e09d12520cc4c74a"),
    )
    assert_equal(
        blake2b("abc".as_bytes(), 32),
        hex_bytes(
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
