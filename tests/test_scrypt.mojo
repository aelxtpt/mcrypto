from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.kdf.scrypt import scrypt


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


def test_rfc7914_empty_vector() raises:
    var password = List[UInt8]()
    var salt = List[UInt8]()
    assert_equal(
        scrypt(Span(password), Span(salt), 64, 16, 1, 1),
        hex_bytes(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
        ),
    )


def test_rfc7914_multiblock_parallel_vector() raises:
    var password: StaticString = "password"
    var salt: StaticString = "NaCl"
    assert_equal(
        scrypt(password.as_bytes(), salt.as_bytes(), 64, 1024, 8, 16),
        hex_bytes(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        ),
    )


def test_scrypt_rejects_zero_output() raises:
    var password = List[UInt8]()
    var salt = List[UInt8]()
    with assert_raises():
        _ = scrypt(Span(password), Span(salt), 0, 16, 1, 1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
