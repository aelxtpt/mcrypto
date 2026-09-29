from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.kdf.argon2 import argon2i_with_data, argon2id_with_data


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high = high - (48 if high <= 57 else 87)
        low = low - (48 if low <= 57 else 87)
        output.append(UInt8(high * 16 + low))
    return output^


def test_rfc9106_argon2i_vector() raises:
    var password = List[UInt8](length=32, fill=1)
    var salt = List[UInt8](length=16, fill=2)
    var secret = List[UInt8](length=8, fill=3)
    var ad = List[UInt8](length=12, fill=4)
    assert_equal(
        argon2i_with_data(
            Span(password), Span(salt), 32, 3, 32, 4, Span(secret), Span(ad)
        ),
        hex_bytes(
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        ),
    )


def test_rfc9106_argon2id_vector() raises:
    var password = List[UInt8](length=32, fill=1)
    var salt = List[UInt8](length=16, fill=2)
    var secret = List[UInt8](length=8, fill=3)
    var ad = List[UInt8](length=12, fill=4)
    assert_equal(
        argon2id_with_data(
            Span(password), Span(salt), 32, 3, 32, 4, Span(secret), Span(ad)
        ),
        hex_bytes(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        ),
    )


def test_argon2_rejects_zero_output() raises:
    var password = List[UInt8](length=8, fill=1)
    var salt = List[UInt8](length=16, fill=2)
    var secret = List[UInt8]()
    var associated = List[UInt8]()
    with assert_raises():
        _ = argon2i_with_data(
            Span(password),
            Span(salt),
            0,
            1,
            32,
            1,
            Span(secret),
            Span(associated),
        )
    with assert_raises():
        _ = argon2id_with_data(
            Span(password),
            Span(salt),
            0,
            1,
            32,
            1,
            Span(secret),
            Span(associated),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
