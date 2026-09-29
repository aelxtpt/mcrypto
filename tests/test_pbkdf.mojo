from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.kdf.pbkdf import pbkdf1, pbkdf2


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


def test_pbkdf2_sha256_vectors() raises:
    assert_equal(
        pbkdf2(
            HashAlgorithm.SHA256,
            "password".as_bytes(),
            "salt".as_bytes(),
            32,
            1,
        ),
        hex_bytes(
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        ),
    )
    assert_equal(
        pbkdf2(
            HashAlgorithm.SHA256,
            "password".as_bytes(),
            "salt".as_bytes(),
            32,
            2,
        ),
        hex_bytes(
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        ),
    )


def test_pbkdf1_sha256_iterated_digest_vector_and_limits() raises:
    var password = "password".as_bytes()
    var salt = "12345678".as_bytes()
    assert_equal(
        pbkdf1(password, salt, 32, 1000),
        hex_bytes(
            "12d71704e64c1619256b9a8b35a1d1a3c1a7e95ee77d0753cf55ebbfa3f3204b"
        ),
    )
    assert_equal(
        pbkdf1(password, salt, 16, 1000),
        hex_bytes("12d71704e64c1619256b9a8b35a1d1a3"),
    )
    with assert_raises():
        _ = pbkdf1(password, salt, 0, 1)
    with assert_raises():
        _ = pbkdf1(password, salt, 33, 1)
    with assert_raises():
        _ = pbkdf1(password, salt, 16, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
