from std.testing import assert_equal, TestSuite
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.kdf.hkdf import derive


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


def test_rfc5869_sha256() raises:
    var secret = List[UInt8](length=22, fill=0x0B)
    var salt = hex_bytes("000102030405060708090a0b0c")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    assert_equal(
        derive(
            HashAlgorithm.SHA256,
            Span(salt),
            Span(secret),
            Span(info),
            42,
        ),
        hex_bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ),
    )


def test_reference_sha512() raises:
    var secret = List[UInt8](length=22, fill=0x0B)
    var salt = hex_bytes("000102030405060708090a0b0c")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    assert_equal(
        derive(
            HashAlgorithm.SHA512,
            Span(salt),
            Span(secret),
            Span(info),
            42,
        ),
        hex_bytes(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
