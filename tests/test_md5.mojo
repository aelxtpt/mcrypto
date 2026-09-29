from std.testing import assert_equal, TestSuite
from mcrypto.hashes.md5 import md5


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_rfc1321_vectors() raises:
    assert_equal(
        md5("".as_bytes()), hex_bytes("d41d8cd98f00b204e9800998ecf8427e")
    )
    assert_equal(
        md5("a".as_bytes()), hex_bytes("0cc175b9c0f1b6a831c399e269772661")
    )
    assert_equal(
        md5("abc".as_bytes()), hex_bytes("900150983cd24fb0d6963f7d28e17f72")
    )
    assert_equal(
        md5("message digest".as_bytes()),
        hex_bytes("f96b697d7cb7938d525a2f31aaf161d0"),
    )
    assert_equal(
        md5("abcdefghijklmnopqrstuvwxyz".as_bytes()),
        hex_bytes("c3fcd3d76192e4007dfb496cca67e13b"),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
