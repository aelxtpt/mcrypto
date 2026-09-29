from std.testing import assert_equal, TestSuite
from mcrypto.hashes.md_legacy import md2, md4


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_rfc1319_md2_vectors() raises:
    assert_equal(
        md2("".as_bytes()), hex_bytes("8350e5a3e24c153df2275c9f80692773")
    )
    assert_equal(
        md2("a".as_bytes()), hex_bytes("32ec01ec4a6dac72c0ab96fb34c0b5d1")
    )
    assert_equal(
        md2("abc".as_bytes()), hex_bytes("da853b0d3f88d99b30283a69e6ded6bb")
    )
    assert_equal(
        md2("message digest".as_bytes()),
        hex_bytes("ab4f496bfb2a530b219ff33031fe06b0"),
    )


def test_rfc1320_md4_vectors() raises:
    assert_equal(
        md4("".as_bytes()), hex_bytes("31d6cfe0d16ae931b73c59d7e0c089c0")
    )
    assert_equal(
        md4("a".as_bytes()), hex_bytes("bde52cb31de33e46245e05fbdbd6fb24")
    )
    assert_equal(
        md4("abc".as_bytes()), hex_bytes("a448017aaf21d8525fc10ae87aa6729d")
    )
    assert_equal(
        md4("message digest".as_bytes()),
        hex_bytes("d9130a8164549fe818874806e1c7014b"),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
