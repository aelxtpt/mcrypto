from std.testing import assert_equal, TestSuite
from mcrypto.hashes.keccak import (
    keccak,
    keccak_four_into,
    sha3,
    sha3_four_into,
    shake,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i]) - (48 if bytes[i] <= 57 else 87)
        var low = Int(bytes[i + 1]) - (48 if bytes[i + 1] <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_nist_sha3_empty_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        sha3(224, Span(empty)),
        hex_bytes("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
    )
    assert_equal(
        sha3(256, Span(empty)),
        hex_bytes(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ),
    )
    assert_equal(
        sha3(384, Span(empty)),
        hex_bytes(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        ),
    )
    assert_equal(
        sha3(512, Span(empty)),
        hex_bytes(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        ),
    )


def test_keccak_and_shake_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        keccak(256, Span(empty)),
        hex_bytes(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ),
    )
    assert_equal(
        shake(128, Span(empty), 32),
        hex_bytes(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        ),
    )
    assert_equal(
        shake(256, Span(empty), 64),
        hex_bytes(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        ),
    )


def test_four_way_sha3_and_keccak_match_independent_hashes() raises:
    var first = List[UInt8](length=300, fill=0x12)
    var second = List[UInt8](length=300, fill=0x34)
    var third = List[UInt8](length=300, fill=0x56)
    var fourth = List[UInt8](length=300, fill=0x78)
    for bits in [224, 256, 384, 512]:
        var first_output = List[UInt8](length=bits // 8, fill=0)
        var second_output = List[UInt8](length=bits // 8, fill=0)
        var third_output = List[UInt8](length=bits // 8, fill=0)
        var fourth_output = List[UInt8](length=bits // 8, fill=0)
        sha3_four_into(
            bits,
            Span(first),
            Span(second),
            Span(third),
            Span(fourth),
            Span(first_output),
            Span(second_output),
            Span(third_output),
            Span(fourth_output),
        )
        assert_equal(first_output, sha3(bits, Span(first)))
        assert_equal(second_output, sha3(bits, Span(second)))
        assert_equal(third_output, sha3(bits, Span(third)))
        assert_equal(fourth_output, sha3(bits, Span(fourth)))
        keccak_four_into(
            bits,
            Span(first),
            Span(second),
            Span(third),
            Span(fourth),
            Span(first_output),
            Span(second_output),
            Span(third_output),
            Span(fourth_output),
        )
        assert_equal(first_output, keccak(bits, Span(first)))
        assert_equal(second_output, keccak(bits, Span(second)))
        assert_equal(third_output, keccak(bits, Span(third)))
        assert_equal(fourth_output, keccak(bits, Span(fourth)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
