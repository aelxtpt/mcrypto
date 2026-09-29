from std.testing import assert_equal, TestSuite
from mcrypto.hashes.whirlpool import whirlpool


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


def test_iso_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        whirlpool(Span(empty)),
        hex_bytes(
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
        ),
    )
    assert_equal(
        whirlpool("abc".as_bytes()),
        hex_bytes(
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
        ),
    )
    assert_equal(
        whirlpool("message digest".as_bytes()),
        hex_bytes(
            "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e"
        ),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
