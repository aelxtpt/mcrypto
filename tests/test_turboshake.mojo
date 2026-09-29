from std.testing import assert_equal, assert_false, TestSuite
from mcrypto.hashes.turboshake import TurboSHAKE, turboshake128, turboshake256


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


def test_interop_vectors() raises:
    var empty = List[UInt8]()
    assert_equal(
        turboshake128(Span(empty), 64),
        hex_bytes(
            "1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c3e8ccae2a4dae56c84a04c2385c03c15e8193bdf58737363321691c05462c8df"
        ),
    )
    assert_equal(
        turboshake128("abc".as_bytes(), 32),
        hex_bytes(
            "dcf1646dfe993a8eb6b782d1faaca6d82416a5dcf1de98ee3c6dbc5e1dc63018"
        ),
    )
    assert_equal(
        turboshake256(Span(empty), 64),
        hex_bytes(
            "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0"
        ),
    )
    assert_equal(
        turboshake256("abc".as_bytes(), 32),
        hex_bytes(
            "63824b1431a7372e85edc022c9d7afdd027472fcfa33c887d6f5aaf8dc5d4db6"
        ),
    )


def test_streaming_and_rate_boundaries() raises:
    var state = TurboSHAKE(128)
    state.update("a".as_bytes())
    state.update("bc".as_bytes())
    var first = state.squeeze(16)
    var second = state.squeeze(16)
    for byte in second:
        first.append(byte)
    assert_equal(
        first,
        hex_bytes(
            "dcf1646dfe993a8eb6b782d1faaca6d82416a5dcf1de98ee3c6dbc5e1dc63018"
        ),
    )

    var block128 = List[UInt8](length=168, fill=0)
    assert_equal(
        turboshake128(Span(block128), 32),
        hex_bytes(
            "dba6e267bdd567db0ad2636e61f1ae589a81c1a9c11f7f76930a35ea424756d0"
        ),
    )
    var block256 = List[UInt8](length=136, fill=0)
    assert_equal(
        turboshake256(Span(block256), 32),
        hex_bytes(
            "91effd08dd4cccb689c626b4649367ad5a2ebfab61611769a37493fa701228ea"
        ),
    )


def test_custom_domain_is_distinct() raises:
    var standard = turboshake128("abc".as_bytes(), 32)
    var customized = turboshake128("abc".as_bytes(), 32, 0x99)
    assert_false(standard == customized)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
