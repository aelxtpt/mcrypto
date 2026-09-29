from std.testing import assert_equal, TestSuite
from mcrypto.macs.cmac import authenticate, authenticate_four_into


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else 87
        c -= 48 if c <= 57 else 87
        o.append(UInt8(a * 16 + c))
    return o^


def test_rfc4493_vectors() raises:
    var key = h("2b7e151628aed2a6abf7158809cf4f3c")
    var empty = List[UInt8]()
    var one = h("6bc1bee22e409f96e93d7e117393172a")
    assert_equal(
        authenticate(Span(key), Span(empty)),
        h("bb1d6929e95937287fa37d129b756746"),
    )
    assert_equal(
        authenticate(Span(key), Span(one)),
        h("070a16b46b4d4144f79bdd9dd04a287c"),
    )


def test_four_way_cmac_matches_independent_tags() raises:
    var key = h("2b7e151628aed2a6abf7158809cf4f3c")
    var first = List[UInt8](length=300, fill=0x12)
    var second = List[UInt8](length=300, fill=0x34)
    var third = List[UInt8](length=300, fill=0x56)
    var fourth = List[UInt8](length=300, fill=0x78)
    var first_output = List[UInt8](length=16, fill=0)
    var second_output = List[UInt8](length=16, fill=0)
    var third_output = List[UInt8](length=16, fill=0)
    var fourth_output = List[UInt8](length=16, fill=0)
    authenticate_four_into(
        Span(key),
        Span(first),
        Span(second),
        Span(third),
        Span(fourth),
        Span(first_output),
        Span(second_output),
        Span(third_output),
        Span(fourth_output),
    )
    assert_equal(first_output, authenticate(Span(key), Span(first)))
    assert_equal(second_output, authenticate(Span(key), Span(second)))
    assert_equal(third_output, authenticate(Span(key), Span(third)))
    assert_equal(fourth_output, authenticate(Span(key), Span(fourth)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
