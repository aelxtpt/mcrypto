from std.testing import assert_false, assert_true, TestSuite
from mcrypto.traits import constant_time_equal


def test_constant_time_equal_contract() raises:
    var a: List[UInt8] = [1, 2, 3]
    var same: List[UInt8] = [1, 2, 3]
    var different: List[UInt8] = [1, 2, 4]
    var shorter: List[UInt8] = [1, 2]
    assert_true(constant_time_equal(Span(a), Span(same)))
    assert_false(constant_time_equal(Span(a), Span(different)))
    assert_false(constant_time_equal(Span(a), Span(shorter)))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
