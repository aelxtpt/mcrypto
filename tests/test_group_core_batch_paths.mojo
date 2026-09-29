from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.groups.algorithm import BatchedCoreAlgorithm
from mcrypto.groups.scalar import (
    core_operation_eight,
    core_operation_eight_into,
    hchacha20_core,
    hsalsa20_core,
    salsa20_core,
)


def _scalar_core[
    key_origin: Origin, input_origin: Origin
](
    family: BatchedCoreAlgorithm,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if family == BatchedCoreAlgorithm.HCHACHA20:
        return hchacha20_core(key, input)
    if family == BatchedCoreAlgorithm.HSALSA20:
        return hsalsa20_core(key, input)
    if family == BatchedCoreAlgorithm.SALSA20:
        return salsa20_core[20](key, input)
    if family == BatchedCoreAlgorithm.SALSA20_12:
        return salsa20_core[12](key, input)
    return salsa20_core[8](key, input)


def test_core_operation_eight_and_into_match_scalar() raises:
    var key = List[UInt8](capacity=32)
    var input = List[UInt8](capacity=16)
    for i in range(32):
        key.append(UInt8((i * 17 + 3) & 0xFF))
    for i in range(16):
        input.append(UInt8((i * 29 + 5) & 0xFF))
    for family in [
        BatchedCoreAlgorithm.HCHACHA20,
        BatchedCoreAlgorithm.HSALSA20,
        BatchedCoreAlgorithm.SALSA20,
        BatchedCoreAlgorithm.SALSA20_12,
        BatchedCoreAlgorithm.SALSA20_8,
    ]:
        var expected = _scalar_core(family, Span(key), Span(input))
        assert_equal(
            core_operation_eight(family, Span(key), Span(input)), expected
        )
        var storage = List[UInt8](length=len(expected) + 7, fill=0xA5)
        core_operation_eight_into(
            family, Span(key), Span(input), Span(storage)[7:]
        )
        for i in range(7):
            assert_equal(storage[i], UInt8(0xA5))
        for i in range(len(expected)):
            assert_equal(storage[7 + i], expected[i])


def test_core_operation_eight_rejects_invalid_spans() raises:
    var key = List[UInt8](length=32, fill=1)
    var input = List[UInt8](length=16, fill=2)
    var short_key = List[UInt8](length=31, fill=1)
    var short_input = List[UInt8](length=15, fill=2)
    var output32 = List[UInt8](length=32, fill=0)
    var output63 = List[UInt8](length=63, fill=0)
    with assert_raises():
        core_operation_eight_into(
            BatchedCoreAlgorithm.HCHACHA20,
            Span(short_key),
            Span(input),
            Span(output32),
        )
    with assert_raises():
        core_operation_eight_into(
            BatchedCoreAlgorithm.HCHACHA20,
            Span(key),
            Span(short_input),
            Span(output32),
        )
    with assert_raises():
        core_operation_eight_into(
            BatchedCoreAlgorithm.SALSA20,
            Span(key),
            Span(input),
            Span(output63),
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
