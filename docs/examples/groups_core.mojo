from std.testing import assert_equal
from mcrypto.groups.algorithm import CoreAlgorithm, GroupFamily
from mcrypto.groups.scalar import scalar_base, scalar_mult, core_operation


def main() raises:
    var scalar = List[UInt8](length=32, fill=0x11)
    var basepoint = List[UInt8](length=32, fill=0)
    basepoint[0] = 9
    assert_equal(
        scalar_mult(GroupFamily.X25519, Span(scalar), Span(basepoint)),
        scalar_base(GroupFamily.X25519, Span(scalar)),
    )
    var key = List[UInt8](length=32, fill=0x22)
    var input = List[UInt8](length=16, fill=0x33)
    var core = core_operation(CoreAlgorithm.HCHACHA20, Span(key), Span(input))
    assert_equal(len(core), 32)
    print("groups-core: ok")
