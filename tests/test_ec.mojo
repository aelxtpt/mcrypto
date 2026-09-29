from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.math.biguint import BigUInt
from mcrypto.math.curve import CurveAlgorithm
from mcrypto.math.ec import ECPoint, PrimeCurve, named_curve


def test_small_curve_group_laws() raises:
    # y^2 = x^3 + 2x + 2 over F_17; (5,1) has order 19.
    var curve = PrimeCurve(BigUInt(17), BigUInt(2), BigUInt(2))
    var generator = ECPoint(BigUInt(5), BigUInt(1))
    assert_true(curve.is_on_curve(generator))
    var doubled = curve.double(generator)
    assert_equal(doubled.x.to_hex(), "6")
    assert_equal(doubled.y.to_hex(), "3")
    var tripled = curve.add(doubled, generator)
    assert_equal(tripled.x.to_hex(), "a")
    assert_equal(tripled.y.to_hex(), "6")
    var inverse = curve.negate(generator)
    assert_true(curve.add(generator, inverse).infinity)
    assert_true(curve.scalar_multiply(BigUInt(19), generator).infinity)
    var eighteen = curve.scalar_multiply(BigUInt(18), generator)
    assert_equal(eighteen.x.to_hex(), inverse.x.to_hex())
    assert_equal(eighteen.y.to_hex(), inverse.y.to_hex())
    var joint = curve.double_scalar_multiply(
        BigUInt(7), generator, BigUInt(5), doubled
    )
    var separate = curve.add(
        curve.scalar_multiply(BigUInt(7), generator),
        curve.scalar_multiply(BigUInt(5), doubled),
    )
    assert_equal(joint.x.to_hex(), separate.x.to_hex())
    assert_equal(joint.y.to_hex(), separate.y.to_hex())


def test_curve_rejects_invalid_points() raises:
    var curve = PrimeCurve(BigUInt(17), BigUInt(2), BigUInt(2))
    var invalid = ECPoint(BigUInt(1), BigUInt(1))
    assert_false(curve.is_on_curve(invalid))
    with assert_raises():
        _ = curve.double(invalid)


def test_nist_specialized_reduction_doubles_generators() raises:
    var p384 = named_curve(CurveAlgorithm.P384)
    var doubled384 = p384.curve.scalar_multiply(BigUInt(2), p384.generator)
    assert_equal(
        doubled384.x.to_hex(),
        "8d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61",
    )
    var p521 = named_curve(CurveAlgorithm.P521)
    var doubled521 = p521.curve.scalar_multiply(BigUInt(2), p521.generator)
    assert_equal(
        doubled521.x.to_hex(),
        "433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
