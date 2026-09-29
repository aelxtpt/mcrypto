"""Type-safe named elliptic-curve selection."""


@fieldwise_init
struct _CurveAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct CurveAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime P256 = CurveAlgorithm(_CurveAlgorithmToken[0]())
    comptime P384 = CurveAlgorithm(_CurveAlgorithmToken[1]())
    comptime P521 = CurveAlgorithm(_CurveAlgorithmToken[2]())
    comptime BRAINPOOL_P256R1 = CurveAlgorithm(_CurveAlgorithmToken[3]())

    def __init__[value: UInt8](out self, token: _CurveAlgorithmToken[value]):
        comptime assert value < 4, "invalid CurveAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_curve_algorithm(name: String) raises -> CurveAlgorithm:
    if name == "P-256":
        return CurveAlgorithm.P256
    if name == "P-384":
        return CurveAlgorithm.P384
    if name == "P-521":
        return CurveAlgorithm.P521
    if name == "brainpoolP256r1" or name == "Brainpool-P256":
        return CurveAlgorithm.BRAINPOOL_P256R1
    raise Error("unknown elliptic curve")


def curve_name(curve: CurveAlgorithm) raises -> String:
    if curve == CurveAlgorithm.P256:
        return "P-256"
    if curve == CurveAlgorithm.P384:
        return "P-384"
    if curve == CurveAlgorithm.P521:
        return "P-521"
    if curve == CurveAlgorithm.BRAINPOOL_P256R1:
        return "brainpoolP256r1"
    raise Error("invalid elliptic-curve selector")
