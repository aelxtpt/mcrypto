"""Type-safe extendable-output function selection."""


@fieldwise_init
struct _XofAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct XofAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime SHAKE128 = XofAlgorithm(_XofAlgorithmToken[0]())
    comptime SHAKE256 = XofAlgorithm(_XofAlgorithmToken[1]())
    comptime TURBOSHAKE128 = XofAlgorithm(_XofAlgorithmToken[2]())
    comptime TURBOSHAKE256 = XofAlgorithm(_XofAlgorithmToken[3]())

    def __init__[value: UInt8](out self, token: _XofAlgorithmToken[value]):
        comptime assert value < 4, "invalid XofAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_xof_algorithm(name: String) raises -> XofAlgorithm:
    if name == "SHAKE128":
        return XofAlgorithm.SHAKE128
    if name == "SHAKE256":
        return XofAlgorithm.SHAKE256
    if name == "TurboSHAKE128":
        return XofAlgorithm.TURBOSHAKE128
    if name == "TurboSHAKE256":
        return XofAlgorithm.TURBOSHAKE256
    raise Error("unknown XOF algorithm")
