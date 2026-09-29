"""Type-safe key-encapsulation algorithm selection."""


@fieldwise_init
struct _KemAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct KemAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ML_KEM_768 = KemAlgorithm(_KemAlgorithmToken[0]())
    comptime X_WING = KemAlgorithm(_KemAlgorithmToken[1]())

    def __init__[value: UInt8](out self, token: _KemAlgorithmToken[value]):
        comptime assert value < 2, "invalid KemAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_kem_algorithm(name: String) raises -> KemAlgorithm:
    if name == "ML-KEM-768":
        return KemAlgorithm.ML_KEM_768
    if name == "X-Wing":
        return KemAlgorithm.X_WING
    raise Error("unknown KEM algorithm")
