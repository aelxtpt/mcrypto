"""Type-safe key-agreement algorithm selection."""


@fieldwise_init
struct _AgreementAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct AgreementAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime DH = AgreementAlgorithm(_AgreementAlgorithmToken[0]())
    comptime DH2 = AgreementAlgorithm(_AgreementAlgorithmToken[1]())
    comptime MQV = AgreementAlgorithm(_AgreementAlgorithmToken[2]())
    comptime HMQV = AgreementAlgorithm(_AgreementAlgorithmToken[3]())
    comptime FHMQV = AgreementAlgorithm(_AgreementAlgorithmToken[4]())
    comptime LUCDIF = AgreementAlgorithm(_AgreementAlgorithmToken[5]())
    comptime XTR_DH = AgreementAlgorithm(_AgreementAlgorithmToken[6]())
    comptime ECDH_P256 = AgreementAlgorithm(_AgreementAlgorithmToken[7]())
    comptime ECMQV_P256 = AgreementAlgorithm(_AgreementAlgorithmToken[8]())
    comptime ECHMQV_P256 = AgreementAlgorithm(_AgreementAlgorithmToken[9]())
    comptime ECFHMQV_P256 = AgreementAlgorithm(_AgreementAlgorithmToken[10]())
    comptime X25519 = AgreementAlgorithm(_AgreementAlgorithmToken[11]())

    def __init__[
        value: UInt8
    ](out self, token: _AgreementAlgorithmToken[value]):
        comptime assert value < 12, "invalid AgreementAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_agreement_algorithm(name: String) raises -> AgreementAlgorithm:
    if name == "DH":
        return AgreementAlgorithm.DH
    if name == "DH2":
        return AgreementAlgorithm.DH2
    if name == "MQV":
        return AgreementAlgorithm.MQV
    if name == "HMQV":
        return AgreementAlgorithm.HMQV
    if name == "FHMQV":
        return AgreementAlgorithm.FHMQV
    if name == "LUCDIF":
        return AgreementAlgorithm.LUCDIF
    if name == "XTR-DH":
        return AgreementAlgorithm.XTR_DH
    if name == "ECDH" or name == "ECDH-P256":
        return AgreementAlgorithm.ECDH_P256
    if name == "ECMQV" or name == "ECMQV-P256":
        return AgreementAlgorithm.ECMQV_P256
    if name == "ECHMQV" or name == "ECHMQV-P256":
        return AgreementAlgorithm.ECHMQV_P256
    if name == "ECFHMQV" or name == "ECFHMQV-P256":
        return AgreementAlgorithm.ECFHMQV_P256
    if name == "X25519":
        return AgreementAlgorithm.X25519
    raise Error("unknown key-agreement algorithm")
