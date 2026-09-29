"""Type-safe IPcrypt family selection."""


@fieldwise_init
struct _IpcryptAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct IpcryptAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime IPCRYPT = IpcryptAlgorithm(_IpcryptAlgorithmToken[0]())
    comptime ND = IpcryptAlgorithm(_IpcryptAlgorithmToken[1]())
    comptime NDX = IpcryptAlgorithm(_IpcryptAlgorithmToken[2]())
    comptime PFX = IpcryptAlgorithm(_IpcryptAlgorithmToken[3]())

    def __init__[value: UInt8](out self, token: _IpcryptAlgorithmToken[value]):
        comptime assert value < 4, "invalid IpcryptAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_ipcrypt_algorithm(name: String) raises -> IpcryptAlgorithm:
    if name == "IPcrypt":
        return IpcryptAlgorithm.IPCRYPT
    if name == "IPcrypt-ND":
        return IpcryptAlgorithm.ND
    if name == "IPcrypt-NDX":
        return IpcryptAlgorithm.NDX
    if name == "IPcrypt-PFX":
        return IpcryptAlgorithm.PFX
    raise Error("unknown IPcrypt algorithm")
