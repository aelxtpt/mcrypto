"""Type-safe deterministic and hardware random-generator selection."""


@fieldwise_init
struct _DrbgAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct DrbgAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime HASH_SHA256 = DrbgAlgorithm(_DrbgAlgorithmToken[0]())
    comptime HASH_SHA512 = DrbgAlgorithm(_DrbgAlgorithmToken[1]())
    comptime HMAC_SHA256 = DrbgAlgorithm(_DrbgAlgorithmToken[2]())
    comptime HMAC_SHA512 = DrbgAlgorithm(_DrbgAlgorithmToken[3]())

    def __init__[value: UInt8](out self, token: _DrbgAlgorithmToken[value]):
        comptime assert value < 4, "invalid DrbgAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _RandomAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct RandomAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ANSI_X917_3DES = RandomAlgorithm(_RandomAlgorithmToken[0]())
    comptime ANSI_X931_AES = RandomAlgorithm(_RandomAlgorithmToken[1]())
    comptime RANDOM_POOL = RandomAlgorithm(_RandomAlgorithmToken[2]())
    comptime RDRAND = RandomAlgorithm(_RandomAlgorithmToken[3]())
    comptime RDSEED = RandomAlgorithm(_RandomAlgorithmToken[4]())

    def __init__[value: UInt8](out self, token: _RandomAlgorithmToken[value]):
        comptime assert value < 5, "invalid RandomAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _HardwareRandomAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct HardwareRandomAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime RDRAND = HardwareRandomAlgorithm(
        _HardwareRandomAlgorithmToken[0]()
    )
    comptime RDSEED = HardwareRandomAlgorithm(
        _HardwareRandomAlgorithmToken[1]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _HardwareRandomAlgorithmToken[value]):
        comptime assert value < 2, "invalid HardwareRandomAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _X917CipherToken[value: UInt8](ImplicitlyCopyable):
    pass


struct X917Cipher(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime AES = X917Cipher(_X917CipherToken[0]())
    comptime TDES = X917Cipher(_X917CipherToken[1]())

    def __init__[value: UInt8](out self, token: _X917CipherToken[value]):
        comptime assert value < 2, "invalid X917Cipher value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_hardware_random_algorithm(
    name: String,
) raises -> HardwareRandomAlgorithm:
    if name == "RDRAND":
        return HardwareRandomAlgorithm.RDRAND
    if name == "RDSEED":
        return HardwareRandomAlgorithm.RDSEED
    raise Error("unknown hardware random algorithm")


def parse_x917_cipher(name: String) raises -> X917Cipher:
    if name == "AES":
        return X917Cipher.AES
    if name == "3DES":
        return X917Cipher.TDES
    raise Error("unknown X9.17 block cipher")


def parse_drbg_algorithm(name: String) raises -> DrbgAlgorithm:
    if name == "Hash-DRBG-SHA256":
        return DrbgAlgorithm.HASH_SHA256
    if name == "Hash-DRBG-SHA512":
        return DrbgAlgorithm.HASH_SHA512
    if name == "HMAC-DRBG-SHA256":
        return DrbgAlgorithm.HMAC_SHA256
    if name == "HMAC-DRBG-SHA512":
        return DrbgAlgorithm.HMAC_SHA512
    raise Error("unknown DRBG algorithm")


def parse_random_algorithm(name: String) raises -> RandomAlgorithm:
    if name == "ANSI-X9.17" or name == "ANSI-X9.31-AES":
        return RandomAlgorithm.ANSI_X931_AES
    if name == "ANSI-X9.17-3DES":
        return RandomAlgorithm.ANSI_X917_3DES
    if name == "RandomPool":
        return RandomAlgorithm.RANDOM_POOL
    if name == "RDRAND":
        return RandomAlgorithm.RDRAND
    if name == "RDSEED":
        return RandomAlgorithm.RDSEED
    raise Error("unknown random-generator algorithm")
