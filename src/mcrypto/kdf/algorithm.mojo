"""Type-safe key-derivation algorithm selection."""


@fieldwise_init
struct _KdfAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct KdfAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime HKDF_SHA256 = KdfAlgorithm(_KdfAlgorithmToken[0]())
    comptime HKDF_SHA512 = KdfAlgorithm(_KdfAlgorithmToken[1]())
    comptime PBKDF1 = KdfAlgorithm(_KdfAlgorithmToken[2]())
    comptime PBKDF2_HMAC_SHA1 = KdfAlgorithm(_KdfAlgorithmToken[3]())
    comptime PBKDF2_HMAC_SHA256 = KdfAlgorithm(_KdfAlgorithmToken[4]())
    comptime PBKDF2_HMAC_SHA512 = KdfAlgorithm(_KdfAlgorithmToken[5]())
    comptime PKCS12_PBKDF_SHA1 = KdfAlgorithm(_KdfAlgorithmToken[6]())
    comptime SCRYPT = KdfAlgorithm(_KdfAlgorithmToken[7]())
    comptime ARGON2I = KdfAlgorithm(_KdfAlgorithmToken[8]())
    comptime ARGON2ID = KdfAlgorithm(_KdfAlgorithmToken[9]())

    def __init__[value: UInt8](out self, token: _KdfAlgorithmToken[value]):
        comptime assert value < 10, "invalid KdfAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _Argon2AlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct Argon2Algorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ARGON2I = Argon2Algorithm(_Argon2AlgorithmToken[0]())
    comptime ARGON2ID = Argon2Algorithm(_Argon2AlgorithmToken[1]())

    def __init__[value: UInt8](out self, token: _Argon2AlgorithmToken[value]):
        comptime assert value < 2, "invalid Argon2Algorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_argon2_algorithm(name: String) raises -> Argon2Algorithm:
    if name == "Argon2i":
        return Argon2Algorithm.ARGON2I
    if name == "Argon2id":
        return Argon2Algorithm.ARGON2ID
    raise Error("unknown Argon2 algorithm")


def parse_kdf_algorithm(name: String) raises -> KdfAlgorithm:
    if name == "HKDF(SHA-256)" or name == "HKDF-SHA256":
        return KdfAlgorithm.HKDF_SHA256
    if name == "HKDF(SHA-512)" or name == "HKDF-SHA512":
        return KdfAlgorithm.HKDF_SHA512
    if name == "PBKDF1":
        return KdfAlgorithm.PBKDF1
    if name == "PBKDF2-HMAC-SHA1":
        return KdfAlgorithm.PBKDF2_HMAC_SHA1
    if name == "PBKDF2" or name == "PBKDF2-HMAC-SHA256":
        return KdfAlgorithm.PBKDF2_HMAC_SHA256
    if name == "PBKDF2-HMAC-SHA512":
        return KdfAlgorithm.PBKDF2_HMAC_SHA512
    if name == "PKCS12-PBKDF" or name == "PKCS12-PBKDF-SHA1":
        return KdfAlgorithm.PKCS12_PBKDF_SHA1
    if (
        name == "Scrypt"
        or name == "scrypt"
        or name == "Scrypt-Salsa20-8-SHA256"
    ):
        return KdfAlgorithm.SCRYPT
    if name == "Argon2i":
        return KdfAlgorithm.ARGON2I
    if name == "Argon2id":
        return KdfAlgorithm.ARGON2ID
    raise Error("unknown KDF algorithm")
