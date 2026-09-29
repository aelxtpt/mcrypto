"""Type-safe public-key encryption algorithm selection."""


@fieldwise_init
struct _PublicKeyEncryptionToken[value: UInt8](ImplicitlyCopyable):
    pass


struct PublicKeyEncryptionAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime RSA = PublicKeyEncryptionAlgorithm(_PublicKeyEncryptionToken[0]())
    comptime RSA_PKCS1 = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[1]()
    )
    comptime RSA_OAEP_SHA1 = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[2]()
    )
    comptime RSA_OAEP_SHA256 = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[3]()
    )
    comptime ELGAMAL = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[4]()
    )
    comptime RABIN = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[5]()
    )
    comptime RABIN_WILLIAMS = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[6]()
    )
    comptime RABIN_OAEP_SHA1 = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[7]()
    )
    comptime LUC = PublicKeyEncryptionAlgorithm(_PublicKeyEncryptionToken[8]())
    comptime LUC_OAEP_SHA1 = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[9]()
    )
    comptime LUCELG = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[10]()
    )
    comptime DLIES = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[11]()
    )
    comptime ECIES = PublicKeyEncryptionAlgorithm(
        _PublicKeyEncryptionToken[12]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _PublicKeyEncryptionToken[value]):
        comptime assert value < 13, "invalid PublicKeyEncryptionAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _RsaEncryptionAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct RsaEncryptionAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime PKCS1 = RsaEncryptionAlgorithm(_RsaEncryptionAlgorithmToken[0]())
    comptime OAEP_SHA1 = RsaEncryptionAlgorithm(
        _RsaEncryptionAlgorithmToken[1]()
    )
    comptime OAEP_SHA256 = RsaEncryptionAlgorithm(
        _RsaEncryptionAlgorithmToken[2]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _RsaEncryptionAlgorithmToken[value]):
        comptime assert value < 3, "invalid RsaEncryptionAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def rsa_encryption_name(algorithm: RsaEncryptionAlgorithm) raises -> String:
    if algorithm == RsaEncryptionAlgorithm.PKCS1:
        return "RSA/PKCS1-1.5"
    if algorithm == RsaEncryptionAlgorithm.OAEP_SHA1:
        return "RSA/OAEP-MGF1(SHA-1)"
    if algorithm == RsaEncryptionAlgorithm.OAEP_SHA256:
        return "RSA/OAEP-MGF1(SHA-256)"
    raise Error("invalid RSA encryption selector")


def as_rsa_encryption_algorithm(
    algorithm: PublicKeyEncryptionAlgorithm,
) raises -> RsaEncryptionAlgorithm:
    if algorithm == PublicKeyEncryptionAlgorithm.RSA:
        return RsaEncryptionAlgorithm.OAEP_SHA256
    if algorithm == PublicKeyEncryptionAlgorithm.RSA_PKCS1:
        return RsaEncryptionAlgorithm.PKCS1
    if algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1:
        return RsaEncryptionAlgorithm.OAEP_SHA1
    if algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256:
        return RsaEncryptionAlgorithm.OAEP_SHA256
    raise Error("public-key algorithm is not an RSA encryption variant")


def public_key_encryption_name(
    algorithm: PublicKeyEncryptionAlgorithm,
) raises -> String:
    if algorithm == PublicKeyEncryptionAlgorithm.RSA:
        return "RSA"
    if algorithm == PublicKeyEncryptionAlgorithm.RSA_PKCS1:
        return "RSA/PKCS1-1.5"
    if algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1:
        return "RSA/OAEP-MGF1(SHA-1)"
    if algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256:
        return "RSA/OAEP-MGF1(SHA-256)"
    if algorithm == PublicKeyEncryptionAlgorithm.ELGAMAL:
        return "ElGamal"
    if algorithm == PublicKeyEncryptionAlgorithm.RABIN:
        return "Rabin"
    if algorithm == PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS:
        return "Rabin-Williams"
    if algorithm == PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1:
        return "Rabin/OAEP-MGF1(SHA-1)"
    if algorithm == PublicKeyEncryptionAlgorithm.LUC:
        return "LUC"
    if algorithm == PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1:
        return "LUC/OAEP-MGF1(SHA-1)"
    if algorithm == PublicKeyEncryptionAlgorithm.LUCELG:
        return "LUCELG"
    if algorithm == PublicKeyEncryptionAlgorithm.DLIES:
        return "DLIES"
    if algorithm == PublicKeyEncryptionAlgorithm.ECIES:
        return "ECIES"
    raise Error("invalid public-key encryption selector")


def parse_public_key_encryption_algorithm(
    name: String,
) raises -> PublicKeyEncryptionAlgorithm:
    if name == "RSA":
        return PublicKeyEncryptionAlgorithm.RSA
    if name == "RSA/PKCS1-1.5":
        return PublicKeyEncryptionAlgorithm.RSA_PKCS1
    if name == "RSA/OAEP-MGF1(SHA-1)":
        return PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1
    if name == "RSA/OAEP-MGF1(SHA-256)":
        return PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256
    if name == "ElGamal":
        return PublicKeyEncryptionAlgorithm.ELGAMAL
    if name == "Rabin":
        return PublicKeyEncryptionAlgorithm.RABIN
    if name == "Rabin-Williams":
        return PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS
    if name == "Rabin/OAEP-MGF1(SHA-1)":
        return PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1
    if name == "LUC":
        return PublicKeyEncryptionAlgorithm.LUC
    if name == "LUC/OAEP-MGF1(SHA-1)":
        return PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1
    if name == "LUCELG" or name == "LUC-IES(KDF2(SHA-1),XOR,HMAC(SHA-1))":
        return PublicKeyEncryptionAlgorithm.LUCELG
    if name == "DLIES":
        return PublicKeyEncryptionAlgorithm.DLIES
    if name == "ECIES" or name == "ECIES(P-256,SHA-256)":
        return PublicKeyEncryptionAlgorithm.ECIES
    raise Error("unknown public-key encryption algorithm")
