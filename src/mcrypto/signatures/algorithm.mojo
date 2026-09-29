"""Type-safe signature algorithm selection."""


@fieldwise_init
struct _SignatureAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct SignatureAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime RSA = SignatureAlgorithm(_SignatureAlgorithmToken[0]())
    comptime RSA_PSS_SHA1 = SignatureAlgorithm(_SignatureAlgorithmToken[1]())
    comptime RSA_PSS_SHA256 = SignatureAlgorithm(_SignatureAlgorithmToken[2]())
    comptime RSA_PKCS1_SHA1 = SignatureAlgorithm(_SignatureAlgorithmToken[3]())
    comptime RSA_PKCS1_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[4]()
    )
    comptime DSA = SignatureAlgorithm(_SignatureAlgorithmToken[5]())
    comptime DSA_RFC6979 = SignatureAlgorithm(_SignatureAlgorithmToken[6]())
    comptime ELGAMAL = SignatureAlgorithm(_SignatureAlgorithmToken[7]())
    comptime NR = SignatureAlgorithm(_SignatureAlgorithmToken[8]())
    comptime RABIN_WILLIAMS = SignatureAlgorithm(_SignatureAlgorithmToken[9]())
    comptime RABIN_PSSR_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[10]()
    )
    comptime RABIN_EMSA2_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[11]()
    )
    comptime LUC = SignatureAlgorithm(_SignatureAlgorithmToken[12]())
    comptime LUC_PKCS1_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[13]()
    )
    comptime LUC_HMP_EMSA1_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[14]()
    )
    comptime ESIGN = SignatureAlgorithm(_SignatureAlgorithmToken[15]())
    comptime ECDSA = SignatureAlgorithm(_SignatureAlgorithmToken[16]())
    comptime ECDSA_RFC6979 = SignatureAlgorithm(_SignatureAlgorithmToken[17]())
    comptime ECDSA_P256_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[18]()
    )
    comptime ECDSA_RFC6979_P256_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[19]()
    )
    comptime ECGDSA = SignatureAlgorithm(_SignatureAlgorithmToken[20]())
    comptime ECGDSA_P256_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[21]()
    )
    comptime ECGDSA_BRAINPOOL_P256_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[22]()
    )
    comptime ECNR = SignatureAlgorithm(_SignatureAlgorithmToken[23]())
    comptime ECNR_P256_SHA256 = SignatureAlgorithm(
        _SignatureAlgorithmToken[24]()
    )
    comptime ED25519 = SignatureAlgorithm(_SignatureAlgorithmToken[25]())

    def __init__[
        value: UInt8
    ](out self, token: _SignatureAlgorithmToken[value]):
        comptime assert value < 26, "invalid SignatureAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _ECSignatureSchemeToken[value: UInt8](ImplicitlyCopyable):
    pass


struct ECSignatureScheme(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ECDSA = ECSignatureScheme(_ECSignatureSchemeToken[0]())
    comptime ECGDSA = ECSignatureScheme(_ECSignatureSchemeToken[1]())
    comptime ECNR = ECSignatureScheme(_ECSignatureSchemeToken[2]())

    def __init__[value: UInt8](out self, token: _ECSignatureSchemeToken[value]):
        comptime assert value < 3, "invalid ECSignatureScheme value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _RsaSignatureAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct RsaSignatureAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime PSS_SHA1 = RsaSignatureAlgorithm(_RsaSignatureAlgorithmToken[0]())
    comptime PSS_SHA256 = RsaSignatureAlgorithm(
        _RsaSignatureAlgorithmToken[1]()
    )
    comptime PKCS1_SHA1 = RsaSignatureAlgorithm(
        _RsaSignatureAlgorithmToken[2]()
    )
    comptime PKCS1_SHA256 = RsaSignatureAlgorithm(
        _RsaSignatureAlgorithmToken[3]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _RsaSignatureAlgorithmToken[value]):
        comptime assert value < 4, "invalid RsaSignatureAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def rsa_signature_name(algorithm: RsaSignatureAlgorithm) raises -> String:
    if algorithm == RsaSignatureAlgorithm.PSS_SHA1:
        return "RSA/PSS-MGF1(SHA-1)"
    if algorithm == RsaSignatureAlgorithm.PSS_SHA256:
        return "RSA/PSS-MGF1(SHA-256)"
    if algorithm == RsaSignatureAlgorithm.PKCS1_SHA1:
        return "RSA/PKCS1-1.5(SHA-1)"
    if algorithm == RsaSignatureAlgorithm.PKCS1_SHA256:
        return "RSA/PKCS1-1.5(SHA-256)"
    raise Error("invalid RSA signature selector")


def as_rsa_signature_algorithm(
    algorithm: SignatureAlgorithm,
) raises -> RsaSignatureAlgorithm:
    if algorithm == SignatureAlgorithm.RSA:
        return RsaSignatureAlgorithm.PSS_SHA256
    if algorithm == SignatureAlgorithm.RSA_PSS_SHA1:
        return RsaSignatureAlgorithm.PSS_SHA1
    if algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
        return RsaSignatureAlgorithm.PSS_SHA256
    if algorithm == SignatureAlgorithm.RSA_PKCS1_SHA1:
        return RsaSignatureAlgorithm.PKCS1_SHA1
    if algorithm == SignatureAlgorithm.RSA_PKCS1_SHA256:
        return RsaSignatureAlgorithm.PKCS1_SHA256
    raise Error("signature algorithm is not an RSA variant")


def signature_algorithm_name(algorithm: SignatureAlgorithm) raises -> String:
    if algorithm == SignatureAlgorithm.RSA:
        return "RSA"
    if algorithm == SignatureAlgorithm.RSA_PSS_SHA1:
        return "RSA/PSS-MGF1(SHA-1)"
    if algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
        return "RSA/PSS-MGF1(SHA-256)"
    if algorithm == SignatureAlgorithm.RSA_PKCS1_SHA1:
        return "RSA/PKCS1-1.5(SHA-1)"
    if algorithm == SignatureAlgorithm.RSA_PKCS1_SHA256:
        return "RSA/PKCS1-1.5(SHA-256)"
    if algorithm == SignatureAlgorithm.DSA:
        return "DSA"
    if algorithm == SignatureAlgorithm.DSA_RFC6979:
        return "DSA-RFC6979"
    if algorithm == SignatureAlgorithm.ELGAMAL:
        return "ElGamal"
    if algorithm == SignatureAlgorithm.NR:
        return "NR"
    if algorithm == SignatureAlgorithm.RABIN_WILLIAMS:
        return "Rabin-Williams"
    if algorithm == SignatureAlgorithm.RABIN_PSSR_SHA256:
        return "Rabin/PSSR(SHA-256)"
    if algorithm == SignatureAlgorithm.RABIN_EMSA2_SHA256:
        return "Rabin-Williams/IEEE-P1363-EMSA2(SHA-256)"
    if algorithm == SignatureAlgorithm.LUC:
        return "LUC"
    if algorithm == SignatureAlgorithm.LUC_PKCS1_SHA256:
        return "LUC/PKCS1-1.5(SHA-256)"
    if algorithm == SignatureAlgorithm.LUC_HMP_EMSA1_SHA256:
        return "LUC-HMP/EMSA1(SHA-256)"
    if algorithm == SignatureAlgorithm.ESIGN:
        return "ESIGN"
    if algorithm == SignatureAlgorithm.ECDSA:
        return "ECDSA"
    if algorithm == SignatureAlgorithm.ECDSA_RFC6979:
        return "ECDSA-RFC6979"
    if algorithm == SignatureAlgorithm.ECDSA_P256_SHA256:
        return "ECDSA(P-256,SHA-256)"
    if algorithm == SignatureAlgorithm.ECDSA_RFC6979_P256_SHA256:
        return "ECDSA-RFC6979(P-256,SHA-256)"
    if algorithm == SignatureAlgorithm.ECGDSA:
        return "ECGDSA"
    if algorithm == SignatureAlgorithm.ECGDSA_P256_SHA256:
        return "ECGDSA(P-256,SHA-256)"
    if algorithm == SignatureAlgorithm.ECGDSA_BRAINPOOL_P256_SHA256:
        return "ECGDSA(Brainpool-P256,SHA-256)"
    if algorithm == SignatureAlgorithm.ECNR:
        return "ECNR"
    if algorithm == SignatureAlgorithm.ECNR_P256_SHA256:
        return "ECNR(P-256,SHA-256)"
    if algorithm == SignatureAlgorithm.ED25519:
        return "Ed25519"
    raise Error("invalid signature algorithm selector")


def parse_signature_algorithm(name: String) raises -> SignatureAlgorithm:
    if name == "RSA":
        return SignatureAlgorithm.RSA
    if name == "RSA/PSS-MGF1(SHA-1)":
        return SignatureAlgorithm.RSA_PSS_SHA1
    if name == "RSA/PSS-MGF1(SHA-256)":
        return SignatureAlgorithm.RSA_PSS_SHA256
    if name == "RSA/PKCS1-1.5(SHA-1)":
        return SignatureAlgorithm.RSA_PKCS1_SHA1
    if name == "RSA/PKCS1-1.5(SHA-256)":
        return SignatureAlgorithm.RSA_PKCS1_SHA256
    if name == "DSA":
        return SignatureAlgorithm.DSA
    if name == "DSA-RFC6979":
        return SignatureAlgorithm.DSA_RFC6979
    if name == "ElGamal":
        return SignatureAlgorithm.ELGAMAL
    if name == "NR":
        return SignatureAlgorithm.NR
    if name == "Rabin-Williams":
        return SignatureAlgorithm.RABIN_WILLIAMS
    if name == "Rabin/PSSR(SHA-256)":
        return SignatureAlgorithm.RABIN_PSSR_SHA256
    if name == "Rabin-Williams/IEEE-P1363-EMSA2(SHA-256)":
        return SignatureAlgorithm.RABIN_EMSA2_SHA256
    if name == "LUC":
        return SignatureAlgorithm.LUC
    if name == "LUC/PKCS1-1.5(SHA-256)":
        return SignatureAlgorithm.LUC_PKCS1_SHA256
    if name == "LUC-HMP/EMSA1(SHA-256)":
        return SignatureAlgorithm.LUC_HMP_EMSA1_SHA256
    if name == "ESIGN":
        return SignatureAlgorithm.ESIGN
    if name == "ECDSA":
        return SignatureAlgorithm.ECDSA
    if name == "ECDSA-RFC6979":
        return SignatureAlgorithm.ECDSA_RFC6979
    if name == "ECDSA(P-256,SHA-256)":
        return SignatureAlgorithm.ECDSA_P256_SHA256
    if name == "ECDSA-RFC6979(P-256,SHA-256)":
        return SignatureAlgorithm.ECDSA_RFC6979_P256_SHA256
    if name == "ECGDSA":
        return SignatureAlgorithm.ECGDSA
    if name == "ECGDSA(P-256,SHA-256)":
        return SignatureAlgorithm.ECGDSA_P256_SHA256
    if name == "ECGDSA(Brainpool-P256,SHA-256)":
        return SignatureAlgorithm.ECGDSA_BRAINPOOL_P256_SHA256
    if name == "ECNR":
        return SignatureAlgorithm.ECNR
    if name == "ECNR(P-256,SHA-256)":
        return SignatureAlgorithm.ECNR_P256_SHA256
    if name == "Ed25519":
        return SignatureAlgorithm.ED25519
    raise Error("unknown signature algorithm")
