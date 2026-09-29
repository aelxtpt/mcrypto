"""Type-safe AEAD algorithm selection and external-name parsing."""


@fieldwise_init
struct _AeadAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct AeadAlgorithm(Equatable, ImplicitlyCopyable):
    """Validated AEAD selector. Use scoped constants, not textual names."""

    var _value: UInt8

    comptime GCM = AeadAlgorithm(_AeadAlgorithmToken[0]())
    comptime CCM = AeadAlgorithm(_AeadAlgorithmToken[1]())
    comptime EAX = AeadAlgorithm(_AeadAlgorithmToken[2]())
    comptime AEGIS128L = AeadAlgorithm(_AeadAlgorithmToken[3]())
    comptime AEGIS256 = AeadAlgorithm(_AeadAlgorithmToken[4]())
    comptime AES256_GCM = AeadAlgorithm(_AeadAlgorithmToken[5]())
    comptime CHACHA20_POLY1305 = AeadAlgorithm(_AeadAlgorithmToken[6]())
    comptime CHACHA20_POLY1305_IETF = AeadAlgorithm(_AeadAlgorithmToken[7]())
    comptime XCHACHA20_POLY1305_IETF = AeadAlgorithm(_AeadAlgorithmToken[8]())

    def __init__[value: UInt8](out self, token: _AeadAlgorithmToken[value]):
        comptime assert value < 9, "invalid AeadAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _AegisAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct AegisAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime AEGIS128L = AegisAlgorithm(_AegisAlgorithmToken[0]())
    comptime AEGIS256 = AegisAlgorithm(_AegisAlgorithmToken[1]())

    def __init__[value: UInt8](out self, token: _AegisAlgorithmToken[value]):
        comptime assert value < 2, "invalid AegisAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _ChachaAeadAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct ChachaAeadAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime CHACHA20_POLY1305 = ChachaAeadAlgorithm(
        _ChachaAeadAlgorithmToken[0]()
    )
    comptime CHACHA20_POLY1305_IETF = ChachaAeadAlgorithm(
        _ChachaAeadAlgorithmToken[1]()
    )
    comptime XCHACHA20_POLY1305_IETF = ChachaAeadAlgorithm(
        _ChachaAeadAlgorithmToken[2]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _ChachaAeadAlgorithmToken[value]):
        comptime assert value < 3, "invalid ChachaAeadAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def as_aegis_algorithm(algorithm: AeadAlgorithm) raises -> AegisAlgorithm:
    if algorithm == AeadAlgorithm.AEGIS128L:
        return AegisAlgorithm.AEGIS128L
    if algorithm == AeadAlgorithm.AEGIS256:
        return AegisAlgorithm.AEGIS256
    raise Error("AEAD algorithm is not an AEGIS variant")


def as_chacha_aead_algorithm(
    algorithm: AeadAlgorithm,
) raises -> ChachaAeadAlgorithm:
    if algorithm == AeadAlgorithm.CHACHA20_POLY1305:
        return ChachaAeadAlgorithm.CHACHA20_POLY1305
    if algorithm == AeadAlgorithm.CHACHA20_POLY1305_IETF:
        return ChachaAeadAlgorithm.CHACHA20_POLY1305_IETF
    if algorithm == AeadAlgorithm.XCHACHA20_POLY1305_IETF:
        return ChachaAeadAlgorithm.XCHACHA20_POLY1305_IETF
    raise Error("AEAD algorithm is not a ChaCha variant")


def parse_aead_algorithm(name: String) raises -> AeadAlgorithm:
    """Parse an AEAD name received from a catalog, CLI, or protocol."""
    if name == "GCM" or name == "AES-GCM":
        return AeadAlgorithm.GCM
    if name == "CCM" or name == "AES-CCM":
        return AeadAlgorithm.CCM
    if name == "EAX" or name == "AES-EAX":
        return AeadAlgorithm.EAX
    if name == "AEGIS-128L" or name == "AEGIS128L":
        return AeadAlgorithm.AEGIS128L
    if name == "AEGIS-256" or name == "AEGIS256":
        return AeadAlgorithm.AEGIS256
    if name == "AES-256-GCM":
        return AeadAlgorithm.AES256_GCM
    if name == "ChaCha20-Poly1305" or name == "ChaCha20/Poly1305":
        return AeadAlgorithm.CHACHA20_POLY1305
    if name == "ChaCha20-Poly1305-IETF" or name == "ChaCha20Poly1305":
        return AeadAlgorithm.CHACHA20_POLY1305_IETF
    if name == "XChaCha20-Poly1305-IETF" or name == "XChaCha20Poly1305":
        return AeadAlgorithm.XCHACHA20_POLY1305_IETF
    raise Error("unknown AEAD algorithm")
