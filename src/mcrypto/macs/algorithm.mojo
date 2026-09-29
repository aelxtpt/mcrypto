"""Type-safe message-authentication algorithm selection."""


@fieldwise_init
struct _MacAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct MacAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime HMAC_SHA1 = MacAlgorithm(_MacAlgorithmToken[0]())
    comptime HMAC_SHA256 = MacAlgorithm(_MacAlgorithmToken[1]())
    comptime HMAC_SHA512 = MacAlgorithm(_MacAlgorithmToken[2]())
    comptime HMAC_SHA512_256 = MacAlgorithm(_MacAlgorithmToken[3]())
    comptime RIPEMD160_HMAC = MacAlgorithm(_MacAlgorithmToken[4]())
    comptime BLAKE2S_MAC = MacAlgorithm(_MacAlgorithmToken[5]())
    comptime BLAKE2B_MAC = MacAlgorithm(_MacAlgorithmToken[6]())
    comptime POLY1305 = MacAlgorithm(_MacAlgorithmToken[7]())
    comptime POLY1305_AES = MacAlgorithm(_MacAlgorithmToken[8]())
    comptime SIPHASH_2_4 = MacAlgorithm(_MacAlgorithmToken[9]())
    comptime SIPHASH_4_8 = MacAlgorithm(_MacAlgorithmToken[10]())
    comptime SIPHASH_X_2_4 = MacAlgorithm(_MacAlgorithmToken[11]())
    comptime CMAC = MacAlgorithm(_MacAlgorithmToken[12]())
    comptime CBC_MAC = MacAlgorithm(_MacAlgorithmToken[13]())
    comptime DMAC = MacAlgorithm(_MacAlgorithmToken[14]())
    comptime TWO_TRACK_MAC = MacAlgorithm(_MacAlgorithmToken[15]())
    comptime GMAC = MacAlgorithm(_MacAlgorithmToken[16]())
    comptime VMAC = MacAlgorithm(_MacAlgorithmToken[17]())
    comptime PANAMA_MAC = MacAlgorithm(_MacAlgorithmToken[18]())

    def __init__[value: UInt8](out self, token: _MacAlgorithmToken[value]):
        comptime assert value < 19, "invalid MacAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _HmacAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct HmacAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime SHA1 = HmacAlgorithm(_HmacAlgorithmToken[0]())
    comptime SHA256 = HmacAlgorithm(_HmacAlgorithmToken[1]())
    comptime SHA512 = HmacAlgorithm(_HmacAlgorithmToken[2]())
    comptime SHA512_256 = HmacAlgorithm(_HmacAlgorithmToken[3]())
    comptime RIPEMD160 = HmacAlgorithm(_HmacAlgorithmToken[4]())

    def __init__[value: UInt8](out self, token: _HmacAlgorithmToken[value]):
        comptime assert value < 5, "invalid HmacAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _SipHashAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct SipHashAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime SIPHASH_2_4 = SipHashAlgorithm(_SipHashAlgorithmToken[0]())
    comptime SIPHASH_4_8 = SipHashAlgorithm(_SipHashAlgorithmToken[1]())
    comptime SIPHASH_X_2_4 = SipHashAlgorithm(_SipHashAlgorithmToken[2]())

    def __init__[value: UInt8](out self, token: _SipHashAlgorithmToken[value]):
        comptime assert value < 3, "invalid SipHashAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def hmac_algorithm_name(algorithm: HmacAlgorithm) raises -> String:
    if algorithm == HmacAlgorithm.SHA1:
        return "HMAC-SHA1"
    if algorithm == HmacAlgorithm.SHA256:
        return "HMAC-SHA256"
    if algorithm == HmacAlgorithm.SHA512:
        return "HMAC-SHA512"
    if algorithm == HmacAlgorithm.SHA512_256:
        return "HMAC-SHA512-256"
    if algorithm == HmacAlgorithm.RIPEMD160:
        return "RIPEMD160-HMAC"
    raise Error("invalid HMAC selector")


def siphash_algorithm_name(algorithm: SipHashAlgorithm) raises -> String:
    if algorithm == SipHashAlgorithm.SIPHASH_2_4:
        return "SipHash-2-4"
    if algorithm == SipHashAlgorithm.SIPHASH_4_8:
        return "SipHash-4-8"
    if algorithm == SipHashAlgorithm.SIPHASH_X_2_4:
        return "SipHash-x-2-4"
    raise Error("invalid SipHash selector")


def as_hmac_algorithm(algorithm: MacAlgorithm) raises -> HmacAlgorithm:
    if algorithm == MacAlgorithm.HMAC_SHA1:
        return HmacAlgorithm.SHA1
    if algorithm == MacAlgorithm.HMAC_SHA256:
        return HmacAlgorithm.SHA256
    if algorithm == MacAlgorithm.HMAC_SHA512:
        return HmacAlgorithm.SHA512
    if algorithm == MacAlgorithm.HMAC_SHA512_256:
        return HmacAlgorithm.SHA512_256
    if algorithm == MacAlgorithm.RIPEMD160_HMAC:
        return HmacAlgorithm.RIPEMD160
    raise Error("MAC algorithm is not an HMAC variant")


def as_siphash_algorithm(algorithm: MacAlgorithm) raises -> SipHashAlgorithm:
    if algorithm == MacAlgorithm.SIPHASH_2_4:
        return SipHashAlgorithm.SIPHASH_2_4
    if algorithm == MacAlgorithm.SIPHASH_4_8:
        return SipHashAlgorithm.SIPHASH_4_8
    if algorithm == MacAlgorithm.SIPHASH_X_2_4:
        return SipHashAlgorithm.SIPHASH_X_2_4
    raise Error("MAC algorithm is not a SipHash variant")


def parse_mac_algorithm(name: String) raises -> MacAlgorithm:
    if name == "HMAC" or name == "HMAC(SHA-1)" or name == "HMAC-SHA1":
        return MacAlgorithm.HMAC_SHA1
    if name == "HMAC(SHA-256)" or name == "HMAC-SHA256":
        return MacAlgorithm.HMAC_SHA256
    if name == "HMAC(SHA-512)" or name == "HMAC-SHA512":
        return MacAlgorithm.HMAC_SHA512
    if name == "HMAC-SHA512-256":
        return MacAlgorithm.HMAC_SHA512_256
    if name == "RIPEMD160-HMAC" or name == "HMAC-RIPEMD160":
        return MacAlgorithm.RIPEMD160_HMAC
    if name == "BLAKE2s-MAC":
        return MacAlgorithm.BLAKE2S_MAC
    if name == "BLAKE2b-MAC":
        return MacAlgorithm.BLAKE2B_MAC
    if name == "Poly1305":
        return MacAlgorithm.POLY1305
    if name == "Poly1305-AES":
        return MacAlgorithm.POLY1305_AES
    if name == "SipHash-2-4":
        return MacAlgorithm.SIPHASH_2_4
    if name == "SipHash-4-8":
        return MacAlgorithm.SIPHASH_4_8
    if name == "SipHash-x-2-4":
        return MacAlgorithm.SIPHASH_X_2_4
    if name == "CMAC" or name == "CMAC(AES)":
        return MacAlgorithm.CMAC
    if name == "CBC-MAC" or name == "CBC-MAC(AES)":
        return MacAlgorithm.CBC_MAC
    if name == "DMAC" or name == "DMAC(AES)":
        return MacAlgorithm.DMAC
    if name == "Two-Track-MAC":
        return MacAlgorithm.TWO_TRACK_MAC
    if name == "GMAC" or name == "GMAC(AES)":
        return MacAlgorithm.GMAC
    if name == "VMAC":
        return MacAlgorithm.VMAC
    if name == "PanamaMAC":
        return MacAlgorithm.PANAMA_MAC
    raise Error("unknown MAC algorithm")
