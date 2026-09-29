"""Type-safe cipher and mode selection with explicit text boundaries."""


@fieldwise_init
struct _BlockCipherToken[value: UInt8](ImplicitlyCopyable):
    pass


struct BlockCipherAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime AES = BlockCipherAlgorithm(_BlockCipherToken[0]())
    comptime RC2 = BlockCipherAlgorithm(_BlockCipherToken[1]())
    comptime RC5 = BlockCipherAlgorithm(_BlockCipherToken[2]())
    comptime RC6 = BlockCipherAlgorithm(_BlockCipherToken[3]())
    comptime MARS = BlockCipherAlgorithm(_BlockCipherToken[4]())
    comptime TWOFISH = BlockCipherAlgorithm(_BlockCipherToken[5]())
    comptime SERPENT = BlockCipherAlgorithm(_BlockCipherToken[6]())
    comptime CAST128 = BlockCipherAlgorithm(_BlockCipherToken[7]())
    comptime CAST256 = BlockCipherAlgorithm(_BlockCipherToken[8]())
    comptime ARIA = BlockCipherAlgorithm(_BlockCipherToken[9]())
    comptime BLOWFISH = BlockCipherAlgorithm(_BlockCipherToken[10]())
    comptime CAMELLIA = BlockCipherAlgorithm(_BlockCipherToken[11]())
    comptime CHAM64 = BlockCipherAlgorithm(_BlockCipherToken[12]())
    comptime CHAM128 = BlockCipherAlgorithm(_BlockCipherToken[13]())
    comptime DES = BlockCipherAlgorithm(_BlockCipherToken[14]())
    comptime DES_XEX3 = BlockCipherAlgorithm(_BlockCipherToken[15]())
    comptime DES_EDE2 = BlockCipherAlgorithm(_BlockCipherToken[16]())
    comptime DES_EDE3 = BlockCipherAlgorithm(_BlockCipherToken[17]())
    comptime THREE_WAY = BlockCipherAlgorithm(_BlockCipherToken[18]())
    comptime GOST = BlockCipherAlgorithm(_BlockCipherToken[19]())
    comptime HIGHT = BlockCipherAlgorithm(_BlockCipherToken[20]())
    comptime IDEA = BlockCipherAlgorithm(_BlockCipherToken[21]())
    comptime KALYNA128 = BlockCipherAlgorithm(_BlockCipherToken[22]())
    comptime KALYNA256 = BlockCipherAlgorithm(_BlockCipherToken[23]())
    comptime KALYNA512 = BlockCipherAlgorithm(_BlockCipherToken[24]())
    comptime LEA = BlockCipherAlgorithm(_BlockCipherToken[25]())
    comptime SAFER = BlockCipherAlgorithm(_BlockCipherToken[26]())
    comptime SAFER_K = BlockCipherAlgorithm(_BlockCipherToken[27]())
    comptime SAFER_SK = BlockCipherAlgorithm(_BlockCipherToken[28]())
    comptime SEED = BlockCipherAlgorithm(_BlockCipherToken[29]())
    comptime SHACAL2 = BlockCipherAlgorithm(_BlockCipherToken[30]())
    comptime SHARK = BlockCipherAlgorithm(_BlockCipherToken[31]())
    comptime SHARK_E = BlockCipherAlgorithm(_BlockCipherToken[32]())
    comptime SIMECK32 = BlockCipherAlgorithm(_BlockCipherToken[33]())
    comptime SIMECK64 = BlockCipherAlgorithm(_BlockCipherToken[34]())
    comptime SIMON64 = BlockCipherAlgorithm(_BlockCipherToken[35]())
    comptime SIMON128 = BlockCipherAlgorithm(_BlockCipherToken[36]())
    comptime SKIPJACK = BlockCipherAlgorithm(_BlockCipherToken[37]())
    comptime SPECK64 = BlockCipherAlgorithm(_BlockCipherToken[38]())
    comptime SPECK128 = BlockCipherAlgorithm(_BlockCipherToken[39]())
    comptime SM4 = BlockCipherAlgorithm(_BlockCipherToken[40]())
    comptime SQUARE = BlockCipherAlgorithm(_BlockCipherToken[41]())
    comptime TEA = BlockCipherAlgorithm(_BlockCipherToken[42]())
    comptime THREEFISH256 = BlockCipherAlgorithm(_BlockCipherToken[43]())
    comptime THREEFISH512 = BlockCipherAlgorithm(_BlockCipherToken[44]())
    comptime THREEFISH1024 = BlockCipherAlgorithm(_BlockCipherToken[45]())
    comptime XTEA = BlockCipherAlgorithm(_BlockCipherToken[46]())

    def __init__[value: UInt8](out self, token: _BlockCipherToken[value]):
        comptime assert value < 47, "invalid BlockCipherAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _StreamCipherToken[value: UInt8](ImplicitlyCopyable):
    pass


struct StreamCipherAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime CHACHA8 = StreamCipherAlgorithm(_StreamCipherToken[0]())
    comptime CHACHA12 = StreamCipherAlgorithm(_StreamCipherToken[1]())
    comptime CHACHA20 = StreamCipherAlgorithm(_StreamCipherToken[2]())
    comptime CHACHA20_IETF = StreamCipherAlgorithm(_StreamCipherToken[3]())
    comptime XCHACHA20 = StreamCipherAlgorithm(_StreamCipherToken[4]())
    comptime XCHACHA20_COUNTER1 = StreamCipherAlgorithm(_StreamCipherToken[5]())
    comptime PANAMA = StreamCipherAlgorithm(_StreamCipherToken[6]())
    comptime PANAMA_BE = StreamCipherAlgorithm(_StreamCipherToken[7]())
    comptime SALSA20 = StreamCipherAlgorithm(_StreamCipherToken[8]())
    comptime SALSA20_12 = StreamCipherAlgorithm(_StreamCipherToken[9]())
    comptime SALSA20_8 = StreamCipherAlgorithm(_StreamCipherToken[10]())
    comptime XSALSA20 = StreamCipherAlgorithm(_StreamCipherToken[11]())
    comptime SOSEMANUK = StreamCipherAlgorithm(_StreamCipherToken[12]())
    comptime ARC4 = StreamCipherAlgorithm(_StreamCipherToken[13]())
    comptime SEAL = StreamCipherAlgorithm(_StreamCipherToken[14]())
    comptime SEAL_LE = StreamCipherAlgorithm(_StreamCipherToken[15]())
    comptime WAKE_OFB = StreamCipherAlgorithm(_StreamCipherToken[16]())
    comptime RABBIT = StreamCipherAlgorithm(_StreamCipherToken[17]())
    comptime HC128 = StreamCipherAlgorithm(_StreamCipherToken[18]())
    comptime HC256 = StreamCipherAlgorithm(_StreamCipherToken[19]())

    def __init__[value: UInt8](out self, token: _StreamCipherToken[value]):
        comptime assert value < 20, "invalid StreamCipherAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _Chacha20StreamToken[value: UInt8](ImplicitlyCopyable):
    pass


struct Chacha20Stream(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime CHACHA20 = Chacha20Stream(_Chacha20StreamToken[0]())
    comptime CHACHA20_IETF = Chacha20Stream(_Chacha20StreamToken[1]())
    comptime XCHACHA20 = Chacha20Stream(_Chacha20StreamToken[2]())

    def __init__[value: UInt8](out self, token: _Chacha20StreamToken[value]):
        comptime assert value < 3, "invalid Chacha20Stream value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def chacha20_stream_name(algorithm: Chacha20Stream) raises -> String:
    if algorithm == Chacha20Stream.CHACHA20:
        return "ChaCha20"
    if algorithm == Chacha20Stream.CHACHA20_IETF:
        return "ChaCha20-IETF"
    if algorithm == Chacha20Stream.XCHACHA20:
        return "XChaCha20"
    raise Error("invalid ChaCha20 stream selector")


@fieldwise_init
struct _CipherModeToken[value: UInt8](ImplicitlyCopyable):
    pass


struct CipherMode(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ECB = CipherMode(_CipherModeToken[0]())
    comptime CBC = CipherMode(_CipherModeToken[1]())
    comptime CBC_CTS = CipherMode(_CipherModeToken[2]())
    comptime CFB = CipherMode(_CipherModeToken[3]())
    comptime OFB = CipherMode(_CipherModeToken[4]())
    comptime CTR = CipherMode(_CipherModeToken[5]())
    comptime XTS = CipherMode(_CipherModeToken[6]())

    def __init__[value: UInt8](out self, token: _CipherModeToken[value]):
        comptime assert value < 7, "invalid CipherMode value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def block_cipher_name(algorithm: BlockCipherAlgorithm) raises -> String:
    if algorithm == BlockCipherAlgorithm.AES:
        return "AES"
    if algorithm == BlockCipherAlgorithm.RC2:
        return "RC2"
    if algorithm == BlockCipherAlgorithm.RC5:
        return "RC5"
    if algorithm == BlockCipherAlgorithm.RC6:
        return "RC6"
    if algorithm == BlockCipherAlgorithm.MARS:
        return "MARS"
    if algorithm == BlockCipherAlgorithm.TWOFISH:
        return "Twofish"
    if algorithm == BlockCipherAlgorithm.SERPENT:
        return "Serpent"
    if algorithm == BlockCipherAlgorithm.CAST128:
        return "CAST-128"
    if algorithm == BlockCipherAlgorithm.CAST256:
        return "CAST-256"
    if algorithm == BlockCipherAlgorithm.ARIA:
        return "ARIA"
    if algorithm == BlockCipherAlgorithm.BLOWFISH:
        return "Blowfish"
    if algorithm == BlockCipherAlgorithm.CAMELLIA:
        return "Camellia"
    if algorithm == BlockCipherAlgorithm.CHAM64:
        return "CHAM-64"
    if algorithm == BlockCipherAlgorithm.CHAM128:
        return "CHAM-128"
    if algorithm == BlockCipherAlgorithm.DES:
        return "DES"
    if algorithm == BlockCipherAlgorithm.DES_XEX3:
        return "DES-XEX3"
    if algorithm == BlockCipherAlgorithm.DES_EDE2:
        return "DES-EDE2"
    if algorithm == BlockCipherAlgorithm.DES_EDE3:
        return "DES-EDE3"
    if algorithm == BlockCipherAlgorithm.THREE_WAY:
        return "3-WAY"
    if algorithm == BlockCipherAlgorithm.GOST:
        return "GOST"
    if algorithm == BlockCipherAlgorithm.HIGHT:
        return "HIGHT"
    if algorithm == BlockCipherAlgorithm.IDEA:
        return "IDEA"
    if algorithm == BlockCipherAlgorithm.KALYNA128:
        return "Kalyna-128"
    if algorithm == BlockCipherAlgorithm.KALYNA256:
        return "Kalyna-256"
    if algorithm == BlockCipherAlgorithm.KALYNA512:
        return "Kalyna-512"
    if algorithm == BlockCipherAlgorithm.LEA:
        return "LEA"
    if algorithm == BlockCipherAlgorithm.SAFER:
        return "SAFER"
    if algorithm == BlockCipherAlgorithm.SAFER_K:
        return "SAFER-K"
    if algorithm == BlockCipherAlgorithm.SAFER_SK:
        return "SAFER-SK"
    if algorithm == BlockCipherAlgorithm.SEED:
        return "SEED"
    if algorithm == BlockCipherAlgorithm.SHACAL2:
        return "SHACAL-2"
    if algorithm == BlockCipherAlgorithm.SHARK:
        return "SHARK"
    if algorithm == BlockCipherAlgorithm.SHARK_E:
        return "SHARK-E"
    if algorithm == BlockCipherAlgorithm.SIMECK32:
        return "SIMECK-32"
    if algorithm == BlockCipherAlgorithm.SIMECK64:
        return "SIMECK-64"
    if algorithm == BlockCipherAlgorithm.SIMON64:
        return "SIMON-64"
    if algorithm == BlockCipherAlgorithm.SIMON128:
        return "SIMON-128"
    if algorithm == BlockCipherAlgorithm.SKIPJACK:
        return "SKIPJACK"
    if algorithm == BlockCipherAlgorithm.SPECK64:
        return "SPECK-64"
    if algorithm == BlockCipherAlgorithm.SPECK128:
        return "SPECK-128"
    if algorithm == BlockCipherAlgorithm.SM4:
        return "SM4"
    if algorithm == BlockCipherAlgorithm.SQUARE:
        return "Square"
    if algorithm == BlockCipherAlgorithm.TEA:
        return "TEA"
    if algorithm == BlockCipherAlgorithm.THREEFISH256:
        return "Threefish-256"
    if algorithm == BlockCipherAlgorithm.THREEFISH512:
        return "Threefish-512"
    if algorithm == BlockCipherAlgorithm.THREEFISH1024:
        return "Threefish-1024"
    if algorithm == BlockCipherAlgorithm.XTEA:
        return "XTEA"
    raise Error("invalid block cipher selector")


def stream_cipher_name(algorithm: StreamCipherAlgorithm) raises -> String:
    if algorithm == StreamCipherAlgorithm.CHACHA8:
        return "ChaCha8"
    if algorithm == StreamCipherAlgorithm.CHACHA12:
        return "ChaCha12"
    if algorithm == StreamCipherAlgorithm.CHACHA20:
        return "ChaCha20"
    if algorithm == StreamCipherAlgorithm.CHACHA20_IETF:
        return "ChaCha20-IETF"
    if algorithm == StreamCipherAlgorithm.XCHACHA20:
        return "XChaCha20"
    if algorithm == StreamCipherAlgorithm.XCHACHA20_COUNTER1:
        return "XChaCha20-Counter1"
    if algorithm == StreamCipherAlgorithm.PANAMA:
        return "Panama"
    if algorithm == StreamCipherAlgorithm.PANAMA_BE:
        return "Panama-BE"
    if algorithm == StreamCipherAlgorithm.SALSA20:
        return "Salsa20"
    if algorithm == StreamCipherAlgorithm.SALSA20_12:
        return "Salsa20-12"
    if algorithm == StreamCipherAlgorithm.SALSA20_8:
        return "Salsa20-8"
    if algorithm == StreamCipherAlgorithm.XSALSA20:
        return "XSalsa20"
    if algorithm == StreamCipherAlgorithm.SOSEMANUK:
        return "Sosemanuk"
    if algorithm == StreamCipherAlgorithm.ARC4:
        return "ARC4"
    if algorithm == StreamCipherAlgorithm.SEAL:
        return "SEAL"
    if algorithm == StreamCipherAlgorithm.SEAL_LE:
        return "SEAL-LE"
    if algorithm == StreamCipherAlgorithm.WAKE_OFB:
        return "WAKE-OFB"
    if algorithm == StreamCipherAlgorithm.RABBIT:
        return "Rabbit"
    if algorithm == StreamCipherAlgorithm.HC128:
        return "HC-128"
    if algorithm == StreamCipherAlgorithm.HC256:
        return "HC-256"
    raise Error("invalid stream cipher selector")


def cipher_mode_name(mode: CipherMode) raises -> String:
    if mode == CipherMode.ECB:
        return "ECB"
    if mode == CipherMode.CBC:
        return "CBC"
    if mode == CipherMode.CBC_CTS:
        return "CBC-CTS"
    if mode == CipherMode.CFB:
        return "CFB"
    if mode == CipherMode.OFB:
        return "OFB"
    if mode == CipherMode.CTR:
        return "CTR"
    if mode == CipherMode.XTS:
        return "XTS"
    raise Error("invalid cipher mode selector")


def parse_block_cipher(name: String) raises -> BlockCipherAlgorithm:
    if name == "AES":
        return BlockCipherAlgorithm.AES
    if name == "RC2":
        return BlockCipherAlgorithm.RC2
    if name == "RC5":
        return BlockCipherAlgorithm.RC5
    if name == "RC6":
        return BlockCipherAlgorithm.RC6
    if name == "MARS":
        return BlockCipherAlgorithm.MARS
    if name == "Twofish":
        return BlockCipherAlgorithm.TWOFISH
    if name == "Serpent":
        return BlockCipherAlgorithm.SERPENT
    if name == "CAST-128":
        return BlockCipherAlgorithm.CAST128
    if name == "CAST-256":
        return BlockCipherAlgorithm.CAST256
    if name == "ARIA":
        return BlockCipherAlgorithm.ARIA
    if name == "Blowfish":
        return BlockCipherAlgorithm.BLOWFISH
    if name == "Camellia":
        return BlockCipherAlgorithm.CAMELLIA
    if name == "CHAM-64":
        return BlockCipherAlgorithm.CHAM64
    if name == "CHAM-128":
        return BlockCipherAlgorithm.CHAM128
    if name == "DES":
        return BlockCipherAlgorithm.DES
    if name == "DES-XEX3":
        return BlockCipherAlgorithm.DES_XEX3
    if name == "DES-EDE2":
        return BlockCipherAlgorithm.DES_EDE2
    if name == "DES-EDE3":
        return BlockCipherAlgorithm.DES_EDE3
    if name == "3-WAY" or name == "3-Way":
        return BlockCipherAlgorithm.THREE_WAY
    if name == "GOST":
        return BlockCipherAlgorithm.GOST
    if name == "HIGHT":
        return BlockCipherAlgorithm.HIGHT
    if name == "IDEA":
        return BlockCipherAlgorithm.IDEA
    if name == "Kalyna-128":
        return BlockCipherAlgorithm.KALYNA128
    if name == "Kalyna-256":
        return BlockCipherAlgorithm.KALYNA256
    if name == "Kalyna-512":
        return BlockCipherAlgorithm.KALYNA512
    if name == "LEA" or name == "LEA-128":
        return BlockCipherAlgorithm.LEA
    if name == "SAFER":
        return BlockCipherAlgorithm.SAFER
    if name == "SAFER-K":
        return BlockCipherAlgorithm.SAFER_K
    if name == "SAFER-SK":
        return BlockCipherAlgorithm.SAFER_SK
    if name == "SEED":
        return BlockCipherAlgorithm.SEED
    if name == "SHACAL-2":
        return BlockCipherAlgorithm.SHACAL2
    if name == "SHARK":
        return BlockCipherAlgorithm.SHARK
    if name == "SHARK-E":
        return BlockCipherAlgorithm.SHARK_E
    if name == "SIMECK-32":
        return BlockCipherAlgorithm.SIMECK32
    if name == "SIMECK-64":
        return BlockCipherAlgorithm.SIMECK64
    if name == "SIMON-64":
        return BlockCipherAlgorithm.SIMON64
    if name == "SIMON-128":
        return BlockCipherAlgorithm.SIMON128
    if name == "SKIPJACK" or name == "Skipjack":
        return BlockCipherAlgorithm.SKIPJACK
    if name == "SPECK-64":
        return BlockCipherAlgorithm.SPECK64
    if name == "SPECK-128":
        return BlockCipherAlgorithm.SPECK128
    if name == "SM4":
        return BlockCipherAlgorithm.SM4
    if name == "Square":
        return BlockCipherAlgorithm.SQUARE
    if name == "TEA":
        return BlockCipherAlgorithm.TEA
    if name == "Threefish-256" or name == "Threefish-256(256)":
        return BlockCipherAlgorithm.THREEFISH256
    if name == "Threefish-512" or name == "Threefish-512(512)":
        return BlockCipherAlgorithm.THREEFISH512
    if name == "Threefish-1024" or name == "Threefish-1024(1024)":
        return BlockCipherAlgorithm.THREEFISH1024
    if name == "XTEA":
        return BlockCipherAlgorithm.XTEA
    raise Error("unknown block cipher algorithm")


def parse_stream_cipher(name: String) raises -> StreamCipherAlgorithm:
    if name == "ChaCha8":
        return StreamCipherAlgorithm.CHACHA8
    if name == "ChaCha12":
        return StreamCipherAlgorithm.CHACHA12
    if name == "ChaCha20":
        return StreamCipherAlgorithm.CHACHA20
    if name == "ChaCha20-IETF" or name == "ChaCha20IETF":
        return StreamCipherAlgorithm.CHACHA20_IETF
    if name == "XChaCha20":
        return StreamCipherAlgorithm.XCHACHA20
    if name == "XChaCha20-Counter1":
        return StreamCipherAlgorithm.XCHACHA20_COUNTER1
    if name == "Panama":
        return StreamCipherAlgorithm.PANAMA
    if name == "Panama-BE":
        return StreamCipherAlgorithm.PANAMA_BE
    if name == "Salsa20":
        return StreamCipherAlgorithm.SALSA20
    if name == "Salsa20-12":
        return StreamCipherAlgorithm.SALSA20_12
    if name == "Salsa20-8":
        return StreamCipherAlgorithm.SALSA20_8
    if name == "XSalsa20":
        return StreamCipherAlgorithm.XSALSA20
    if name == "Sosemanuk":
        return StreamCipherAlgorithm.SOSEMANUK
    if name == "ARC4":
        return StreamCipherAlgorithm.ARC4
    if name == "SEAL":
        return StreamCipherAlgorithm.SEAL
    if name == "SEAL-LE":
        return StreamCipherAlgorithm.SEAL_LE
    if name == "WAKE-OFB":
        return StreamCipherAlgorithm.WAKE_OFB
    if name == "Rabbit":
        return StreamCipherAlgorithm.RABBIT
    if name == "HC-128":
        return StreamCipherAlgorithm.HC128
    if name == "HC-256":
        return StreamCipherAlgorithm.HC256
    raise Error("unknown stream cipher algorithm")


def parse_cipher_mode(name: String) raises -> CipherMode:
    if name == "ECB":
        return CipherMode.ECB
    if name == "CBC":
        return CipherMode.CBC
    if name == "CBC-CTS":
        return CipherMode.CBC_CTS
    if name == "CFB":
        return CipherMode.CFB
    if name == "OFB":
        return CipherMode.OFB
    if name == "CTR":
        return CipherMode.CTR
    if name == "XTS":
        return CipherMode.XTS
    raise Error("unknown cipher mode")


def parse_cipher_path(
    name: String,
) raises -> Tuple[BlockCipherAlgorithm, CipherMode]:
    for suffix, mode in [
        ("/CBC-CTS", CipherMode.CBC_CTS),
        ("/CTR", CipherMode.CTR),
        ("/ECB", CipherMode.ECB),
        ("/CBC", CipherMode.CBC),
        ("/CFB", CipherMode.CFB),
        ("/OFB", CipherMode.OFB),
        ("/XTS", CipherMode.XTS),
    ]:
        var cipher = name.removesuffix(suffix)
        if cipher.byte_length() != name.byte_length():
            return (parse_block_cipher(String(cipher)), mode)
    raise Error("unknown cipher path")
