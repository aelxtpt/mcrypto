"""Type-safe fixed-hash algorithm selection and name parsing."""


@fieldwise_init
struct _HashAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct HashAlgorithm(Equatable, ImplicitlyCopyable):
    """A validated fixed-hash algorithm selector.

    Use the scoped constants such as `HashAlgorithm.SHA256`. Convert external
    catalog or command-line names with `parse_hash_algorithm`.
    """

    var _value: UInt8

    comptime ADLER32 = HashAlgorithm(_HashAlgorithmToken[0]())
    comptime BLAKE2B = HashAlgorithm(_HashAlgorithmToken[1]())
    comptime BLAKE2S = HashAlgorithm(_HashAlgorithmToken[2]())
    comptime CRC32 = HashAlgorithm(_HashAlgorithmToken[3]())
    comptime CRC32C = HashAlgorithm(_HashAlgorithmToken[4]())
    comptime KECCAK224 = HashAlgorithm(_HashAlgorithmToken[5]())
    comptime KECCAK256 = HashAlgorithm(_HashAlgorithmToken[6]())
    comptime KECCAK384 = HashAlgorithm(_HashAlgorithmToken[7]())
    comptime KECCAK512 = HashAlgorithm(_HashAlgorithmToken[8]())
    comptime LSH224 = HashAlgorithm(_HashAlgorithmToken[9]())
    comptime LSH256 = HashAlgorithm(_HashAlgorithmToken[10]())
    comptime LSH384 = HashAlgorithm(_HashAlgorithmToken[11]())
    comptime LSH512 = HashAlgorithm(_HashAlgorithmToken[12]())
    comptime LSH512_256 = HashAlgorithm(_HashAlgorithmToken[13]())
    comptime MD2 = HashAlgorithm(_HashAlgorithmToken[14]())
    comptime MD4 = HashAlgorithm(_HashAlgorithmToken[15]())
    comptime MD5 = HashAlgorithm(_HashAlgorithmToken[16]())
    comptime PANAMA_HASH = HashAlgorithm(_HashAlgorithmToken[17]())
    comptime RIPEMD128 = HashAlgorithm(_HashAlgorithmToken[18]())
    comptime RIPEMD160 = HashAlgorithm(_HashAlgorithmToken[19]())
    comptime RIPEMD256 = HashAlgorithm(_HashAlgorithmToken[20]())
    comptime RIPEMD320 = HashAlgorithm(_HashAlgorithmToken[21]())
    comptime SHA1 = HashAlgorithm(_HashAlgorithmToken[22]())
    comptime SHA224 = HashAlgorithm(_HashAlgorithmToken[23]())
    comptime SHA256 = HashAlgorithm(_HashAlgorithmToken[24]())
    comptime SHA384 = HashAlgorithm(_HashAlgorithmToken[25]())
    comptime SHA512 = HashAlgorithm(_HashAlgorithmToken[26]())
    comptime SHA3_224 = HashAlgorithm(_HashAlgorithmToken[27]())
    comptime SHA3_256 = HashAlgorithm(_HashAlgorithmToken[28]())
    comptime SHA3_384 = HashAlgorithm(_HashAlgorithmToken[29]())
    comptime SHA3_512 = HashAlgorithm(_HashAlgorithmToken[30]())
    comptime SM3 = HashAlgorithm(_HashAlgorithmToken[31]())
    comptime TIGER = HashAlgorithm(_HashAlgorithmToken[32]())
    comptime WHIRLPOOL = HashAlgorithm(_HashAlgorithmToken[33]())

    def __init__[value: UInt8](out self, token: _HashAlgorithmToken[value]):
        comptime assert value < 34, "invalid HashAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def hash_algorithm_name(algorithm: HashAlgorithm) raises -> String:
    if algorithm == HashAlgorithm.ADLER32:
        return "Adler32"
    if algorithm == HashAlgorithm.BLAKE2B:
        return "BLAKE2b"
    if algorithm == HashAlgorithm.BLAKE2S:
        return "BLAKE2s"
    if algorithm == HashAlgorithm.CRC32:
        return "CRC32"
    if algorithm == HashAlgorithm.CRC32C:
        return "CRC32C"
    if algorithm == HashAlgorithm.KECCAK224:
        return "Keccak-224"
    if algorithm == HashAlgorithm.KECCAK256:
        return "Keccak-256"
    if algorithm == HashAlgorithm.KECCAK384:
        return "Keccak-384"
    if algorithm == HashAlgorithm.KECCAK512:
        return "Keccak-512"
    if algorithm == HashAlgorithm.LSH224:
        return "LSH-224"
    if algorithm == HashAlgorithm.LSH256:
        return "LSH-256"
    if algorithm == HashAlgorithm.LSH384:
        return "LSH-384"
    if algorithm == HashAlgorithm.LSH512:
        return "LSH-512"
    if algorithm == HashAlgorithm.LSH512_256:
        return "LSH-512-256"
    if algorithm == HashAlgorithm.MD2:
        return "MD2"
    if algorithm == HashAlgorithm.MD4:
        return "MD4"
    if algorithm == HashAlgorithm.MD5:
        return "MD5"
    if algorithm == HashAlgorithm.PANAMA_HASH:
        return "PanamaHash"
    if algorithm == HashAlgorithm.RIPEMD128:
        return "RIPEMD-128"
    if algorithm == HashAlgorithm.RIPEMD160:
        return "RIPEMD-160"
    if algorithm == HashAlgorithm.RIPEMD256:
        return "RIPEMD-256"
    if algorithm == HashAlgorithm.RIPEMD320:
        return "RIPEMD-320"
    if algorithm == HashAlgorithm.SHA1:
        return "SHA-1"
    if algorithm == HashAlgorithm.SHA224:
        return "SHA-224"
    if algorithm == HashAlgorithm.SHA256:
        return "SHA-256"
    if algorithm == HashAlgorithm.SHA384:
        return "SHA-384"
    if algorithm == HashAlgorithm.SHA512:
        return "SHA-512"
    if algorithm == HashAlgorithm.SHA3_224:
        return "SHA3-224"
    if algorithm == HashAlgorithm.SHA3_256:
        return "SHA3-256"
    if algorithm == HashAlgorithm.SHA3_384:
        return "SHA3-384"
    if algorithm == HashAlgorithm.SHA3_512:
        return "SHA3-512"
    if algorithm == HashAlgorithm.SM3:
        return "SM3"
    if algorithm == HashAlgorithm.TIGER:
        return "Tiger"
    if algorithm == HashAlgorithm.WHIRLPOOL:
        return "Whirlpool"
    raise Error("invalid hash algorithm selector")


def parse_hash_algorithm(name: String) raises -> HashAlgorithm:
    """Parse a canonical catalog/CLI name at an external boundary."""
    if name.byte_length() == 0:
        raise Error("unknown pure-Mojo hash algorithm")
    var initial = name.as_bytes()[0]
    if initial == UInt8(ord("S")):
        if name == "SHA-1":
            return HashAlgorithm.SHA1
        if name == "SHA-224":
            return HashAlgorithm.SHA224
        if name == "SHA-256":
            return HashAlgorithm.SHA256
        if name == "SHA-384":
            return HashAlgorithm.SHA384
        if name == "SHA-512":
            return HashAlgorithm.SHA512
        if name == "SHA3-224":
            return HashAlgorithm.SHA3_224
        if name == "SHA3-256":
            return HashAlgorithm.SHA3_256
        if name == "SHA3-384":
            return HashAlgorithm.SHA3_384
        if name == "SHA3-512":
            return HashAlgorithm.SHA3_512
        if name == "SM3":
            return HashAlgorithm.SM3
    elif initial == UInt8(ord("K")):
        if name == "Keccak-224":
            return HashAlgorithm.KECCAK224
        if name == "Keccak-256":
            return HashAlgorithm.KECCAK256
        if name == "Keccak-384":
            return HashAlgorithm.KECCAK384
        if name == "Keccak-512":
            return HashAlgorithm.KECCAK512
    elif initial == UInt8(ord("B")):
        if name == "BLAKE2s":
            return HashAlgorithm.BLAKE2S
        if name == "BLAKE2b":
            return HashAlgorithm.BLAKE2B
    elif initial == UInt8(ord("M")):
        if name == "MD2":
            return HashAlgorithm.MD2
        if name == "MD4":
            return HashAlgorithm.MD4
        if name == "MD5":
            return HashAlgorithm.MD5
    elif initial == UInt8(ord("R")):
        if name == "RIPEMD-128":
            return HashAlgorithm.RIPEMD128
        if name == "RIPEMD-160":
            return HashAlgorithm.RIPEMD160
        if name == "RIPEMD-256":
            return HashAlgorithm.RIPEMD256
        if name == "RIPEMD-320":
            return HashAlgorithm.RIPEMD320
    elif initial == UInt8(ord("C")):
        if name == "CRC32":
            return HashAlgorithm.CRC32
        if name == "CRC32C":
            return HashAlgorithm.CRC32C
    elif initial == UInt8(ord("L")):
        if name == "LSH-224":
            return HashAlgorithm.LSH224
        if name == "LSH-256":
            return HashAlgorithm.LSH256
        if name == "LSH-384":
            return HashAlgorithm.LSH384
        if name == "LSH-512":
            return HashAlgorithm.LSH512
        if name == "LSH-512-256":
            return HashAlgorithm.LSH512_256
    elif initial == UInt8(ord("A")) and name == "Adler32":
        return HashAlgorithm.ADLER32
    elif initial == UInt8(ord("P")) and name == "PanamaHash":
        return HashAlgorithm.PANAMA_HASH
    elif initial == UInt8(ord("T")) and name == "Tiger":
        return HashAlgorithm.TIGER
    elif initial == UInt8(ord("W")) and name == "Whirlpool":
        return HashAlgorithm.WHIRLPOOL
    raise Error("unknown pure-Mojo hash algorithm")
