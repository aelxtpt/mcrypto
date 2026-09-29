"""Pure-Mojo public-key encryption dispatcher."""

from .algorithm import (
    PublicKeyEncryptionAlgorithm,
    as_rsa_encryption_algorithm,
)
from ..math.curve import CurveAlgorithm
from ..math.biguint import BigUInt
from ..signatures.finite_field import (
    PrimeGroup,
    encode_parameters,
    rfc5114_group1,
)
from ._legacy_math import generate_safe_prime_pair
from .rsa import (
    generate_keypair as rsa_keypair,
    encrypt as rsa_encrypt,
    decrypt as rsa_decrypt,
)
from ..signatures.elgamal import (
    generate_keypair as elgamal_keypair,
    encrypt as elgamal_encrypt,
    decrypt as elgamal_decrypt,
)
from .rabin import (
    encryption_keypair as rabin_keypair,
    encryption_apply as rabin_apply,
    encryption_invert as rabin_invert,
)
from .luc import (
    keypair as luc_keypair,
    apply as luc_apply,
    invert as luc_invert,
    lucelg_keypair,
    lucelg_encrypt,
    lucelg_decrypt,
)
from ._legacy_math import decode_key
from ._trapdoor_encoding import oaep_sha1_encode, oaep_sha1_decode
from .dlies import (
    keypair as dlies_keypair,
    encrypt as dlies_encrypt,
    decrypt as dlies_decrypt,
)
from .ecies import (
    ECIESEncryptor,
    ECIESDecryptor,
    ECIESKeyGenerator,
    keypair as ecies_keypair,
    encrypt as ecies_encrypt,
    decrypt as ecies_decrypt,
)


def _append_u32(mut output: List[UInt8], value: Int) raises:
    if value < 0 or value > 0xFFFFFFFF:
        raise Error("public-key frame component is too large")
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


def _read_u32[
    origin: Origin
](input: Span[UInt8, origin], offset: Int) raises -> Int:
    if offset < 0 or offset + 4 > len(input):
        raise Error("truncated public-key frame")
    return Int(
        (UInt32(input[offset]) << 24)
        | (UInt32(input[offset + 1]) << 16)
        | (UInt32(input[offset + 2]) << 8)
        | UInt32(input[offset + 3])
    )


def _frame[
    origin: Origin
](magic: StaticString, payload: Span[UInt8, origin]) raises -> List[UInt8]:
    var output = List[UInt8](capacity=8 + len(payload))
    for byte in magic.as_bytes():
        output.append(byte)
    _append_u32(output, len(payload))
    for byte in payload:
        output.append(byte)
    return output^


def _unframe[
    origin: Origin
](input: Span[UInt8, origin], magic: StaticString) raises -> List[UInt8]:
    var expected = magic.as_bytes()
    if len(input) < 8:
        raise Error("truncated public-key frame")
    for i in range(4):
        if input[i] != expected[i]:
            raise Error("public-key frame has the wrong type")
    var size = _read_u32(input, 4)
    if size < 0 or 8 + size != len(input):
        raise Error("invalid public-key frame length")
    var output = List[UInt8](capacity=size)
    for i in range(size):
        output.append(input[8 + i])
    return output^


def _group_frame[
    po: Origin, ko: Origin
](
    magic: StaticString, parameters: Span[UInt8, po], key: Span[UInt8, ko]
) raises -> List[UInt8]:
    var payload = List[UInt8](capacity=4 + len(parameters) + len(key))
    _append_u32(payload, len(parameters))
    for byte in parameters:
        payload.append(byte)
    for byte in key:
        payload.append(byte)
    return _frame(magic, Span(payload))


def _group_unframe[
    origin: Origin
](input: Span[UInt8, origin], magic: StaticString) raises -> Tuple[
    List[UInt8], List[UInt8]
]:
    var payload = _unframe(input, magic)
    var parameters_size = _read_u32(Span(payload), 0)
    if parameters_size <= 0 or 4 + parameters_size >= len(payload):
        raise Error("invalid finite-field key frame")
    var parameters = List[UInt8](capacity=parameters_size)
    var key = List[UInt8](capacity=len(payload) - 4 - parameters_size)
    for i in range(parameters_size):
        parameters.append(payload[4 + i])
    for i in range(4 + parameters_size, len(payload)):
        key.append(payload[i])
    return (parameters^, key^)


def _prime_group(bits: Int) raises -> List[UInt8]:
    if bits < 128:
        raise Error("finite-field key size must be at least 128 bits")
    if bits == 1024:
        return encode_parameters(rfc5114_group1())
    var primes = generate_safe_prime_pair(bits)
    var p = primes[0].copy()
    var q = primes[1].copy()
    var g = BigUInt(2)
    while g.modular_power(q, p).compare(BigUInt(1)) != 0:
        g.add_small(1)
    return encode_parameters(PrimeGroup(p, q, g))


def _modulus_size[
    origin: Origin
](key: Span[UInt8, origin], rabin: Bool, private: Bool) raises -> Int:
    var modulus: BigUInt
    if rabin:
        if private:
            var components = decode_key(key, "RBS1", 6)
            modulus = components[0].copy()
        else:
            var components = decode_key(key, "RBW1", 3)
            modulus = components[0].copy()
    else:
        if private:
            var components = decode_key(key, "LUS1", 5)
            modulus = components[0].copy()
        else:
            var components = decode_key(key, "LUC1", 2)
            modulus = components[0].copy()
    return (modulus.bit_length() + 7) // 8


def _oaep_encrypt[
    ko: Origin, mo: Origin
](key: Span[UInt8, ko], message: Span[UInt8, mo], rabin: Bool) raises -> List[
    UInt8
]:
    var size = _modulus_size(key, rabin, False)
    var encoded = oaep_sha1_encode(message, size)
    return rabin_apply(key, Span(encoded)) if rabin else luc_apply(
        key, Span(encoded)
    )


def _oaep_decrypt[
    ko: Origin, co: Origin
](
    key: Span[UInt8, ko], ciphertext: Span[UInt8, co], rabin: Bool
) raises -> List[UInt8]:
    var size = _modulus_size(key, rabin, True)
    if len(ciphertext) != size:
        raise Error("invalid OAEP trapdoor ciphertext length")
    var encoded = rabin_invert(key, ciphertext) if rabin else luc_invert(
        key, ciphertext
    )
    if len(encoded) != size:
        raise Error("invalid OAEP trapdoor representative")
    return oaep_sha1_decode(Span(encoded))


struct PreparedECIESEncryptor(Movable):
    """Framed ECIES public key prepared for repeated encryption."""

    var inner: ECIESEncryptor

    def __init__[
        origin: Origin
    ](
        out self,
        algorithm: PublicKeyEncryptionAlgorithm,
        public_key: Span[UInt8, origin],
    ) raises:
        if algorithm != PublicKeyEncryptionAlgorithm.ECIES:
            raise Error("prepared ECIES encryptor requires an ECIES algorithm")
        var raw = _unframe(public_key, "ECP1")
        self.inner = ECIESEncryptor(CurveAlgorithm.P256, Span(raw))

    def __init__(out self, *, deinit move: Self):
        self.inner = move.inner^

    def encrypt[
        origin: Origin
    ](self, message: Span[UInt8, origin]) raises -> List[UInt8]:
        var label = List[UInt8]()
        var derivation = List[UInt8]()
        return self.inner.encrypt(message, Span(label), Span(derivation))


struct PreparedECIESDecryptor(Movable):
    """Framed ECIES private key prepared for repeated decryption."""

    var inner: ECIESDecryptor

    def __init__[
        origin: Origin
    ](
        out self,
        algorithm: PublicKeyEncryptionAlgorithm,
        private_key: Span[UInt8, origin],
    ) raises:
        if algorithm != PublicKeyEncryptionAlgorithm.ECIES:
            raise Error("prepared ECIES decryptor requires an ECIES algorithm")
        var raw = _unframe(private_key, "ECS1")
        self.inner = ECIESDecryptor(CurveAlgorithm.P256, Span(raw))

    def __init__(out self, *, deinit move: Self):
        self.inner = move.inner^

    def decrypt[
        origin: Origin
    ](self, ciphertext: Span[UInt8, origin]) raises -> List[UInt8]:
        var label = List[UInt8]()
        var derivation = List[UInt8]()
        return self.inner.decrypt(ciphertext, Span(label), Span(derivation))


struct PreparedECIESKeyGenerator(Movable):
    """Framed P-256 ECIES keys from a reusable base-point table."""

    var inner: ECIESKeyGenerator

    def __init__(out self) raises:
        self.inner = ECIESKeyGenerator(CurveAlgorithm.P256)

    def __init__(out self, *, deinit move: Self):
        self.inner = move.inner^

    def generate(self) raises -> Tuple[List[UInt8], List[UInt8]]:
        var keys = self.inner.generate()
        return (
            _frame("ECS1", Span(keys[1])),
            _frame("ECP1", Span(keys[0])),
        )


def generate_keypair(
    algorithm: PublicKeyEncryptionAlgorithm, key_bits: Int = 2048
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if (
        algorithm == PublicKeyEncryptionAlgorithm.RSA
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_PKCS1
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256
    ):
        return rsa_keypair(key_bits)
    if algorithm == PublicKeyEncryptionAlgorithm.ELGAMAL:
        var parameters = _prime_group(key_bits)
        var keys = elgamal_keypair(Span(parameters))
        var private_raw = keys[0].copy()
        var public_raw = keys[1].copy()
        return (
            _group_frame("EGS1", Span(parameters), Span(private_raw)),
            _group_frame("EGP1", Span(parameters), Span(public_raw)),
        )
    if (
        algorithm == PublicKeyEncryptionAlgorithm.RABIN
        or algorithm == PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS
        or algorithm == PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1
    ):
        var keys = rabin_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if (
        algorithm == PublicKeyEncryptionAlgorithm.LUC
        or algorithm == PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1
    ):
        var keys = luc_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if algorithm == PublicKeyEncryptionAlgorithm.LUCELG:
        var keys = lucelg_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if algorithm == PublicKeyEncryptionAlgorithm.DLIES:
        var keys = dlies_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if algorithm == PublicKeyEncryptionAlgorithm.ECIES:
        var keys = ecies_keypair(CurveAlgorithm.P256)
        var public_raw = keys[0].copy()
        var private_raw = keys[1].copy()
        return (
            _frame("ECS1", Span(private_raw)),
            _frame("ECP1", Span(public_raw)),
        )
    raise Error("unsupported public-key encryption algorithm")


def encrypt[
    public_origin: Origin, message_origin: Origin
](
    algorithm: PublicKeyEncryptionAlgorithm,
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    if (
        algorithm == PublicKeyEncryptionAlgorithm.RSA
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_PKCS1
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256
    ):
        return rsa_encrypt(
            as_rsa_encryption_algorithm(algorithm), public_key, message
        )
    if algorithm == PublicKeyEncryptionAlgorithm.ELGAMAL:
        var parts = _group_unframe(public_key, "EGP1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return elgamal_encrypt(Span(parameters), Span(raw_key), message)
    if (
        algorithm == PublicKeyEncryptionAlgorithm.RABIN
        or algorithm == PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS
    ):
        return rabin_apply(public_key, message)
    if algorithm == PublicKeyEncryptionAlgorithm.LUC:
        return luc_apply(public_key, message)
    if algorithm == PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1:
        return _oaep_encrypt(public_key, message, True)
    if algorithm == PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1:
        return _oaep_encrypt(public_key, message, False)
    if algorithm == PublicKeyEncryptionAlgorithm.LUCELG:
        return lucelg_encrypt(public_key, message)
    if algorithm == PublicKeyEncryptionAlgorithm.DLIES:
        return dlies_encrypt(public_key, message)
    if algorithm == PublicKeyEncryptionAlgorithm.ECIES:
        var raw = _unframe(public_key, "ECP1")
        var label = List[UInt8]()
        var derivation = List[UInt8]()
        return ecies_encrypt(
            CurveAlgorithm.P256,
            message,
            Span(raw),
            Span(label),
            Span(derivation),
        )
    raise Error("unsupported public-key encryption algorithm")


def decrypt[
    private_origin: Origin, ciphertext_origin: Origin
](
    algorithm: PublicKeyEncryptionAlgorithm,
    private_key: Span[UInt8, private_origin],
    ciphertext: Span[UInt8, ciphertext_origin],
) raises -> List[UInt8]:
    if (
        algorithm == PublicKeyEncryptionAlgorithm.RSA
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_PKCS1
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA1
        or algorithm == PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256
    ):
        return rsa_decrypt(
            as_rsa_encryption_algorithm(algorithm), private_key, ciphertext
        )
    if algorithm == PublicKeyEncryptionAlgorithm.ELGAMAL:
        var parts = _group_unframe(private_key, "EGS1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return elgamal_decrypt(Span(parameters), Span(raw_key), ciphertext)
    if (
        algorithm == PublicKeyEncryptionAlgorithm.RABIN
        or algorithm == PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS
    ):
        return rabin_invert(private_key, ciphertext)
    if algorithm == PublicKeyEncryptionAlgorithm.LUC:
        return luc_invert(private_key, ciphertext)
    if algorithm == PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1:
        return _oaep_decrypt(private_key, ciphertext, True)
    if algorithm == PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1:
        return _oaep_decrypt(private_key, ciphertext, False)
    if algorithm == PublicKeyEncryptionAlgorithm.LUCELG:
        return lucelg_decrypt(private_key, ciphertext)
    if algorithm == PublicKeyEncryptionAlgorithm.DLIES:
        return dlies_decrypt(private_key, ciphertext)
    if algorithm == PublicKeyEncryptionAlgorithm.ECIES:
        var raw = _unframe(private_key, "ECS1")
        var label = List[UInt8]()
        var derivation = List[UInt8]()
        return ecies_decrypt(
            CurveAlgorithm.P256,
            ciphertext,
            Span(raw),
            Span(label),
            Span(derivation),
        )
    raise Error("unsupported public-key encryption algorithm")
