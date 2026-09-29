"""Pure-Mojo public-key signature dispatcher."""

from .algorithm import SignatureAlgorithm, as_rsa_signature_algorithm
from ..hashes.algorithm import HashAlgorithm
from ..math.curve import CurveAlgorithm, curve_name
from ..math.biguint import BigUInt
from ..math.ec import (
    NamedPrimeCurve,
    FixedBaseMultiplier,
    named_curve,
    biguint_from_be,
)
from ..public_key._legacy_math import (
    generate_safe_prime_pair,
    decode_key,
    constant_time_equal,
)
from ..public_key.rsa import (
    generate_keypair as rsa_keypair,
    sign as rsa_sign,
    verify as rsa_verify,
)
from ..public_key.rabin import (
    signature_keypair as rabin_keypair,
    signature_apply as rabin_apply,
    signature_invert as rabin_invert,
)
from ..public_key.luc import (
    keypair as luc_keypair,
    invert as luc_invert,
    apply_decoded as luc_apply_decoded,
)
from ..public_key._trapdoor_encoding import (
    pssr_sha256_encode,
    pssr_sha256_verify,
    emsa2_sha256,
    pkcs1_v15_sha256,
)
from ..public_key.luc_hmp import (
    keypair as luc_hmp_keypair,
    sign as luc_hmp_sign,
    verify as luc_hmp_verify,
)
from ..public_key.esign import (
    keypair as esign_keypair,
    sign as esign_sign,
    verify as esign_verify,
)
from .finite_field import PrimeGroup, encode_parameters, rfc5114_group1
from .dsa import (
    PreparedDSAVerifier,
    generate_keypair as dsa_keypair,
    sign as dsa_sign,
    sign_random as dsa_sign_random,
    verify as dsa_verify,
)
from .elgamal import (
    generate_keypair as elgamal_keypair,
    sign as elgamal_sign,
    verify as elgamal_verify,
)
from .nr import (
    PreparedNRVerifier,
    generate_keypair as nr_keypair,
    sign as nr_sign,
    verify as nr_verify,
)
from .ecdsa import (
    keypair as ec_keypair,
    _generate_private_key as ec_private_key,
    sign as ecdsa_sign,
    verify as ecdsa_verify,
    ecnr_sign,
    ecnr_verify,
    ecgdsa_public_key,
    ecgdsa_sign,
    ecgdsa_verify,
)
from .ed25519 import (
    keypair as ed25519_keypair,
    sign as ed25519_sign,
    verify as ed25519_verify,
)


def _append_u32(mut output: List[UInt8], value: Int) raises:
    if value < 0 or value > 0xFFFFFFFF:
        raise Error("signature frame component is too large")
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


def _read_u32[
    origin: Origin
](input: Span[UInt8, origin], offset: Int) raises -> Int:
    if offset < 0 or offset + 4 > len(input):
        raise Error("truncated signature key frame")
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
        raise Error("truncated signature key frame")
    for i in range(4):
        if input[i] != expected[i]:
            raise Error("signature key frame has the wrong type")
    var size = _read_u32(input, 4)
    if size < 0 or 8 + size != len(input):
        raise Error("invalid signature key frame length")
    var output = List[UInt8](capacity=size)
    for i in range(size):
        output.append(input[8 + i])
    return output^


def _ec_frame[
    origin: Origin
](
    magic: StaticString, curve_name: String, key: Span[UInt8, origin]
) raises -> List[UInt8]:
    """Frame an EC key with its exact named-curve domain."""
    var curve = curve_name.as_bytes()
    var payload_bytes = 4 + len(curve) + len(key)
    var output = List[UInt8](unsafe_uninit_length=8 + payload_bytes)
    var magic_bytes = magic.as_bytes()
    for i in range(4):
        output[i] = magic_bytes[i]
    output[4] = UInt8(payload_bytes >> 24)
    output[5] = UInt8(payload_bytes >> 16)
    output[6] = UInt8(payload_bytes >> 8)
    output[7] = UInt8(payload_bytes)
    output[8] = UInt8(len(curve) >> 24)
    output[9] = UInt8(len(curve) >> 16)
    output[10] = UInt8(len(curve) >> 8)
    output[11] = UInt8(len(curve))
    for i in range(len(curve)):
        output[12 + i] = curve[i]
    for i in range(len(key)):
        output[12 + len(curve) + i] = key[i]
    return output^


def _ec_unframe[
    origin: Origin
](
    input: Span[UInt8, origin], magic: StaticString, expected_curve: String
) raises -> List[UInt8]:
    var expected_magic = magic.as_bytes()
    if len(input) < 12:
        raise Error("truncated EC signature key frame")
    for i in range(4):
        if input[i] != expected_magic[i]:
            raise Error("signature key frame has the wrong type")
    var payload_bytes = _read_u32(input, 4)
    if payload_bytes < 4 or payload_bytes + 8 != len(input):
        raise Error("invalid signature key frame length")
    var curve_size = _read_u32(input, 8)
    var expected = expected_curve.as_bytes()
    var key_offset = 12 + curve_size
    if curve_size != len(expected) or key_offset >= len(input):
        raise Error("EC signature key frame has the wrong curve")
    for i in range(curve_size):
        if input[12 + i] != expected[i]:
            raise Error("EC signature key frame has the wrong curve")
    var key = List[UInt8](unsafe_uninit_length=len(input) - key_offset)
    for i in range(len(key)):
        key[i] = input[key_offset + i]
    return key^


def _group_frame[
    po: Origin, ko: Origin
](
    magic: StaticString, parameters: Span[UInt8, po], key: Span[UInt8, ko]
) raises -> List[UInt8]:
    var payload_bytes = 4 + len(parameters) + len(key)
    var output = List[UInt8](unsafe_uninit_length=8 + payload_bytes)
    var magic_bytes = magic.as_bytes()
    for i in range(4):
        output[i] = magic_bytes[i]
    output[4] = UInt8(payload_bytes >> 24)
    output[5] = UInt8(payload_bytes >> 16)
    output[6] = UInt8(payload_bytes >> 8)
    output[7] = UInt8(payload_bytes)
    output[8] = UInt8(len(parameters) >> 24)
    output[9] = UInt8(len(parameters) >> 16)
    output[10] = UInt8(len(parameters) >> 8)
    output[11] = UInt8(len(parameters))
    for i in range(len(parameters)):
        output[12 + i] = parameters[i]
    for i in range(len(key)):
        output[12 + len(parameters) + i] = key[i]
    return output^


def _group_unframe[
    origin: Origin
](input: Span[UInt8, origin], magic: StaticString) raises -> Tuple[
    List[UInt8], List[UInt8]
]:
    var expected_magic = magic.as_bytes()
    if len(input) < 12:
        raise Error("truncated finite-field signature key frame")
    for i in range(4):
        if input[i] != expected_magic[i]:
            raise Error("signature key frame has the wrong type")
    var payload_bytes = _read_u32(input, 4)
    if payload_bytes < 4 or payload_bytes + 8 != len(input):
        raise Error("invalid signature key frame length")
    var size = _read_u32(input, 8)
    var key_offset = 12 + size
    if size <= 0 or key_offset >= len(input):
        raise Error("invalid finite-field signature key frame")
    var parameters = List[UInt8](unsafe_uninit_length=size)
    var key = List[UInt8](unsafe_uninit_length=len(input) - key_offset)
    for i in range(size):
        parameters[i] = input[12 + i]
    for i in range(len(key)):
        key[i] = input[key_offset + i]
    return (parameters^, key^)


def _prime_group(bits: Int) raises -> List[UInt8]:
    if bits < 128:
        raise Error("finite-field signature key size must be at least 128 bits")
    if bits == 1024:
        return encode_parameters(rfc5114_group1())
    var primes = generate_safe_prime_pair(bits)
    var p = primes[0].copy()
    var q = primes[1].copy()
    var g = BigUInt(2)
    while g.modular_power(q, p).compare(BigUInt(1)) != 0:
        g.add_small(1)
    return encode_parameters(PrimeGroup(p, q, g))


def _is_rsa(algorithm: SignatureAlgorithm) -> Bool:
    return (
        algorithm == SignatureAlgorithm.RSA
        or algorithm == SignatureAlgorithm.RSA_PSS_SHA1
        or algorithm == SignatureAlgorithm.RSA_PSS_SHA256
        or algorithm == SignatureAlgorithm.RSA_PKCS1_SHA1
        or algorithm == SignatureAlgorithm.RSA_PKCS1_SHA256
    )


def _is_dsa(algorithm: SignatureAlgorithm) -> Bool:
    return (
        algorithm == SignatureAlgorithm.DSA
        or algorithm == SignatureAlgorithm.DSA_RFC6979
    )


def _is_rabin(algorithm: SignatureAlgorithm) -> Bool:
    return (
        algorithm == SignatureAlgorithm.RABIN_WILLIAMS
        or algorithm == SignatureAlgorithm.RABIN_PSSR_SHA256
        or algorithm == SignatureAlgorithm.RABIN_EMSA2_SHA256
    )


def _is_ecdsa(algorithm: SignatureAlgorithm) -> Bool:
    return (
        algorithm == SignatureAlgorithm.ECDSA
        or algorithm == SignatureAlgorithm.ECDSA_RFC6979
        or algorithm == SignatureAlgorithm.ECDSA_P256_SHA256
        or algorithm == SignatureAlgorithm.ECDSA_RFC6979_P256_SHA256
    )


def _is_ecgdsa(algorithm: SignatureAlgorithm) -> Bool:
    return (
        algorithm == SignatureAlgorithm.ECGDSA
        or algorithm == SignatureAlgorithm.ECGDSA_P256_SHA256
        or algorithm == SignatureAlgorithm.ECGDSA_BRAINPOOL_P256_SHA256
    )


def _is_ecnr(algorithm: SignatureAlgorithm) -> Bool:
    return (
        algorithm == SignatureAlgorithm.ECNR
        or algorithm == SignatureAlgorithm.ECNR_P256_SHA256
    )


def _ec_curve(algorithm: SignatureAlgorithm) raises -> CurveAlgorithm:
    if (
        algorithm == SignatureAlgorithm.ECGDSA
        or algorithm == SignatureAlgorithm.ECGDSA_BRAINPOOL_P256_SHA256
    ):
        return CurveAlgorithm.BRAINPOOL_P256R1
    if _is_ecdsa(algorithm) or _is_ecgdsa(algorithm) or _is_ecnr(algorithm):
        return CurveAlgorithm.P256
    raise Error("unsupported elliptic-curve signature algorithm")


struct PreparedECSignatureKeyGenerator(Movable):
    """Named-curve signature key generator with a reusable base table."""

    var curve: CurveAlgorithm
    var ecgdsa: Bool
    var domain: NamedPrimeCurve
    var multiplier: FixedBaseMultiplier

    def __init__(out self, algorithm: SignatureAlgorithm) raises:
        self.curve = _ec_curve(algorithm)
        self.ecgdsa = _is_ecgdsa(algorithm)
        self.domain = named_curve(self.curve)
        self.multiplier = FixedBaseMultiplier(
            self.domain.curve,
            self.domain.generator,
            self.domain.order.bit_length(),
        )

    def __init__(out self, *, deinit move: Self):
        self.curve = move.curve
        self.ecgdsa = move.ecgdsa
        self.domain = move.domain^
        self.multiplier = move.multiplier^

    def generate(self) raises -> Tuple[List[UInt8], List[UInt8]]:
        var private = ec_private_key(self.curve)
        var scalar = biguint_from_be(Span(private))
        if self.ecgdsa:
            scalar = scalar.modular_inverse(self.domain.order)
        var public = self.domain.encode_point(
            self.multiplier.multiply(scalar), False
        )
        return (
            _ec_frame("ECS1", curve_name(self.curve), Span(private)),
            _ec_frame("ECP1", curve_name(self.curve), Span(public)),
        )


struct PreparedPrimeSignatureVerifier(Movable):
    """Framed DSA or NR verifier with decoded fixed-base tables."""

    var dsa: List[PreparedDSAVerifier]
    var nr: List[PreparedNRVerifier]

    def __init__[
        public_origin: Origin
    ](
        out self,
        algorithm: SignatureAlgorithm,
        public_key: Span[UInt8, public_origin],
    ) raises:
        self.dsa = List[PreparedDSAVerifier]()
        self.nr = List[PreparedNRVerifier]()
        if _is_dsa(algorithm):
            var parts = _group_unframe(public_key, "DSP1")
            var parameters = parts[0].copy()
            var raw_key = parts[1].copy()
            self.dsa.append(
                PreparedDSAVerifier(Span(parameters), Span(raw_key))
            )
        elif algorithm == SignatureAlgorithm.NR:
            var parts = _group_unframe(public_key, "NRP1")
            var parameters = parts[0].copy()
            var raw_key = parts[1].copy()
            self.nr.append(PreparedNRVerifier(Span(parameters), Span(raw_key)))
        else:
            raise Error("prepared verifier requires DSA or NR")

    def __init__(out self, *, deinit move: Self):
        self.dsa = move.dsa^
        self.nr = move.nr^

    def verify[
        message_origin: Origin, signature_origin: Origin
    ](
        self,
        message: Span[UInt8, message_origin],
        signature: Span[UInt8, signature_origin],
    ) raises -> Bool:
        if len(self.dsa) != 0:
            return self.dsa[0].verify(HashAlgorithm.SHA256, message, signature)
        return self.nr[0].verify(message, signature)


def generate_keypair(
    algorithm: SignatureAlgorithm, key_bits: Int = 2048
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if _is_rsa(algorithm):
        return rsa_keypair(key_bits)
    if (
        _is_dsa(algorithm)
        or algorithm == SignatureAlgorithm.ELGAMAL
        or algorithm == SignatureAlgorithm.NR
    ):
        var parameters = _prime_group(key_bits)
        var keys: Tuple[List[UInt8], List[UInt8]]
        if _is_dsa(algorithm):
            keys = dsa_keypair(Span(parameters))
        elif algorithm == SignatureAlgorithm.ELGAMAL:
            keys = elgamal_keypair(Span(parameters))
        else:
            keys = nr_keypair(Span(parameters))
        var private_raw = keys[0].copy()
        var public_raw = keys[1].copy()
        if _is_dsa(algorithm):
            return (
                _group_frame("DSS1", Span(parameters), Span(private_raw)),
                _group_frame("DSP1", Span(parameters), Span(public_raw)),
            )
        if algorithm == SignatureAlgorithm.ELGAMAL:
            return (
                _group_frame("ELS1", Span(parameters), Span(private_raw)),
                _group_frame("ELP1", Span(parameters), Span(public_raw)),
            )
        return (
            _group_frame("NRS1", Span(parameters), Span(private_raw)),
            _group_frame("NRP1", Span(parameters), Span(public_raw)),
        )
    if _is_rabin(algorithm):
        var keys = rabin_keypair(key_bits)
        if algorithm != SignatureAlgorithm.RABIN_PSSR_SHA256:
            while (
                decode_key(Span(keys[0]), "RWV1", 1)[0].bit_length() != key_bits
            ):
                keys = rabin_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if (
        algorithm == SignatureAlgorithm.LUC
        or algorithm == SignatureAlgorithm.LUC_PKCS1_SHA256
    ):
        var keys = luc_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if algorithm == SignatureAlgorithm.LUC_HMP_EMSA1_SHA256:
        var keys = luc_hmp_keypair(key_bits)
        return (keys[1].copy(), keys[0].copy())
    if algorithm == SignatureAlgorithm.ESIGN:
        var bits = key_bits - key_bits % 3
        var keys = esign_keypair(bits)
        return (keys[1].copy(), keys[0].copy())
    if _is_ecdsa(algorithm) or _is_ecgdsa(algorithm) or _is_ecnr(algorithm):
        var curve = _ec_curve(algorithm)
        var private: List[UInt8]
        var public: List[UInt8]
        if _is_ecgdsa(algorithm):
            private = ec_private_key(curve)
            public = ecgdsa_public_key(curve, Span(private))
        else:
            var keys = ec_keypair(curve)
            public = keys[0].copy()
            private = keys[1].copy()
        return (
            _ec_frame("ECS1", curve_name(curve), Span(private)),
            _ec_frame("ECP1", curve_name(curve), Span(public)),
        )
    if algorithm == SignatureAlgorithm.ED25519:
        var keys = ed25519_keypair()
        var public = keys[0].copy()
        var private = keys[1].copy()
        return (_frame("EDS1", Span(private)), _frame("EDP1", Span(public)))
    raise Error("unsupported signature algorithm")


def _trapdoor_size[
    origin: Origin
](key: Span[UInt8, origin], rabin: Bool, private: Bool) raises -> Tuple[
    Int, Int
]:
    var modulus: BigUInt
    if rabin:
        if private:
            var components = decode_key(key, "RWS1", 4)
            modulus = components[0].copy()
        else:
            var components = decode_key(key, "RWV1", 1)
            modulus = components[0].copy()
    else:
        if private:
            var components = decode_key(key, "LUS1", 5)
            modulus = components[0].copy()
        else:
            var components = decode_key(key, "LUC1", 2)
            modulus = components[0].copy()
    return ((modulus.bit_length() + 7) // 8, modulus.bit_length())


def _rabin_sign[
    ko: Origin, mo: Origin
](
    algorithm: SignatureAlgorithm,
    private_key: Span[UInt8, ko],
    message: Span[UInt8, mo],
) raises -> List[UInt8]:
    var sizing = _trapdoor_size(private_key, True, True)
    var encoded = pssr_sha256_encode(message, sizing[1] - 1) if (
        algorithm == SignatureAlgorithm.RABIN_PSSR_SHA256
    ) else emsa2_sha256(message, sizing[1] - 1)
    return rabin_invert(private_key, Span(encoded))


def _rabin_verify[
    ko: Origin, mo: Origin, so: Origin
](
    algorithm: SignatureAlgorithm,
    public_key: Span[UInt8, ko],
    message: Span[UInt8, mo],
    signature: Span[UInt8, so],
) raises -> Bool:
    var sizing = _trapdoor_size(public_key, True, False)
    if len(signature) != sizing[0]:
        return False
    try:
        var image = rabin_apply(public_key, signature)
        if algorithm == SignatureAlgorithm.RABIN_PSSR_SHA256:
            return pssr_sha256_verify(message, Span(image), sizing[1] - 1)
        var expected = emsa2_sha256(message, sizing[1] - 1)
        return constant_time_equal(Span(image), Span(expected))
    except:
        return False


def _luc_sign[
    ko: Origin, mo: Origin
](private_key: Span[UInt8, ko], message: Span[UInt8, mo]) raises -> List[UInt8]:
    var sizing = _trapdoor_size(private_key, False, True)
    var encoded = pkcs1_v15_sha256(message, sizing[0])
    return luc_invert(private_key, Span(encoded))


def _luc_verify[
    ko: Origin, mo: Origin, so: Origin
](
    public_key: Span[UInt8, ko],
    message: Span[UInt8, mo],
    signature: Span[UInt8, so],
) raises -> Bool:
    var components = decode_key(public_key, "LUC1", 2)
    var modulus = components[0].copy()
    var exponent = components[1].copy()
    if modulus.compare(BigUInt(1)) <= 0 or exponent.compare(BigUInt(1)) <= 0:
        raise Error("invalid LUC public key")
    var size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    try:
        var image = luc_apply_decoded(modulus, exponent, signature)
        var expected = pkcs1_v15_sha256(message, size)
        return constant_time_equal(Span(image), Span(expected))
    except:
        return False


def sign[
    private_origin: Origin, message_origin: Origin
](
    algorithm: SignatureAlgorithm,
    private_key: Span[UInt8, private_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    if _is_rsa(algorithm):
        return rsa_sign(
            as_rsa_signature_algorithm(algorithm), private_key, message
        )
    if _is_dsa(algorithm):
        var parts = _group_unframe(private_key, "DSS1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        if algorithm == SignatureAlgorithm.DSA_RFC6979:
            return dsa_sign(
                HashAlgorithm.SHA256, Span(parameters), Span(raw_key), message
            )
        return dsa_sign_random(
            HashAlgorithm.SHA256, Span(parameters), Span(raw_key), message
        )
    if algorithm == SignatureAlgorithm.ELGAMAL:
        var parts = _group_unframe(private_key, "ELS1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return elgamal_sign(Span(parameters), Span(raw_key), message)
    if algorithm == SignatureAlgorithm.NR:
        var parts = _group_unframe(private_key, "NRS1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return nr_sign(Span(parameters), Span(raw_key), message)
    if _is_rabin(algorithm):
        return _rabin_sign(algorithm, private_key, message)
    if (
        algorithm == SignatureAlgorithm.LUC
        or algorithm == SignatureAlgorithm.LUC_PKCS1_SHA256
    ):
        return _luc_sign(private_key, message)
    if algorithm == SignatureAlgorithm.LUC_HMP_EMSA1_SHA256:
        return luc_hmp_sign(private_key, message)
    if algorithm == SignatureAlgorithm.ESIGN:
        return esign_sign(private_key, message)
    if _is_ecdsa(algorithm):
        var curve = _ec_curve(algorithm)
        var raw = _ec_unframe(private_key, "ECS1", curve_name(curve))
        return ecdsa_sign(curve, HashAlgorithm.SHA256, message, Span(raw))
    if _is_ecgdsa(algorithm):
        var curve = _ec_curve(algorithm)
        var raw = _ec_unframe(private_key, "ECS1", curve_name(curve))
        return ecgdsa_sign(curve, HashAlgorithm.SHA256, message, Span(raw))
    if _is_ecnr(algorithm):
        var curve = _ec_curve(algorithm)
        var raw = _ec_unframe(private_key, "ECS1", curve_name(curve))
        return ecnr_sign(curve, HashAlgorithm.SHA256, message, Span(raw))
    if algorithm == SignatureAlgorithm.ED25519:
        var raw = _unframe(private_key, "EDS1")
        return ed25519_sign(message, Span(raw))
    raise Error("unsupported signature algorithm")


def verify[
    public_origin: Origin, message_origin: Origin, signature_origin: Origin
](
    algorithm: SignatureAlgorithm,
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    """Verify a signature.

    Forged or structurally invalid signatures return `False`. Malformed keys
    and unsupported algorithm selectors raise.
    """
    if _is_rsa(algorithm):
        return rsa_verify(
            as_rsa_signature_algorithm(algorithm),
            public_key,
            message,
            signature,
        )
    if _is_dsa(algorithm):
        var parts = _group_unframe(public_key, "DSP1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return dsa_verify(
            HashAlgorithm.SHA256,
            Span(parameters),
            Span(raw_key),
            message,
            signature,
        )
    if algorithm == SignatureAlgorithm.ELGAMAL:
        var parts = _group_unframe(public_key, "ELP1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return elgamal_verify(
            Span(parameters), Span(raw_key), message, signature
        )
    if algorithm == SignatureAlgorithm.NR:
        var parts = _group_unframe(public_key, "NRP1")
        var parameters = parts[0].copy()
        var raw_key = parts[1].copy()
        return nr_verify(Span(parameters), Span(raw_key), message, signature)
    if _is_rabin(algorithm):
        return _rabin_verify(algorithm, public_key, message, signature)
    if (
        algorithm == SignatureAlgorithm.LUC
        or algorithm == SignatureAlgorithm.LUC_PKCS1_SHA256
    ):
        return _luc_verify(public_key, message, signature)
    if algorithm == SignatureAlgorithm.LUC_HMP_EMSA1_SHA256:
        return luc_hmp_verify(public_key, message, signature)
    if algorithm == SignatureAlgorithm.ESIGN:
        return esign_verify(public_key, message, signature)
    if _is_ecdsa(algorithm):
        var curve = _ec_curve(algorithm)
        var raw = _ec_unframe(public_key, "ECP1", curve_name(curve))
        return ecdsa_verify(
            curve,
            HashAlgorithm.SHA256,
            message,
            signature,
            Span(raw),
        )
    if _is_ecgdsa(algorithm):
        var curve = _ec_curve(algorithm)
        var raw = _ec_unframe(public_key, "ECP1", curve_name(curve))
        return ecgdsa_verify(
            curve,
            HashAlgorithm.SHA256,
            message,
            signature,
            Span(raw),
        )
    if _is_ecnr(algorithm):
        var curve = _ec_curve(algorithm)
        var raw = _ec_unframe(public_key, "ECP1", curve_name(curve))
        return ecnr_verify(
            curve,
            HashAlgorithm.SHA256,
            message,
            signature,
            Span(raw),
        )
    if algorithm == SignatureAlgorithm.ED25519:
        var raw = _unframe(public_key, "EDP1")
        return ed25519_verify(signature, message, Span(raw))
    raise Error("unsupported signature algorithm selector")
