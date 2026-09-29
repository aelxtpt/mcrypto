"""ECIES over NIST prime curves in pure Mojo.

Keys are fixed-width big-endian private scalars and validated SEC1 public points.
Ciphertexts are `R || C || T`, where R is an uncompressed SEC1 ephemeral point,
C is the XOR ciphertext, and T is a 20-byte HMAC-SHA1 tag. The default
DHAES construction uses P1363 KDF2-SHA1 over `R || x(rQ)`, splits a 16-byte
HMAC key before the XOR stream, and authenticates `C || label || be64(bitlen(label))`.
"""

from ..math.curve import CurveAlgorithm
from ..macs.algorithm import HmacAlgorithm
from ..math.biguint import BigUInt
from ..math.ec import (
    ECPoint,
    NamedPrimeCurve,
    biguint_from_be,
    biguint_to_be,
    named_curve,
    FixedBaseMultiplier,
)
from ..hashes.sha1 import sha1
from ..macs.hmac import authenticate
from ..random.entropy import system_entropy


comptime MAC_KEY_BYTES = 16
comptime TAG_BYTES = 20


def _append[origin: Origin](mut output: List[UInt8], data: Span[UInt8, origin]):
    for byte in data:
        output.append(byte)


def _ct_equal[
    ao: Origin, bo: Origin
](left: Span[UInt8, ao], right: Span[UInt8, bo]) -> Bool:
    if len(left) != len(right):
        return False
    var difference: UInt8 = 0
    for i in range(len(left)):
        difference |= left[i] ^ right[i]
    return difference == 0


def _kdf2[
    so: Origin, po: Origin
](
    secret: Span[UInt8, so], parameters: Span[UInt8, po], output_bytes: Int
) raises -> List[UInt8]:
    var output = List[UInt8](capacity=output_bytes)
    var counter = UInt32(1)
    while len(output) < output_bytes:
        var input = List[UInt8](capacity=len(secret) + 4 + len(parameters))
        _append(input, secret)
        input.append(UInt8(counter >> 24))
        input.append(UInt8(counter >> 16))
        input.append(UInt8(counter >> 8))
        input.append(UInt8(counter))
        _append(input, parameters)
        var digest = sha1(Span(input))
        for byte in digest:
            if len(output) < output_bytes:
                output.append(byte)
        counter += 1
    return output^


def _tag[
    ko: Origin, co: Origin, lo: Origin
](
    mac_key: Span[UInt8, ko],
    ciphertext: Span[UInt8, co],
    label: Span[UInt8, lo],
) raises -> List[UInt8]:
    var authenticated = List[UInt8](capacity=len(ciphertext) + len(label) + 8)
    _append(authenticated, ciphertext)
    _append(authenticated, label)
    var bit_length = UInt64(len(label)) * 8
    for i in range(8):
        authenticated.append(UInt8(bit_length >> UInt64(56 - 8 * i)))
    return authenticate(HmacAlgorithm.SHA1, mac_key, Span(authenticated))


def keypair(
    curve: CurveAlgorithm = CurveAlgorithm.P256,
    compressed: Bool = False,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    var domain = named_curve(curve)
    while True:
        var random = system_entropy(domain.field_bytes)
        var scalar = biguint_from_be(Span(random)).modulo(domain.order)
        if not scalar.is_zero():
            var private_key = biguint_to_be(scalar, domain.field_bytes)
            var public_key = domain.encode_point(
                domain.curve.scalar_multiply(scalar, domain.generator),
                compressed,
            )
            return (public_key^, private_key^)


struct ECIESKeyGenerator(Movable):
    """Named-curve ECIES key generator with a reusable base table."""

    var domain: NamedPrimeCurve
    var multiplier: FixedBaseMultiplier

    def __init__(out self, curve: CurveAlgorithm = CurveAlgorithm.P256) raises:
        self.domain = named_curve(curve)
        self.multiplier = FixedBaseMultiplier(
            self.domain.curve,
            self.domain.generator,
            self.domain.order.bit_length(),
        )

    def __init__(out self, *, deinit move: Self):
        self.domain = move.domain^
        self.multiplier = move.multiplier^

    def generate(self) raises -> Tuple[List[UInt8], List[UInt8]]:
        while True:
            var random = system_entropy(self.domain.field_bytes)
            var scalar = biguint_from_be(Span(random)).modulo(self.domain.order)
            if not scalar.is_zero():
                var private_key = biguint_to_be(scalar, self.domain.field_bytes)
                var public_key = self.domain.encode_point(
                    self.multiplier.multiply(scalar), False
                )
                return (public_key^, private_key^)


def _finish_encryption[
    mo: Origin, lo: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    rpoint: ECPoint,
    shared: ECPoint,
    message: Span[UInt8, mo],
    label: Span[UInt8, lo],
    derivation_parameters: Span[UInt8, ko],
) raises -> List[UInt8]:
    if shared.infinity:
        raise Error("ECIES agreement produced infinity")
    var encoded_r = domain.encode_point(rpoint)
    var shared_x = biguint_to_be(shared.x, domain.field_bytes)
    var agreed = List[UInt8](capacity=len(encoded_r) + len(shared_x))
    _append(agreed, Span(encoded_r))
    _append(agreed, Span(shared_x))
    var derived = _kdf2(
        Span(agreed), derivation_parameters, MAC_KEY_BYTES + len(message)
    )
    var encrypted = List[UInt8](length=len(message), fill=0)
    for i in range(len(message)):
        encrypted[i] = message[i] ^ derived[MAC_KEY_BYTES + i]
    var tag = _tag(Span(derived)[0:MAC_KEY_BYTES], Span(encrypted), label)
    var output = List[UInt8](
        capacity=len(encoded_r) + len(encrypted) + TAG_BYTES
    )
    _append(output, Span(encoded_r))
    _append(output, Span(encrypted))
    _append(output, Span(tag))
    return output^


def _encrypt_prepared[
    mo: Origin, lo: Origin, ko: Origin
](
    domain: NamedPrimeCurve,
    recipient: ECPoint,
    message: Span[UInt8, mo],
    ephemeral: BigUInt,
    label: Span[UInt8, lo],
    derivation_parameters: Span[UInt8, ko],
) raises -> List[UInt8]:
    return _finish_encryption(
        domain,
        domain.curve.scalar_multiply(ephemeral, domain.generator),
        domain.curve.scalar_multiply(ephemeral, recipient),
        message,
        label,
        derivation_parameters,
    )


struct ECIESEncryptor(Movable):
    """Validated ECIES recipient key and named curve reusable across messages.
    """

    var domain: NamedPrimeCurve
    var recipient: ECPoint
    var generator_power: FixedBaseMultiplier
    var recipient_power: FixedBaseMultiplier

    def __init__[
        origin: Origin
    ](
        out self,
        curve: CurveAlgorithm,
        encoded_public_key: Span[UInt8, origin],
    ) raises:
        self.domain = named_curve(curve)
        self.recipient = self.domain.decode_point(encoded_public_key)
        self.generator_power = FixedBaseMultiplier(
            self.domain.curve,
            self.domain.generator,
            self.domain.order.bit_length(),
        )
        self.recipient_power = FixedBaseMultiplier(
            self.domain.curve,
            self.recipient,
            self.domain.order.bit_length(),
        )

    def __init__(out self, *, deinit move: Self):
        self.domain = move.domain^
        self.recipient = move.recipient^
        self.generator_power = move.generator_power^
        self.recipient_power = move.recipient_power^

    def encrypt[
        mo: Origin, lo: Origin, ko: Origin
    ](
        self,
        message: Span[UInt8, mo],
        label: Span[UInt8, lo],
        derivation_parameters: Span[UInt8, ko],
    ) raises -> List[UInt8]:
        while True:
            var random = system_entropy(self.domain.field_bytes)
            var ephemeral = biguint_from_be(Span(random)).modulo(
                self.domain.order
            )
            if not ephemeral.is_zero():
                return _finish_encryption(
                    self.domain,
                    self.generator_power.multiply(ephemeral),
                    self.recipient_power.multiply(ephemeral),
                    message,
                    label,
                    derivation_parameters,
                )


struct ECIESDecryptor(Movable):
    """Validated ECIES private key and named curve reusable across ciphertexts.
    """

    var domain: NamedPrimeCurve
    var secret: BigUInt

    def __init__[
        origin: Origin
    ](
        out self,
        curve: CurveAlgorithm,
        private_key: Span[UInt8, origin],
    ) raises:
        self.domain = named_curve(curve)
        if len(private_key) != self.domain.field_bytes:
            raise Error("private key has invalid width")
        self.secret = biguint_from_be(private_key)
        if self.secret.is_zero() or self.secret.compare(self.domain.order) >= 0:
            raise Error("invalid private scalar")

    def __init__(out self, *, deinit move: Self):
        self.domain = move.domain^
        self.secret = move.secret^

    def decrypt[
        co: Origin, lo: Origin, po: Origin
    ](
        self,
        ciphertext: Span[UInt8, co],
        label: Span[UInt8, lo],
        derivation_parameters: Span[UInt8, po],
    ) raises -> List[UInt8]:
        var point_bytes = 1 + 2 * self.domain.field_bytes
        if len(ciphertext) < point_bytes + TAG_BYTES:
            raise Error("truncated ECIES ciphertext")
        var rpoint = self.domain.decode_point(ciphertext[0:point_bytes])
        var shared = self.domain.curve.scalar_multiply(self.secret, rpoint)
        if shared.infinity:
            raise Error("ECIES agreement produced infinity")
        var shared_x = biguint_to_be(shared.x, self.domain.field_bytes)
        var agreed = List[UInt8](capacity=point_bytes + self.domain.field_bytes)
        _append(agreed, ciphertext[0:point_bytes])
        _append(agreed, Span(shared_x))
        var message_bytes = len(ciphertext) - point_bytes - TAG_BYTES
        var derived = _kdf2(
            Span(agreed),
            derivation_parameters,
            MAC_KEY_BYTES + message_bytes,
        )
        var encrypted = ciphertext[point_bytes : point_bytes + message_bytes]
        var expected = _tag(Span(derived)[0:MAC_KEY_BYTES], encrypted, label)
        if not _ct_equal(
            Span(expected),
            ciphertext[point_bytes + message_bytes : len(ciphertext)],
        ):
            raise Error("ECIES authentication failed")
        var plaintext = List[UInt8](length=message_bytes, fill=0)
        for i in range(message_bytes):
            plaintext[i] = encrypted[i] ^ derived[MAC_KEY_BYTES + i]
        return plaintext^


def encrypt_with_ephemeral[
    mo: Origin, po: Origin, eo: Origin, lo: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    message: Span[UInt8, mo],
    encoded_public_key: Span[UInt8, po],
    ephemeral_private_key: Span[UInt8, eo],
    label: Span[UInt8, lo],
    derivation_parameters: Span[UInt8, ko],
) raises -> List[UInt8]:
    """Deterministic ECIES primitive for KATs; ephemeral key must be 1..n-1."""
    var domain = named_curve(curve)
    if len(ephemeral_private_key) != domain.field_bytes:
        raise Error("ephemeral private key has invalid width")
    var ephemeral = biguint_from_be(ephemeral_private_key)
    if ephemeral.is_zero() or ephemeral.compare(domain.order) >= 0:
        raise Error("invalid ephemeral private scalar")
    var recipient = domain.decode_point(encoded_public_key)
    return _encrypt_prepared(
        domain,
        recipient,
        message,
        ephemeral,
        label,
        derivation_parameters,
    )


def encrypt[
    mo: Origin, po: Origin, lo: Origin, ko: Origin
](
    curve: CurveAlgorithm,
    message: Span[UInt8, mo],
    encoded_public_key: Span[UInt8, po],
    label: Span[UInt8, lo],
    derivation_parameters: Span[UInt8, ko],
) raises -> List[UInt8]:
    var encryptor = ECIESEncryptor(curve, encoded_public_key)
    return encryptor.encrypt(message, label, derivation_parameters)


def decrypt[
    co: Origin, ko: Origin, lo: Origin, po: Origin
](
    curve: CurveAlgorithm,
    ciphertext: Span[UInt8, co],
    private_key: Span[UInt8, ko],
    label: Span[UInt8, lo],
    derivation_parameters: Span[UInt8, po],
) raises -> List[UInt8]:
    var decryptor = ECIESDecryptor(curve, private_key)
    return decryptor.decrypt(ciphertext, label, derivation_parameters)
