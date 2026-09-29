"""ElGamal encryption and signatures in a prime-order subgroup, in pure Mojo.

Parameters use ``finite_field``'s explicit ``p,q,g`` block. Private/public keys are
``x[q_len]`` and ``y[p_len]``. Ciphertexts are ``c1[p_len] || c2[p_len]`` and use
the historical padding block ``random || message || one-byte length``.
Signatures are the subgroup-safe ElGamal form ``r[p_len] || s[q_len]`` with
``s=k^-1(H(m)-x*r) mod q``; verification checks ``g^H = y^r*r^s mod p``.
"""

from ..hashes.sha256 import sha256
from ..random.generator import random_bytes
from .finite_field import (
    decode_parameters,
    decode_private,
    decode_public,
    from_be,
    generate_keypair as _generate_keypair,
    random_scalar,
    to_be_fixed,
)


def generate_keypair[
    origin: Origin
](parameters: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Return ``(private_x[q_len], public_y[p_len])`` for a parameter block."""
    return _generate_keypair(parameters)


def public_key[
    parameters_origin: Origin, private_origin: Origin
](
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
) raises -> List[UInt8]:
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    return to_be_fixed(group.g.modular_power(x, group.p), group.p_bytes)


def max_plaintext_length[
    origin: Origin
](parameters: Span[UInt8, origin]) raises -> Int:
    var group = decode_parameters(parameters)
    return min(255, group.p_bytes - 3)


def encrypt[
    parameters_origin: Origin, public_origin: Origin, message_origin: Origin
](
    parameters: Span[UInt8, parameters_origin],
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    """Encrypt with interoperable random-prefix/length padding."""
    var group = decode_parameters(parameters)
    var y = decode_public(public_key, group)
    var maximum = min(255, group.p_bytes - 3)
    if len(message) > maximum:
        raise Error("ElGamal plaintext is too long")
    var prefix_len = group.p_bytes - 2 - len(message)
    var block = random_bytes(prefix_len)
    for byte in message:
        block.append(byte)
    block.append(UInt8(len(message)))
    var encoded_message = from_be(Span(block))
    var k = random_scalar(group)
    var c1 = group.g.modular_power(k, group.p)
    var c2 = encoded_message.modular_multiply(
        y.modular_power(k, group.p), group.p
    )
    var output = to_be_fixed(c1, group.p_bytes)
    var encoded_c2 = to_be_fixed(c2, group.p_bytes)
    for byte in encoded_c2:
        output.append(byte)
    return output^


def decrypt[
    parameters_origin: Origin, private_origin: Origin, ciphertext_origin: Origin
](
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
    ciphertext: Span[UInt8, ciphertext_origin],
) raises -> List[UInt8]:
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    if len(ciphertext) != 2 * group.p_bytes:
        raise Error("ElGamal ciphertext has the wrong width")
    var c1_bytes = List[UInt8](capacity=group.p_bytes)
    var c2_bytes = List[UInt8](capacity=group.p_bytes)
    for i in range(group.p_bytes):
        c1_bytes.append(ciphertext[i])
        c2_bytes.append(ciphertext[group.p_bytes + i])
    var c1 = decode_public(Span(c1_bytes), group)
    var c2 = from_be(Span(c2_bytes))
    if c2.is_zero() or c2.compare(group.p) >= 0:
        raise Error("invalid ElGamal ciphertext element")
    var shared = c1.modular_power(x, group.p)
    var encoded_message = c2.modular_multiply(
        shared.modular_inverse(group.p), group.p
    )
    var block = to_be_fixed(encoded_message, group.p_bytes - 1)
    var message_len = Int(block[len(block) - 1])
    if message_len > min(255, group.p_bytes - 3):
        raise Error("invalid ElGamal padding")
    var output = List[UInt8](capacity=message_len)
    for i in range(message_len):
        output.append(block[len(block) - 1 - message_len + i])
    return output^


def sign[
    parameters_origin: Origin, private_origin: Origin, message_origin: Origin
](
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    var group = decode_parameters(parameters)
    var x = decode_private(private_key, group)
    var digest = sha256(message)
    var h = from_be(Span(digest)).modulo(group.q)
    var k = random_scalar(group)
    var r = group.g.modular_power(k, group.p)
    var exponent = h.modular_subtract(
        x.modular_multiply(r.modulo(group.q), group.q), group.q
    )
    var s = k.modular_inverse(group.q).modular_multiply(exponent, group.q)
    var output = to_be_fixed(r, group.p_bytes)
    var encoded_s = to_be_fixed(s, group.q_bytes)
    for byte in encoded_s:
        output.append(byte)
    return output^


def verify[
    parameters_origin: Origin,
    public_origin: Origin,
    message_origin: Origin,
    signature_origin: Origin,
](
    parameters: Span[UInt8, parameters_origin],
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    var group = decode_parameters(parameters)
    var y = decode_public(public_key, group)
    if len(signature) != group.p_bytes + group.q_bytes:
        return False
    try:
        var r_bytes = List[UInt8](capacity=group.p_bytes)
        var s_bytes = List[UInt8](capacity=group.q_bytes)
        for i in range(group.p_bytes):
            r_bytes.append(signature[i])
        for i in range(group.q_bytes):
            s_bytes.append(signature[group.p_bytes + i])
        var r = decode_public(Span(r_bytes), group)
        var s = from_be(Span(s_bytes))
        if s.is_zero() or s.compare(group.q) >= 0:
            return False
        var digest = sha256(message)
        var h = from_be(Span(digest)).modulo(group.q)
        var left = group.g.modular_power(h, group.p)
        var right = y.modular_power(
            r.modulo(group.q), group.p
        ).modular_multiply(r.modular_power(s, group.p), group.p)
        return left.compare(right) == 0
    except:
        return False
