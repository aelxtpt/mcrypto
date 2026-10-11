"""XEd25519 signatures with raw X25519 keys (XEdDSA, Curve25519 instance).

Signing follows https://signal.org/docs/specifications/xeddsa/. Private keys
are clamped as in X25519; they are not Ed25519 seeds. Verification uses the
library's strict Ed25519 policy: canonical encodings and scalar s < q, with
small-order public keys and R points rejected. This is stricter than the
original XEdDSA verifier. Legacy signatures carrying a sign bit in s are
not accepted. Only the Curve25519 instance is implemented.
"""

from ..hashes.sha512 import SHA512
from ..internal.field25519 import (
    add as _field_add,
    inverse as _field_inverse,
    multiply as _field_multiply,
    pack as _field_pack,
    subtract as _field_subtract,
    unpack as _field_unpack,
)
from ..internal.secret import secure_zero
from ..random.entropy import system_entropy
from .ed25519 import (
    _L,
    _encode,
    _join32,
    _multiply_add_scalar,
    _one,
    _reduce_scalar,
    _scalar_multiply_base,
    verify as _ed25519_verify,
)

comptime PRIVATE_KEY_BYTES = 32
comptime PUBLIC_KEY_BYTES = 32
comptime SIGNATURE_BYTES = 64
comptime RANDOM_BYTES = 64
comptime _SIGN_BIT = UInt8(0x80)
comptime _CLEAR_SIGN_BIT = UInt8(0x7F)
comptime _CLAMP_LOW = UInt8(0xF8)
comptime _CLAMP_HIGH = UInt8(0x40)


def sign_with_randomness[
    message_origin: Origin, key_origin: Origin, random_origin: Origin
](
    message: Span[UInt8, message_origin],
    private_key: Span[UInt8, key_origin],
    randomness: Span[UInt8, random_origin],
) raises -> List[UInt8]:
    """Sign using an explicit 64-byte secret random input Z.

    Prefer ``sign`` for application use. Callers of this advanced API must
    supply fresh cryptographically secure randomness for every signature.
    Fixed randomness is for known-answer tests only. Inputs are not modified.
    """
    if len(private_key) != PRIVATE_KEY_BYTES:
        raise Error("XEd25519 private key must be 32 bytes")
    if len(randomness) != RANDOM_BYTES:
        raise Error("XEd25519 randomness must be 64 bytes")

    var scalar = InlineArray[UInt8, PRIVATE_KEY_BYTES](fill=0)
    for i in range(PRIVATE_KEY_BYTES):
        scalar[i] = private_key[i]
    scalar[0] &= _CLAMP_LOW
    scalar[PRIVATE_KEY_BYTES - 1] &= _CLEAR_SIGN_BIT
    scalar[PRIVATE_KEY_BYTES - 1] |= _CLAMP_HIGH

    var ed_public_key = _encode(_scalar_multiply_base(Span(scalar)))
    # Montgomery u omits the Edwards x sign. Choose sign zero, negating the
    # private scalar modulo q when necessary. Masked selection avoids a
    # secret-dependent branch. Keep the clamped scalar bytes when sign is zero,
    # as in the reference nonce derivation (do not reduce that branch first).
    var zero = InlineArray[UInt8, PRIVATE_KEY_BYTES](fill=0)
    var order_minus_one = materialize[_L]()
    order_minus_one[0] -= 1
    var negated = _multiply_add_scalar(
        Span(zero), Span(order_minus_one), Span(scalar)
    )
    var negate_mask = UInt8(0) - (ed_public_key[PUBLIC_KEY_BYTES - 1] >> 7)
    for i in range(PRIVATE_KEY_BYTES):
        scalar[i] ^= negate_mask & (scalar[i] ^ negated[i])
    ed_public_key[PUBLIC_KEY_BYTES - 1] &= _CLEAR_SIGN_BIT
    secure_zero(Span(negated))

    # hash_1(X) = SHA-512((2^256 - 2) little-endian || X).
    # The domain prefix separates nonce hashing from the challenge hash.
    var nonce_prefix = InlineArray[UInt8, 32](fill=0xFF)
    nonce_prefix[0] = 0xFE
    var nonce_hash = SHA512()
    nonce_hash.update(Span(nonce_prefix))
    nonce_hash.update(Span(scalar))
    nonce_hash.update(message)
    nonce_hash.update(randomness)
    var nonce_digest = nonce_hash.finalize()
    var nonce = _reduce_scalar(Span(nonce_digest))
    secure_zero(Span(nonce_digest))
    var encoded_r = _encode(_scalar_multiply_base(Span(nonce)))

    var challenge_hash = SHA512()
    challenge_hash.update(Span(encoded_r))
    challenge_hash.update(Span(ed_public_key))
    challenge_hash.update(message)
    var challenge_digest = challenge_hash.finalize()
    var challenge = _reduce_scalar(Span(challenge_digest))
    var s = _multiply_add_scalar(Span(nonce), Span(challenge), Span(scalar))
    secure_zero(Span(scalar))
    secure_zero(Span(nonce))
    return _join32(Span(encoded_r), Span(s))


def sign[
    message_origin: Origin, key_origin: Origin
](
    message: Span[UInt8, message_origin],
    private_key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    """Sign with a raw 32-byte X25519 private key and fresh OS randomness.

    Returns a detached 64-byte R || s signature. Entropy failures propagate.
    """
    if len(private_key) != PRIVATE_KEY_BYTES:
        raise Error("XEd25519 private key must be 32 bytes")
    var randomness = system_entropy(RANDOM_BYTES)
    var signature = sign_with_randomness(message, private_key, Span(randomness))
    secure_zero(Span(randomness))
    return signature^


def verify[
    signature_origin: Origin, message_origin: Origin, key_origin: Origin
](
    signature: Span[UInt8, signature_origin],
    message: Span[UInt8, message_origin],
    public_key: Span[UInt8, key_origin],
) -> Bool:
    """Verify with a canonical 32-byte Montgomery public key; fail closed.

    Rejects malformed lengths, u >= p, s >= q, invalid Edwards points,
    small-order public keys/R, and the legacy signature sign-bit format.
    """
    if len(signature) != SIGNATURE_BYTES or len(public_key) != PUBLIC_KEY_BYTES:
        return False
    # Unlike X25519 agreement decoding, signature keys must be canonical.
    if public_key[PUBLIC_KEY_BYTES - 1] & _SIGN_BIT:
        return False
    try:
        var u = _field_unpack(public_key)
        var canonical_u = _field_pack(u)
        for i in range(PUBLIC_KEY_BYTES):
            if canonical_u[i] != public_key[i]:
                return False

        # Convert u to Edwards y = (u - 1)/(u + 1); its sign bit stays zero.
        var one = _one()
        var numerator = InlineArray[UInt64, 5](fill=0)
        var denominator = InlineArray[UInt64, 5](fill=0)
        var inverse = InlineArray[UInt64, 5](fill=0)
        var y = InlineArray[UInt64, 5](fill=0)
        _field_subtract(numerator, u, one)
        _field_add(denominator, u, one)
        _field_inverse(inverse, denominator)
        _field_multiply(y, numerator, inverse)
        var ed_public_key = _field_pack(y)
        return _ed25519_verify(signature, message, Span(ed_public_key))
    except:
        return False
