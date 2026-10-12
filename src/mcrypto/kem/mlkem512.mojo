"""FIPS 203 ML-KEM-512, backed by the shared pure-Mojo core.

seed_keypair consumes d[32] || z[32]. Deterministic encapsulation consumes
an independent 32-byte randomness input. Prefer keypair/encapsulate normally.
"""
from . import _mlkem
from ..random.entropy import system_entropy
from ..internal.secret import secure_zero

comptime PUBLIC_KEY_BYTES = 800
comptime SECRET_KEY_BYTES = 1632
comptime CIPHERTEXT_BYTES = 768
comptime SHARED_SECRET_BYTES = 32
comptime SEED_BYTES = 64
comptime ENCAPS_SEED_BYTES = 32
comptime _RANK = 2


def seed_keypair[
    origin: Origin
](seed: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Return (encapsulation_key, decapsulation_key) from exactly 64 bytes."""
    return _mlkem.seed_keypair[_RANK](seed)


def keypair() raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate a key pair using fresh OS entropy."""
    var seed = system_entropy(SEED_BYTES)
    try:
        var result = seed_keypair(Span(seed))
        secure_zero(Span(seed))
        return result^
    except error:
        secure_zero(Span(seed))
        raise error^


def encapsulate_deterministic[
    pk_origin: Origin, seed_origin: Origin
](
    public_key: Span[UInt8, pk_origin], seed: Span[UInt8, seed_origin]
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Return (ciphertext, shared_secret) with explicit 32-byte randomness."""
    return _mlkem.encapsulate_deterministic[_RANK](public_key, seed)


def encapsulate[
    origin: Origin
](public_key: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encapsulate using fresh OS entropy."""
    var seed = system_entropy(ENCAPS_SEED_BYTES)
    try:
        var result = encapsulate_deterministic(public_key, Span(seed))
        secure_zero(Span(seed))
        return result^
    except error:
        secure_zero(Span(seed))
        raise error^


def decapsulate[
    ct_origin: Origin, sk_origin: Origin
](
    ciphertext: Span[UInt8, ct_origin], secret_key: Span[UInt8, sk_origin]
) raises -> List[UInt8]:
    """Return a shared secret with FIPS 203 implicit ciphertext rejection."""
    return _mlkem.decapsulate[_RANK](ciphertext, secret_key)
