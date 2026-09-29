"""X25519-BLAKE2b session-key exchange in pure Mojo."""

from .x25519 import public_key as derive_public, agree
from ..random.entropy import system_entropy
from ..hashes.blake2 import blake2b


def keypair() raises -> Tuple[List[UInt8], List[UInt8]]:
    var secret_key = system_entropy(32)
    var public_key = derive_public(Span(secret_key))
    return (public_key^, secret_key^)


def session_keys[
    public_origin: Origin, secret_origin: Origin, peer_origin: Origin
](
    client: Bool,
    public_key: Span[UInt8, public_origin],
    secret_key: Span[UInt8, secret_origin],
    peer_public_key: Span[UInt8, peer_origin],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    if (
        len(public_key) != 32
        or len(secret_key) != 32
        or len(peer_public_key) != 32
    ):
        raise Error("key exchange inputs must be 32 bytes")
    var shared = agree(secret_key, peer_public_key)
    var transcript = List[UInt8](capacity=96)
    for byte in shared:
        transcript.append(byte)
    if client:
        for byte in public_key:
            transcript.append(byte)
        for byte in peer_public_key:
            transcript.append(byte)
    else:
        for byte in peer_public_key:
            transcript.append(byte)
        for byte in public_key:
            transcript.append(byte)
    var material = blake2b(Span(transcript), 64)
    var first = List[UInt8](capacity=32)
    var second = List[UInt8](capacity=32)
    for i in range(32):
        first.append(material[i])
        second.append(material[32 + i])
    return (first^, second^) if client else (second^, first^)
