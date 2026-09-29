"""Argon2id v1.3 password-based key derivation in pure Mojo."""

from ..kdf.argon2 import argon2id

comptime SALT_BYTES = 16
comptime ALGORITHM_ID = 2


def derive[
    password_origin: Origin, salt_origin: Origin
](
    password: Span[UInt8, password_origin],
    salt: Span[UInt8, salt_origin],
    output_bytes: Int = 32,
    operations: UInt64 = 2,
    memory_bytes: Int = 67108864,
) raises -> List[UInt8]:
    if len(salt) != SALT_BYTES:
        raise Error("Argon2id salt must be 16 bytes")
    if output_bytes < 16:
        raise Error("Argon2id output must be at least 16 bytes")
    if operations < 1 or memory_bytes < 8192:
        raise Error("Argon2id work limits are below the safe API minimum")
    return argon2id(
        password, salt, output_bytes, Int(operations), memory_bytes // 1024, 1
    )
