"""Pure-Mojo SHA-2, SHA-3, and BLAKE2b convenience dispatcher."""

from .algorithm import HashAlgorithm
from .sha256 import sha256
from .sha512 import sha512
from .keccak import sha3
from .blake2 import blake2b


def hash[
    origin: Origin
](
    algorithm: HashAlgorithm,
    data: Span[UInt8, origin],
    output_bytes: Int = 0,
) raises -> List[UInt8]:
    if algorithm == HashAlgorithm.SHA256:
        return sha256(data)
    if algorithm == HashAlgorithm.SHA512:
        return sha512(data)
    if algorithm == HashAlgorithm.SHA3_224:
        return sha3(224, data)
    if algorithm == HashAlgorithm.SHA3_384:
        return sha3(384, data)
    if algorithm == HashAlgorithm.SHA3_256:
        return sha3(256, data)
    if algorithm == HashAlgorithm.SHA3_512:
        return sha3(512, data)
    if algorithm == HashAlgorithm.BLAKE2B:
        var size = 32 if output_bytes == 0 else output_bytes
        if size < 16 or size > 64:
            raise Error("BLAKE2b output must be 16..64 bytes")
        return blake2b(data, size)
    raise Error("hash algorithm is not supported by the convenience dispatcher")
