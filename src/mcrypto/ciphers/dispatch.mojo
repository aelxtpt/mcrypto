"""Pure-Mojo block cipher mode dispatcher."""

from .algorithm import (
    BlockCipherAlgorithm,
    CipherMode,
)
from .modes import process as mode_process
from .xts import process as xts_process


@always_inline("nodebug")
def _xts_supported(algorithm: BlockCipherAlgorithm) -> Bool:
    return (
        algorithm == BlockCipherAlgorithm.AES
        or algorithm == BlockCipherAlgorithm.THREEFISH256
        or algorithm == BlockCipherAlgorithm.THREEFISH512
        or algorithm == BlockCipherAlgorithm.THREEFISH1024
    )


def process[
    key_origin: Origin, iv_origin: Origin, input_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    mode: CipherMode,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) == 0:
        raise Error("block cipher key must not be empty")
    if mode == CipherMode.XTS:
        if not _xts_supported(algorithm):
            raise Error("cipher does not support XTS")
        return xts_process(algorithm, encrypt, key, iv, input)
    return mode_process(algorithm, mode, encrypt, key, iv, input)
