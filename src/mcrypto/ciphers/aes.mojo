"""AES-specific pure-Mojo helpers."""

from .algorithm import BlockCipherAlgorithm, CipherMode
from .modes import process as mode_process


def aes_cbc_cts[
    key_origin: Origin, iv_origin: Origin, input_origin: Origin
](
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    return mode_process(
        BlockCipherAlgorithm.AES,
        CipherMode.CBC_CTS,
        encrypt,
        key,
        iv,
        input,
    )
