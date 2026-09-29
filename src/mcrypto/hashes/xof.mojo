"""Pure-Mojo extendable-output hash functions."""

from .xof_algorithm import XofAlgorithm
from .keccak import _sponge_rounds


def xof[
    origin: Origin
](
    algorithm: XofAlgorithm,
    data: Span[UInt8, origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    if output_bytes <= 0:
        raise Error("XOF output must be positive")
    if algorithm == XofAlgorithm.SHAKE128:
        return _sponge_rounds[168, False](data, output_bytes, 0x1F)
    if algorithm == XofAlgorithm.SHAKE256:
        return _sponge_rounds[136, False](data, output_bytes, 0x1F)
    if algorithm == XofAlgorithm.TURBOSHAKE128:
        return _sponge_rounds[168, True](data, output_bytes, 0x1F)
    if algorithm == XofAlgorithm.TURBOSHAKE256:
        return _sponge_rounds[136, True](data, output_bytes, 0x1F)
    raise Error("invalid XOF selector")
