"""TurboSHAKE-128 and TurboSHAKE-256 in pure Mojo."""

from .keccak import KeccakSponge


struct TurboSHAKE(Movable):
    var _sponge: KeccakSponge

    def __init__(out self, bits: Int, domain: UInt8 = 0x1F) raises:
        if bits == 128:
            self._sponge = KeccakSponge(168, domain, True)
        elif bits == 256:
            self._sponge = KeccakSponge(136, domain, True)
        else:
            raise Error("TurboSHAKE size must be 128 or 256")

    def __init__(out self, *, deinit move: Self):
        self._sponge = move._sponge^

    def update[origin: Origin](mut self, data: Span[UInt8, origin]) raises:
        self._sponge.update(data)

    def squeeze(mut self, output_bytes: Int) raises -> List[UInt8]:
        if output_bytes < 0:
            raise Error("TurboSHAKE output length cannot be negative")
        return self._sponge.squeeze(output_bytes)


def turboshake[
    origin: Origin
](
    bits: Int,
    data: Span[UInt8, origin],
    output_bytes: Int,
    domain: UInt8 = 0x1F,
) raises -> List[UInt8]:
    var state = TurboSHAKE(bits, domain)
    state.update(data)
    return state.squeeze(output_bytes)


def turboshake128[
    origin: Origin
](
    data: Span[UInt8, origin], output_bytes: Int, domain: UInt8 = 0x1F
) raises -> List[UInt8]:
    return turboshake(128, data, output_bytes, domain)


def turboshake256[
    origin: Origin
](
    data: Span[UInt8, origin], output_bytes: Int, domain: UInt8 = 0x1F
) raises -> List[UInt8]:
    return turboshake(256, data, output_bytes, domain)
