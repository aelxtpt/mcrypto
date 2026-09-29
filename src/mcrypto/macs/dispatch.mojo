"""Generic dispatcher for pure-Mojo keyed authenticators."""

from .algorithm import (
    MacAlgorithm,
    as_hmac_algorithm,
    as_siphash_algorithm,
)
from ..ciphers.algorithm import BlockCipherAlgorithm
from .hmac import authenticate as hmac_authenticate
from .poly1305 import authenticate as poly1305_authenticate
from .siphash import hash as siphash
from ..hashes.blake2 import blake2b_keyed, blake2s_keyed
from ..hashes.panama import panama
from ..internal.bytes import copy_into

from .cmac import authenticate as cmac_authenticate
from .cbc_mac import authenticate as cbc_mac_authenticate
from .dmac import authenticate as dmac_authenticate
from .two_track import authenticate as two_track_authenticate


def _truncate(value: List[UInt8], size: Int) raises -> List[UInt8]:
    if size <= 0 or size > len(value):
        raise Error("invalid MAC tag length")
    var output = List[UInt8](capacity=size)
    for i in range(size):
        output.append(value[i])
    return output^


def authenticate[
    key_origin: Origin, input_origin: Origin
](
    algorithm: MacAlgorithm,
    key: Span[UInt8, key_origin],
    input: Span[UInt8, input_origin],
    tag_bytes: Int,
) raises -> List[UInt8]:
    if tag_bytes <= 0:
        raise Error("invalid MAC tag length")
    if (
        algorithm == MacAlgorithm.HMAC_SHA1
        or algorithm == MacAlgorithm.HMAC_SHA256
        or algorithm == MacAlgorithm.HMAC_SHA512
        or algorithm == MacAlgorithm.HMAC_SHA512_256
        or algorithm == MacAlgorithm.RIPEMD160_HMAC
    ):
        return _truncate(
            hmac_authenticate(as_hmac_algorithm(algorithm), key, input),
            tag_bytes,
        )
    if algorithm == MacAlgorithm.BLAKE2S_MAC:
        return blake2s_keyed(input, key, tag_bytes)
    if algorithm == MacAlgorithm.BLAKE2B_MAC:
        return blake2b_keyed(input, key, tag_bytes)
    if algorithm == MacAlgorithm.POLY1305:
        return _truncate(poly1305_authenticate(key, input), tag_bytes)
    if (
        algorithm == MacAlgorithm.SIPHASH_2_4
        or algorithm == MacAlgorithm.SIPHASH_4_8
        or algorithm == MacAlgorithm.SIPHASH_X_2_4
    ):
        return _truncate(
            siphash(as_siphash_algorithm(algorithm), key, input), tag_bytes
        )
    if algorithm == MacAlgorithm.CMAC:
        return _truncate(cmac_authenticate(key, input), tag_bytes)
    if algorithm == MacAlgorithm.CBC_MAC:
        return cbc_mac_authenticate(
            BlockCipherAlgorithm.AES, key, input, tag_bytes
        )
    if algorithm == MacAlgorithm.DMAC:
        return dmac_authenticate(
            BlockCipherAlgorithm.AES, key, input, tag_bytes
        )
    if algorithm == MacAlgorithm.TWO_TRACK_MAC:
        return two_track_authenticate(key, input, tag_bytes)
    if algorithm == MacAlgorithm.GMAC:
        raise Error("GMAC requires a nonce; use mcrypto.macs.gmac.authenticate")
    if algorithm == MacAlgorithm.POLY1305_AES:
        raise Error(
            "Poly1305-AES requires a nonce; use"
            " mcrypto.macs.poly1305_aes.authenticate"
        )
    if algorithm == MacAlgorithm.VMAC:
        raise Error("VMAC requires a nonce; use mcrypto.macs.vmac.authenticate")
    if algorithm == MacAlgorithm.PANAMA_MAC:
        var keyed = List[UInt8](length=len(key) + len(input), fill=0)
        copy_into(key, Span(keyed))
        copy_into(input, Span(keyed), len(key))
        return _truncate(panama(Span(keyed)), tag_bytes)
    raise Error("MAC algorithm requires a specialized API")
