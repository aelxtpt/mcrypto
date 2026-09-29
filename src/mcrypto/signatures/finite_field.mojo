"""Shared prime-field arithmetic and explicit wire encodings for finite-field schemes.

A parameter block is ``u16be(p_len) || u16be(q_len) || u16be(g_len) || p || q || g``.
All integers are unsigned, minimally encoded, big-endian.  Private scalars and signature
components use exactly ``q_len`` bytes; public elements use exactly ``p_len`` bytes.
"""

from ..math.biguint import BigUInt
from ..random.generator import random_bytes
from ..math.primes import is_probable_prime
from ..key_exchange._common import parse_hex


struct PrimeGroup(Copyable, Movable):
    var p: BigUInt
    var q: BigUInt
    var g: BigUInt
    var p_bytes: Int
    var q_bytes: Int

    def __init__(
        out self,
        p: BigUInt,
        q: BigUInt,
        g: BigUInt,
        *,
        trusted: Bool = False,
    ) raises:
        if not trusted:
            var one = BigUInt(1)
            if p.compare(BigUInt(5)) < 0 or p.bit(0) == 0:
                raise Error(
                    "prime-group p must be an odd integer at least five"
                )
            if q.compare(BigUInt(2)) < 0 or q.bit(0) == 0:
                raise Error("prime-group q must be an odd integer")
            if not is_probable_prime(p) or not is_probable_prime(q):
                raise Error("prime-group p and q must be probable primes")
            if not p.subtract(one).modulo(q).is_zero():
                raise Error("prime-group q must divide p-1")
            if g.compare(one) <= 0 or g.compare(p) >= 0:
                raise Error("prime-group generator is out of range")
            if g.modular_power(q, p).compare(one) != 0:
                raise Error(
                    "prime-group generator is not in the q-order subgroup"
                )
        self.p = p.copy()
        self.q = q.copy()
        self.g = g.copy()
        self.p_bytes = (p.bit_length() + 7) // 8
        self.q_bytes = (q.bit_length() + 7) // 8


def rfc5114_group1() raises -> PrimeGroup:
    """Return RFC 5114's 1024-bit MODP group with a 160-bit subgroup."""
    var p = parse_hex(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
    )
    var q = parse_hex("F518AA8781A8DF278ABA4E7D64B7CB9D49462353")
    var g = parse_hex(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
    )
    return PrimeGroup(p, q, g, trusted=True)


def from_be[origin: Origin](data: Span[UInt8, origin]) raises -> BigUInt:
    if len(data) == 0:
        raise Error("integer encoding cannot be empty")
    var limbs = List[UInt32](length=max(1, (len(data) + 3) // 4), fill=0)
    for i in range(len(data)):
        var source = len(data) - 1 - i
        limbs[i // 4] |= UInt32(data[source]) << UInt32(8 * (i % 4))
    return BigUInt.from_limbs(Span(limbs))


def to_be_fixed(value: BigUInt, width: Int) raises -> List[UInt8]:
    if width <= 0 or value.bit_length() > width * 8:
        raise Error("integer does not fit its fixed-width encoding")
    var output = List[UInt8](length=width, fill=0)
    for i in range(min(width, len(value.limbs) * 4)):
        output[width - 1 - i] = UInt8(
            value.limbs[i // 4] >> UInt32(8 * (i % 4))
        )
    return output^


def _append_u16(mut output: List[UInt8], value: Int) raises:
    if value <= 0 or value > 65535:
        raise Error("parameter component length is out of range")
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


def encode_parameters(group: PrimeGroup) raises -> List[UInt8]:
    """Encode a group using the parameter-block format documented by this module.
    """
    var p = to_be_fixed(group.p, group.p_bytes)
    var q = to_be_fixed(group.q, group.q_bytes)
    var g = to_be_fixed(group.g, group.p_bytes)
    var output = List[UInt8](capacity=6 + len(p) + len(q) + len(g))
    _append_u16(output, len(p))
    _append_u16(output, len(q))
    _append_u16(output, len(g))
    for byte in p:
        output.append(byte)
    for byte in q:
        output.append(byte)
    for byte in g:
        output.append(byte)
    return output^


def decode_parameters[
    origin: Origin
](encoded: Span[UInt8, origin]) raises -> PrimeGroup:
    if len(encoded) < 9:
        raise Error("truncated prime-group parameter block")
    var p_len = (Int(encoded[0]) << 8) | Int(encoded[1])
    var q_len = (Int(encoded[2]) << 8) | Int(encoded[3])
    var g_len = (Int(encoded[4]) << 8) | Int(encoded[5])
    if (
        p_len <= 0
        or q_len <= 0
        or g_len != p_len
        or 6 + p_len + q_len + g_len != len(encoded)
    ):
        raise Error("invalid prime-group parameter lengths")
    var p_bytes = List[UInt8](capacity=p_len)
    var q_bytes = List[UInt8](capacity=q_len)
    var g_bytes = List[UInt8](capacity=g_len)
    for i in range(p_len):
        p_bytes.append(encoded[6 + i])
    for i in range(q_len):
        q_bytes.append(encoded[6 + p_len + i])
    for i in range(g_len):
        g_bytes.append(encoded[6 + p_len + q_len + i])
    var p = from_be(Span(p_bytes))
    var q = from_be(Span(q_bytes))
    var g = from_be(Span(g_bytes))
    var standard = rfc5114_group1()
    if (
        p.compare(standard.p) == 0
        and q.compare(standard.q) == 0
        and g.compare(standard.g) == 0
    ):
        return standard^
    return PrimeGroup(p, q, g)


def random_scalar(group: PrimeGroup) raises -> BigUInt:
    """Uniformly sample an integer in [1,q-1] by rejection sampling."""
    while True:
        var encoded = random_bytes(group.q_bytes)
        var candidate = from_be(Span(encoded))
        if not candidate.is_zero() and candidate.compare(group.q) < 0:
            return candidate^


def generate_keypair[
    origin: Origin
](parameters: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Return ``(private_x[q_len], public_y[p_len])`` for an encoded group."""
    var group = decode_parameters(parameters)
    var x = random_scalar(group)
    var y = group.g.modular_power(x, group.p)
    return (to_be_fixed(x, group.q_bytes), to_be_fixed(y, group.p_bytes))


def decode_private[
    origin: Origin
](encoded: Span[UInt8, origin], group: PrimeGroup) raises -> BigUInt:
    if len(encoded) != group.q_bytes:
        raise Error("private scalar has the wrong width")
    var value = from_be(encoded)
    if value.is_zero() or value.compare(group.q) >= 0:
        raise Error("private scalar is out of range")
    return value^


def decode_public[
    origin: Origin
](encoded: Span[UInt8, origin], group: PrimeGroup) raises -> BigUInt:
    if len(encoded) != group.p_bytes:
        raise Error("public element has the wrong width")
    var value = from_be(encoded)
    if value.compare(BigUInt(1)) <= 0 or value.compare(group.p) >= 0:
        raise Error("public element is out of range")
    if value.modular_power(group.q, group.p).compare(BigUInt(1)) != 0:
        raise Error("public element is outside the q-order subgroup")
    return value^


def hash_bits_to_int[
    origin: Origin
](digest: Span[UInt8, origin], bits: Int) -> BigUInt:
    """RFC 6979 bits2int: the leftmost ``bits`` bits of a big-endian digest."""
    var result = BigUInt()
    var available = min(bits, len(digest) * 8)
    for i in range(available):
        result.shift_left_one()
        var byte_index = i // 8
        var bit_index = 7 - i % 8
        result.add_small(UInt32((digest[byte_index] >> UInt8(bit_index)) & 1))
    return result^
