"""Lucas-function Diffie-Hellman (LUCDIF)."""

from ..math.biguint import BigUInt
from ._common import from_be, to_be, parse_hex


struct LUCDomain(Copyable, Movable):
    """LUC-DH parameters p, q and Lucas seed P with fixed-width keys."""

    var modulus: BigUInt
    var order: BigUInt
    var seed: BigUInt
    var bytes: Int
    var private_bytes: Int

    def __init__(
        out self, modulus: BigUInt, order: BigUInt, seed: BigUInt
    ) raises:
        if (
            modulus.compare(BigUInt(5)) <= 0
            or modulus.bit(0) == 0
            or order.compare(BigUInt(2)) <= 0
        ):
            raise Error("invalid LUCDIF group")
        if seed.compare(BigUInt(2)) <= 0 or seed.compare(modulus) >= 0:
            raise Error("invalid LUCDIF Lucas seed")
        self.modulus = modulus.copy()
        self.order = order.copy()
        self.seed = seed.copy()
        self.bytes = (modulus.bit_length() + 7) // 8
        self.private_bytes = (order.bit_length() + 7) // 8

    def __init__(out self, *, copy: Self):
        self.modulus = copy.modulus.copy()
        self.order = copy.order.copy()
        self.seed = copy.seed.copy()
        self.bytes = copy.bytes
        self.private_bytes = copy.private_bytes

    def __init__(out self, *, deinit move: Self):
        self.modulus = move.modulus^
        self.order = move.order^
        self.seed = move.seed^
        self.bytes = move.bytes
        self.private_bytes = move.private_bytes


def lucd512_domain() raises -> LUCDomain:
    """Return the canonical 512-bit LUCDIF domain."""
    var p = parse_hex(
        "c339d027e5812ed5d9de044f3697d0273625e5ea9ec4ef3fb89adbfa9cd1fbf"
        "4d8c0ec1118c44609f499ef644eeaece2f38b3f67fac81a075f31a60b5757a87d"
    )
    var q = parse_hex(
        "619ce813f2c0976aecef02279b4be8139b12f2f54f62779fdc4d6dfd4e68fdfa"
        "6c6076088c622304fa4cf7b22775767179c59fb3fd640d03af98d305ababd43f"
    )
    return LUCDomain(p, q, BigUInt(9))


def _lucas_v(
    domain: LUCDomain, index: BigUInt, parameter: BigUInt
) raises -> BigUInt:
    return parameter.modular_lucas(index, domain.modulus)


def _private[
    origin: Origin
](domain: LUCDomain, key: Span[UInt8, origin]) raises -> BigUInt:
    if len(key) != domain.private_bytes:
        raise Error("LUCDIF private key has the wrong fixed width")
    var value = from_be(key)
    if value.is_zero() or value.compare(domain.order) >= 0:
        raise Error("LUCDIF private exponent is outside [1,q-1]")
    return value^


def public_key[
    origin: Origin
](domain: LUCDomain, private_key: Span[UInt8, origin]) raises -> List[UInt8]:
    """Return the fixed-width V_x(P,1) public element."""
    return to_be(
        _lucas_v(domain, _private(domain, private_key), domain.seed),
        domain.bytes,
    )


def agree[
    so: Origin, po: Origin
](
    domain: LUCDomain,
    private_key: Span[UInt8, so],
    peer_public: Span[UInt8, po],
) raises -> List[UInt8]:
    """Return the fixed-width raw V_ab(P,1) agreed value."""
    if len(peer_public) != domain.bytes:
        raise Error("LUCDIF public key has the wrong fixed width")
    var peer = from_be(peer_public)
    if peer.compare(domain.modulus) >= 0 or peer.compare(BigUInt(2)) == 0:
        raise Error("LUCDIF rejected a degenerate peer value")
    var discriminant = peer.modular_multiply(
        peer, domain.modulus
    ).modular_subtract(BigUInt(4), domain.modulus)
    if discriminant.jacobi_symbol(domain.modulus) != -1:
        raise Error("LUCDIF peer value is outside the q-order subgroup")
    var secret = _lucas_v(domain, _private(domain, private_key), peer)
    return to_be(secret, domain.bytes)
