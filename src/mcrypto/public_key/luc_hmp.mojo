"""LUC-HMP with IEEE P1363 EMSA1(SHA-256) and P1363 signatures."""
from ..hashes.sha256 import sha256
from ..math.biguint import BigUInt
from ..signatures.finite_field import hash_bits_to_int
from ._legacy_math import (
    decode_key,
    encode_key,
    generate_safe_prime_pair,
    random_below,
    uint_from_bytes,
    uint_to_bytes,
)
from .luc import lucas


def _magic(text: StaticString) -> List[UInt8]:
    return [
        UInt8(ord(text[byte=0])),
        UInt8(ord(text[byte=1])),
        UInt8(ord(text[byte=2])),
        UInt8(ord(text[byte=3])),
    ]


def keypair(bits: Int = 512) raises -> Tuple[List[UInt8], List[UInt8]]:
    if bits < 128:
        raise Error("LUC-HMP modulus must be at least 128 bits")
    var primes = generate_safe_prime_pair(bits, -1)
    var p = primes[0].copy()
    var q = primes[1].copy()
    var g: BigUInt
    while True:
        g = random_below(p.subtract(BigUInt(3))).add(BigUInt(2))
        if (
            g.compare(BigUInt(2)) != 0
            and lucas(q, g, p).compare(BigUInt(2)) == 0
        ):
            break
    var x = random_below(q.subtract(BigUInt(1))).add(BigUInt(1))
    var y = lucas(x, g, p)
    return (
        encode_key(
            Span(_magic("LHP1")), [p.copy(), q.copy(), g.copy(), y.copy()]
        ),
        encode_key(
            Span(_magic("LHS1")), [p.copy(), q.copy(), g.copy(), x.copy()]
        ),
    )


def _emsa1[o: Origin](message: Span[UInt8, o], bits: Int) raises -> BigUInt:
    var digest = sha256(message)
    return hash_bits_to_int(Span(digest), bits)


def sign[
    ko: Origin, mo: Origin
](private_key: Span[UInt8, ko], message: Span[UInt8, mo]) raises -> List[UInt8]:
    var key = decode_key(private_key, "LHS1", 4)
    var p = key[0].copy()
    var q = key[1].copy()
    var g = key[2].copy()
    var x = key[3].copy()
    if (
        p.add(BigUInt(1)).compare(q.add(q)) != 0
        or g.compare(BigUInt(2)) == 0
        or g.compare(p) >= 0
        or lucas(q, g, p).compare(BigUInt(2)) != 0
        or x.is_zero()
        or x.compare(q) >= 0
    ):
        raise Error("invalid LUC-HMP private key")
    var e = _emsa1(message, q.bit_length())
    var k = random_below(q.subtract(BigUInt(1))).add(BigUInt(1))
    var r = lucas(k, g, p)
    var s = k.modular_add(x.modular_multiply(r.modular_add(e, q), q), q)
    var out = uint_to_bytes(r, (p.bit_length() + 7) // 8)
    var encoded_s = uint_to_bytes(s, (q.bit_length() + 7) // 8)
    for b in encoded_s:
        out.append(b)
    return out^


def verify[
    ko: Origin, mo: Origin, so: Origin
](
    public_key: Span[UInt8, ko],
    message: Span[UInt8, mo],
    signature: Span[UInt8, so],
) raises -> Bool:
    var key = decode_key(public_key, "LHP1", 4)
    var p = key[0].copy()
    var q = key[1].copy()
    var g = key[2].copy()
    var y = key[3].copy()
    if (
        p.add(BigUInt(1)).compare(q.add(q)) != 0
        or g.compare(BigUInt(2)) == 0
        or g.compare(p) >= 0
        or lucas(q, g, p).compare(BigUInt(2)) != 0
        or y.compare(p) >= 0
        or lucas(q, y, p).compare(BigUInt(2)) != 0
    ):
        return False
    var p_bytes = (p.bit_length() + 7) // 8
    var q_bytes = (q.bit_length() + 7) // 8
    if len(signature) != p_bytes + q_bytes:
        return False
    var r = uint_from_bytes(signature[0:p_bytes])
    var s = uint_from_bytes(signature[p_bytes:])
    if r.compare(p) >= 0 or s.compare(q) >= 0:
        return False
    var e = _emsa1(message, q.bit_length())
    var vsg = lucas(s, g, p)
    var vry = lucas(r.modular_add(e, q), y, p)
    var left = (
        vsg.modular_multiply(vsg, p)
        .modular_add(vry.modular_multiply(vry, p), p)
        .modular_add(r.modular_multiply(r, p), p)
    )
    var right = (
        vsg.modular_multiply(vry, p)
        .modular_multiply(r, p)
        .modular_add(BigUInt(4), p)
    )
    return left.compare(right) == 0
