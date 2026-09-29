"""Rabin trapdoor encryption and Rabin-Williams signatures in pure Mojo.

Encryption keys are ``RBW1 || 3 || n,r,s`` and ``RBS1 || 6 ||
n,r,s,p,q,q^-1 mod p``. Signature keys retain the distinct ``RWV1`` and
``RWS1`` frames. Lengths are 32-bit big-endian; outputs are fixed-width.
"""

from ..math.biguint import BigUInt
from ..hashes.sha1 import sha1
from ._legacy_math import (
    encode_key,
    decode_key,
    generate_prime,
    inverse,
    random_below,
    uint_from_bytes,
    uint_to_bytes,
    quotient,
)


def _magic(text: StaticString) -> List[UInt8]:
    return [
        UInt8(ord(text[byte=0])),
        UInt8(ord(text[byte=1])),
        UInt8(ord(text[byte=2])),
        UInt8(ord(text[byte=3])),
    ]


def signature_keypair(
    bits: Int = 512,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate an IEEE P1363 Rabin-Williams signature keypair."""
    if bits < 192 or bits % 8 != 0:
        raise Error(
            "Rabin-Williams modulus must be byte-aligned and >= 192 bits"
        )
    var p: BigUInt
    var q: BigUInt
    var n: BigUInt
    while True:
        p = generate_prime(bits // 2, -1, 3)
        q = generate_prime(bits - bits // 2, -1, 7)
        if p.compare(q) == 0:
            continue
        n = p.multiply(q)
        if n.bit_length() == bits:
            break
    var u = inverse(q, p)
    var public = encode_key(Span(_magic("RWV1")), [n.copy()])
    var private = encode_key(
        Span(_magic("RWS1")), [n.copy(), p.copy(), q.copy(), u.copy()]
    )
    return (public^, private^)


def signature_apply[
    public_origin: Origin, input_origin: Origin
](
    public_key: Span[UInt8, public_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    var key = decode_key(public_key, "RWV1", 1)
    var n = key[0].copy()
    var x = uint_from_bytes(input)
    var bound = n.copy()
    bound.shift_right_one()
    bound.add_small(1)
    if x.compare(bound) >= 0:
        raise Error("Rabin-Williams input outside preimage bound")
    var result = x.modular_multiply(x, n)
    var residue = result.modulo(BigUInt(16))
    if residue.compare(BigUInt(12)) == 0:
        pass
    elif residue.compare(BigUInt(6)) == 0 or residue.compare(BigUInt(14)) == 0:
        result = result.add(result)
    elif residue.compare(BigUInt(9)) == 0 or residue.compare(BigUInt(1)) == 0:
        result = n.subtract(result)
    elif residue.compare(BigUInt(7)) == 0 or residue.compare(BigUInt(15)) == 0:
        result = n.subtract(result).multiply(BigUInt(2))
    else:
        result = BigUInt()
    return uint_to_bytes(result, (n.bit_length() + 7) // 8)


def _crt(
    aq: BigUInt, q: BigUInt, ap: BigUInt, p: BigUInt, u: BigUInt
) raises -> BigUInt:
    var delta = ap.modular_subtract(aq.modulo(p), p)
    var coefficient = delta.modular_multiply(u, p)
    return aq.add(q.multiply(coefficient))


def signature_invert[
    private_origin: Origin, input_origin: Origin
](
    private_key: Span[UInt8, private_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    var k = decode_key(private_key, "RWS1", 4)
    var n = k[0].copy()
    var p = k[1].copy()
    var q = k[2].copy()
    var u = k[3].copy()
    var h = uint_from_bytes(input)
    if h.compare(n) >= 0:
        raise Error("Rabin-Williams image outside modulus")
    var exponent_u = quotient(q.add(BigUInt(1)), BigUInt(8))
    var root_u = h.modular_power(exponent_u, q)
    var root_u_fourth = root_u.modular_power(BigUInt(4), q)
    var e_positive = root_u_fourth.compare(h.modulo(q)) == 0
    var eh_p = h.modulo(p) if e_positive else p.subtract(h.modulo(p))
    var exponent_v = quotient(p.subtract(BigUInt(3)), BigUInt(8))
    var root_v = eh_p.modular_power(exponent_v, p)
    var probe = root_v.modular_power(BigUInt(4), p)
    probe = probe.modular_multiply(eh_p.modular_multiply(eh_p, p), p)
    var f_one = probe.compare(eh_p) == 0
    var root_w = root_u.copy()
    if not f_one:
        var power = quotient(
            q.multiply(BigUInt(3)).subtract(BigUInt(5)), BigUInt(8)
        )
        root_w = root_w.modular_multiply(BigUInt(2).modular_power(power, q), q)
    var root_x = root_v.modular_power(BigUInt(3), p)
    root_x = root_x.modular_multiply(eh_p, p)
    if not f_one:
        var power = quotient(
            p.multiply(BigUInt(9)).subtract(BigUInt(11)), BigUInt(8)
        )
        root_x = root_x.modular_multiply(BigUInt(2).modular_power(power, p), p)
    var y = _crt(root_w, q, root_x, p, u)
    var signature = y.modular_multiply(y, n)
    var opposite = n.subtract(signature)
    if opposite.compare(signature) < 0:
        signature = opposite^
    var encoded = uint_to_bytes(signature, (n.bit_length() + 7) // 8)
    return encoded^


def _validate_encryption_public(n: BigUInt, r: BigUInt, s: BigUInt) raises:
    var one = BigUInt(1)
    if (
        n.compare(one) <= 0
        or n.modulo(BigUInt(4)).compare(one) != 0
        or r.compare(one) <= 0
        or r.compare(n) >= 0
        or s.compare(one) <= 0
        or s.compare(n) >= 0
        or r.jacobi_symbol(n) != -1
        or s.jacobi_symbol(n) != -1
    ):
        raise Error("invalid Rabin encryption public key")


def _validate_encryption_private(
    n: BigUInt,
    r: BigUInt,
    s: BigUInt,
    p: BigUInt,
    q: BigUInt,
    u: BigUInt,
) raises:
    _validate_encryption_public(n, r, s)
    var one = BigUInt(1)
    var three = BigUInt(3)
    if (
        p.compare(one) <= 0
        or q.compare(one) <= 0
        or p.compare(q) == 0
        or p.modulo(BigUInt(4)).compare(three) != 0
        or q.modulo(BigUInt(4)).compare(three) != 0
        or p.multiply(q).compare(n) != 0
        or u.compare(one) < 0
        or u.compare(p) >= 0
        or u.modular_multiply(q, p).compare(one) != 0
        or r.jacobi_symbol(p) != 1
        or r.jacobi_symbol(q) != -1
        or s.jacobi_symbol(p) != -1
        or s.jacobi_symbol(q) != 1
    ):
        raise Error("invalid Rabin encryption private key")


def encryption_keypair(
    bits: Int = 512,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate a Rabin encryption keypair with the interoperable encoding."""
    if bits < 128 or bits % 8 != 0:
        raise Error(
            "Rabin encryption modulus must be byte-aligned and >= 128 bits"
        )
    var p: BigUInt
    var q: BigUInt
    var n: BigUInt
    while True:
        p = generate_prime(bits // 2, 3)
        q = generate_prime(bits - bits // 2, 3)
        if p.compare(q) == 0:
            continue
        n = p.multiply(q)
        if n.bit_length() == bits:
            break
    var r = BigUInt()
    var s = BigUInt()
    var found_r = False
    var found_s = False
    var candidate = BigUInt(2)
    while not found_r or not found_s:
        var jp = candidate.jacobi_symbol(p)
        var jq = candidate.jacobi_symbol(q)
        if not found_r and jp == 1 and jq == -1:
            r = candidate.copy()
            found_r = True
        if not found_s and jp == -1 and jq == 1:
            s = candidate.copy()
            found_s = True
        candidate.add_small(1)
    var u = inverse(q, p)
    _validate_encryption_private(n, r, s, p, q, u)
    var public = encode_key(
        Span(_magic("RBW1")), [n.copy(), r.copy(), s.copy()]
    )
    var private = encode_key(
        Span(_magic("RBS1")),
        [n.copy(), r.copy(), s.copy(), p.copy(), q.copy(), u.copy()],
    )
    return (public^, private^)


def _encryption_forward(
    x: BigUInt, n: BigUInt, r: BigUInt, s: BigUInt
) raises -> BigUInt:
    var result = x.modular_multiply(x, n)
    if x.bit(0) != 0:
        result = result.modular_multiply(r, n)
    if x.jacobi_symbol(n) == -1:
        result = result.modular_multiply(s, n)
    return result^


def encryption_apply[
    public_origin: Origin, input_origin: Origin
](
    public_key: Span[UInt8, public_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    var key = decode_key(public_key, "RBW1", 3)
    var n = key[0].copy()
    var r = key[1].copy()
    var s = key[2].copy()
    _validate_encryption_public(n, r, s)
    var x = uint_from_bytes(input)
    if x.compare(n) >= 0:
        raise Error("Rabin encryption input outside modulus")
    return uint_to_bytes(
        _encryption_forward(x, n, r, s), (n.bit_length() + 7) // 8
    )


def _blinded_square_root(value: BigUInt, prime: BigUInt) raises -> BigUInt:
    var blinder = random_below(prime.subtract(BigUInt(1))).add(BigUInt(1))
    var square = blinder.modular_multiply(blinder, prime)
    var blinded = value.modular_multiply(square, prime)
    var exponent = quotient(prime.add(BigUInt(1)), BigUInt(4))
    var root = blinded.modular_power(exponent, prime)
    return root.modular_multiply(blinder.modular_inverse(prime), prime)


def encryption_invert[
    private_origin: Origin, input_origin: Origin
](
    private_key: Span[UInt8, private_origin], input: Span[UInt8, input_origin]
) raises -> List[UInt8]:
    var key = decode_key(private_key, "RBS1", 6)
    var n = key[0].copy()
    var r = key[1].copy()
    var s = key[2].copy()
    var p = key[3].copy()
    var q = key[4].copy()
    var u = key[5].copy()
    _validate_encryption_private(n, r, s, p, q, u)
    var width = (n.bit_length() + 7) // 8
    if len(input) != width:
        raise Error("invalid Rabin encryption image length")
    var ciphertext = uint_from_bytes(input)
    if ciphertext.compare(n) >= 0:
        raise Error("Rabin encryption image outside modulus")
    var cp = ciphertext.modulo(p)
    var cq = ciphertext.modulo(q)
    var jp = cp.jacobi_symbol(p)
    var jq = cq.jacobi_symbol(q)

    # Precompute every residue class with the same full-width inverse work.
    # The class branch below only selects an already-computed pair.
    var r_inverse_p = r.modular_inverse(p)
    var r_inverse_q = r.modular_inverse(q)
    var s_inverse_p = s.modular_inverse(p)
    var s_inverse_q = s.modular_inverse(q)
    var cp_r = cp.modular_multiply(r_inverse_p, p)
    var cq_r = cq.modular_multiply(r_inverse_q, q)
    var cp_s = cp.modular_multiply(s_inverse_p, p)
    var cq_s = cq.modular_multiply(s_inverse_q, q)
    var cp_rs = cp_r.modular_multiply(s_inverse_p, p)
    var cq_rs = cq_r.modular_multiply(s_inverse_q, q)
    if jq == -1 and jp == -1:
        cp = cp_rs^
        cq = cq_rs^
    elif jq == -1:
        cp = cp_r^
        cq = cq_r^
    elif jp == -1:
        cp = cp_s^
        cq = cq_s^

    # Each prime uses an independent nonzero blinder.  Enumerate all root-sign
    # combinations, do the same forward work for each, and release only the
    # unique preimage whose public image matches the complete ciphertext.
    var root_p = _blinded_square_root(cp, p)
    var root_q = _blinded_square_root(cq, q)
    var negative_p = BigUInt() if root_p.is_zero() else p.subtract(root_p)
    var negative_q = BigUInt() if root_q.is_zero() else q.subtract(root_q)
    var candidate0 = _crt(root_q, q, root_p, p, u)
    var candidate1 = _crt(root_q, q, negative_p, p, u)
    var candidate2 = _crt(negative_q, q, root_p, p, u)
    var candidate3 = _crt(negative_q, q, negative_p, p, u)
    var valid0 = (
        _encryption_forward(candidate0, n, r, s).compare(ciphertext) == 0
    )
    var valid1 = (
        _encryption_forward(candidate1, n, r, s).compare(ciphertext) == 0
    )
    var valid2 = (
        _encryption_forward(candidate2, n, r, s).compare(ciphertext) == 0
    )
    var valid3 = (
        _encryption_forward(candidate3, n, r, s).compare(ciphertext) == 0
    )
    var result = BigUInt()
    var found = False
    var ambiguous = False
    if valid0:
        result = candidate0^
        found = True
    if valid1:
        if found and result.compare(candidate1) != 0:
            ambiguous = True
        elif not found:
            result = candidate1^
            found = True
    if valid2:
        if found and result.compare(candidate2) != 0:
            ambiguous = True
        elif not found:
            result = candidate2^
            found = True
    if valid3:
        if found and result.compare(candidate3) != 0:
            ambiguous = True
        elif not found:
            result = candidate3^
            found = True
    if not found or ambiguous:
        raise Error("invalid Rabin encryption image")
    return uint_to_bytes(result, width)


def _representative[
    origin: Origin
](message: Span[UInt8, origin], n: BigUInt) raises -> BigUInt:
    var representative_bits = n.bit_length() - 1
    if representative_bits % 8 != 7:
        raise Error("EMSA2 requires a byte-aligned modulus")
    var digest = sha1(message)
    var width = (representative_bits + 7) // 8
    if representative_bits < 8 * len(digest) + 31:
        raise Error("Rabin-Williams modulus too small for EMSA2(SHA-1)")
    var encoded = List[UInt8](length=width, fill=0xBB)
    encoded[0] = 0x4B if len(message) == 0 else 0x6B
    var delimiter = width - len(digest) - 3
    encoded[delimiter] = 0xBA
    for i in range(len(digest)):
        encoded[delimiter + 1 + i] = digest[i]
    encoded[width - 2] = 0x33
    encoded[width - 1] = 0xCC
    return uint_from_bytes(Span(encoded))


def sign[
    key_origin: Origin, message_origin: Origin
](
    private_key: Span[UInt8, key_origin], message: Span[UInt8, message_origin]
) raises -> List[UInt8]:
    var key = decode_key(private_key, "RWS1", 4)
    var rep = _representative(message, key[0])
    var encoded = uint_to_bytes(rep, (key[0].bit_length() + 7) // 8)
    return signature_invert(private_key, Span(encoded))


def verify[
    key_origin: Origin, message_origin: Origin, signature_origin: Origin
](
    public_key: Span[UInt8, key_origin],
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    var key = decode_key(public_key, "RWV1", 1)
    var width = (key[0].bit_length() + 7) // 8
    if len(signature) != width:
        return False
    try:
        var image = signature_apply(public_key, signature)
        var expected = uint_to_bytes(_representative(message, key[0]), width)
        if len(image) != len(expected):
            return False
        var diff = UInt8(0)
        for i in range(len(image)):
            diff |= image[i] ^ expected[i]
        return diff == 0
    except:
        return False
