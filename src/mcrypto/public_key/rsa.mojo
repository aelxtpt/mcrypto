"""Pure-Mojo RSA encryption and signatures (PKCS #1 v2.2).

Key encodings are explicit binary component containers.  A public key is
``RSA1 || u32be(len(n)) || I2OSP(n) || u32be(len(e)) || I2OSP(e)``.  A private
key is ``RSA2 || u32be(len(n)) || I2OSP(n) || u32be(len(e)) || I2OSP(e) ||
u32be(len(d)) || I2OSP(d)``.  Integers are unsigned, minimally encoded,
big-endian; zero has the one-byte encoding 00.  These formats are internal to
mcrypto and deliberately are not ambiguous with DER.
"""
from .algorithm import RsaEncryptionAlgorithm
from ..signatures.algorithm import RsaSignatureAlgorithm
from ..hashes.algorithm import HashAlgorithm

from mcrypto.hashes.sha1 import sha1
from mcrypto.hashes.sha256 import sha256
from mcrypto.math.biguint import BigUInt
from mcrypto.random.entropy import system_entropy


comptime _PUBLIC_MAGIC: StaticString = "RSA1"
comptime _PRIVATE_MAGIC: StaticString = "RSA2"
comptime _PUBLIC_EXPONENT = UInt32(65537)


def os2ip[origin: Origin](input: Span[UInt8, origin]) -> BigUInt:
    """Convert an unsigned big-endian octet string to a nonnegative integer."""
    var limbs = List[UInt32](length=max(1, (len(input) + 3) // 4), fill=0)
    for i in range(len(input)):
        var source = len(input) - 1 - i
        limbs[i // 4] |= UInt32(input[source]) << UInt32(8 * (i % 4))
    return BigUInt.from_limbs(Span(limbs))


def i2osp(value: BigUInt, output_length: Int) raises -> List[UInt8]:
    """Convert an integer to exactly output_length big-endian octets."""
    if output_length < 0 or value.bit_length() > output_length * 8:
        raise Error("RSA integer does not fit the requested octet length")
    var output = List[UInt8](length=output_length, fill=0)
    for i in range(output_length):
        var source_byte = output_length - 1 - i
        var limb_index = source_byte // 4
        if limb_index < len(value.limbs):
            output[i] = UInt8(
                value.limbs[limb_index] >> UInt32((source_byte % 4) * 8)
            )
    return output^


def _minimal_i2osp(value: BigUInt) raises -> List[UInt8]:
    return i2osp(value, max(1, (value.bit_length() + 7) // 8))


def _append_u32(mut output: List[UInt8], value: UInt32):
    output.append(UInt8(value >> 24))
    output.append(UInt8(value >> 16))
    output.append(UInt8(value >> 8))
    output.append(UInt8(value))


def _read_u32[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) raises -> Int:
    if offset < 0 or offset + 4 > len(data):
        raise Error("truncated RSA key")
    return Int(
        (UInt32(data[offset]) << 24)
        | (UInt32(data[offset + 1]) << 16)
        | (UInt32(data[offset + 2]) << 8)
        | UInt32(data[offset + 3])
    )


def _append_bytes[
    origin: Origin
](mut output: List[UInt8], data: Span[UInt8, origin]):
    for byte in data:
        output.append(byte)


def _component[
    origin: Origin
](data: Span[UInt8, origin], offset: Int, size: Int) raises -> BigUInt:
    if size <= 0 or offset < 0 or offset + size > len(data):
        raise Error("invalid RSA key component")
    if size > 1 and data[offset] == 0:
        raise Error("non-minimal RSA key component")
    return os2ip(data[offset : offset + size])


def _has_magic[
    origin: Origin
](data: Span[UInt8, origin], magic: StaticString) -> Bool:
    var expected = magic.as_bytes()
    if len(data) < 4:
        return False
    for i in range(4):
        if data[i] != expected[i]:
            return False
    return True


def public_key_from_components[
    n_origin: Origin, e_origin: Origin
](
    modulus: Span[UInt8, n_origin], public_exponent: Span[UInt8, e_origin]
) raises -> List[UInt8]:
    """Encode minimal big-endian RSA public components in the RSA1 format."""
    var n = os2ip(modulus)
    var e = os2ip(public_exponent)
    if n.bit_length() < 16 or e.compare(BigUInt(3)) < 0 or e.bit(0) == 0:
        raise Error("invalid RSA public components")
    var n_bytes = _minimal_i2osp(n)
    var e_bytes = _minimal_i2osp(e)
    var output = List[UInt8](capacity=12 + len(n_bytes) + len(e_bytes))
    _append_bytes(output, _PUBLIC_MAGIC.as_bytes())
    _append_u32(output, UInt32(len(n_bytes)))
    _append_bytes(output, Span(n_bytes))
    _append_u32(output, UInt32(len(e_bytes)))
    _append_bytes(output, Span(e_bytes))
    return output^


def private_key_from_components[
    n_origin: Origin, e_origin: Origin, d_origin: Origin
](
    modulus: Span[UInt8, n_origin],
    public_exponent: Span[UInt8, e_origin],
    private_exponent: Span[UInt8, d_origin],
) raises -> List[UInt8]:
    """Encode minimal big-endian RSA n, e, d components in the RSA2 format."""
    var n = os2ip(modulus)
    var e = os2ip(public_exponent)
    var d = os2ip(private_exponent)
    if (
        n.bit_length() < 16
        or e.compare(BigUInt(3)) < 0
        or e.bit(0) == 0
        or d.is_zero()
    ):
        raise Error("invalid RSA private components")
    var n_bytes = _minimal_i2osp(n)
    var e_bytes = _minimal_i2osp(e)
    var d_bytes = _minimal_i2osp(d)
    var output = List[UInt8](
        capacity=16 + len(n_bytes) + len(e_bytes) + len(d_bytes)
    )
    _append_bytes(output, _PRIVATE_MAGIC.as_bytes())
    _append_u32(output, UInt32(len(n_bytes)))
    _append_bytes(output, Span(n_bytes))
    _append_u32(output, UInt32(len(e_bytes)))
    _append_bytes(output, Span(e_bytes))
    _append_u32(output, UInt32(len(d_bytes)))
    _append_bytes(output, Span(d_bytes))
    return output^


def _parse_public[
    origin: Origin
](key: Span[UInt8, origin]) raises -> Tuple[BigUInt, BigUInt]:
    if not _has_magic(key, _PUBLIC_MAGIC):
        raise Error("invalid RSA public key magic")
    var n_len = _read_u32(key, 4)
    var n_offset = 8
    var e_len_offset = n_offset + n_len
    var e_len = _read_u32(key, e_len_offset)
    var e_offset = e_len_offset + 4
    if e_offset + e_len != len(key):
        raise Error("invalid RSA public key length")
    var n = _component(key, n_offset, n_len)
    var e = _component(key, e_offset, e_len)
    if n.bit_length() < 16 or e.compare(BigUInt(3)) < 0 or e.bit(0) == 0:
        raise Error("invalid RSA public key")
    return (n^, e^)


def _parse_private[
    origin: Origin
](key: Span[UInt8, origin]) raises -> Tuple[BigUInt, BigUInt, BigUInt]:
    if not _has_magic(key, _PRIVATE_MAGIC):
        raise Error("invalid RSA private key magic")
    var n_len = _read_u32(key, 4)
    var n_offset = 8
    var e_len_offset = n_offset + n_len
    var e_len = _read_u32(key, e_len_offset)
    var e_offset = e_len_offset + 4
    var d_len_offset = e_offset + e_len
    var d_len = _read_u32(key, d_len_offset)
    var d_offset = d_len_offset + 4
    if d_offset + d_len != len(key):
        raise Error("invalid RSA private key length")
    var n = _component(key, n_offset, n_len)
    var e = _component(key, e_offset, e_len)
    var d = _component(key, d_offset, d_len)
    if (
        n.bit_length() < 16
        or e.compare(BigUInt(3)) < 0
        or e.bit(0) == 0
        or d.is_zero()
    ):
        raise Error("invalid RSA private key")
    return (n^, e^, d^)


def _hash[
    origin: Origin
](algorithm: HashAlgorithm, data: Span[UInt8, origin]) raises -> List[UInt8]:
    if algorithm == HashAlgorithm.SHA1:
        return sha1(data)
    if algorithm == HashAlgorithm.SHA256:
        return sha256(data)
    raise Error("unsupported RSA hash")


def _mgf1[
    origin: Origin
](
    hash_algorithm: HashAlgorithm,
    seed: Span[UInt8, origin],
    mask_length: Int,
) raises -> List[UInt8]:
    """PKCS #1 MGF1 using SHA-1 or SHA-256."""
    if mask_length < 0:
        raise Error("negative MGF1 length")
    var output = List[UInt8](capacity=mask_length)
    var counter = UInt32(0)
    while len(output) < mask_length:
        var block = List[UInt8](capacity=len(seed) + 4)
        _append_bytes(block, seed)
        _append_u32(block, counter)
        var digest = _hash(hash_algorithm, Span(block))
        for byte in digest:
            if len(output) == mask_length:
                break
            output.append(byte)
        counter += 1
    return output^


def _xor(mut left: List[UInt8], right: List[UInt8]) raises:
    if len(left) != len(right):
        raise Error("RSA mask length mismatch")
    for i in range(len(left)):
        left[i] ^= right[i]


def _rsa_public(
    message: BigUInt, modulus: BigUInt, exponent: BigUInt
) raises -> BigUInt:
    if message.compare(modulus) >= 0:
        raise Error("RSA message representative out of range")
    return message.modular_power(exponent, modulus)


def _rsa_private(
    message: BigUInt, modulus: BigUInt, exponent: BigUInt
) raises -> BigUInt:
    if message.compare(modulus) >= 0:
        raise Error("RSA ciphertext representative out of range")
    return message.modular_power(exponent, modulus)


def _oaep_encode[
    origin: Origin
](
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, origin],
    size: Int,
) raises -> List[UInt8]:
    var empty = List[UInt8]()
    var label_hash = _hash(hash_algorithm, Span(empty))
    var h_len = len(label_hash)
    if len(message) > size - 2 * h_len - 2:
        raise Error("RSA OAEP message too long")
    var db = List[UInt8](capacity=size - h_len - 1)
    _append_bytes(db, Span(label_hash))
    for _ in range(size - len(message) - 2 * h_len - 2):
        db.append(0)
    db.append(1)
    _append_bytes(db, message)
    var seed = system_entropy(h_len)
    var db_mask = _mgf1(hash_algorithm, Span(seed), len(db))
    _xor(db, db_mask)
    var seed_mask = _mgf1(hash_algorithm, Span(db), h_len)
    _xor(seed, seed_mask)
    var encoded = List[UInt8](capacity=size)
    encoded.append(0)
    _append_bytes(encoded, Span(seed))
    _append_bytes(encoded, Span(db))
    return encoded^


def _oaep_decode(
    hash_algorithm: HashAlgorithm, encoded: List[UInt8]
) raises -> List[UInt8]:
    var empty = List[UInt8]()
    var label_hash = _hash(hash_algorithm, Span(empty))
    var h_len = len(label_hash)
    if len(encoded) < 2 * h_len + 2 or encoded[0] != 0:
        raise Error("invalid RSA OAEP encoding")
    var seed = List[UInt8](capacity=h_len)
    for i in range(h_len):
        seed.append(encoded[1 + i])
    var db = List[UInt8](capacity=len(encoded) - h_len - 1)
    for i in range(1 + h_len, len(encoded)):
        db.append(encoded[i])
    var seed_mask = _mgf1(hash_algorithm, Span(db), h_len)
    _xor(seed, seed_mask)
    var db_mask = _mgf1(hash_algorithm, Span(seed), len(db))
    _xor(db, db_mask)
    var bad = False
    for i in range(h_len):
        bad = bad or db[i] != label_hash[i]
    var delimiter = -1
    for i in range(h_len, len(db)):
        if delimiter < 0:
            if db[i] == 1:
                delimiter = i
            elif db[i] != 0:
                bad = True
    if bad or delimiter < 0:
        raise Error("invalid RSA OAEP encoding")
    var message = List[UInt8](capacity=len(db) - delimiter - 1)
    for i in range(delimiter + 1, len(db)):
        message.append(db[i])
    return message^


def _pkcs1_encrypt_encode[
    origin: Origin
](message: Span[UInt8, origin], size: Int) raises -> List[UInt8]:
    if len(message) > size - 11:
        raise Error("RSA PKCS1 v1.5 message too long")
    var padding_length = size - len(message) - 3
    var padding = system_entropy(padding_length)
    for i in range(padding_length):
        while padding[i] == 0:
            var replacement = system_entropy(1)
            padding[i] = replacement[0]
    var encoded = List[UInt8](capacity=size)
    encoded.append(0)
    encoded.append(2)
    _append_bytes(encoded, Span(padding))
    encoded.append(0)
    _append_bytes(encoded, message)
    return encoded^


def _pkcs1_encrypt_decode(encoded: List[UInt8]) raises -> List[UInt8]:
    if len(encoded) < 11 or encoded[0] != 0 or encoded[1] != 2:
        raise Error("invalid RSA PKCS1 v1.5 encryption encoding")
    var delimiter = -1
    for i in range(2, len(encoded)):
        if delimiter < 0 and encoded[i] == 0:
            delimiter = i
    if delimiter < 10:
        raise Error("invalid RSA PKCS1 v1.5 encryption encoding")
    var message = List[UInt8](capacity=len(encoded) - delimiter - 1)
    for i in range(delimiter + 1, len(encoded)):
        message.append(encoded[i])
    return message^


def encrypt[
    public_origin: Origin, message_origin: Origin
](
    algorithm: RsaEncryptionAlgorithm,
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    """Encrypt with RSA/OAEP-MGF1(SHA-{1,256}) or RSA/PKCS1-1.5."""
    var parsed = _parse_public(public_key)
    var modulus = parsed[0].copy()
    var exponent = parsed[1].copy()
    var size = (modulus.bit_length() + 7) // 8
    var encoded: List[UInt8]
    if algorithm == RsaEncryptionAlgorithm.PKCS1:
        encoded = _pkcs1_encrypt_encode(message, size)
    elif algorithm == RsaEncryptionAlgorithm.OAEP_SHA1:
        encoded = _oaep_encode(HashAlgorithm.SHA1, message, size)
    elif algorithm == RsaEncryptionAlgorithm.OAEP_SHA256:
        encoded = _oaep_encode(HashAlgorithm.SHA256, message, size)
    else:
        raise Error("invalid RSA encryption selector")
    var transformed = _rsa_public(os2ip(Span(encoded)), modulus, exponent)
    return i2osp(transformed, size)


def decrypt[
    private_origin: Origin, ciphertext_origin: Origin
](
    algorithm: RsaEncryptionAlgorithm,
    private_key: Span[UInt8, private_origin],
    ciphertext: Span[UInt8, ciphertext_origin],
) raises -> List[UInt8]:
    """Decrypt RSA OAEP or PKCS1 v1.5, rejecting every malformed encoding."""
    var parsed = _parse_private(private_key)
    var modulus = parsed[0].copy()
    var exponent = parsed[2].copy()
    var size = (modulus.bit_length() + 7) // 8
    if len(ciphertext) != size:
        raise Error("invalid RSA ciphertext length")
    var encoded = i2osp(
        _rsa_private(os2ip(ciphertext), modulus, exponent), size
    )
    if algorithm == RsaEncryptionAlgorithm.PKCS1:
        return _pkcs1_encrypt_decode(encoded)
    if algorithm == RsaEncryptionAlgorithm.OAEP_SHA1:
        return _oaep_decode(HashAlgorithm.SHA1, encoded)
    if algorithm == RsaEncryptionAlgorithm.OAEP_SHA256:
        return _oaep_decode(HashAlgorithm.SHA256, encoded)
    raise Error("invalid RSA encryption selector")


def _digest_info[
    origin: Origin
](hash_algorithm: HashAlgorithm, message: Span[UInt8, origin]) raises -> List[
    UInt8
]:
    var prefix: List[UInt8]
    if hash_algorithm == HashAlgorithm.SHA1:
        prefix = [
            0x30,
            0x21,
            0x30,
            0x09,
            0x06,
            0x05,
            0x2B,
            0x0E,
            0x03,
            0x02,
            0x1A,
            0x05,
            0x00,
            0x04,
            0x14,
        ]
    elif hash_algorithm == HashAlgorithm.SHA256:
        prefix = [
            0x30,
            0x31,
            0x30,
            0x0D,
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,
            0x05,
            0x00,
            0x04,
            0x20,
        ]
    else:
        raise Error("unsupported RSA hash")
    var digest = _hash(hash_algorithm, message)
    _append_bytes(prefix, Span(digest))
    return prefix^


def _pkcs1_signature_encode[
    origin: Origin
](
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, origin],
    size: Int,
) raises -> List[UInt8]:
    var info = _digest_info(hash_algorithm, message)
    if size < len(info) + 11:
        raise Error("RSA modulus too short for PKCS1 v1.5 signature")
    var encoded = List[UInt8](capacity=size)
    encoded.append(0)
    encoded.append(1)
    for _ in range(size - len(info) - 3):
        encoded.append(0xFF)
    encoded.append(0)
    _append_bytes(encoded, Span(info))
    return encoded^


def _pss_encode[
    origin: Origin
](
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, origin],
    modulus_bits: Int,
) raises -> List[UInt8]:
    var digest = _hash(hash_algorithm, message)
    var h_len = len(digest)
    var encoded_bits = modulus_bits - 1
    var size = (encoded_bits + 7) // 8
    if size < 2 * h_len + 2:
        raise Error("RSA modulus too short for PSS")
    var salt = system_entropy(h_len)
    var m_prime = List[UInt8](length=8, fill=0)
    _append_bytes(m_prime, Span(digest))
    _append_bytes(m_prime, Span(salt))
    var h = _hash(hash_algorithm, Span(m_prime))
    var db = List[UInt8](length=size - h_len - 1, fill=0)
    db[len(db) - h_len - 1] = 1
    for i in range(h_len):
        db[len(db) - h_len + i] = salt[i]
    var mask = _mgf1(hash_algorithm, Span(h), len(db))
    _xor(db, mask)
    var unused_bits = size * 8 - encoded_bits
    db[0] &= UInt8(0xFF >> UInt8(unused_bits))
    var encoded = List[UInt8](capacity=size)
    _append_bytes(encoded, Span(db))
    _append_bytes(encoded, Span(h))
    encoded.append(0xBC)
    return encoded^


def _pss_verify[
    message_origin: Origin
](
    hash_algorithm: HashAlgorithm,
    message: Span[UInt8, message_origin],
    encoded: List[UInt8],
    modulus_bits: Int,
) raises -> Bool:
    var digest = _hash(hash_algorithm, message)
    var h_len = len(digest)
    var encoded_bits = modulus_bits - 1
    var size = (encoded_bits + 7) // 8
    if (
        len(encoded) != size
        or size < 2 * h_len + 2
        or encoded[size - 1] != 0xBC
    ):
        return False
    var db_len = size - h_len - 1
    var unused_bits = size * 8 - encoded_bits
    if (encoded[0] & UInt8(0xFF << UInt8(8 - unused_bits))) != 0:
        return False
    var db = List[UInt8](capacity=db_len)
    var h = List[UInt8](capacity=h_len)
    for i in range(db_len):
        db.append(encoded[i])
    for i in range(h_len):
        h.append(encoded[db_len + i])
    var mask = _mgf1(hash_algorithm, Span(h), db_len)
    _xor(db, mask)
    db[0] &= UInt8(0xFF >> UInt8(unused_bits))
    var ps_len = size - 2 * h_len - 2
    var bad = False
    for i in range(ps_len):
        bad = bad or db[i] != 0
    bad = bad or db[ps_len] != 1
    if bad:
        return False
    var m_prime = List[UInt8](length=8, fill=0)
    _append_bytes(m_prime, Span(digest))
    for i in range(h_len):
        m_prime.append(db[ps_len + 1 + i])
    var expected = _hash(hash_algorithm, Span(m_prime))
    var difference = UInt8(0)
    for i in range(h_len):
        difference |= expected[i] ^ h[i]
    return difference == 0


def sign[
    private_origin: Origin, message_origin: Origin
](
    algorithm: RsaSignatureAlgorithm,
    private_key: Span[UInt8, private_origin],
    message: Span[UInt8, message_origin],
) raises -> List[UInt8]:
    """Sign using the selected RSA PSS or PKCS1 v1.5 hash variant."""
    var parsed = _parse_private(private_key)
    var modulus = parsed[0].copy()
    var exponent = parsed[2].copy()
    var size = (modulus.bit_length() + 7) // 8
    var hash_algorithm: HashAlgorithm
    if (
        algorithm == RsaSignatureAlgorithm.PSS_SHA1
        or algorithm == RsaSignatureAlgorithm.PKCS1_SHA1
    ):
        hash_algorithm = HashAlgorithm.SHA1
    elif (
        algorithm == RsaSignatureAlgorithm.PSS_SHA256
        or algorithm == RsaSignatureAlgorithm.PKCS1_SHA256
    ):
        hash_algorithm = HashAlgorithm.SHA256
    else:
        raise Error("invalid RSA signature selector")
    var encoded: List[UInt8]
    if (
        algorithm == RsaSignatureAlgorithm.PSS_SHA1
        or algorithm == RsaSignatureAlgorithm.PSS_SHA256
    ):
        encoded = _pss_encode(hash_algorithm, message, modulus.bit_length())
    else:
        encoded = _pkcs1_signature_encode(hash_algorithm, message, size)
    return i2osp(_rsa_private(os2ip(Span(encoded)), modulus, exponent), size)


def verify[
    public_origin: Origin, message_origin: Origin, signature_origin: Origin
](
    algorithm: RsaSignatureAlgorithm,
    public_key: Span[UInt8, public_origin],
    message: Span[UInt8, message_origin],
    signature: Span[UInt8, signature_origin],
) raises -> Bool:
    """Verify RSA PSS or PKCS1 v1.5; malformed/tampered signatures return false.
    """
    var parsed = _parse_public(public_key)
    var modulus = parsed[0].copy()
    var exponent = parsed[1].copy()
    var size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    var representative = os2ip(signature)
    if representative.compare(modulus) >= 0:
        return False
    var encoded = i2osp(_rsa_public(representative, modulus, exponent), size)
    var hash_algorithm: HashAlgorithm
    if (
        algorithm == RsaSignatureAlgorithm.PSS_SHA1
        or algorithm == RsaSignatureAlgorithm.PKCS1_SHA1
    ):
        hash_algorithm = HashAlgorithm.SHA1
    elif (
        algorithm == RsaSignatureAlgorithm.PSS_SHA256
        or algorithm == RsaSignatureAlgorithm.PKCS1_SHA256
    ):
        hash_algorithm = HashAlgorithm.SHA256
    else:
        raise Error("invalid RSA signature selector")
    if (
        algorithm == RsaSignatureAlgorithm.PSS_SHA1
        or algorithm == RsaSignatureAlgorithm.PSS_SHA256
    ):
        var pss_size = (modulus.bit_length() - 1 + 7) // 8
        if pss_size != size:
            var shortened = List[UInt8](capacity=pss_size)
            for i in range(size - pss_size, size):
                shortened.append(encoded[i])
            return _pss_verify(
                hash_algorithm, message, shortened, modulus.bit_length()
            )
        return _pss_verify(
            hash_algorithm, message, encoded, modulus.bit_length()
        )
    if (
        algorithm == RsaSignatureAlgorithm.PKCS1_SHA1
        or algorithm == RsaSignatureAlgorithm.PKCS1_SHA256
    ):
        var expected = _pkcs1_signature_encode(hash_algorithm, message, size)
        var difference = UInt8(0)
        for i in range(size):
            difference |= encoded[i] ^ expected[i]
        return difference == 0
    raise Error("invalid RSA signature selector")


def _mod_small(value: BigUInt, divisor: UInt32) -> UInt32:
    var remainder = UInt64(0)
    for i in range(len(value.limbs) - 1, -1, -1):
        remainder = ((remainder << 32) + UInt64(value.limbs[i])) % UInt64(
            divisor
        )
    return UInt32(remainder)


def _shift_right_one(mut value: BigUInt):
    var carry = UInt32(0)
    for i in range(len(value.limbs) - 1, -1, -1):
        var next = value.limbs[i] & 1
        value.limbs[i] = (value.limbs[i] >> 1) | (carry << 31)
        carry = next
    value._normalize()


def _multiply_small(value: BigUInt, multiplier: UInt32) -> BigUInt:
    var result = BigUInt()
    result.limbs.clear()
    var carry = UInt64(0)
    for limb in value.limbs:
        var product = UInt64(limb) * UInt64(multiplier) + carry
        result.limbs.append(UInt32(product))
        carry = product >> 32
    if carry != 0:
        result.limbs.append(UInt32(carry))
    if len(result.limbs) == 0:
        result.limbs.append(0)
    return result^


def _divide_small(value: BigUInt, divisor: UInt32) raises -> BigUInt:
    if divisor == 0:
        raise Error("division by zero")
    var result = BigUInt()
    result.limbs = List[UInt32](length=len(value.limbs), fill=0)
    var remainder = UInt64(0)
    for i in range(len(value.limbs) - 1, -1, -1):
        var current = (remainder << 32) | UInt64(value.limbs[i])
        result.limbs[i] = UInt32(current // UInt64(divisor))
        remainder = current % UInt64(divisor)
    if remainder != 0:
        raise Error("non-exact RSA exponent division")
    result._normalize()
    return result^


def _is_probable_prime(candidate: BigUInt) raises -> Bool:
    if candidate.compare(BigUInt(3)) <= 0:
        return candidate.compare(BigUInt(2)) >= 0
    if candidate.bit(0) == 0:
        return False
    var small_primes: List[Int] = [
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
        137,
        139,
        149,
        151,
        157,
        163,
        167,
        173,
        179,
        181,
        191,
        193,
        197,
        199,
        211,
        223,
        227,
        229,
        233,
        239,
        241,
        251,
    ]
    for prime in small_primes:
        if _mod_small(candidate, UInt32(prime)) == 0:
            return candidate.compare(BigUInt(UInt64(prime))) == 0
    var one = BigUInt(1)
    var d = candidate.subtract(one)
    var rounds = 0
    while d.bit(0) == 0:
        _shift_right_one(d)
        rounds += 1
    var bases: List[Int] = [2, 3, 5, 7, 11, 13, 17, 19]
    var minus_one = candidate.subtract(one)
    for base_value in bases:
        var base = BigUInt(UInt64(base_value))
        if base.compare(candidate) >= 0:
            continue
        var x = base.modular_power(d, candidate)
        if x.compare(one) == 0 or x.compare(minus_one) == 0:
            continue
        var witnessed_composite = True
        for _ in range(1, rounds):
            x = x.modular_multiply(x, candidate)
            if x.compare(minus_one) == 0:
                witnessed_composite = False
                break
        if witnessed_composite:
            return False
    return True


def _generate_prime(bits: Int) raises -> BigUInt:
    var byte_length = (bits + 7) // 8
    while True:
        var bytes = system_entropy(byte_length)
        var excess = byte_length * 8 - bits
        bytes[0] &= UInt8(0xFF >> UInt8(excess))
        bytes[0] |= UInt8(1 << UInt8(7 - excess))
        bytes[byte_length - 1] |= 1
        var candidate = os2ip(Span(bytes))
        while candidate.bit_length() == bits:
            if _mod_small(
                candidate, _PUBLIC_EXPONENT
            ) != 1 and _is_probable_prime(candidate):
                return candidate^
            candidate.add_small(2)


def _private_exponent(phi: BigUInt) raises -> BigUInt:
    var residue = _mod_small(phi, _PUBLIC_EXPONENT)
    if residue == 0:
        raise Error("RSA totient is not coprime to public exponent")
    var k = UInt32(1)
    while k < _PUBLIC_EXPONENT:
        if (
            UInt32((UInt64(k) * UInt64(residue) + 1) % UInt64(_PUBLIC_EXPONENT))
            == 0
        ):
            var numerator = _multiply_small(phi, k)
            numerator.add_small(1)
            return _divide_small(numerator, _PUBLIC_EXPONENT)
        k += 1
    raise Error("unable to invert RSA public exponent")


def generate_keypair(
    key_bits: Int = 2048,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Generate an RSA keypair; returns (private RSA2, public RSA1) containers.
    """
    if key_bits < 512 or key_bits % 8 != 0:
        raise Error(
            "RSA key size must be a multiple of 8 and at least 512 bits"
        )
    var p_bits = key_bits // 2
    var q_bits = key_bits - p_bits
    while True:
        var p = _generate_prime(p_bits)
        var q = _generate_prime(q_bits)
        if p.compare(q) == 0:
            continue
        var modulus = p.multiply(q)
        if modulus.bit_length() != key_bits:
            continue
        var one = BigUInt(1)
        var phi = p.subtract(one).multiply(q.subtract(one))
        var d = _private_exponent(phi)
        var e = BigUInt(UInt64(_PUBLIC_EXPONENT))
        var n_bytes = _minimal_i2osp(modulus)
        var e_bytes = _minimal_i2osp(e)
        var d_bytes = _minimal_i2osp(d)
        var private_key = private_key_from_components(
            Span(n_bytes), Span(e_bytes), Span(d_bytes)
        )
        var public_key = public_key_from_components(
            Span(n_bytes), Span(e_bytes)
        )
        return (private_key^, public_key^)
