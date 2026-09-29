"""Standards-based encodings for integer trapdoor permutations."""
from ..hashes.sha1 import sha1
from ..hashes.sha256 import sha256
from ..random.entropy import system_entropy
from ._legacy_math import constant_time_equal, mgf1_sha1


def _append[o: Origin](mut out: List[UInt8], data: Span[UInt8, o]):
    for b in data:
        out.append(b)


def _mgf256[o: Origin](seed: Span[UInt8, o], length: Int) raises -> List[UInt8]:
    if length < 0:
        raise Error("negative MGF1 length")
    var out = List[UInt8](capacity=length)
    var counter = UInt32(0)
    while len(out) < length:
        var block = List[UInt8](capacity=len(seed) + 4)
        _append(block, seed)
        block.append(UInt8(counter >> 24))
        block.append(UInt8(counter >> 16))
        block.append(UInt8(counter >> 8))
        block.append(UInt8(counter))
        var digest = sha256(Span(block))
        for b in digest:
            if len(out) == length:
                break
            out.append(b)
        counter += 1
    return out^


def _xor(mut value: List[UInt8], mask: List[UInt8]) raises:
    if len(value) != len(mask):
        raise Error("mask length mismatch")
    for i in range(len(value)):
        value[i] ^= mask[i]


def oaep_sha1_encode[
    o: Origin
](message: Span[UInt8, o], size: Int) raises -> List[UInt8]:
    comptime H = 20
    var empty = List[UInt8]()
    var label_hash = sha1(Span(empty))
    if size < 2 * H + 2 or len(message) > size - 2 * H - 2:
        raise Error("message too long for OAEP-MGF1(SHA-1)")
    var db = List[UInt8](capacity=size - H - 1)
    _append(db, Span(label_hash))
    for _ in range(size - len(message) - 2 * H - 2):
        db.append(0)
    db.append(1)
    _append(db, message)
    var seed = system_entropy(H)
    var db_mask = mgf1_sha1(Span(seed), len(db))
    _xor(db, db_mask)
    var seed_mask = mgf1_sha1(Span(db), H)
    _xor(seed, seed_mask)
    var out = List[UInt8](capacity=size)
    out.append(0)
    _append(out, Span(seed))
    _append(out, Span(db))
    return out^


def oaep_sha1_decode[o: Origin](encoded: Span[UInt8, o]) raises -> List[UInt8]:
    comptime H = 20
    if len(encoded) < 2 * H + 2:
        raise Error("invalid OAEP-MGF1(SHA-1) encoding")
    var seed = List[UInt8](capacity=H)
    var db = List[UInt8](capacity=len(encoded) - H - 1)
    for i in range(H):
        seed.append(encoded[1 + i])
    for i in range(1 + H, len(encoded)):
        db.append(encoded[i])
    var seed_mask = mgf1_sha1(Span(db), H)
    _xor(seed, seed_mask)
    var db_mask = mgf1_sha1(Span(seed), len(db))
    _xor(db, db_mask)
    var empty = List[UInt8]()
    var label_hash = sha1(Span(empty))
    var bad = encoded[0] != 0
    var difference = UInt8(0)
    for i in range(H):
        difference |= db[i] ^ label_hash[i]
    bad = bad or difference != 0
    var delimiter = -1
    for i in range(H, len(db)):
        if delimiter < 0:
            if db[i] == 1:
                delimiter = i
            elif db[i] != 0:
                bad = True
    if bad or delimiter < 0:
        raise Error("invalid OAEP-MGF1(SHA-1) encoding")
    var out = List[UInt8](capacity=len(db) - delimiter - 1)
    for i in range(delimiter + 1, len(db)):
        out.append(db[i])
    return out^


def _length_bits(mut out: List[UInt8], length: Int) raises:
    if length < 0:
        raise Error("invalid message length")
    var bits = UInt64(length) * 8
    for shift in range(56, -1, -8):
        out.append(UInt8(bits >> UInt64(shift)))


def pssr_sha256_encode[
    o: Origin
](message: Span[UInt8, o], representative_bits: Int) raises -> List[UInt8]:
    comptime H = 32
    var size = (representative_bits + 7) // 8
    var db_len = size - H - 1
    var maximum_recovery = db_len - H - 1
    if representative_bits <= 0 or maximum_recovery < 0:
        raise Error("modulus too short for Rabin PSSR(SHA-256)")
    var recovered_len = min(len(message), maximum_recovery)
    var recovered_start = len(message) - recovered_len
    var digest = sha256(message[0:recovered_start])
    var salt = system_entropy(H)
    var input = List[UInt8](capacity=8 + recovered_len + 2 * H)
    _length_bits(input, recovered_len)
    for i in range(recovered_start, len(message)):
        input.append(message[i])
    _append(input, Span(digest))
    _append(input, Span(salt))
    var hashed = sha256(Span(input))
    var db = List[UInt8](length=db_len, fill=0)
    var delimiter = db_len - H - recovered_len - 1
    db[delimiter] = 1
    for i in range(recovered_len):
        db[delimiter + 1 + i] = message[recovered_start + i]
    for i in range(H):
        db[db_len - H + i] = salt[i]
    var mask = _mgf256(Span(hashed), db_len)
    _xor(db, mask)
    var unused = size * 8 - representative_bits
    if unused != 0:
        db[0] &= UInt8(0xFF >> unused)
    var out = db^
    _append(out, Span(hashed))
    out.append(0xBC)
    return out^


def pssr_sha256_verify[
    mo: Origin, eo: Origin
](
    message: Span[UInt8, mo], encoded: Span[UInt8, eo], representative_bits: Int
) raises -> Bool:
    comptime H = 32
    var size = (representative_bits + 7) // 8
    if len(encoded) != size or size < 2 * H + 2 or encoded[size - 1] != 0xBC:
        return False
    var db_len = size - H - 1
    var unused = size * 8 - representative_bits
    if unused != 0 and (encoded[0] & UInt8(0xFF << (8 - unused))) != 0:
        return False
    var db = List[UInt8](capacity=db_len)
    var hashed = List[UInt8](capacity=H)
    for i in range(db_len):
        db.append(encoded[i])
    for i in range(H):
        hashed.append(encoded[db_len + i])
    var mask = _mgf256(Span(hashed), db_len)
    _xor(db, mask)
    if unused != 0:
        db[0] &= UInt8(0xFF >> unused)
    var salt_start = db_len - H
    var delimiter = -1
    var bad = False
    for i in range(salt_start):
        if delimiter < 0:
            if db[i] == 1:
                delimiter = i
            elif db[i] != 0:
                bad = True
    var maximum_recovery = salt_start - 1
    var recovered_len = min(len(message), maximum_recovery)
    var recovered_start = len(message) - recovered_len
    if bad or delimiter < 0 or salt_start - delimiter - 1 != recovered_len:
        return False
    var diff = UInt8(0)
    for i in range(recovered_len):
        diff |= db[delimiter + 1 + i] ^ message[recovered_start + i]
    if diff != 0:
        return False
    var digest = sha256(message[0:recovered_start])
    var input = List[UInt8](capacity=8 + recovered_len + 2 * H)
    _length_bits(input, recovered_len)
    for i in range(recovered_start, len(message)):
        input.append(message[i])
    _append(input, Span(digest))
    for i in range(salt_start, db_len):
        input.append(db[i])
    var expected = sha256(Span(input))
    return constant_time_equal(Span(expected), Span(hashed))


def emsa2_sha256[
    o: Origin
](message: Span[UInt8, o], representative_bits: Int) raises -> List[UInt8]:
    comptime H = 32
    if representative_bits % 8 != 7:
        raise Error("EMSA2 representative length must be 7 modulo 8")
    var size = (representative_bits + 7) // 8
    if size < H + 4:
        raise Error("modulus too short for EMSA2(SHA-256)")
    var digest = sha256(message)
    var out = List[UInt8](length=size, fill=0xBB)
    out[0] = 0x4B if len(message) == 0 else 0x6B
    var sep = size - H - 3
    out[sep] = 0xBA
    for i in range(H):
        out[sep + 1 + i] = digest[i]
    out[size - 2] = 0x34
    out[size - 1] = 0xCC
    return out^


def pkcs1_v15_sha256[
    o: Origin
](message: Span[UInt8, o], size: Int) raises -> List[UInt8]:
    var prefix: List[UInt8] = [
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
    var digest = sha256(message)
    if size < len(prefix) + len(digest) + 11:
        raise Error("modulus too short for PKCS1-v1.5(SHA-256)")
    var out = List[UInt8](capacity=size)
    out.append(0)
    out.append(1)
    for _ in range(size - len(prefix) - len(digest) - 3):
        out.append(0xFF)
    out.append(0)
    _append(out, Span(prefix))
    _append(out, Span(digest))
    return out^
