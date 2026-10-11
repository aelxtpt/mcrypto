"""Shared FIPS 203 K-PKE/KEM core, specialized at compile time by rank."""
from ..hashes.keccak import _shake128_four, sha3, shake
from ._mlkem_polynomial import (
    _montgomery,
    _montgomery4,
    _barrett4,
    _csubq4,
    _barrett,
    _ntt,
    _invntt,
    _reduce,
    _canonicalize,
    _basemul_impl,
    _poly_to_bytes,
    _poly_from_bytes,
    _noise_into,
    _rejection_sample,
    _fill_matrix_entry,
    _poly_from_msg,
    _poly_to_msg,
    _compress_du,
    _decompress_du,
    _compress_dv,
    _decompress_dv,
    _Q,
    _N,
    _POLY_BYTES,
    _DU_BYTES,
    _DV_BYTES,
    _ZETAS,
    SEED_BYTES,
    ENCAPS_SEED_BYTES,
)


def _basemul_acc[
    rank: Int,
    out_origin: MutOrigin,
    a_origin: Origin,
    b_origin: Origin,
    z_origin: Origin,
](
    output: Span[mut=True, Int, out_origin],
    oo: Int,
    a: Span[Int, a_origin],
    ao: Int,
    b: Span[Int, b_origin],
    bo: Int,
    zetas: Span[Int, z_origin],
):
    _basemul_impl[False](output, oo, a, ao, b, bo, zetas)
    for v in range(1, rank):
        _basemul_impl[True](output, oo, a, ao + v * _N, b, bo + v * _N, zetas)
    _reduce(output, oo)


def _vec_to_bytes[
    rank: Int, p_origin: Origin
](p: Span[Int, p_origin], output_bytes: Int = (rank * _POLY_BYTES)) -> List[
    UInt8
]:
    var out = List[UInt8](length=output_bytes, fill=0)
    for i in range(rank):
        _poly_to_bytes(p, i * _N, Span(out), i * _POLY_BYTES)
    return out^


def _vec_from_bytes_into[
    rank: Int, data_origin: Origin, p_origin: MutOrigin
](
    data: Span[UInt8, data_origin],
    p: Span[mut=True, Int, p_origin],
    off: Int = 0,
):
    for i in range(rank):
        _poly_from_bytes(data, off + i * _POLY_BYTES, p, i * _N)


def _matrix_into[
    rank: Int, seed_origin: Origin, matrix_origin: MutOrigin
](
    seed: Span[UInt8, seed_origin],
    transposed: Bool,
    matrix: Span[mut=True, Int, matrix_origin],
) raises:
    for base in range(0, rank * rank, 4):
        # All four suffix lanes are assigned below, including padded final lanes.
        var suffixes = InlineArray[UInt16, 4](uninitialized=True)
        comptime for lane in range(4):
            var index = min(base + lane, rank * rank - 1)
            var i = index // rank
            var j = index % rank
            var first = i if transposed else j
            var second = j if transposed else i
            suffixes[lane] = UInt16(first | (second << 8))
        var buffers = _shake128_four(seed, suffixes, 768)
        _fill_matrix_entry(seed, suffixes[0], buffers[0], matrix, base * _N)
        if base + 1 < rank * rank:
            _fill_matrix_entry(
                seed, suffixes[1], buffers[1], matrix, (base + 1) * _N
            )
        if base + 2 < rank * rank:
            _fill_matrix_entry(
                seed, suffixes[2], buffers[2], matrix, (base + 2) * _N
            )
        if base + 3 < rank * rank:
            _fill_matrix_entry(
                seed, suffixes[3], buffers[3], matrix, (base + 3) * _N
            )


def _indcpa_keypair[
    rank: Int, encode_secret: Bool, origin: Origin
](
    seed: Span[UInt8, origin],
    public_output_bytes: Int = (rank * _POLY_BYTES + 32),
) raises -> Tuple[List[UInt8], List[UInt8]]:
    comptime polynomial_vector_bytes = rank * _POLY_BYTES
    var expanded = sha3(512, seed)
    var zetas = materialize[_ZETAS]()
    var matrix = InlineArray[Int, rank * rank * _N](uninitialized=True)
    _matrix_into[rank](expanded[0:32], False, Span(matrix))
    var s = InlineArray[Int, rank * _N](uninitialized=True)
    var e = InlineArray[Int, rank * _N](uninitialized=True)
    for i in range(rank):
        _noise_into[3 if rank == 2 else 2](expanded[32:64], i, Span(s), i * _N)
        _noise_into[3 if rank == 2 else 2](
            expanded[32:64], i + rank, Span(e), i * _N
        )
        _ntt(Span(s), Span(zetas), i * _N)
        _ntt(Span(e), Span(zetas), i * _N)
    var pk = InlineArray[Int, rank * _N](uninitialized=True)
    var pk_pointer = Span(pk).unsafe_ptr()
    var e_pointer = Span(e).unsafe_ptr()
    for i in range(rank):
        _basemul_acc[rank](
            Span(pk),
            i * _N,
            Span(matrix),
            i * rank * _N,
            Span(s),
            0,
            Span(zetas),
        )
        for j in range(0, _N, 4):
            var offset = i * _N + j
            pk_pointer.unsafe_store[width=4](
                offset,
                _montgomery4(1353 * pk_pointer.unsafe_load[width=4](offset))
                + e_pointer.unsafe_load[width=4](offset),
            )
        _reduce(Span(pk), i * _N)
        _canonicalize(Span(pk), i * _N)
        _reduce(Span(s), i * _N)
        _canonicalize(Span(s), i * _N)
    # Optional trailing storage lets hybrid callers append without a second key copy.
    var pkb = _vec_to_bytes[rank](Span(pk), public_output_bytes)
    var pkb_pointer = Span(pkb).unsafe_ptr()
    pkb_pointer.unsafe_store[width=16](
        polynomial_vector_bytes,
        Span(expanded).unsafe_ptr().unsafe_load[width=16](0),
    )
    pkb_pointer.unsafe_store[width=16](
        polynomial_vector_bytes + 16,
        Span(expanded).unsafe_ptr().unsafe_load[width=16](16),
    )
    comptime if encode_secret:
        var skb = _vec_to_bytes[rank](Span(s))
        return (pkb^, skb^)
    else:
        var empty = List[UInt8]()
        return (pkb^, empty^)


def _indcpa_enc_parsed[
    rank: Int,
    msg_origin: Origin,
    pk_origin: Origin,
    coin_origin: Origin,
    pv_origin: Origin,
](
    msg: Span[UInt8, msg_origin],
    pk: Span[UInt8, pk_origin],
    coins: Span[UInt8, coin_origin],
    pv: Span[Int, pv_origin],
    ciphertext_output_bytes: Int = (rank * _DU_BYTES + _DV_BYTES),
) raises -> List[UInt8]:
    comptime polynomial_vector_bytes = rank * _POLY_BYTES
    var zetas = materialize[_ZETAS]()
    # `pv` is the caller's canonical, fully decoded public polynomial vector.
    var matrix = InlineArray[Int, rank * rank * _N](uninitialized=True)
    _matrix_into[rank](
        pk[polynomial_vector_bytes : polynomial_vector_bytes + 32],
        True,
        Span(matrix),
    )
    var sp = InlineArray[Int, rank * _N](uninitialized=True)
    var ep = InlineArray[Int, rank * _N](uninitialized=True)
    for i in range(rank):
        _noise_into[3 if rank == 2 else 2](coins, i, Span(sp), i * _N)
        _noise_into[2](coins, i + rank, Span(ep), i * _N)
        _ntt(Span(sp), Span(zetas), i * _N)
        _reduce(Span(sp), i * _N)
    var epp = InlineArray[Int, _N](uninitialized=True)
    _noise_into[2](coins, 2 * rank, Span(epp))
    var b = InlineArray[Int, rank * _N](uninitialized=True)
    var v = InlineArray[Int, _N](uninitialized=True)
    for i in range(rank):
        _basemul_acc[rank](
            Span(b),
            i * _N,
            Span(matrix),
            i * rank * _N,
            Span(sp),
            0,
            Span(zetas),
        )
    _basemul_acc[rank](Span(v), 0, Span(pv), 0, Span(sp), 0, Span(zetas))
    for i in range(rank):
        _invntt(Span(b), Span(zetas), i * _N)
    _invntt(Span(v), Span(zetas))
    var m = InlineArray[Int, _N](uninitialized=True)
    _poly_from_msg(msg, Span(m))
    var b_pointer = Span(b).unsafe_ptr()
    var ep_pointer = Span(ep).unsafe_ptr()
    for i in range(0, rank * _N, 4):
        b_pointer.unsafe_store[width=4](
            i,
            b_pointer.unsafe_load[width=4](i)
            + ep_pointer.unsafe_load[width=4](i),
        )
    var v_pointer = Span(v).unsafe_ptr()
    var epp_pointer = Span(epp).unsafe_ptr()
    var m_pointer = Span(m).unsafe_ptr()
    for i in range(0, _N, 4):
        v_pointer.unsafe_store[width=4](
            i,
            v_pointer.unsafe_load[width=4](i)
            + epp_pointer.unsafe_load[width=4](i)
            + m_pointer.unsafe_load[width=4](i),
        )
    for i in range(rank):
        _reduce(Span(b), i * _N)
        _canonicalize(Span(b), i * _N)
    _reduce(Span(v))
    _canonicalize(Span(v))
    # Optional trailing storage is reserved for hybrid ciphertext components.
    var out = List[UInt8](length=ciphertext_output_bytes, fill=0)
    for i in range(rank):
        _compress_du(Span(b), i * _N, Span(out), i * _DU_BYTES)
    _compress_dv(Span(v), Span(out), rank * _DU_BYTES)
    return out^


def _indcpa_enc[
    rank: Int, msg_origin: Origin, pk_origin: Origin, coin_origin: Origin
](
    msg: Span[UInt8, msg_origin],
    pk: Span[UInt8, pk_origin],
    coins: Span[UInt8, coin_origin],
) raises -> List[UInt8]:
    comptime ciphertext_bytes = rank * _DU_BYTES + _DV_BYTES
    var pv = InlineArray[Int, rank * _N](uninitialized=True)
    _vec_from_bytes_into[rank](pk, Span(pv))
    return _indcpa_enc_parsed[rank](msg, pk, coins, Span(pv), ciphertext_bytes)


def _indcpa_dec[
    rank: Int, ct_origin: Origin, sk_origin: Origin
](ct: Span[UInt8, ct_origin], sk: Span[UInt8, sk_origin]) -> List[UInt8]:
    var zetas = materialize[_ZETAS]()
    var b = InlineArray[Int, rank * _N](uninitialized=True)
    for i in range(rank):
        _decompress_du(ct, i * _DU_BYTES, Span(b), i * _N)
    var v = InlineArray[Int, _N](uninitialized=True)
    _decompress_dv(ct, rank * _DU_BYTES, Span(v))
    var s = InlineArray[Int, rank * _N](uninitialized=True)
    _vec_from_bytes_into[rank](sk, Span(s))
    for i in range(rank):
        _ntt(Span(b), Span(zetas), i * _N)
        _reduce(Span(b), i * _N)
    var m = InlineArray[Int, _N](uninitialized=True)
    _basemul_acc[rank](Span(m), 0, Span(s), 0, Span(b), 0, Span(zetas))
    _invntt(Span(m), Span(zetas))
    var m_pointer = Span(m).unsafe_ptr()
    var v_pointer = Span(v).unsafe_ptr()
    for i in range(0, _N, 4):
        m_pointer.unsafe_store[width=4](
            i,
            v_pointer.unsafe_load[width=4](i)
            - m_pointer.unsafe_load[width=4](i),
        )
    _reduce(Span(m))
    _canonicalize(Span(m))
    return _poly_to_msg(Span(m))


def _seed_keypair_public[
    rank: Int, origin: Origin
](
    seed: Span[UInt8, origin],
    output_bytes: Int = (rank * _POLY_BYTES + 32),
) raises -> List[UInt8]:
    comptime public_key_bytes = rank * _POLY_BYTES + 32
    if len(seed) != SEED_BYTES:
        raise Error("ML-KEM key seed must be 64 bytes")
    comptime assert rank == 2 or rank == 3, "unsupported ML-KEM rank"
    var ind = InlineArray[UInt8, 33](uninitialized=True)
    var ind_pointer = Span(ind).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    ind_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    ind_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    ind[32] = UInt8(rank)
    if output_bytes < public_key_bytes:
        raise Error("ML-KEM public output buffer is too short")
    var keys = _indcpa_keypair[rank, False](Span(ind), output_bytes)
    # Consume the tuple so the generated key and reserved tail are not recopied.
    var public_key = List[UInt8]()

    @parameter
    def take_public_key[idx: Int](var key: keys.element_types[idx]):
        comptime if idx == 0:
            public_key = key^

    keys^.consume_elements[take_public_key]()
    return public_key^


def seed_keypair[
    rank: Int, origin: Origin
](seed: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Derive `(ek, dk)` from exactly 64 bytes `d || z`."""
    comptime secret_key_bytes = 2 * rank * _POLY_BYTES + 96
    comptime public_key_bytes = rank * _POLY_BYTES + 32
    comptime polynomial_vector_bytes = rank * _POLY_BYTES
    if len(seed) != SEED_BYTES:
        raise Error("ML-KEM key seed must be 64 bytes")
    comptime assert rank == 2 or rank == 3, "unsupported ML-KEM rank"
    var ind = InlineArray[UInt8, 33](uninitialized=True)
    var ind_pointer = Span(ind).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    ind_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    ind_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    ind[32] = UInt8(rank)
    var keys = _indcpa_keypair[rank, True](Span(ind))
    # Consume the tuple so neither encoded polynomial vector is recopied.
    var pk = List[UInt8]()
    var encoded_secret = List[UInt8]()

    @parameter
    def take_key[idx: Int](var key: keys.element_types[idx]):
        comptime if idx == 0:
            pk = key^
        else:
            encoded_secret = key^

    keys^.consume_elements[take_key]()
    var h = sha3(256, Span(pk))
    var sk = List[UInt8](length=secret_key_bytes, fill=0)
    var sk_pointer = Span(sk).unsafe_ptr()
    var encoded_secret_pointer = Span(encoded_secret).unsafe_ptr()
    var pk_pointer = Span(pk).unsafe_ptr()
    var h_pointer = Span(h).unsafe_ptr()
    for i in range(0, polynomial_vector_bytes, 16):
        sk_pointer.unsafe_store[width=16](
            i, encoded_secret_pointer.unsafe_load[width=16](i)
        )
    for i in range(0, public_key_bytes, 16):
        sk_pointer.unsafe_store[width=16](
            polynomial_vector_bytes + i, pk_pointer.unsafe_load[width=16](i)
        )
    sk_pointer.unsafe_store[width=16](
        polynomial_vector_bytes + public_key_bytes,
        h_pointer.unsafe_load[width=16](0),
    )
    sk_pointer.unsafe_store[width=16](
        polynomial_vector_bytes + public_key_bytes + 16,
        h_pointer.unsafe_load[width=16](16),
    )
    sk_pointer.unsafe_store[width=16](
        secret_key_bytes - 32,
        seed_pointer.unsafe_load[width=16](32),
    )
    sk_pointer.unsafe_store[width=16](
        secret_key_bytes - 16,
        seed_pointer.unsafe_load[width=16](48),
    )
    return (pk^, sk^)


def _encapsulate_deterministic_padded[
    rank: Int, pk_origin: Origin, seed_origin: Origin
](
    public_key: Span[UInt8, pk_origin],
    seed: Span[UInt8, seed_origin],
    ciphertext_output_bytes: Int,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encapsulate while reserving a caller-owned ciphertext tail."""
    comptime public_key_bytes = rank * _POLY_BYTES + 32
    comptime ciphertext_bytes = rank * _DU_BYTES + _DV_BYTES
    if len(public_key) != public_key_bytes:
        raise Error("invalid ML-KEM public key length")
    if len(seed) != ENCAPS_SEED_BYTES:
        raise Error("ML-KEM encapsulation seed must be 32 bytes")
    if ciphertext_output_bytes < ciphertext_bytes:
        raise Error("ML-KEM ciphertext output buffer is too short")
    var parsed = InlineArray[Int, rank * _N](uninitialized=True)
    _vec_from_bytes_into[rank](public_key, Span(parsed))
    for x in parsed:
        if x >= _Q:
            raise Error("non-canonical ML-KEM public key")
    var input = InlineArray[UInt8, 64](uninitialized=True)
    var input_pointer = Span(input).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    input_pointer.unsafe_store[width=16](
        0, seed_pointer.unsafe_load[width=16](0)
    )
    input_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    var h = sha3(256, public_key)
    var h_pointer = Span(h).unsafe_ptr()
    input_pointer.unsafe_store[width=16](32, h_pointer.unsafe_load[width=16](0))
    input_pointer.unsafe_store[width=16](
        48, h_pointer.unsafe_load[width=16](16)
    )
    var kr = sha3(512, Span(input))
    # Reuse the vector decoded for canonical validation; decoding twice is redundant.
    var ct = _indcpa_enc_parsed[rank](
        seed,
        public_key,
        kr[32:64],
        Span(parsed),
        ciphertext_output_bytes,
    )
    var ss = List[UInt8](length=32, fill=0)
    var ss_pointer = Span(ss).unsafe_ptr()
    var kr_pointer = Span(kr).unsafe_ptr()
    ss_pointer.unsafe_store[width=16](0, kr_pointer.unsafe_load[width=16](0))
    ss_pointer.unsafe_store[width=16](16, kr_pointer.unsafe_load[width=16](16))
    return (ct^, ss^)


def encapsulate_deterministic[
    rank: Int, pk_origin: Origin, seed_origin: Origin
](
    public_key: Span[UInt8, pk_origin], seed: Span[UInt8, seed_origin]
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encapsulate with a supplied 32-byte FIPS randomness input."""
    comptime ciphertext_bytes = rank * _DU_BYTES + _DV_BYTES
    return _encapsulate_deterministic_padded[rank](
        public_key, seed, ciphertext_bytes
    )


def decapsulate[
    rank: Int, ct_origin: Origin, sk_origin: Origin
](
    ciphertext: Span[UInt8, ct_origin], secret_key: Span[UInt8, sk_origin]
) raises -> List[UInt8]:
    """Decapsulate, returning FIPS 203 implicit-rejection output for invalid ciphertext.
    """
    comptime secret_key_bytes = 2 * rank * _POLY_BYTES + 96
    comptime public_key_bytes = rank * _POLY_BYTES + 32
    comptime ciphertext_bytes = rank * _DU_BYTES + _DV_BYTES
    comptime polynomial_vector_bytes = rank * _POLY_BYTES
    if len(ciphertext) != ciphertext_bytes:
        raise Error("invalid ML-KEM ciphertext length")
    if len(secret_key) != secret_key_bytes:
        raise Error("invalid ML-KEM secret key length")
    # FIPS 203 section 7.3: validate the embedded encapsulation-key hash
    # before using an expanded decapsulation key. Ciphertext rejection below
    # is distinct and remains implicit.
    var public_hash = sha3(
        256, secret_key[polynomial_vector_bytes : (2 * rank * _POLY_BYTES + 32)]
    )
    var invalid_hash = UInt8(0)
    for i in range(32):
        invalid_hash |= (
            public_hash[i] ^ secret_key[2 * rank * _POLY_BYTES + 32 + i]
        )
    if invalid_hash != 0:
        raise Error("invalid ML-KEM decapsulation key hash")
    var msg = _indcpa_dec[rank](
        ciphertext, secret_key[0:polynomial_vector_bytes]
    )
    var input = InlineArray[UInt8, 64](uninitialized=True)
    var input_pointer = Span(input).unsafe_ptr()
    var msg_pointer = Span(msg).unsafe_ptr()
    var secret_pointer = secret_key.unsafe_ptr()
    input_pointer.unsafe_store[width=16](
        0, msg_pointer.unsafe_load[width=16](0)
    )
    input_pointer.unsafe_store[width=16](
        16, msg_pointer.unsafe_load[width=16](16)
    )
    input_pointer.unsafe_store[width=16](
        32,
        secret_pointer.unsafe_load[width=16](
            polynomial_vector_bytes + public_key_bytes
        ),
    )
    input_pointer.unsafe_store[width=16](
        48,
        secret_pointer.unsafe_load[width=16](
            polynomial_vector_bytes + public_key_bytes + 16
        ),
    )
    var kr = sha3(512, Span(input))
    var expected = _indcpa_enc[rank](
        Span(msg),
        secret_key[
            polynomial_vector_bytes : polynomial_vector_bytes + public_key_bytes
        ],
        kr[32:64],
    )
    # Accumulate every byte without an early exit; validity remains data-oblivious.
    var different = UInt8(0)
    for i in range(ciphertext_bytes):
        different |= ciphertext[i] ^ expected[i]
    var reject_input = InlineArray[UInt8, 32 + ciphertext_bytes](
        uninitialized=True
    )
    var reject_pointer = Span(reject_input).unsafe_ptr()
    var ciphertext_pointer = ciphertext.unsafe_ptr()
    reject_pointer.unsafe_store[width=16](
        0,
        secret_pointer.unsafe_load[width=16](secret_key_bytes - 32),
    )
    reject_pointer.unsafe_store[width=16](
        16,
        secret_pointer.unsafe_load[width=16](secret_key_bytes - 16),
    )
    comptime for i in range(0, ciphertext_bytes, 16):
        reject_pointer.unsafe_store[width=16](
            32 + i, ciphertext_pointer.unsafe_load[width=16](i)
        )
    # Rejection derivation is unconditional and the final choice is mask-only.
    var rejected = shake(256, Span(reject_input), 32)
    var reject_bit = UInt8((UInt16(different) + 255) >> 8)
    var reject_mask = UInt8(0) - reject_bit
    var shared_secret = List[UInt8](length=32, fill=0)
    var shared_pointer = Span(shared_secret).unsafe_ptr()
    var kr_pointer = Span(kr).unsafe_ptr()
    var rejected_pointer = Span(rejected).unsafe_ptr()
    var reject_vector = SIMD[DType.uint8, 16](reject_mask)
    comptime for i in range(0, 32, 16):
        shared_pointer.unsafe_store[width=16](
            i,
            (
                kr_pointer.unsafe_load[width=16](i) & ~reject_vector
                | rejected_pointer.unsafe_load[width=16](i) & reject_vector
            ),
        )
    return shared_secret^
