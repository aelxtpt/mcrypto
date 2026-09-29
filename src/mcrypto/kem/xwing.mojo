"""Pure-Mojo X-Wing hybrid KEM matching interop.

The 1216-byte public key is `ML-KEM-768 ek[1184] || X25519 pk[32]`.
The 32-byte secret key is the X-Wing expansion seed.  Ciphertexts are
`ML-KEM-768 ct[1088] || ephemeral X25519 pk[32]`; shared secrets are 32 bytes.
`encapsulate_deterministic` takes `ML-KEM randomness[32] || X25519 scalar[32]`.
"""

from . import mlkem768
from ..hashes.keccak import sha3, shake
from ..key_exchange.x25519 import (
    public_key as x25519_public,
    agree as x25519_agree,
)
from ..random.entropy import system_entropy

comptime PUBLIC_KEY_BYTES = 1216
comptime SECRET_KEY_BYTES = 32
comptime CIPHERTEXT_BYTES = 1120
comptime SHARED_SECRET_BYTES = 32
comptime SEED_BYTES = 32
comptime ENCAPS_SEED_BYTES = 64


def _combine[
    ml_origin: Origin, x_origin: Origin, ct_origin: Origin, pk_origin: Origin
](
    ml: Span[UInt8, ml_origin],
    x: Span[UInt8, x_origin],
    xct: Span[UInt8, ct_origin],
    xpk: Span[UInt8, pk_origin],
) raises -> List[UInt8]:
    var input = InlineArray[UInt8, 134](uninitialized=True)
    var input_pointer = Span(input).unsafe_ptr()
    var ml_pointer = ml.unsafe_ptr()
    var x_pointer = x.unsafe_ptr()
    var xct_pointer = xct.unsafe_ptr()
    var xpk_pointer = xpk.unsafe_ptr()
    input_pointer.unsafe_store[width=16](0, ml_pointer.unsafe_load[width=16](0))
    input_pointer.unsafe_store[width=16](
        16, ml_pointer.unsafe_load[width=16](16)
    )
    input_pointer.unsafe_store[width=16](32, x_pointer.unsafe_load[width=16](0))
    input_pointer.unsafe_store[width=16](
        48, x_pointer.unsafe_load[width=16](16)
    )
    input_pointer.unsafe_store[width=16](
        64, xct_pointer.unsafe_load[width=16](0)
    )
    input_pointer.unsafe_store[width=16](
        80, xct_pointer.unsafe_load[width=16](16)
    )
    input_pointer.unsafe_store[width=16](
        96, xpk_pointer.unsafe_load[width=16](0)
    )
    input_pointer.unsafe_store[width=16](
        112, xpk_pointer.unsafe_load[width=16](16)
    )
    input[128] = 0x5C
    input[129] = 0x2E
    input[130] = 0x2F
    input[131] = 0x2F
    input[132] = 0x5E
    input[133] = 0x5C
    return sha3(256, Span(input))


def seed_keypair[
    origin: Origin
](seed: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Derive `(public_key, secret_seed)` from exactly 32 bytes."""
    if len(seed) != SEED_BYTES:
        raise Error("X-Wing key seed must be 32 bytes")
    var expanded = shake(256, seed, 96)
    # ML-KEM allocates the final hybrid width so its public key is never recopied.
    var pk = mlkem768._seed_keypair_public(expanded[0:64], PUBLIC_KEY_BYTES)
    var xpk = x25519_public(expanded[64:96])
    # Bytes 0..1183 already hold ML-KEM; X25519 overwrites the reserved tail.
    var sk = List[UInt8](length=SECRET_KEY_BYTES, fill=0)
    var pk_pointer = Span(pk).unsafe_ptr()
    var xpk_pointer = Span(xpk).unsafe_ptr()
    var sk_pointer = Span(sk).unsafe_ptr()
    var seed_pointer = seed.unsafe_ptr()
    # The 32-byte reserved tail is defined by the two stores below.
    pk_pointer.unsafe_store[width=16](
        mlkem768.PUBLIC_KEY_BYTES,
        xpk_pointer.unsafe_load[width=16](0),
    )
    pk_pointer.unsafe_store[width=16](
        mlkem768.PUBLIC_KEY_BYTES + 16,
        xpk_pointer.unsafe_load[width=16](16),
    )
    sk_pointer.unsafe_store[width=16](0, seed_pointer.unsafe_load[width=16](0))
    sk_pointer.unsafe_store[width=16](
        16, seed_pointer.unsafe_load[width=16](16)
    )
    return (pk^, sk^)


def keypair() raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = system_entropy(SEED_BYTES)
    return seed_keypair(Span(seed))


def encapsulate_deterministic[
    pk_origin: Origin, seed_origin: Origin
](
    public_key: Span[UInt8, pk_origin], seed: Span[UInt8, seed_origin]
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Encapsulate using a supplied 64-byte `m || ephemeral_scalar`."""
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise Error("X-Wing public key must be 1216 bytes")
    if len(seed) != ENCAPS_SEED_BYTES:
        raise Error("X-Wing encapsulation seed must be 64 bytes")
    # ML-KEM reserves the X25519 tail, eliminating the 1088-byte ciphertext copy.
    var ml = mlkem768._encapsulate_deterministic_padded(
        public_key[0 : mlkem768.PUBLIC_KEY_BYTES],
        seed[0:32],
        CIPHERTEXT_BYTES,
    )
    var xct = x25519_public(seed[32:64])
    var xss = x25519_agree(
        seed[32:64], public_key[mlkem768.PUBLIC_KEY_BYTES : PUBLIC_KEY_BYTES]
    )
    var ss = _combine(
        Span(ml[1]),
        Span(xss),
        Span(xct),
        public_key[mlkem768.PUBLIC_KEY_BYTES : PUBLIC_KEY_BYTES],
    )
    var ct = List[UInt8]()

    @parameter
    def take_ciphertext[idx: Int](var element: ml.element_types[idx]):
        comptime if idx == 0:
            ct = element^

    ml^.consume_elements[take_ciphertext]()
    var ct_pointer = Span(ct).unsafe_ptr()
    var xct_pointer = Span(xct).unsafe_ptr()
    # ML-KEM defined the prefix; these stores define the reserved 32-byte tail.
    ct_pointer.unsafe_store[width=16](
        mlkem768.CIPHERTEXT_BYTES,
        xct_pointer.unsafe_load[width=16](0),
    )
    ct_pointer.unsafe_store[width=16](
        mlkem768.CIPHERTEXT_BYTES + 16,
        xct_pointer.unsafe_load[width=16](16),
    )
    return (ct^, ss^)


def encapsulate[
    origin: Origin
](public_key: Span[UInt8, origin]) raises -> Tuple[List[UInt8], List[UInt8]]:
    var seed = system_entropy(ENCAPS_SEED_BYTES)
    return encapsulate_deterministic(public_key, Span(seed))


def decapsulate[
    ct_origin: Origin, sk_origin: Origin
](
    ciphertext: Span[UInt8, ct_origin], secret_key: Span[UInt8, sk_origin]
) raises -> List[UInt8]:
    """Decapsulate; ML-KEM ciphertext faults use its implicit-rejection secret.
    """
    if len(ciphertext) != CIPHERTEXT_BYTES:
        raise Error("X-Wing ciphertext must be 1120 bytes")
    if len(secret_key) != SECRET_KEY_BYTES:
        raise Error("X-Wing secret key must be 32 bytes")
    var expanded = shake(256, secret_key, 96)
    var mlkeys = mlkem768.seed_keypair(expanded[0:64])
    var xpk = x25519_public(expanded[64:96])
    var mlss = mlkem768.decapsulate(
        ciphertext[0 : mlkem768.CIPHERTEXT_BYTES], Span(mlkeys[1])
    )
    var xct = ciphertext[mlkem768.CIPHERTEXT_BYTES : CIPHERTEXT_BYTES]
    var xss = x25519_agree(expanded[64:96], xct)
    return _combine(Span(mlss), Span(xss), xct, Span(xpk))
