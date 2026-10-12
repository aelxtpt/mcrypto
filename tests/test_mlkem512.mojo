from std.testing import assert_equal, assert_not_equal, assert_raises, TestSuite
from mcrypto.kem import mlkem512, mlkem768
from mcrypto.kem.algorithm import KemAlgorithm, parse_kem_algorithm
from mcrypto.kem.dispatch import keypair, encapsulate, decapsulate
from mcrypto.encoding.transforms import transform
from mcrypto.encoding.algorithm import EncodingTransform
from mlkem_acvp_vectors import (
    keygen_512,
    keygen_768,
    encapsulation_512,
    encapsulation_768,
    decapsulation_512,
    decapsulation_768,
)


def _hex(text: String) raises -> List[UInt8]:
    return transform(EncodingTransform.HEX_DECODE, text.as_bytes())


def test_acvp_keygen_512_complete_keys() raises:
    for seed_hex, public_hex, secret_hex in keygen_512():
        var seed = _hex(seed_hex)
        var keys = mlkem512.seed_keypair(Span(seed))
        assert_equal(keys[0], _hex(public_hex))
        assert_equal(keys[1], _hex(secret_hex))


def test_acvp_encapsulation_512_complete_ciphertext_and_secret() raises:
    for (
        public_hex,
        secret_hex,
        randomness_hex,
        ciphertext_hex,
        shared_hex,
    ) in encapsulation_512():
        var public_key = _hex(public_hex)
        var secret_key = _hex(secret_hex)
        var randomness = _hex(randomness_hex)
        var sealed = mlkem512.encapsulate_deterministic(
            Span(public_key), Span(randomness)
        )
        assert_equal(sealed[0], _hex(ciphertext_hex))
        assert_equal(sealed[1], _hex(shared_hex))
        assert_equal(
            mlkem512.decapsulate(Span(sealed[0]), Span(secret_key)),
            _hex(shared_hex),
        )


def test_acvp_decapsulation_512_including_implicit_rejection() raises:
    for secret_hex, ciphertext_hex, shared_hex in decapsulation_512():
        var secret_key = _hex(secret_hex)
        var ciphertext = _hex(ciphertext_hex)
        assert_equal(
            mlkem512.decapsulate(Span(ciphertext), Span(secret_key)),
            _hex(shared_hex),
        )


def test_acvp_keygen_768_complete_keys() raises:
    for seed_hex, public_hex, secret_hex in keygen_768():
        var seed = _hex(seed_hex)
        var keys = mlkem768.seed_keypair(Span(seed))
        assert_equal(keys[0], _hex(public_hex))
        assert_equal(keys[1], _hex(secret_hex))


def test_acvp_encapsulation_768_complete_ciphertext_and_secret() raises:
    for (
        public_hex,
        secret_hex,
        randomness_hex,
        ciphertext_hex,
        shared_hex,
    ) in encapsulation_768():
        var public_key = _hex(public_hex)
        var secret_key = _hex(secret_hex)
        var randomness = _hex(randomness_hex)
        var sealed = mlkem768.encapsulate_deterministic(
            Span(public_key), Span(randomness)
        )
        assert_equal(sealed[0], _hex(ciphertext_hex))
        assert_equal(sealed[1], _hex(shared_hex))
        assert_equal(
            mlkem768.decapsulate(Span(sealed[0]), Span(secret_key)),
            _hex(shared_hex),
        )


def test_acvp_decapsulation_768_including_implicit_rejection() raises:
    for secret_hex, ciphertext_hex, shared_hex in decapsulation_768():
        var secret_key = _hex(secret_hex)
        var ciphertext = _hex(ciphertext_hex)
        assert_equal(
            mlkem768.decapsulate(Span(ciphertext), Span(secret_key)),
            _hex(shared_hex),
        )


def test_mlkem512_random_and_dispatch_paths() raises:
    assert_equal(
        parse_kem_algorithm("ML-KEM-512") == KemAlgorithm.ML_KEM_512, True
    )
    var keys = keypair(KemAlgorithm.ML_KEM_512)
    var second = mlkem512.keypair()
    assert_not_equal(keys[0], second[0])
    assert_equal(len(keys[0]), mlkem512.PUBLIC_KEY_BYTES)
    assert_equal(len(keys[1]), mlkem512.SECRET_KEY_BYTES)
    var sealed = encapsulate(KemAlgorithm.ML_KEM_512, Span(keys[0]))
    var next_sealed = mlkem512.encapsulate(Span(keys[0]))
    assert_not_equal(sealed[0], next_sealed[0])
    assert_equal(len(sealed[0]), mlkem512.CIPHERTEXT_BYTES)
    assert_equal(len(sealed[1]), mlkem512.SHARED_SECRET_BYTES)
    assert_equal(
        decapsulate(KemAlgorithm.ML_KEM_512, Span(sealed[0]), Span(keys[1])),
        sealed[1],
    )


def test_mlkem512_rejects_invalid_input_lengths_and_noncanonical_keys() raises:
    var seed = List[UInt8](length=64, fill=0)
    var randomness = List[UInt8](length=32, fill=0)
    var keys = mlkem512.seed_keypair(Span(seed))
    var sealed = mlkem512.encapsulate_deterministic(
        Span(keys[0]), Span(randomness)
    )
    for length in [0, 63, 65]:
        var invalid = List[UInt8](length=length, fill=0)
        with assert_raises():
            _ = mlkem512.seed_keypair(Span(invalid))
    for length in [0, 31, 33]:
        var invalid = List[UInt8](length=length, fill=0)
        with assert_raises():
            _ = mlkem512.encapsulate_deterministic(Span(keys[0]), Span(invalid))
    for length in [0, 799, 801]:
        var invalid = List[UInt8](length=length, fill=0)
        with assert_raises():
            _ = mlkem512.encapsulate_deterministic(
                Span(invalid), Span(randomness)
            )
    for length in [0, 767, 769]:
        var invalid = List[UInt8](length=length, fill=0)
        with assert_raises():
            _ = mlkem512.decapsulate(Span(invalid), Span(keys[1]))
    for length in [0, 1631, 1633]:
        var invalid = List[UInt8](length=length, fill=0)
        with assert_raises():
            _ = mlkem512.decapsulate(Span(sealed[0]), Span(invalid))
    for coefficient in [3329, 4095]:
        var public_key = keys[0].copy()
        public_key[0] = UInt8(coefficient)
        public_key[1] = (public_key[1] & 0xF0) | UInt8(coefficient >> 8)
        with assert_raises():
            _ = mlkem512.encapsulate_deterministic(
                Span(public_key), Span(randomness)
            )


def test_mlkem512_rejects_corrupted_decapsulation_key_hash() raises:
    var seed = List[UInt8](length=64, fill=0)
    var randomness = List[UInt8](length=32, fill=0)
    var keys = mlkem512.seed_keypair(Span(seed))
    var sealed = mlkem512.encapsulate_deterministic(
        Span(keys[0]), Span(randomness)
    )
    for position in [768, 1568, 1599]:
        var secret_key = keys[1].copy()
        secret_key[position] ^= 1
        with assert_raises():
            _ = mlkem512.decapsulate(Span(sealed[0]), Span(secret_key))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
