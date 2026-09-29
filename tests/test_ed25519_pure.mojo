from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.signatures.ed25519 import (
    keypair,
    keypair_from_seed,
    sign,
    sign_ph,
    verify,
    verify_ph,
)


def _nibble(value: UInt8) raises -> UInt8:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    raise Error("invalid test hex")


def _hex(value: String) raises -> List[UInt8]:
    var data = value.as_bytes()
    if len(data) % 2 != 0:
        raise Error("odd test hex")
    var output = List[UInt8](capacity=len(data) // 2)
    for i in range(0, len(data), 2):
        output.append((_nibble(data[i]) << 4) | _nibble(data[i + 1]))
    return output^


def _hex_of(data: List[UInt8]) -> String:
    comptime digits: StaticString = "0123456789abcdef"
    var output = String(capacity=len(data) * 2)
    for byte in data:
        output += digits[byte=Int(byte >> 4)]
        output += digits[byte=Int(byte & 15)]
    return output^


def test_rfc8032_vector_1_and_interop_key_format() raises:
    var seed = _hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    var keys = keypair_from_seed(Span(seed))
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    assert_equal(
        _hex_of(public_key),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    )
    assert_equal(_hex_of(secret_key), _hex_of(seed) + _hex_of(public_key))
    var message = List[UInt8]()
    var signature = sign(Span(message), Span(secret_key))
    assert_equal(
        _hex_of(signature),
        (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    )
    assert_true(verify(Span(signature), Span(message), Span(public_key)))


def test_rfc8032_vector_2_tamper_and_strictness() raises:
    var seed = _hex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    var keys = keypair_from_seed(Span(seed))
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var message: List[UInt8] = [0x72]
    var signature = sign(Span(message), Span(secret_key))
    assert_equal(
        _hex_of(signature),
        (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    )
    signature[0] ^= 1
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    signature[0] ^= 1
    message[0] ^= 1
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    var short_signature = signature[0:63]
    assert_false(verify(short_signature, Span(message), Span(public_key)))
    var identity = List[UInt8](length=32, fill=0)
    identity[0] = 1
    assert_false(verify(Span(signature), Span(message), Span(identity)))
    var noncanonical = _hex(
        "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    )
    assert_false(verify(Span(signature), Span(message), Span(noncanonical)))
    var invalid_point = List[UInt8](length=32, fill=0)
    invalid_point[0] = 2
    assert_false(verify(Span(signature), Span(message), Span(invalid_point)))
    for i in range(32, 64):
        signature[i] = 0xFF
    assert_false(verify(Span(signature), Span(message), Span(public_key)))


def test_rfc8032_ed25519ph_vector() raises:
    var seed = _hex(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
    )
    var keys = keypair_from_seed(Span(seed))
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var message: List[UInt8] = [0x61, 0x62, 0x63]
    var signature = sign_ph(Span(message), Span(secret_key))
    assert_equal(
        _hex_of(signature),
        (
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
            "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
        ),
    )
    assert_true(verify_ph(Span(signature), Span(message), Span(public_key)))
    assert_false(verify(Span(signature), Span(message), Span(public_key)))


def test_interop_sign_exp_keypair() raises:
    # Embedded deterministic key-format vector.
    var seed = _hex(
        "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee"
    )
    var keys = keypair_from_seed(Span(seed))
    assert_equal(
        _hex_of(keys[0]),
        "b5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e",
    )
    assert_equal(
        _hex_of(keys[1]),
        (
            "421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee"
            "b5076a8474a832daee4dd5b4040983b6623b5f344aca57d4d6ee4baf3f259e6e"
        ),
    )


def test_invalid_lengths_and_random_generation() raises:
    var bad_seed = List[UInt8](length=31, fill=0)
    with assert_raises():
        _ = keypair_from_seed(Span(bad_seed))
    var keys = keypair()
    assert_equal(len(keys[0]), 32)
    assert_equal(len(keys[1]), 64)
    var message: List[UInt8] = [1, 2, 3]
    var bad_key = List[UInt8](length=63, fill=0)
    with assert_raises():
        _ = sign(Span(message), Span(bad_key))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
