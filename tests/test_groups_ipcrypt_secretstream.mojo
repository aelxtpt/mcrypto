from std.testing import (
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
    TestSuite,
)
from mcrypto.groups.algorithm import (
    CoreAlgorithm,
    EdwardsGroupAlgorithm,
    GroupFamily,
    GroupOperation,
)
from mcrypto.groups.scalar import (
    core_operation,
    group_operation,
    hchacha20_core,
    hsalsa20_core,
    keccak_f1600_core,
    salsa20_core,
    scalar_base,
    scalar_invert,
    scalar_mult,
    scalar_multiply_mod_l,
)
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt
from mcrypto.secretstream.xchacha20poly1305 import (
    FINAL as SECRETSTREAM_FINAL,
    MESSAGE as SECRETSTREAM_MESSAGE,
    PullStream as SecretStreamPull,
    PushStream as SecretStreamPush,
    push_streams_eight,
)


def test_ipcrypt_families() raises:
    var input = List[UInt8](length=16, fill=7)
    var no_tweak = List[UInt8]()
    for algorithm, key_bytes, tweak_bytes in [
        (IpcryptAlgorithm.IPCRYPT, 16, 0),
        (IpcryptAlgorithm.ND, 16, 8),
        (IpcryptAlgorithm.NDX, 32, 16),
        (IpcryptAlgorithm.PFX, 32, 0),
    ]:
        var key = List[UInt8](length=key_bytes, fill=1)
        if algorithm == IpcryptAlgorithm.PFX:
            key[16] = 2
        var tweak = List[UInt8](length=tweak_bytes, fill=2)
        var encrypted = ipcrypt(
            algorithm, False, Span(key), Span(tweak), Span(input)
        )
        assert_equal(
            ipcrypt(
                algorithm,
                True,
                Span(key),
                Span(no_tweak),
                Span(encrypted),
            ),
            input,
        )


def test_scalar_groups_and_core_operations() raises:
    var scalar = List[UInt8](length=32, fill=0)
    scalar[0] = 8
    for family in [
        GroupFamily.X25519,
        GroupFamily.ED25519,
        GroupFamily.RISTRETTO255,
    ]:
        var point = scalar_base(family, Span(scalar))
        assert_equal(len(point), 32)
        assert_equal(len(scalar_mult(family, Span(scalar), Span(point))), 32)
    var left = List[UInt8](length=32, fill=0)
    var right = List[UInt8](length=32, fill=0)
    left[0] = 3
    right[0] = 5
    var sum = group_operation(
        EdwardsGroupAlgorithm.RISTRETTO255,
        GroupOperation.SCALAR_ADD,
        Span(left),
        Span(right),
    )
    var difference = group_operation(
        EdwardsGroupAlgorithm.RISTRETTO255,
        GroupOperation.SCALAR_SUB,
        Span(sum),
        Span(right),
    )
    assert_equal(difference, left)
    assert_equal(
        scalar_multiply_mod_l(Span(left), Span(right)),
        group_operation(
            EdwardsGroupAlgorithm.RISTRETTO255,
            GroupOperation.SCALAR_MUL,
            Span(left),
            Span(right),
        ),
    )
    var core_key = List[UInt8](length=32, fill=7)
    var core_input = List[UInt8](length=16, fill=11)
    assert_equal(
        hchacha20_core(Span(core_key), Span(core_input)),
        core_operation(
            CoreAlgorithm.HCHACHA20, Span(core_key), Span(core_input)
        ),
    )
    assert_equal(
        hsalsa20_core(Span(core_key), Span(core_input)),
        core_operation(
            CoreAlgorithm.HSALSA20, Span(core_key), Span(core_input)
        ),
    )
    assert_equal(
        salsa20_core[8](Span(core_key), Span(core_input)),
        core_operation(
            CoreAlgorithm.SALSA20_8, Span(core_key), Span(core_input)
        ),
    )
    assert_equal(
        salsa20_core[12](Span(core_key), Span(core_input)),
        core_operation(
            CoreAlgorithm.SALSA20_12, Span(core_key), Span(core_input)
        ),
    )
    assert_equal(
        salsa20_core[20](Span(core_key), Span(core_input)),
        core_operation(CoreAlgorithm.SALSA20, Span(core_key), Span(core_input)),
    )
    var keccak_state = List[UInt8](length=200, fill=3)
    assert_equal(
        keccak_f1600_core(Span(keccak_state)),
        core_operation(
            CoreAlgorithm.KECCAK_F1600,
            Span(keccak_state),
            Span(right)[0:0],
        ),
    )


def _hex_bytes(text: String) -> List[UInt8]:
    var output = List[UInt8]()
    var index = 0
    for codepoint in text.codepoints():
        var value = Int(codepoint)
        var nibble = UInt8(value - 48 if value <= 57 else value - 87)
        if index % 2 == 0:
            output.append(nibble << 4)
        else:
            output[len(output) - 1] |= nibble
        index += 1
    return output^


def test_interop_core_known_answers() raises:
    var hchacha_key = _hex_bytes(
        "24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc"
    )
    var hchacha_input = _hex_bytes("d9660c5900ae19ddad28d6e06e45fe5e")
    assert_equal(
        hchacha20_core(Span(hchacha_key), Span(hchacha_input)),
        _hex_bytes(
            "5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3"
        ),
    )
    var salsa_key = _hex_bytes(
        "ee304fca27008d8c126f90027901d80f7f1d8b8dc936cf3b9f819692827e5777"
    )
    var salsa_input = _hex_bytes("81918ef2a5e0da9b3e9060521e4bb352")
    assert_equal(
        hsalsa20_core(Span(salsa_key), Span(salsa_input)),
        _hex_bytes(
            "bc1b30fc072cc14075e4baa731b5a845ea9b11e9a5191f94e18cba8fd821a7cd"
        ),
    )
    var salsa_block_key = _hex_bytes(
        "0102030405060708090a0b0c0d0e0f10c9cacbcccdcecfd0d1d2d3d4d5d6d7d8"
    )
    var salsa_block_input = _hex_bytes("65666768696a6b6c6d6e6f7071727374")
    assert_equal(
        salsa20_core[20](Span(salsa_block_key), Span(salsa_block_input)),
        _hex_bytes(
            "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e"
            "68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a"
        ),
    )
    var zero_state = List[UInt8](length=200, fill=0)
    assert_equal(
        keccak_f1600_core(Span(zero_state)),
        _hex_bytes(
            "e7dde140798f25f18a47c033f9ccd584eea95aa61e2698d54d49806f304715bd"
            "57d05362054e288bd46f8e7f2da497ffc44746a4a0e5fe90762e19d60cda5b8c"
            "9c05191bf7a630ad64fc8fd0b75a933035d617233fa95aeb0321710d26e6a6a9"
            "5f55cfdb167ca58126c84703cd31b8439f56a5111a2ff20161aed9215a63e505"
            "f270c98cf2febe641166c47b95703661cb0ed04f555a7cb8c832cf1c8ae83e8c"
            "14263aae22790c94e409c5a224f94118c26504e72635f5163ba1307fe944f675"
            "49a2ec5c7bfff1ea"
        ),
    )
    var short_key = List[UInt8](length=31, fill=0)
    with assert_raises():
        _ = hchacha20_core(Span(short_key), Span(hchacha_input))
    var short_state = List[UInt8](length=199, fill=0)
    with assert_raises():
        _ = keccak_f1600_core(Span(short_state))


def test_interop_group_vectors_and_rejection() raises:
    var zero = List[UInt8](length=32, fill=0)
    var one = zero.copy()
    one[0] = 1
    var two = zero.copy()
    two[0] = 2
    var uniform = _hex_bytes(
        "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1"
        "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6"
    )
    assert_equal(
        group_operation(
            EdwardsGroupAlgorithm.RISTRETTO255,
            GroupOperation.FROM_HASH,
            Span(uniform),
            Span(zero),
        ),
        _hex_bytes(
            "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46"
        ),
    )
    var point = scalar_base(GroupFamily.RISTRETTO255, Span(one))
    var point_copy = point.copy()
    assert_equal(
        group_operation(
            EdwardsGroupAlgorithm.RISTRETTO255,
            GroupOperation.ADD,
            Span(point),
            Span(point_copy),
        ),
        scalar_base(GroupFamily.RISTRETTO255, Span(two)),
    )
    var eight = zero.copy()
    eight[0] = 8
    var inverse = scalar_invert(Span(eight))
    assert_equal(
        group_operation(
            EdwardsGroupAlgorithm.RISTRETTO255,
            GroupOperation.SCALAR_MUL,
            Span(eight),
            Span(inverse),
        ),
        one,
    )
    var noncanonical = _hex_bytes(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    )
    assert_equal(
        group_operation(
            EdwardsGroupAlgorithm.RISTRETTO255,
            GroupOperation.IS_VALID,
            Span(noncanonical),
            Span(zero),
        )[0],
        0,
    )
    var ed_base = _hex_bytes(
        "5866666666666666666666666666666666666666666666666666666666666666"
    )
    assert_equal(
        scalar_base(GroupFamily.ED25519, Span(eight)),
        scalar_mult(GroupFamily.ED25519, Span(eight), Span(ed_base)),
    )
    var not_subgroup = _hex_bytes(
        "9599999999999999999999999999999999999999999999999999999999999999"
    )
    with assert_raises():
        _ = scalar_mult(GroupFamily.ED25519, Span(one), Span(not_subgroup))
    with assert_raises():
        _ = scalar_base(GroupFamily.ED25519, Span(zero))


def test_secretstream_roundtrip_tamper_and_final() raises:
    var key = List[UInt8](length=32, fill=9)
    var aad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4, 5, 6, 7]
    var push = SecretStreamPush(Span(key))
    var header = push.header.copy()
    var first = push.push(Span(message), Span(aad), SECRETSTREAM_MESSAGE)
    var last = push.push(Span(message), Span(aad), SECRETSTREAM_FINAL)
    with assert_raises():
        _ = push.push(Span(message), Span(aad))
    var pull = SecretStreamPull(Span(key), Span(header))
    var opened = pull.pull(Span(first), Span(aad))
    assert_equal(opened[0], message)
    assert_equal(opened[1], SECRETSTREAM_MESSAGE)
    var final_opened = pull.pull(Span(last), Span(aad))
    assert_equal(final_opened[0], message)
    assert_equal(final_opened[1], SECRETSTREAM_FINAL)
    with assert_raises():
        _ = pull.pull(Span(last), Span(aad))


def test_secretstream_authentication_failure() raises:
    var key = List[UInt8](length=32, fill=3)
    var aad: List[UInt8] = [1]
    var message: List[UInt8] = [2]
    var push = SecretStreamPush(Span(key))
    var header = push.header.copy()
    var ciphertext = push.push(Span(message), Span(aad))
    ciphertext[0] ^= 1
    var pull = SecretStreamPull(Span(key), Span(header))
    with assert_raises():
        _ = pull.pull(Span(ciphertext), Span(aad))


def test_batched_secretstream_initialization() raises:
    var key = List[UInt8](length=32, fill=5)
    var aad: List[UInt8] = [7, 8]
    var message: List[UInt8] = [9, 10, 11]
    var streams = push_streams_eight(Span(key))
    assert_equal(len(streams), 8)
    for i in range(8):
        assert_equal(len(streams[i].header), 24)
    var header = streams[0].header.copy()
    var ciphertext = streams[0].push(Span(message), Span(aad))
    var pull = SecretStreamPull(Span(key), Span(header))
    var opened = pull.pull(Span(ciphertext), Span(aad))
    assert_equal(opened[0], message)
    assert_equal(opened[1], SECRETSTREAM_MESSAGE)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
