from std.testing import assert_equal, assert_false, assert_raises, TestSuite
from mcrypto.math.biguint import BigUInt
from mcrypto.hashes.sha256 import sha256
from mcrypto.key_exchange._common import to_be
from mcrypto.key_exchange.algorithm import AgreementAlgorithm
from mcrypto.key_exchange.finite_field import (
    rfc3526_group14,
    public_key as ff_public,
    dh,
    dh2,
    authenticated_agree as ff_auth,
)
from mcrypto.key_exchange.elliptic import (
    p256,
    public_key as ec_public,
    ecdh,
    authenticated_agree as ec_auth,
)
from mcrypto.key_exchange.lucdif import (
    lucd512_domain,
    public_key as luc_public,
    agree as luc_agree,
)
from mcrypto.key_exchange.xtr_dh import (
    xtr171_domain,
    public_key as xtr_public,
    agree as xtr_agree,
)


def scalar(value: UInt64, size: Int) raises -> List[UInt8]:
    return to_be(BigUInt(value), size)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var encoded = text.as_bytes()
    var output = List[UInt8](capacity=len(encoded) // 2)
    for i in range(0, len(encoded), 2):
        var high = Int(encoded[i])
        var low = Int(encoded[i + 1])
        high = high - 48 if high <= 57 else high - 87
        low = low - 48 if low <= 57 else low - 87
        output.append(UInt8(high * 16 + low))
    return output^


def test_dh_and_dh2_agree_and_reject_peer() raises:
    var group = rfc3526_group14()
    var a = scalar(5, 256)
    var b = scalar(7, 256)
    var x = scalar(11, 256)
    var y = scalar(13, 256)
    var ap = ff_public(group, Span(a))
    var bp = ff_public(group, Span(b))
    var xp = ff_public(group, Span(x))
    var yp = ff_public(group, Span(y))
    assert_equal(dh(group, Span(a), Span(bp)), dh(group, Span(b), Span(ap)))
    assert_equal(len(dh(group, Span(a), Span(bp))), 256)
    assert_equal(
        dh2(group, Span(a), Span(x), Span(bp), Span(yp)),
        dh2(group, Span(b), Span(y), Span(ap), Span(xp)),
    )
    assert_equal(len(dh2(group, Span(a), Span(x), Span(bp), Span(yp))), 512)
    var invalid = List[UInt8](length=256, fill=0)
    with assert_raises():
        _ = dh(group, Span(a), Span(invalid))
    # 11 is a quadratic non-residue modulo the RFC 3526 group-14 prime.
    var non_subgroup = scalar(11, 256)
    with assert_raises():
        _ = dh(group, Span(a), Span(non_subgroup))


def test_ff_mqv_families_are_distinct_and_symmetric() raises:
    var group = rfc3526_group14()
    var a = scalar(5, 256)
    var b = scalar(7, 256)
    var x = scalar(11, 256)
    var y = scalar(13, 256)
    var ap = ff_public(group, Span(a))
    var bp = ff_public(group, Span(b))
    var xp = ff_public(group, Span(x))
    var yp = ff_public(group, Span(y))
    var mqva = ff_auth(
        group,
        AgreementAlgorithm.MQV,
        Span(a),
        Span(x),
        Span(ap),
        Span(xp),
        Span(bp),
        Span(yp),
        True,
    )
    var mqvb = ff_auth(
        group,
        AgreementAlgorithm.MQV,
        Span(b),
        Span(y),
        Span(bp),
        Span(yp),
        Span(ap),
        Span(xp),
        False,
    )
    assert_equal(mqva, mqvb)
    assert_equal(
        sha256(Span(mqva)),
        hex_bytes(
            "ff8c699342bf3dda844b805810201341150c0fd0d5ca73461de0f0b52e519d56"
        ),
    )
    var ha = ff_auth(
        group,
        AgreementAlgorithm.HMQV,
        Span(a),
        Span(x),
        Span(ap),
        Span(xp),
        Span(bp),
        Span(yp),
        True,
    )
    var hb = ff_auth(
        group,
        AgreementAlgorithm.HMQV,
        Span(b),
        Span(y),
        Span(bp),
        Span(yp),
        Span(ap),
        Span(xp),
        False,
    )
    assert_equal(ha, hb)
    assert_equal(
        sha256(Span(ha)),
        hex_bytes(
            "7c39a66b7704d5ea089cea551be3feb779d372ddff83101b2cb1b999e343ac89"
        ),
    )
    assert_false(ha == mqva)
    var fa = ff_auth(
        group,
        AgreementAlgorithm.FHMQV,
        Span(a),
        Span(x),
        Span(ap),
        Span(xp),
        Span(bp),
        Span(yp),
        True,
    )
    var fb = ff_auth(
        group,
        AgreementAlgorithm.FHMQV,
        Span(b),
        Span(y),
        Span(bp),
        Span(yp),
        Span(ap),
        Span(xp),
        False,
    )
    assert_equal(fa, fb)
    assert_equal(
        sha256(Span(fa)),
        hex_bytes(
            "900b44edc65d063dc4ff2cc79e591fdf798edacf0c66611f268ab0cdb8db53ef"
        ),
    )
    assert_false(fa == ha)


def test_p256_sec2_base_vector_and_ecdh() raises:
    var domain = p256()
    var one = scalar(1, 32)
    var encoded = ec_public(domain, Span(one))
    assert_equal(encoded[0], UInt8(4))
    assert_equal(len(encoded), 65)
    var a = scalar(5, 32)
    var b = scalar(7, 32)
    var ap = ec_public(domain, Span(a))
    var bp = ec_public(domain, Span(b))
    assert_equal(
        ecdh(domain, Span(a), Span(bp)), ecdh(domain, Span(b), Span(ap))
    )
    var damaged = bp.copy()
    damaged[10] ^= 1
    with assert_raises():
        _ = ecdh(domain, Span(a), Span(damaged))


def test_ec_authenticated_families() raises:
    var d = p256()
    var a = scalar(5, 32)
    var b = scalar(7, 32)
    var x = scalar(11, 32)
    var y = scalar(13, 32)
    var ap = ec_public(d, Span(a))
    var bp = ec_public(d, Span(b))
    var xp = ec_public(d, Span(x))
    var yp = ec_public(d, Span(y))
    var schemes: List[AgreementAlgorithm] = [
        AgreementAlgorithm.ECMQV_P256,
        AgreementAlgorithm.ECHMQV_P256,
        AgreementAlgorithm.ECFHMQV_P256,
    ]
    for scheme in schemes:
        var sa = ec_auth(
            d,
            scheme,
            Span(a),
            Span(x),
            Span(ap),
            Span(xp),
            Span(bp),
            Span(yp),
            True,
        )
        var sb = ec_auth(
            d,
            scheme,
            Span(b),
            Span(y),
            Span(bp),
            Span(yp),
            Span(ap),
            Span(xp),
            False,
        )
        assert_equal(sa, sb)
        if scheme == AgreementAlgorithm.ECMQV_P256:
            assert_equal(
                sa,
                hex_bytes(
                    "5f4923e3abf5ae2bb13750f244b93e54b0fb4b6f3ba578739230ac80005b4cfa"
                ),
            )
        elif scheme == AgreementAlgorithm.ECHMQV_P256:
            assert_equal(
                sa,
                hex_bytes(
                    "4596fae56d2d4a6a0d4609766591c99617f68fab1fb1d7b0cb37be9969e8e236"
                ),
            )
        else:
            assert_equal(
                sa,
                hex_bytes(
                    "96f6c6ae2754f358b417d150cc80874b1341d53fa995a2f4a625381eb991cdff"
                ),
            )


def test_lucdif_composition_and_tamper() raises:
    # Canonical lucd512 domain parameters; values independently computed with LUC-DH.
    var d = lucd512_domain()
    var a = scalar(5, 64)
    var b = scalar(7, 64)
    var ap = luc_public(d, Span(a))
    var bp = luc_public(d, Span(b))
    assert_equal(
        ap,
        hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000d899"
        ),
    )
    assert_equal(
        bp,
        hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000042d479"
        ),
    )
    var shared = luc_agree(d, Span(a), Span(bp))
    assert_equal(shared, luc_agree(d, Span(b), Span(ap)))
    assert_equal(
        shared,
        hex_bytes(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000004f7531ad4a14f31a44e1eef1a669"
        ),
    )
    var zero = List[UInt8](length=64, fill=0)
    with assert_raises():
        _ = luc_agree(d, Span(a), Span(zero))
    # For peer P=3, P^2-4=5 is a quadratic residue modulo this prime.
    var non_subgroup = scalar(3, 64)
    with assert_raises():
        _ = luc_agree(d, Span(a), Span(non_subgroup))


def test_xtr_trace_vector_and_agreement() raises:
    # Canonical xtrdh171 domain parameters; values independently computed with XTR-DH.
    var d = xtr171_domain()
    var a = scalar(5, 21)
    var b = scalar(7, 21)
    var ap = xtr_public(d, Span(a))
    var bp = xtr_public(d, Span(b))
    assert_equal(
        ap,
        hex_bytes(
            "012bfdba302f3b8a06fe8010527ee5d2cef028db47e601360980f773efe65eb8a9324be0a6e316a50ba8d4b4"
        ),
    )
    assert_equal(
        bp,
        hex_bytes(
            "027300d4814da03d61c82cc349b6830787522977d4ba022c218b548da8f575761a181c88e211a432b900b8a6"
        ),
    )
    var shared = xtr_agree(d, Span(a), Span(bp))
    assert_equal(shared, xtr_agree(d, Span(b), Span(ap)))
    assert_equal(
        shared,
        hex_bytes(
            "011dc9cdf6cc2ecf0c77bc20e80953b422d5b2a74e6e03d7182d4faf099bce26811293184461250e8cc73ce7"
        ),
    )
    var bad = List[UInt8](length=44, fill=0)
    with assert_raises():
        _ = xtr_agree(d, Span(a), Span(bad))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
