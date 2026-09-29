from std.testing import assert_equal, assert_not_equal, assert_raises, TestSuite
from mcrypto.kem import mlkem768, xwing
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def _hex(value: String) raises -> List[UInt8]:
    return transform(EncodingTransform.HEX_DECODE, value.as_bytes())


def _prefix(data: List[UInt8], size: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=size)
    for i in range(size):
        out.append(data[i])
    return out^


def test_mlkem768_fips_kat() raises:
    var seed = _hex(
        "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a"
    )
    var coins = _hex(
        "eb4a7c66ef4eba2ddb38c88d8bc706b1d639002198172a7b1942eca8f6c001ba"
    )
    var keys = mlkem768.seed_keypair(Span(seed))
    var pk = keys[0].copy()
    var sk = keys[1].copy()
    assert_equal(len(pk), 1184)
    assert_equal(len(sk), 2400)
    assert_equal(
        _prefix(pk, 32),
        _hex(
            "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f3679"
        ),
    )
    var sealed = mlkem768.encapsulate_deterministic(Span(pk), Span(coins))
    var ct = sealed[0].copy()
    var ss = sealed[1].copy()
    assert_equal(len(ct), 1088)
    assert_equal(len(ss), 32)
    assert_equal(
        _prefix(ct, 32),
        _hex(
            "3b835a5fa145387a0819c4daa1e65fbe2ba5400afcd640bbddbbe3585f24bedd"
        ),
    )
    assert_equal(
        ss,
        _hex(
            "ac865f839fef1bf3d528dd7504bed2f64b5502b0fa81d1c32763658e4aac5037"
        ),
    )
    assert_equal(mlkem768.decapsulate(Span(ct), Span(sk)), ss)
    ct[0] ^= 1
    var rejected = mlkem768.decapsulate(Span(ct), Span(sk))
    assert_not_equal(rejected, ss)
    assert_equal(
        rejected,
        _hex(
            "088b6554ddf5887adfe8d4e82ff6809ca0cd56aee96aea3a0cc0d29bd5f87bb0"
        ),
    )


def test_xwing_interop_kat() raises:
    var seed = List[UInt8](length=32, fill=0)
    var coins = List[UInt8](length=64, fill=UInt8(0x64))
    var keys = xwing.seed_keypair(Span(seed))
    var pk = keys[0].copy()
    var sk = keys[1].copy()
    assert_equal(len(pk), 1216)
    assert_equal(len(sk), 32)
    assert_equal(
        _prefix(pk, 32),
        _hex(
            "3d209f716752f6408e7f89bceef97ac388530045377927644ef046c0a7cae978"
        ),
    )
    var sealed = xwing.encapsulate_deterministic(Span(pk), Span(coins))
    var ct = sealed[0].copy()
    var ss = sealed[1].copy()
    assert_equal(len(ct), 1120)
    assert_equal(len(ss), 32)
    assert_equal(
        _prefix(ct, 26),
        _hex("d81018a94f8078e02105beaa814e003390befa4589bb614f7739"),
    )
    assert_equal(
        ss,
        _hex(
            "e5ba94031ea6efd69c09c254f6d9783136ba6037e2d4c43bcccf19d6f3f4343a"
        ),
    )
    assert_equal(xwing.decapsulate(Span(ct), Span(sk)), ss)
    ct[0] ^= 1
    assert_not_equal(xwing.decapsulate(Span(ct), Span(sk)), ss)


def test_kem_invalid_sizes() raises:
    var short = List[UInt8](length=31, fill=0)
    with assert_raises():
        _ = mlkem768.seed_keypair(Span(short))
    with assert_raises():
        _ = xwing.seed_keypair(Span(short))
    with assert_raises():
        _ = mlkem768.encapsulate(Span(short))
    with assert_raises():
        _ = xwing.encapsulate(Span(short))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
