from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.utilities.secret_sharing import (
    ida_recover,
    ida_split,
    shamir_recover,
    shamir_split_deterministic,
)


def _pick(
    source: List[List[UInt8]], a: Int, b: Int, c: Int
) -> List[List[UInt8]]:
    var selected = List[List[UInt8]](capacity=3)
    selected.append(source[a].copy())
    selected.append(source[b].copy())
    selected.append(source[c].copy())
    return selected^


def test_shamir_deterministic_vector_and_threshold_subsets() raises:
    # GF(2^8), x^8+x^4+x^3+x+1.  For secret 0x42 and coefficients
    # 0x10,0x20, f(x)=0x42 + 0x10*x + 0x20*x^2 gives these ordinates.
    var one_byte: List[UInt8] = [0x42]
    var ids: List[UInt8] = [1, 2, 3]
    var coefficients: List[UInt8] = [0x10, 0x20]
    var vector = shamir_split_deterministic(
        Span(one_byte), 3, Span(ids), Span(coefficients)
    )
    assert_equal(vector[0][28], UInt8(0x72))
    assert_equal(vector[1][28], UInt8(0xE2))
    assert_equal(vector[2][28], UInt8(0xD2))
    assert_equal(shamir_recover(vector), one_byte)

    var message = List("threshold secret sharing".as_bytes())
    var five_ids: List[UInt8] = [1, 2, 7, 11, 255]
    var random = List[UInt8](capacity=len(message) * 2)
    for i in range(len(message) * 2):
        random.append(UInt8((i * 29 + 7) & 0xFF))
    var shares = shamir_split_deterministic(
        Span(message), 3, Span(five_ids), Span(random)
    )
    assert_equal(shamir_recover(_pick(shares, 0, 1, 2)), message)
    assert_equal(shamir_recover(_pick(shares, 0, 3, 4)), message)
    assert_equal(shamir_recover(_pick(shares, 1, 2, 4)), message)


def test_ida_any_threshold_and_deterministic_payload() raises:
    var message: List[UInt8] = [1, 2, 3, 4, 5, 6, 7]
    var ids: List[UInt8] = [1, 2, 3, 9, 201]
    var shares = ida_split(Span(message), 3, Span(ids))
    # Systematic points 1,2,3 expose padded 3-byte stripes directly.
    assert_equal(shares[0][28], UInt8(1))
    assert_equal(shares[0][29], UInt8(4))
    assert_equal(shares[0][30], UInt8(7))
    assert_equal(shares[1][28], UInt8(2))
    assert_equal(shares[1][29], UInt8(5))
    assert_equal(shares[1][30], UInt8(0))
    assert_equal(shares[2][28], UInt8(3))
    assert_equal(shares[2][29], UInt8(6))
    assert_equal(shares[2][30], UInt8(0))
    assert_equal(ida_recover(_pick(shares, 0, 1, 2)), message)
    assert_equal(ida_recover(_pick(shares, 0, 3, 4)), message)
    assert_equal(ida_recover(_pick(shares, 1, 2, 4)), message)


def test_rejects_invalid_and_detectably_corrupt_shares() raises:
    var message = List("integrity".as_bytes())
    var ids: List[UInt8] = [1, 2, 3, 4]
    var random = List[UInt8](length=len(message) * 2, fill=0xA5)
    var shares = shamir_split_deterministic(
        Span(message), 3, Span(ids), Span(random)
    )
    var too_few = List[List[UInt8]](capacity=2)
    too_few.append(shares[0].copy())
    too_few.append(shares[1].copy())
    with assert_raises():
        _ = shamir_recover(too_few)
    var duplicate = _pick(shares, 0, 0, 2)
    with assert_raises():
        _ = shamir_recover(duplicate)
    var corrupt = _pick(shares, 0, 1, 2)
    corrupt[1][28] ^= 1
    with assert_raises():
        _ = shamir_recover(corrupt)

    var ida_shares = ida_split(Span(message), 3, Span(ids))
    var all = List[List[UInt8]](capacity=4)
    for share in ida_shares:
        all.append(share.copy())
    all[3][28] ^= 1
    with assert_raises():
        _ = ida_recover(all)

    var zero_id: List[UInt8] = [0, 1, 2]
    with assert_raises():
        _ = ida_split(Span(message), 2, Span(zero_id))
    var duplicate_ids: List[UInt8] = [1, 1, 2]
    with assert_raises():
        _ = ida_split(Span(message), 2, Span(duplicate_ids))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
