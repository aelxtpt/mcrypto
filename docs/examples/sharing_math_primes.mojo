from std.testing import assert_equal, assert_true
from mcrypto.utilities.secret_sharing import (
    shamir_split,
    shamir_recover,
    ida_split,
    ida_recover,
)
from mcrypto.math.biguint import BigUInt
from mcrypto.math.fields import PrimeField64
from mcrypto.math.primes import is_probable_prime


def first_three(shares: List[List[UInt8]]) -> List[List[UInt8]]:
    var selected = List[List[UInt8]](capacity=3)
    selected.append(shares[0].copy())
    selected.append(shares[1].copy())
    selected.append(shares[2].copy())
    return selected^


def main() raises:
    var message = List("threshold data".as_bytes())
    var ids: List[UInt8] = [1, 2, 3, 7, 11]
    var shamir = shamir_split(Span(message), 3, Span(ids))
    assert_equal(shamir_recover(first_three(shamir)), message)
    var ida = ida_split(Span(message), 3, Span(ids))
    assert_equal(ida_recover(first_three(ida)), message)

    var field = PrimeField64(17)
    assert_equal(field.multiply(9, 11), UInt64(14))
    assert_true(is_probable_prime(BigUInt(UInt64(65537))))
    print("sharing-math-primes: ok")
