---
title: Secret sharing and information dispersal
---

# Secret sharing and information dispersal

Shares are self-describing byte strings with a threshold, share identifier, original length, and integrity digest. The digest detects accidental or obvious corruption; use authenticated transport and access controls when shares cross trust boundaries.

<!-- algorithm: secret-sharing/shamir-secret-sharing -->
<a id="secret-sharing-shamir-secret-sharing"></a>
## Shamir secret sharing

Shamir sharing hides the secret unless the threshold number of distinct shares is available. Coefficients come from the operating-system CSPRNG; distribute shares to independent failure domains.

<a id="example-secret-sharing-shamir-secret-sharing"></a>
<!-- runnable-example: secret-sharing-shamir-secret-sharing -->
```mojo
from std.testing import assert_equal
from mcrypto.utilities.secret_sharing import shamir_recover, shamir_split

def main() raises:
    var secret = List("threshold secret".as_bytes())
    var ids: List[UInt8] = [1, 2, 3, 4, 5]
    var shares = shamir_split(Span(secret), 3, Span(ids))
    var selected = List[List[UInt8]](capacity=3)
    selected.append(shares[0].copy())
    selected.append(shares[2].copy())
    selected.append(shares[4].copy())
    assert_equal(shamir_recover(selected), secret)
    print("secret-sharing-shamir-secret-sharing: ok")
```

<!-- algorithm: secret-sharing/rabin-ida -->
<a id="secret-sharing-rabin-ida"></a>
## Rabin information dispersal

Rabin IDA spreads data so any threshold subset can reconstruct it, but it does not hide the plaintext from individual shares. Use encryption before dispersal when confidentiality is required.

<a id="example-secret-sharing-rabin-ida"></a>
<!-- runnable-example: secret-sharing-rabin-ida -->
```mojo
from std.testing import assert_equal
from mcrypto.utilities.secret_sharing import ida_recover, ida_split

def main() raises:
    var data = List("dispersed but not encrypted".as_bytes())
    var ids: List[UInt8] = [1, 2, 3, 9, 201]
    var shares = ida_split(Span(data), 3, Span(ids))
    var selected = List[List[UInt8]](capacity=3)
    selected.append(shares[0].copy())
    selected.append(shares[3].copy())
    selected.append(shares[4].copy())
    assert_equal(ida_recover(selected), data)
    print("secret-sharing-rabin-ida: ok")
```
