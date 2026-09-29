---
title: Finite fields and prime testing
---

# Finite fields and prime testing

These types support mcrypto primitives and compatible protocols. Field parameters are part of the algorithm definition. Probable-prime testing is a probabilistic classification, not a primality certificate.

<!-- algorithm: math/gf-p -->
<a id="math-gf-p"></a>
## Prime fields GF(p)

`PrimeField64` performs arithmetic modulo a caller-supplied 64-bit modulus; `BigUInt` supports larger integer operations used by public-key code. A modulus must be prime when field semantics are required.

<a id="example-math-gf-p"></a>
<!-- runnable-example: math-gf-p -->
```mojo
from std.testing import assert_equal
from mcrypto.math.biguint import BigUInt
from mcrypto.math.fields import PrimeField64

def main() raises:
    var field = PrimeField64(17)
    assert_equal(field.multiply(5, 7), UInt64(1))
    assert_equal(field.multiply(5, field.inverse(5)), UInt64(1))
    var value = BigUInt(97)
    assert_equal(value.compare(BigUInt(97)), 0)
    print("math-gf-p: ok")
```

<!-- algorithm: math/gf-2n -->
<a id="math-gf-2n"></a>
## Binary extension fields GF(2^n)

`GF256` and `GF2_32` add through XOR and multiply modulo fixed irreducible polynomials. Use the polynomial required by the surrounding primitive; different representations are not interchangeable.

<a id="example-math-gf-2n"></a>
<!-- runnable-example: math-gf-2n -->
```mojo
from std.testing import assert_equal
from mcrypto.math.fields import GF256, GF2_32

def main() raises:
    var small = GF256()
    assert_equal(small.multiply(UInt8(0x53), small.inverse(UInt8(0x53))), UInt8(1))
    var wide = GF2_32()
    assert_equal(wide.multiply(UInt32(7), wide.inverse(UInt32(7))), UInt32(1))
    print("math-gf-2n: ok")
```

<!-- algorithm: math/prime-generation -->
<a id="math-prime-generation"></a>
## Prime generation and testing

`generate_probable_prime` returns an exact-width candidate that passes BPSW and configurable Miller–Rabin screens; it is not a proof. `generate_provable_prime` recursively builds and verifies a Pocklington certificate internally. Use the proved path when the protocol requires proven primality.

<a id="example-math-prime-generation"></a>
<!-- runnable-example: math-prime-generation -->
```mojo
from std.testing import assert_false, assert_true
from mcrypto.math.biguint import BigUInt
from mcrypto.math.primes import generate_probable_prime, generate_provable_prime, is_probable_prime

def main() raises:
    var probable = generate_probable_prime(32, 16)
    var proved = generate_provable_prime(32)
    assert_true(is_probable_prime(probable, 16))
    assert_true(is_probable_prime(proved, 16))
    assert_false(is_probable_prime(BigUInt(104730), 16))
    print("math-prime-generation: ok")
```
