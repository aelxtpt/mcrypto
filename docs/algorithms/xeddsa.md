---
title: XEd25519 signatures
---

# XEd25519 signatures

XEd25519 is the Curve25519 instance of [XEdDSA](https://signal.org/docs/specifications/xeddsa/). It signs messages using an existing X25519 private key and verifies using its Montgomery public key. The implementation is pure Mojo and shares the library's Edwards and field arithmetic.

## Direct API and key formats

```mojo
from mcrypto.signatures.xeddsa import sign, sign_with_randomness, verify
```

- `sign(message, private_key)` returns a detached 64-byte `R || s` signature, using 64 fresh random bytes from the OS. Entropy failures propagate as errors.
- `sign_with_randomness(message, private_key, randomness)` exposes the same operation with an explicit 64-byte secret random input. Use this advanced entry point only when supplying fresh cryptographically secure randomness for each signature. Fixed random inputs belong only in tests.
- `verify(signature, message, public_key)` returns `Bool`; malformed inputs return `False`.

All inputs are byte spans and remain unchanged. The private key is 32 raw X25519 bytes, clamped internally exactly as in `mcrypto.key_exchange.x25519.public_key`. It is **not** an Ed25519 seed or a 64-byte Ed25519 secret key. Public keys are canonical 32-byte little-endian Montgomery u coordinates, without a type prefix. Use the existing X25519 module to derive them.

This specialized API is direct-only; there is no `SignatureAlgorithm` dispatcher constant. XEd448 and X-VEdDSA are not implemented.

## Example

<a id="example-xed25519"></a>

```mojo
from std.testing import assert_false, assert_true
from mcrypto.key_exchange.x25519 import public_key as x25519_public_key
from mcrypto.random.entropy import system_entropy
from mcrypto.signatures.xeddsa import sign, verify


def main() raises:
    var private_key = system_entropy(32)
    var public_key = x25519_public_key(Span(private_key))
    var message = List("signed message".as_bytes())
    var signature = sign(Span(message), Span(private_key))
    assert_true(verify(Span(signature), Span(message), Span(public_key)))
    message[0] ^= 1
    assert_false(verify(Span(signature), Span(message), Span(public_key)))
    print("XEd25519: ok")
```

## Signing and verification policy

A Montgomery public key omits the Edwards x sign. Signing chooses the Edwards representative whose sign is zero and conditionally negates the private scalar modulo the subgroup order q. The selection scans all scalar bytes with a mask. The nonce is derived from `SHA-512(prefix || a || message || Z)`, reduced modulo q; the 32-byte prefix is `FE` followed by 31 `FF` bytes. The challenge is `SHA-512(R || A || message)`, reduced modulo q. The signature scalar is `s = r + h*a (mod q)`.

The normal signing entry point obtains fresh Z internally. The implementation uses the existing masked fixed-base multiplication for secret scalars; verification may use variable-time operations on public inputs. This describes the source-level implementation, not an independent side-channel audit.

Verification converts u to Edwards y using `(u - 1)/(u + 1)` and applies the library's strict Ed25519 checks:

- Exact key and signature lengths, canonical `u < 2^255 - 19`, and no ignored high bit on public keys.
- Canonical Edwards points and signature scalar `s < q`.
- Rejection of small-order public keys and R points, and verification of the uncofactored signature equation.

These checks are deliberately stricter than the original XEdDSA verifier, which permits some noncanonical scalars below `2^253` and does not explicitly reject small-order points. In particular, `s + q` signatures are rejected. This API does not interpret the legacy Curve25519 format's sign bit in the final signature byte: signatures with that bit set are rejected. Legacy signatures whose sign bit is zero overlap with the XEd25519 format.

## Reference evidence

`tests/test_xeddsa.mojo` embeds five byte-exact known answers checked with Signal's [public C implementation](https://github.com/signalapp/libsignal-protocol-c/tree/3a83a4f4ed2302ff6e68ab569c88793b50c22d28/src/curve25519), pinned at commit `3a83a4f4ed2302ff6e68ab569c88793b50c22d28`.

The first is the published [`xeddsa_fast_test`](https://github.com/signalapp/libsignal-protocol-c/blob/3a83a4f4ed2302ff6e68ab569c88793b50c22d28/src/curve25519/ed25519/tests/internal_fast_tests.c#L324): a zero private input with byte 8 set to 189, a 200-byte zero message, and 64 zero random bytes. The other four use private inputs filled with 1, 2, 3, or 4, respectively; their messages are empty, `abc`, bytes 0 through 255, and 128 bytes of `FF`. All four use random input bytes 0 through 63. These cover both original Edwards signs.

To reproduce with that reference, clamp each private input using `sc_clamp`, derive its public key using `curve25519_keygen`, and invoke `xed25519_sign` with the message and the specified 64-byte random input. The expected public keys and signatures are embedded in the tests; `xed25519_verify` also accepts all five. The test suite itself has no C or network dependency.

Additional tests cover clamping and input preservation, randomized signing, long/binary/empty messages, tampering, wrong keys, invalid lengths, noncanonical encodings, scalar malleability, and small-order forgeries. The coverage registry binds both signing entry points and verification to these executed tests.

Run `pixi run test-xeddsa` for the focused suite. The VS Code/ExprCode launch configuration builds this suite with debug information and assertions enabled.
