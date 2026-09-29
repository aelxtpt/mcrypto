---
title: Signatures
---

# Digital signatures

A signature authenticates a message under a public key; it does not encrypt the message. Serialize the exact algorithm, parameters, and public key with the protocol, reject malformed keys and signatures, and never treat successful parsing as successful verification.

<!-- algorithm: signature/rsa -->
<a id="signature-rsa"></a>
## RSA

RSA signatures require an encoding scheme as well as the trapdoor operation. The `RSA` selector defaults to PSS with SHA-256; protocol compatibility selectors are explicit.

<a id="example-signature-rsa"></a>
<!-- runnable-example: signature-rsa -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.RSA
    var keys = generate_keypair(algorithm, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-rsa: ok")
```

<!-- algorithm: signature/elgamal -->
<a id="signature-elgamal"></a>
## ElGamal

ElGamal signatures use finite-field discrete logarithms and fresh per-signature randomness. Prefer a deterministic modern signature unless a deployed protocol requires this form.

<a id="example-signature-elgamal"></a>
<!-- runnable-example: signature-elgamal -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ELGAMAL
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-elgamal: ok")
```

<!-- algorithm: signature/luc -->
<a id="signature-luc"></a>
## LUC

LUC signatures use Lucas-sequence trapdoor arithmetic. The default selector is provided for compatibility; bind the exact encoding and digest in the protocol.

<a id="example-signature-luc"></a>
<!-- runnable-example: signature-luc -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.LUC
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-luc: ok")
```

<!-- algorithm: signature/dsa -->
<a id="signature-dsa"></a>
## DSA

DSA signs through a finite-field subgroup. Every signature needs an unpredictable nonce; nonce reuse or bias reveals the private key.

<a id="example-signature-dsa"></a>
<!-- runnable-example: signature-dsa -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.DSA
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-dsa: ok")
```

<!-- algorithm: signature/dsa-rfc6979 -->
<a id="signature-dsa-rfc6979"></a>
## DSA-RFC6979

Deterministic DSA derives the signing nonce from the key and message digest. It removes dependence on per-signature entropy while keeping DSA verification semantics.

<a id="example-signature-dsa-rfc6979"></a>
<!-- runnable-example: signature-dsa-rfc6979 -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.DSA_RFC6979
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-dsa-rfc6979: ok")
```

<!-- algorithm: signature/nr -->
<a id="signature-nr"></a>
## NR

Nyberg–Rueppel signatures are finite-field signatures retained for compatible formats. Keep their parameters and message encoding fixed by the protocol.

<a id="example-signature-nr"></a>
<!-- runnable-example: signature-nr -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.NR
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-nr: ok")
```

<!-- algorithm: signature/rabin-williams -->
<a id="signature-rabin-williams"></a>
## Rabin-Williams

Rabin-Williams signatures use a restricted squaring trapdoor. Verification must use the matching public key and encoded signature scheme.

<a id="example-signature-rabin-williams"></a>
<!-- runnable-example: signature-rabin-williams -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.RABIN_WILLIAMS
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-rabin-williams: ok")
```

<!-- algorithm: signature/ecgdsa -->
<a id="signature-ecgdsa"></a>
## ECGDSA

ECGDSA is an elliptic-curve signature variant. The example uses the P-256 and SHA-256 selector and verifies the signature before accepting the message.

<a id="example-signature-ecgdsa"></a>
<!-- runnable-example: signature-ecgdsa -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ECGDSA_P256_SHA256
    var keys = generate_keypair(algorithm, 256)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-ecgdsa: ok")
```

<!-- algorithm: signature/esign -->
<a id="signature-esign"></a>
## ESIGN

ESIGN is an integer-factorization signature with EMSA5 encoding. It is exposed for interoperability; use a protocol-defined key size and encoding.

<a id="example-signature-esign"></a>
<!-- runnable-example: signature-esign -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ESIGN
    var keys = generate_keypair(algorithm, 384)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-esign: ok")
```

<!-- algorithm: signature/ecdsa -->
<a id="signature-ecdsa"></a>
## ECDSA

ECDSA signs a digest with an elliptic-curve key and a per-signature nonce. The example chooses P-256 with SHA-256 explicitly.

<a id="example-signature-ecdsa"></a>
<!-- runnable-example: signature-ecdsa -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ECDSA_P256_SHA256
    var keys = generate_keypair(algorithm, 256)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-ecdsa: ok")
```

<!-- algorithm: signature/ecdsa-rfc6979 -->
<a id="signature-ecdsa-rfc6979"></a>
## ECDSA-RFC6979

Deterministic ECDSA derives its nonce according to RFC 6979. It produces stable signatures for a fixed key and message while using ordinary ECDSA verification.

<a id="example-signature-ecdsa-rfc6979"></a>
<!-- runnable-example: signature-ecdsa-rfc6979 -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ECDSA_RFC6979_P256_SHA256
    var keys = generate_keypair(algorithm, 256)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-ecdsa-rfc6979: ok")
```

<!-- algorithm: signature/ed25519 -->
<a id="signature-ed25519"></a>
## Ed25519

Ed25519 combines Edwards-curve signing with deterministic nonce derivation and a fixed encoding. Keep secret keys secret and verify the complete 64-byte signature.

<a id="example-signature-ed25519"></a>
<!-- runnable-example: signature-ed25519 -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ED25519
    var keys = generate_keypair(algorithm, 256)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-ed25519: ok")
```

<!-- algorithm: signature/ecnr -->
<a id="signature-ecnr"></a>
## ECNR

ECNR is the elliptic-curve Nyberg–Rueppel signature scheme. The example fixes P-256 and SHA-256 rather than relying on an implicit curve choice.

<a id="example-signature-ecnr"></a>
<!-- runnable-example: signature-ecnr -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ECNR_P256_SHA256
    var keys = generate_keypair(algorithm, 256)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("signed mcrypto message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("signature-ecnr: ok")
```

<!-- algorithm: signature/ed25519ph -->
<a id="signature-ed25519ph"></a>
## Ed25519ph

Ed25519ph hashes the message before the Ed25519 group operation and uses a distinct domain. It is not interchangeable with signing the same bytes through plain Ed25519.

<a id="example-signature-ed25519ph"></a>
<!-- runnable-example: signature-ed25519ph -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.ed25519 import keypair, sign_ph, verify_ph

def main() raises:
    var keys = keypair()
    var public_key = keys[0].copy()
    var secret_key = keys[1].copy()
    var message = List("prehashed signature domain".as_bytes())
    var signature = sign_ph(Span(message), Span(secret_key))
    assert_true(verify_ph(Span(signature), Span(message), Span(public_key)))
    print("signature-ed25519ph: ok")
```
