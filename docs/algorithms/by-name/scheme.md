---
title: Public-key encoding schemes
---

# Public-key encoding schemes

These encodings are composed into complete public-key encryption or signature selectors. They are not standalone padding APIs. Always choose the full algorithm token so the trapdoor operation, digest, mask generation, and encoding agree.

<!-- algorithm: scheme/pkcs1-v1-5 -->
<a id="scheme-pkcs1-v1-5"></a>
## PKCS#1 v1.5

PKCS#1 v1.5 encryption padding is deterministic in structure and has a long history of oracle attacks when decryption errors leak. Use it only for compatibility and make every failure externally indistinguishable.

<a id="example-scheme-pkcs1-v1-5"></a>
<!-- runnable-example: scheme-pkcs1-v1-5 -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.RSA_PKCS1
    var keys = generate_keypair(algorithm, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 3, 3, 7]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    assert_equal(decrypt(algorithm, Span(private_key), Span(ciphertext)), message)
    print("scheme-pkcs1-v1-5: ok")
```

<!-- algorithm: scheme/pkcs1-v2-0 -->
<a id="scheme-pkcs1-v2-0"></a>
## PKCS#1 v2.0

PKCS#1 v2.0 introduced OAEP for encryption and PSS for signatures. Select the complete algorithm token rather than passing this family label to a dispatcher.

<a id="example-scheme-pkcs1-v2-0"></a>
<!-- runnable-example: scheme-pkcs1-v2-0 -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.RSA_OAEP_SHA256
    var keys = generate_keypair(algorithm, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 3, 3, 7]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    assert_equal(decrypt(algorithm, Span(private_key), Span(ciphertext)), message)
    print("scheme-pkcs1-v2-0: ok")
```

<!-- algorithm: scheme/oaep -->
<a id="scheme-oaep"></a>
## OAEP

OAEP is a randomized encoding for trapdoor encryption. The hash and mask-generation choices are part of the protocol and ciphertext failures must not become a decryption oracle.

<a id="example-scheme-oaep"></a>
<!-- runnable-example: scheme-oaep -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 3, 3, 7]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    assert_equal(decrypt(algorithm, Span(private_key), Span(ciphertext)), message)
    print("scheme-oaep: ok")
```

<!-- algorithm: scheme/pss -->
<a id="scheme-pss"></a>
## PSS

PSS is a randomized RSA signature encoding. Salt length and digest selection are protocol parameters; the mcrypto selector binds them to the signature algorithm.

<a id="example-scheme-pss"></a>
<!-- runnable-example: scheme-pss -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.RSA_PSS_SHA256
    var keys = generate_keypair(algorithm, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("encoded signature message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("scheme-pss: ok")
```

<!-- algorithm: scheme/pssr -->
<a id="scheme-pssr"></a>
## PSSR

PSSR is a Rabin-family signature encoding with message recovery structure. The exposed selector binds it to SHA-256 and the Rabin trapdoor.

<a id="example-scheme-pssr"></a>
<!-- runnable-example: scheme-pssr -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.RABIN_PSSR_SHA256
    var keys = generate_keypair(algorithm, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("encoded signature message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("scheme-pssr: ok")
```

<!-- algorithm: scheme/ieee-p1363-emsa2 -->
<a id="scheme-ieee-p1363-emsa2"></a>
## IEEE P1363 EMSA2

EMSA2 is the message encoding used by the Rabin-Williams compatibility signature selector. It is not a standalone hash or signing function.

<a id="example-scheme-ieee-p1363-emsa2"></a>
<!-- runnable-example: scheme-ieee-p1363-emsa2 -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.RABIN_EMSA2_SHA256
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("encoded signature message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("scheme-ieee-p1363-emsa2: ok")
```

<!-- algorithm: scheme/ieee-p1363-emsa5 -->
<a id="scheme-ieee-p1363-emsa5"></a>
## IEEE P1363 EMSA5

EMSA5 expands a digest into the representative used by ESIGN. The complete ESIGN selector owns key generation, representative construction, signing, and verification.

<a id="example-scheme-ieee-p1363-emsa5"></a>
<!-- runnable-example: scheme-ieee-p1363-emsa5 -->
```mojo
from std.testing import assert_true
from mcrypto.signatures.algorithm import SignatureAlgorithm
from mcrypto.signatures.dispatch import generate_keypair, sign, verify

def main() raises:
    var algorithm = SignatureAlgorithm.ESIGN
    var keys = generate_keypair(algorithm, 384)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message = List("encoded signature message".as_bytes())
    var signature = sign(algorithm, Span(private_key), Span(message))
    assert_true(verify(algorithm, Span(public_key), Span(message), Span(signature)))
    print("scheme-ieee-p1363-emsa5: ok")
```

