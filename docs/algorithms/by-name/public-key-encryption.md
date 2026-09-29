---
title: Public-key encryption
---

# Public-key encryption

Public-key encryption lets a sender encrypt to a recipient public key. It does not authenticate the sender. Generate keys with the system CSPRNG, bind algorithm identifiers to the protocol, and use an authenticated, encoded scheme rather than a raw trapdoor operation.

<!-- algorithm: public-key-encryption/rsa -->
<a id="public-key-encryption-rsa"></a>
## RSA

RSA public-key encryption is a family of trapdoor permutations wrapped in an encoding scheme. The `RSA` selector defaults to OAEP with SHA-256; choose an explicit compatibility selector only when a protocol requires it.

<a id="example-public-key-encryption-rsa"></a>
<!-- runnable-example: public-key-encryption-rsa -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.RSA
    var keys = generate_keypair(algorithm, 1024)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-rsa: ok")
```

<!-- algorithm: public-key-encryption/rabin -->
<a id="public-key-encryption-rabin"></a>
## Rabin

Rabin encryption is based on modular squaring. Raw Rabin has ambiguous roots, so this example selects the OAEP-wrapped path rather than treating the primitive as a message format.

<a id="example-public-key-encryption-rabin"></a>
<!-- runnable-example: public-key-encryption-rabin -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.RABIN_OAEP_SHA1
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-rabin: ok")
```

<!-- algorithm: public-key-encryption/rabin-williams -->
<a id="public-key-encryption-rabin-williams"></a>
## Rabin-Williams

Rabin-Williams restricts the Rabin trapdoor structure to make inversion deterministic. The raw operation still needs a protocol encoding before it can safely carry arbitrary messages.

<a id="example-public-key-encryption-rabin-williams"></a>
<!-- runnable-example: public-key-encryption-rabin-williams -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.RABIN_WILLIAMS
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [42]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered[len(recovered) - 1], UInt8(42))
    print("public-key-encryption-rabin-williams: ok")
```

<!-- algorithm: public-key-encryption/elgamal -->
<a id="public-key-encryption-elgamal"></a>
## ElGamal

ElGamal encryption is randomized and expands the ciphertext into two finite-field elements. Never reuse its ephemeral exponent, and authenticate the resulting protocol transcript separately.

<a id="example-public-key-encryption-elgamal"></a>
<!-- runnable-example: public-key-encryption-elgamal -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.ELGAMAL
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-elgamal: ok")
```

<!-- algorithm: public-key-encryption/luc -->
<a id="public-key-encryption-luc"></a>
## LUC

LUC uses Lucas sequences for a trapdoor operation. This example selects its OAEP wrapper; raw LUC representatives are not an application message format.

<a id="example-public-key-encryption-luc"></a>
<!-- runnable-example: public-key-encryption-luc -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.LUC_OAEP_SHA1
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-luc: ok")
```

<!-- algorithm: public-key-encryption/lucelg -->
<a id="public-key-encryption-lucelg"></a>
## LUCELG

LUCELG is the Lucas-sequence analogue of ElGamal encryption. Treat it as a compatibility construction and preserve the complete framed public and private keys.

<a id="example-public-key-encryption-lucelg"></a>
<!-- runnable-example: public-key-encryption-lucelg -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.LUCELG
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-lucelg: ok")
```

<!-- algorithm: public-key-encryption/dlies -->
<a id="public-key-encryption-dlies"></a>
## DLIES

DLIES combines finite-field agreement, a KDF, stream masking, and authentication. Decryption authenticates before returning plaintext; key generation and ciphertext randomness require the system CSPRNG.

<a id="example-public-key-encryption-dlies"></a>
<!-- runnable-example: public-key-encryption-dlies -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.DLIES
    var keys = generate_keypair(algorithm, 512)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-dlies: ok")
```

<!-- algorithm: public-key-encryption/ecies -->
<a id="public-key-encryption-ecies"></a>
## ECIES

ECIES combines elliptic-curve agreement, key derivation, encryption, and authentication. The mcrypto selector uses P-256 and SHA-256 and rejects modified ciphertexts.

<a id="example-public-key-encryption-ecies"></a>
<!-- runnable-example: public-key-encryption-ecies -->
```mojo
from std.testing import assert_equal
from mcrypto.public_key.algorithm import PublicKeyEncryptionAlgorithm
from mcrypto.public_key.encryption import decrypt, encrypt, generate_keypair

def main() raises:
    var algorithm = PublicKeyEncryptionAlgorithm.ECIES
    var keys = generate_keypair(algorithm, 256)
    var private_key = keys[0].copy()
    var public_key = keys[1].copy()
    var message: List[UInt8] = [1, 2, 3, 4, 5]
    var ciphertext = encrypt(algorithm, Span(public_key), Span(message))
    var recovered = decrypt(algorithm, Span(private_key), Span(ciphertext))
    assert_equal(recovered, message)
    print("public-key-encryption-ecies: ok")
```

