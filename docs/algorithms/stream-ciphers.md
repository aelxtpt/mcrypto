---
title: Stream ciphers
---

# Stream ciphers

## What this family does

A stream cipher XORs plaintext with a keyed nonce-dependent stream. Applying the same operation again with the same key and nonce recovers the input.

## Safe selection and legacy warning

Prefer XChaCha20 with a unique 24-byte nonce, or an AEAD/secretbox that also authenticates. Never reuse a key/nonce pair. ARC4, SEAL, WAKE-OFB, Panama, Rabbit, HC, Sosemanuk, and reduced-round variants exist for compatibility rather than new protocols.

## Public imports and signatures

```mojo
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor, xor_eight

def xor[key_origin: Origin, nonce_origin: Origin, input_origin: Origin](algorithm: StreamCipherAlgorithm, key: Span[UInt8, key_origin], nonce: Span[UInt8, nonce_origin], input: Span[UInt8, input_origin]) raises -> List[UInt8]
def xor_eight[key_origin: Origin](algorithm: StreamCipherAlgorithm, key: Span[UInt8, key_origin], nonces: List[List[UInt8]], inputs: List[List[UInt8]]) raises -> List[List[UInt8]]
```

## Inventory names and invocation spellings

The catalog name `ChaCha20IETF` maps at the external-name boundary to `StreamCipherAlgorithm.CHACHA20_IETF`. Application code passes constants such as `StreamCipherAlgorithm.CHACHA20`, `StreamCipherAlgorithm.XCHACHA20`, `StreamCipherAlgorithm.SALSA20`, or `StreamCipherAlgorithm.XSALSA20`; misspelled algorithm names do not compile.

## Dimensions

ChaCha/Salsa families use 32-byte keys. ChaCha8/12/20 and Salsa20 variants use 8-byte nonces; `ChaCha20-IETF` uses 12; XChaCha20 and XSalsa20 use 24. Panama uses a 32-byte key and nonce; SEAL uses 20 and 4; WAKE-OFB consumes an empty nonce. Output length equals input length.

## Return and wire layout

`xor` returns only XOR output; it does not prefix a nonce, counter, or tag. Protocol framing must carry the nonce separately. Eight-way output preserves lane order.

## Executable examples

<a id="example-stream-ciphers"></a>
### Stream round trip

```mojo
from std.testing import assert_equal, assert_true
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor


def main() raises:
    var key = List[UInt8](length=32, fill=0x19)
    var nonce = List[UInt8](length=24, fill=0x2A)
    var message = List("stream ciphers need unique nonces".as_bytes())
    var ciphertext = xor(
        StreamCipherAlgorithm.XCHACHA20,
        Span(key),
        Span(nonce),
        Span(message),
    )
    assert_true(ciphertext != message)
    assert_equal(
        xor(
            StreamCipherAlgorithm.XCHACHA20,
            Span(key),
            Span(nonce),
            Span(ciphertext),
        ),
        message,
    )
    print("stream-ciphers: ok")
```

## Authentication, errors, and state

Ciphertext changes predictably change plaintext. No tamper signal exists. Unknown names and invalid key/nonce dimensions raise. Counter-based direct helpers must not wrap or reuse a stream position.

## Prepared, into, and batch APIs

`xor_eight` requires exactly eight nonce/message lanes and equal message widths; each lane needs a distinct nonce. Direct counter and `*_into` helpers support caller storage without adding a CPU fallback or authentication.

## Inventory and test evidence

See [`ChaCha20-IETF`](../reference/algorithms.md#stream-cipher-chacha20-ietf) and [`XChaCha20`](../reference/algorithms.md#stream-cipher-xchacha20). Representative tests: `tests/test_stream_pure.mojo`, `tests/test_legacy_stream.mojo`, and `tests/test_cipher_prepared_stream_paths.mojo`.