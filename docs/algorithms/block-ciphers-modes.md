---
title: Block ciphers and modes
---

# Block ciphers and modes

## What this family does

A block cipher is a keyed permutation over fixed-width blocks. Modes adapt it to messages. These APIs provide confidentiality only unless a separate authenticator is applied correctly.

## Safe selection and legacy warning

Prefer an AEAD. When a protocol requires a conventional mode, use AES with a protocol-defined mode and fresh IV/tweak. ECB reveals block equality. CBC/CFB/OFB/CTR are malleable. Several supported ciphers are obsolete or narrowly deployed; consult [legacy compatibility](legacy-compatibility.md).

## Public imports and signatures

```mojo
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process

def process[key_origin: Origin, iv_origin: Origin, input_origin: Origin](algorithm: BlockCipherAlgorithm, mode: CipherMode, encrypt: Bool, key: Span[UInt8, key_origin], iv: Span[UInt8, iv_origin], input: Span[UInt8, input_origin]) raises -> List[UInt8]
```

Cipher and mode are separate typed selectors, for example `BlockCipherAlgorithm.AES` and `CipherMode.CBC`.

## Inventory names and invocation spellings

Catalog paths such as `AES/CBC` are parsed once into separate `BlockCipherAlgorithm` and `CipherMode` values. XTS accepts AES and the implemented Threefish-256/512/1024 variants. `CBC-CTS` and `XTS` have distinct length and tweak rules.

## Dimensions

AES has a 16-byte block and 16/24/32-byte keys. ECB uses an empty IV; CBC, CBC-CTS, CFB, OFB, and CTR use one block-sized IV. ECB/CBC input is block-aligned; CBC-CTS accepts at least one block and preserves length. AES-XTS uses a 32- or 64-byte concatenated data/tweak key, a 16-byte tweak, and at least 16 bytes. Other ciphers enforce their own key and block dimensions.

## Return and wire layout

`process` returns raw ciphertext or plaintext with no tag. Ordinary modes preserve length except padding is not added for callers; CBC/ECB therefore require aligned input. CBC-CTS and XTS steal ciphertext for a final partial block and preserve input length. The IV or tweak is not prepended.

## Executable examples

<a id="example-block-modes"></a>
### Ordinary modes
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode


def main() raises:
    var key = List[UInt8](length=16, fill=0x11)
    var iv = List[UInt8](length=16, fill=0x22)
    var message = List[UInt8](length=32, fill=0)
    for i in range(len(message)):
        message[i] = UInt8(i)
    for mode in [CipherMode.CBC, CipherMode.CTR]:
        var ciphertext = process(
            BlockCipherAlgorithm.AES,
            mode,
            True,
            Span(key),
            Span(iv),
            Span(message),
        )
        assert_true(ciphertext != message)
        assert_equal(
            process(
                BlockCipherAlgorithm.AES,
                mode,
                False,
                Span(key),
                Span(iv),
                Span(ciphertext),
            ),
            message,
        )
    print("block-modes: ok")
```

<a id="example-cbc-cts-xts"></a>
### CBC-CTS and XTS
```mojo
from std.testing import assert_equal, assert_true
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode


def main() raises:
    var cbc_key = List[UInt8](length=16, fill=0x31)
    var iv = List[UInt8](length=16, fill=0x42)
    var message = List[UInt8](length=37, fill=0)
    for i in range(len(message)):
        message[i] = UInt8(i * 3 + 1)
    var cts = process(
        BlockCipherAlgorithm.AES,
        CipherMode.CBC_CTS,
        True,
        Span(cbc_key),
        Span(iv),
        Span(message),
    )
    assert_equal(len(cts), len(message))
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            False,
            Span(cbc_key),
            Span(iv),
            Span(cts),
        ),
        message,
    )

    var xts_key = List[UInt8](length=32, fill=0x53)
    var tweak = List[UInt8](length=16, fill=0x64)
    var xts = process(
        BlockCipherAlgorithm.AES,
        CipherMode.XTS,
        True,
        Span(xts_key),
        Span(tweak),
        Span(message),
    )
    assert_true(xts != message)
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.XTS,
            False,
            Span(xts_key),
            Span(tweak),
            Span(xts),
        ),
        message,
    )
    print("cbc-cts-xts: ok")
```

## Authentication, errors, and state

Wrong key/IV sizes, unknown composite names, alignment errors, and too-short CTS/XTS input raise. Decryption cannot detect a wrong key, IV, reordered block, or modified ciphertext. Authenticate the complete framing or use AEAD.

## Prepared, into, and batch APIs

Cipher modules expose prepared key schedules, `process_prepared`, `*_into`, four-way, and eight-way paths. Batch messages must have equal width and correctly sized flat output. They do not change mode semantics or add authentication.

## Inventory and test evidence

See [`AES`](../reference/algorithms.md#block-cipher-aes), [`CBC-CTS`](../reference/algorithms.md#cipher-mode-cbc-cts), and the known affected [`SIMON-128`](../reference/algorithms.md#block-cipher-simon-128). Representative tests: `tests/test_modes.mojo`, `tests/test_aes_modes.mojo`, and `tests/test_cipher_prepared_batch_paths.mojo`.