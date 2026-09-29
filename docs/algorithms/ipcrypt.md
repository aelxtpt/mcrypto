---
title: IPcrypt
---

# IPcrypt

## What this family does

IPcrypt provides deterministic and tweakable reversible transforms for 16-byte IP-address blocks, including prefix-preserving mode.

## Safe selection and legacy warning

IPcrypt is specialized address pseudonymization, not general message encryption and not authenticated encryption. Choose the exact family required by the data-analysis protocol. Manage keys and tweaks as sensitive protocol state.

## Public imports and signatures

```mojo
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt, ipcrypt_eight

def ipcrypt[key_origin: Origin, tweak_origin: Origin, input_origin: Origin](algorithm: IpcryptAlgorithm, decrypt: Bool, key: Span[UInt8, key_origin], tweak: Span[UInt8, tweak_origin], input: Span[UInt8, input_origin]) raises -> List[UInt8]
```

## Inventory names and invocation spellings

Text boundaries map the inventory names to `IpcryptAlgorithm.IPCRYPT`, `IpcryptAlgorithm.ND`, `IpcryptAlgorithm.NDX`, or `IpcryptAlgorithm.PFX`; application code passes those constants directly.

## Dimensions

`IPcrypt` uses a 16-byte key and 16-byte block. ND uses a 16-byte key and 8-byte tweak; encryption maps 16 to 24 bytes. NDX uses a 32-byte key and 16-byte tweak; encryption maps 16 to 32 bytes. PFX uses a 32-byte key and 16-byte address.

## Return and wire layout

Basic/PFX return 16 bytes. ND ciphertext is `8-byte tweak || 16-byte body`; NDX is `16-byte tweak || 16-byte body`. Encryption receives the tweak separately. Decryption consumes the prepended tweak from ciphertext and must be called with an empty tweak argument.

## Executable examples

<a id="example-ipcrypt"></a>
### All framing models
```mojo
from std.testing import assert_equal
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt


def main() raises:
    var address = List[UInt8](length=16, fill=0)
    for i in range(len(address)):
        address[i] = UInt8(i * 7 + 1)
    var empty = List[UInt8]()

    var key16 = List[UInt8](length=16, fill=0x34)
    var basic = ipcrypt(
        IpcryptAlgorithm.IPCRYPT,
        False,
        Span(key16),
        Span(empty),
        Span(address),
    )
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.IPCRYPT,
            True,
            Span(key16),
            Span(empty),
            Span(basic),
        ),
        address,
    )

    var tweak8 = List[UInt8](length=8, fill=0x45)
    var nd = ipcrypt(
        IpcryptAlgorithm.ND,
        False,
        Span(key16),
        Span(tweak8),
        Span(address),
    )
    assert_equal(len(nd), 24)
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.ND,
            True,
            Span(key16),
            Span(empty),
            Span(nd),
        ),
        address,
    )

    var key32 = List[UInt8](length=32, fill=0x56)
    for i in range(16, 32):
        key32[i] ^= 0xA5
    var tweak16 = List[UInt8](length=16, fill=0x67)
    var ndx = ipcrypt(
        IpcryptAlgorithm.NDX,
        False,
        Span(key32),
        Span(tweak16),
        Span(address),
    )
    assert_equal(len(ndx), 32)
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.NDX,
            True,
            Span(key32),
            Span(empty),
            Span(ndx),
        ),
        address,
    )
    var pfx = ipcrypt(
        IpcryptAlgorithm.PFX,
        False,
        Span(key32),
        Span(empty),
        Span(address),
    )
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.PFX,
            True,
            Span(key32),
            Span(empty),
            Span(pfx),
        ),
        address,
    )
    print("ipcrypt: ok")
```

## Authentication, errors, and state

IPcrypt provides no tamper detection. Wrong key/tweak/input lengths and unknown names raise. NDX requires distinct key halves. Deterministic reuse is part of its pseudonymization semantics, not AEAD nonce guidance.

## Prepared, into, and batch APIs

`ipcrypt_eight` requires eight 16-byte inputs and corresponding tweak widths for ND/NDX. Decryption lanes consume the prefixed tweak just like scalar decryption. Results preserve lane order.

## Inventory and test evidence

See [`IPcrypt-ND`](../reference/algorithms.md#ipcrypt-ipcrypt-nd) and [`IPcrypt-PFX`](../reference/algorithms.md#ipcrypt-ipcrypt-pfx). Representative tests: `tests/test_groups_ipcrypt_secretstream.mojo` and `tests/test_group_core_batch_paths.mojo`.