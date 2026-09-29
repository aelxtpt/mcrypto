---
title: IP address encryption
---

# IP address encryption

IPcrypt transforms exact 16-byte IPv6 representations; encode IPv4 addresses according to the caller's data model before use. These transforms preserve selected structure and do not authenticate records. Keep keys separate from general encryption keys.

<!-- algorithm: ipcrypt/ipcrypt -->
<a id="ipcrypt-ipcrypt"></a>
## IPcrypt

IPcrypt deterministically permutes one 16-byte IP address under a 16-byte key. Equal inputs produce equal outputs, so frequency and equality remain visible.

<a id="example-ipcrypt-ipcrypt"></a>
<!-- runnable-example: ipcrypt-ipcrypt -->
```mojo
from std.testing import assert_equal
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt

def main() raises:
    var key = List[UInt8](length=16, fill=0x31)
    var tweak = List[UInt8](length=0, fill=0x51)
    var no_tweak = List[UInt8]()
    var address = List[UInt8](length=16, fill=0)
    address[15] = 1
    var encrypted = ipcrypt(IpcryptAlgorithm.IPCRYPT, False, Span(key), Span(tweak), Span(address))
    assert_equal(ipcrypt(IpcryptAlgorithm.IPCRYPT, True, Span(key), Span(no_tweak), Span(encrypted)), address)
    print("ipcrypt-ipcrypt: ok")
```

<!-- algorithm: ipcrypt/ipcrypt-nd -->
<a id="ipcrypt-ipcrypt-nd"></a>
## IPcrypt-ND

IPcrypt-ND adds an 8-byte tweak so the same address can map differently across domains. Preserve the tweak beside the ciphertext because decryption derives it from the encoded result.

<a id="example-ipcrypt-ipcrypt-nd"></a>
<!-- runnable-example: ipcrypt-ipcrypt-nd -->
```mojo
from std.testing import assert_equal
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt

def main() raises:
    var key = List[UInt8](length=16, fill=0x32)
    var tweak = List[UInt8](length=8, fill=0x52)
    var no_tweak = List[UInt8]()
    var address = List[UInt8](length=16, fill=0)
    address[15] = 1
    var encrypted = ipcrypt(IpcryptAlgorithm.ND, False, Span(key), Span(tweak), Span(address))
    assert_equal(ipcrypt(IpcryptAlgorithm.ND, True, Span(key), Span(no_tweak), Span(encrypted)), address)
    print("ipcrypt-ipcrypt-nd: ok")
```

<!-- algorithm: ipcrypt/ipcrypt-ndx -->
<a id="ipcrypt-ipcrypt-ndx"></a>
## IPcrypt-NDX

IPcrypt-NDX uses a 32-byte key and 16-byte tweak for a larger domain-separation input. The transform remains address-format preserving rather than authenticated encryption.

<a id="example-ipcrypt-ipcrypt-ndx"></a>
<!-- runnable-example: ipcrypt-ipcrypt-ndx -->
```mojo
from std.testing import assert_equal
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x33)
    var tweak = List[UInt8](length=16, fill=0x53)
    var no_tweak = List[UInt8]()
    var address = List[UInt8](length=16, fill=0)
    address[15] = 1
    var encrypted = ipcrypt(IpcryptAlgorithm.NDX, False, Span(key), Span(tweak), Span(address))
    assert_equal(ipcrypt(IpcryptAlgorithm.NDX, True, Span(key), Span(no_tweak), Span(encrypted)), address)
    print("ipcrypt-ipcrypt-ndx: ok")
```

<!-- algorithm: ipcrypt/ipcrypt-pfx -->
<a id="ipcrypt-ipcrypt-pfx"></a>
## IPcrypt-PFX

IPcrypt-PFX preserves IP prefixes so subnet relationships remain queryable after transformation. That leakage is intentional; use it only when prefix analytics are required.

<a id="example-ipcrypt-ipcrypt-pfx"></a>
<!-- runnable-example: ipcrypt-ipcrypt-pfx -->
```mojo
from std.testing import assert_equal
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt

def main() raises:
    var key = List[UInt8](length=32, fill=0x34)
    key[16] = 0x7A
    var tweak = List[UInt8](length=0, fill=0x54)
    var no_tweak = List[UInt8]()
    var address = List[UInt8](length=16, fill=0)
    address[15] = 1
    var encrypted = ipcrypt(IpcryptAlgorithm.PFX, False, Span(key), Span(tweak), Span(address))
    assert_equal(ipcrypt(IpcryptAlgorithm.PFX, True, Span(key), Span(no_tweak), Span(encrypted)), address)
    print("ipcrypt-ipcrypt-pfx: ok")
```

