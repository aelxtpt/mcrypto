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
