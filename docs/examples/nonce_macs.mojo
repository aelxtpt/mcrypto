from std.testing import assert_false, assert_true
from mcrypto.macs.gmac import authenticate, verify


def main() raises:
    var key = List[UInt8](length=16, fill=0x72)
    var nonce = List[UInt8](length=12, fill=0x83)
    var message = List("nonce-bearing MAC input".as_bytes())
    var tag = authenticate(Span(key), Span(nonce), Span(message), 16)
    assert_true(verify(Span(key), Span(nonce), Span(message), Span(tag)))
    nonce[0] ^= 1
    assert_false(verify(Span(key), Span(nonce), Span(message), Span(tag)))
    print("nonce-macs: ok")
