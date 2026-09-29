---
title: Authenticated secret streams
---

# Authenticated secret streams

Secretstream turns a sequence of records into one stateful authenticated channel. Transmit the 24-byte header once, preserve message order, authenticate associated data identically on both sides, and stop after a final tag.

<!-- algorithm: secretstream/xchacha20-poly1305-secretstream -->
<a id="secretstream-xchacha20-poly1305-secretstream"></a>
## XChaCha20-Poly1305 secretstream

`PushStream` ratchets the stream state as it encrypts records; `PullStream` authenticates and advances in the same order. The final tag is an authenticated state transition and prevents further records.

<a id="example-secretstream-xchacha20-poly1305-secretstream"></a>
<!-- runnable-example: secretstream-xchacha20-poly1305-secretstream -->
```mojo
from std.testing import assert_equal
from mcrypto.secretstream.xchacha20poly1305 import FINAL, MESSAGE, PullStream, PushStream

def main() raises:
    var key = List[UInt8](length=32, fill=0x49)
    var aad = List("record header".as_bytes())
    var message = List("stream record".as_bytes())
    var push = PushStream(Span(key))
    var header = push.header.copy()
    var ciphertext = push.push(Span(message), Span(aad), FINAL)
    var pull = PullStream(Span(key), Span(header))
    var opened = pull.pull(Span(ciphertext), Span(aad))
    assert_equal(opened[0], message)
    assert_equal(opened[1], FINAL)
    print("secretstream-xchacha20-poly1305-secretstream: ok")
```
