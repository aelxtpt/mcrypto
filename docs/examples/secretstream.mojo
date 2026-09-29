from std.testing import assert_equal, assert_raises
from mcrypto.secretstream.xchacha20poly1305 import (
    MESSAGE,
    FINAL,
    PushStream,
    PullStream,
)


def main() raises:
    var key = List[UInt8](length=32, fill=0xC7)
    var header = List[UInt8](length=24, fill=0)
    for i in range(len(header)):
        header[i] = UInt8(i + 1)
    var aad = List("stream header".as_bytes())
    var first_message = List("first ordered record".as_bytes())
    var final_message = List("final ordered record".as_bytes())
    var push = PushStream(Span(key), Span(header))
    var pull = PullStream(Span(key), Span(header))
    var first_cipher = push.push(Span(first_message), Span(aad), MESSAGE)
    var final_cipher = push.push(Span(final_message), Span(aad), FINAL)
    assert_equal(len(first_cipher), len(first_message) + 17)
    var first = pull.pull(Span(first_cipher), Span(aad))
    assert_equal(first[0], first_message)
    assert_equal(first[1], MESSAGE)
    var final = pull.pull(Span(final_cipher), Span(aad))
    assert_equal(final[0], final_message)
    assert_equal(final[1], FINAL)
    with assert_raises():
        _ = push.push(Span(first_message), Span(aad), MESSAGE)
    with assert_raises():
        _ = pull.pull(Span(first_cipher), Span(aad))
    print("secretstream: ok")
