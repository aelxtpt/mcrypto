from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.secretstream.xchacha20poly1305 import (
    PushStream,
    PullStream,
    MESSAGE,
    REKEY,
    FINAL,
)


def test_roundtrip_rekey_final_and_tamper() raises:
    var key = List[UInt8](length=32, fill=9)
    var aad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4, 5, 6, 7]
    var push = PushStream(Span(key))
    var header = push.header.copy()
    var a = push.push(Span(message), Span(aad), MESSAGE)
    var b = push.push(Span(message), Span(aad), REKEY)
    var c = push.push(Span(message), Span(aad), FINAL)
    with assert_raises():
        _ = push.push(Span(message), Span(aad))
    var pull = PullStream(Span(key), Span(header))
    var oa = pull.pull(Span(a), Span(aad))
    assert_equal(oa[0], message)
    assert_equal(oa[1], MESSAGE)
    var ob = pull.pull(Span(b), Span(aad))
    assert_equal(ob[0], message)
    assert_equal(ob[1], REKEY)
    var oc = pull.pull(Span(c), Span(aad))
    assert_equal(oc[0], message)
    assert_equal(oc[1], FINAL)
    var push2 = PushStream(Span(key))
    var header2 = push2.header.copy()
    var bad = push2.push(Span(message), Span(aad))
    bad[1] ^= 1
    var pull2 = PullStream(Span(key), Span(header2))
    with assert_raises():
        _ = pull2.pull(Span(bad), Span(aad))


def test_fused_push_boundaries() raises:
    var key = List[UInt8](length=32, fill=13)
    var aad: List[UInt8] = [1, 3, 5, 7, 9]
    for size in [0, 15, 16, 31, 32, 63, 64, 4095, 4096, 4097, 32768]:
        var message = List[UInt8](length=size, fill=0)
        for i in range(size):
            message[i] = UInt8(i * 29 + 17)
        var push = PushStream(Span(key))
        var header = push.header.copy()
        var ciphertext = push.push(Span(message), Span(aad))
        var pull = PullStream(Span(key), Span(header))
        var opened = pull.pull(Span(ciphertext), Span(aad))
        assert_equal(opened[0], message)
        assert_equal(opened[1], MESSAGE)


def test_explicit_rekey_keeps_push_and_pull_synchronized() raises:
    var key = List[UInt8](length=32, fill=21)
    var aad: List[UInt8] = [8, 5, 3]
    var message: List[UInt8] = [1, 1, 2, 3, 5, 8]
    var push = PushStream(Span(key))
    var header = push.header.copy()
    push.rekey()
    var ciphertext = push.push(Span(message), Span(aad), MESSAGE)
    var pull = PullStream(Span(key), Span(header))
    pull.rekey()
    var opened = pull.pull(Span(ciphertext), Span(aad))
    assert_equal(opened[0], message)
    assert_equal(opened[1], MESSAGE)


def test_authentication_failure_does_not_advance_pull_state() raises:
    var key = List[UInt8](length=32, fill=34)
    var aad: List[UInt8] = [1, 4, 9]
    var first_message: List[UInt8] = [2, 7, 1, 8]
    var second_message: List[UInt8] = [2, 8, 1, 8]
    var push = PushStream(Span(key))
    var header = push.header.copy()
    var first = push.push(Span(first_message), Span(aad), MESSAGE)
    var second = push.push(Span(second_message), Span(aad), MESSAGE)
    var corrupted = first.copy()
    corrupted[len(corrupted) - 1] ^= 1
    var pull = PullStream(Span(key), Span(header))
    with assert_raises():
        _ = pull.pull(Span(corrupted), Span(aad))
    var opened_first = pull.pull(Span(first), Span(aad))
    assert_equal(opened_first[0], first_message)
    var opened_second = pull.pull(Span(second), Span(aad))
    assert_equal(opened_second[0], second_message)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
