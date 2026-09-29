from std.testing import assert_equal, assert_true, TestSuite
from mcrypto.secure_memory import (
    SecretBytes,
    LockedSecretBytes,
    secure_zero,
    page_locking_available,
    lock_memory,
    unlock_memory,
)


def test_explicit_zeroization_and_secret_clear() raises:
    var bytes: List[UInt8] = [1, 2, 3, 4]
    secure_zero(Span(bytes))
    assert_equal(bytes, List[UInt8](length=4, fill=0))
    var input: List[UInt8] = [5, 6, 7]
    var secret = SecretBytes(Span(input))
    secret.clear()
    assert_equal(secret.expose_copy(), List[UInt8](length=3, fill=0))


def test_page_locking_and_locked_owner() raises:
    assert_true(page_locking_available())
    var input: List[UInt8] = [5, 6, 7]
    var secret = LockedSecretBytes(Span(input))
    assert_equal(secret.expose_copy(), input)
    secret.clear()
    assert_equal(secret.expose_copy(), List[UInt8](length=3, fill=0))
    var raw: List[UInt8] = [1, 2, 3, 4]
    lock_memory(Span(raw))
    unlock_memory(Span(raw))
    assert_equal(raw, List[UInt8](length=4, fill=0))


def test_unaligned_subspan_locking_preserves_prefix() raises:
    var guarded = List[UInt8](length=17, fill=0xA5)
    var secret = Span(guarded)[1:16]
    lock_memory(secret)
    unlock_memory(secret)
    assert_equal(guarded[0], UInt8(0xA5))
    assert_equal(guarded[16], UInt8(0xA5))
    for index in range(1, 16):
        assert_equal(guarded[index], UInt8(0))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
