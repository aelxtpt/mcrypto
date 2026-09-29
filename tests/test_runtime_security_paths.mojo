from std.testing import assert_equal, assert_false, assert_true, TestSuite
from mcrypto.random.entropy import system_entropy
from mcrypto.secure_memory import (
    LockedSecretBytes,
    SecretBytes,
    lock_memory,
    page_locking_available,
    secure_zero,
    unlock_memory,
)




def test_caller_buffer_zeroization_and_secret_owners() raises:
    var caller: List[UInt8] = [1, 2, 3, 4, 5]
    secure_zero(Span(caller)[1:4])
    var expected_caller: List[UInt8] = [1, 0, 0, 0, 5]
    assert_equal(caller, expected_caller)
    var secret_input: List[UInt8] = [6, 7, 8, 9]
    var secret = SecretBytes(Span(secret_input))
    assert_equal(secret.expose_copy(), secret_input)
    secret.clear()
    assert_equal(secret.expose_copy(), List[UInt8](length=4, fill=0))


def test_locked_owner_and_explicit_unlock_wipe() raises:
    assert_true(page_locking_available())
    var secret_input: List[UInt8] = [10, 11, 12, 13]
    var locked = LockedSecretBytes(Span(secret_input))
    assert_equal(locked.expose_copy(), secret_input)
    locked.clear()
    assert_equal(locked.expose_copy(), List[UInt8](length=4, fill=0))
    var caller: List[UInt8] = [21, 22, 23, 24]
    lock_memory(Span(caller))
    unlock_memory(Span(caller))
    assert_equal(caller, List[UInt8](length=4, fill=0))


def test_system_entropy_boundaries_and_nonrepeatability() raises:
    assert_equal(system_entropy(0), List[UInt8]())
    var first = system_entropy(32)
    var second = system_entropy(32)
    assert_equal(len(first), 32)
    assert_equal(len(second), 32)
    assert_false(first == second)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
