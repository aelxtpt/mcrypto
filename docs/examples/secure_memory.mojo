from std.testing import assert_equal
from mcrypto.secure_memory import (
    SecretBytes,
    LockedSecretBytes,
    page_locking_available,
    secure_zero,
)


def main() raises:
    var caller: List[UInt8] = [1, 2, 3, 4, 5]
    secure_zero(Span(caller)[1:4])
    var expected: List[UInt8] = [1, 0, 0, 0, 5]
    assert_equal(caller, expected)

    var input: List[UInt8] = [6, 7, 8, 9]
    var secret = SecretBytes(Span(input))
    secret.clear()
    assert_equal(secret.expose_copy(), List[UInt8](length=4, fill=0))

    if page_locking_available():
        var locked = LockedSecretBytes(Span(input))
        locked.clear()
        assert_equal(locked.expose_copy(), List[UInt8](length=4, fill=0))
    print("secure-memory: ok")
