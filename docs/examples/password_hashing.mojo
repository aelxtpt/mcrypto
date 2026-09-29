from std.testing import assert_equal
from mcrypto.passwords.argon2id import derive


def main() raises:
    var password = List("correct horse battery staple".as_bytes())
    var salt = List[UInt8](length=16, fill=0)
    for i in range(len(salt)):
        salt[i] = UInt8(i + 1)
    # Uses the high-level defaults: 2 operations, 64 MiB, one lane, 32 bytes.
    var derived = derive(Span(password), Span(salt))
    assert_equal(len(derived), 32)
    print("password-hashing: ok")
