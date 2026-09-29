from std.testing import assert_equal
from mcrypto.hashes.sha256 import SHA256, sha256


def main() raises:
    var state = SHA256()
    state.update("a".as_bytes())
    state.update("b".as_bytes())
    state.update("c".as_bytes())
    assert_equal(state.finalize(), sha256("abc".as_bytes()))
    print("incremental-hash: ok")
