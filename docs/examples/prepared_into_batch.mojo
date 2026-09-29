from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash, hash_into
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.modes import PreparedCipher
from mcrypto.ciphers.algorithm import (
    BlockCipherAlgorithm,
    StreamCipherAlgorithm,
    CipherMode,
)
from mcrypto.ciphers.stream import xor, xor_eight


def main() raises:
    var data = List("caller-owned hash output".as_bytes())
    var digest_output = List[UInt8](length=32, fill=0)
    hash_into(HashAlgorithm.SHA256, Span(data), Span(digest_output))
    assert_equal(digest_output, hash(HashAlgorithm.SHA256, Span(data)))

    var aes_key = List[UInt8](length=16, fill=0x78)
    var iv = List[UInt8](length=16, fill=0x89)
    var block_message = List[UInt8](length=32, fill=0x9A)
    var prepared = PreparedCipher(
        BlockCipherAlgorithm.AES, CipherMode.CBC, True, Span(aes_key)
    )
    assert_equal(
        prepared.process(Span(iv), Span(block_message)),
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC,
            True,
            Span(aes_key),
            Span(iv),
            Span(block_message),
        ),
    )

    var stream_key = List[UInt8](length=32, fill=0xAB)
    var nonces = List[List[UInt8]](capacity=8)
    var messages = List[List[UInt8]](capacity=8)
    for lane in range(8):
        var nonce = List[UInt8](length=8, fill=0)
        nonce[0] = UInt8(lane + 1)
        nonces.append(nonce^)
        var message = List[UInt8](length=32, fill=UInt8(lane + 3))
        messages.append(message^)
    var outputs = xor_eight(
        StreamCipherAlgorithm.CHACHA20, Span(stream_key), nonces, messages
    )
    for lane in range(8):
        assert_equal(
            outputs[lane],
            xor(
                StreamCipherAlgorithm.CHACHA20,
                Span(stream_key),
                Span(nonces[lane]),
                Span(messages[lane]),
            ),
        )
    print("prepared-into-batch: ok")
