from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.ciphers.algorithm import StreamCipherAlgorithm
from mcrypto.ciphers.stream import xor, xor_eight


def hex_bytes(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var h = Int(b[i])
        var l = Int(b[i + 1])
        h -= 48 if h <= 57 else 87
        l -= 48 if l <= 57 else 87
        o.append(UInt8(h * 16 + l))
    return o^


def test_chacha_and_salsa_known_answers() raises:
    # Fixed all-zero key, nonce, and input are published KAT material, not
    # production key or nonce generation.
    var key = List[UInt8](length=32, fill=0)
    var nonce8 = List[UInt8](length=8, fill=0)
    var nonce12 = List[UInt8](length=12, fill=0)
    var nonce24 = List[UInt8](length=24, fill=0)
    var zero = List[UInt8](length=64, fill=0)
    assert_equal(
        xor(
            StreamCipherAlgorithm.CHACHA8,
            Span(key),
            Span(nonce8),
            Span(zero),
        ),
        hex_bytes(
            "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e"
            "984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.CHACHA12,
            Span(key),
            Span(nonce8),
            Span(zero),
        ),
        hex_bytes(
            "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f"
            "0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.CHACHA20,
            Span(key),
            Span(nonce8),
            Span(zero),
        ),
        hex_bytes(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.CHACHA20_IETF,
            Span(key),
            Span(nonce12),
            Span(zero),
        ),
        hex_bytes(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.XCHACHA20,
            Span(key),
            Span(nonce24),
            Span(zero),
        ),
        hex_bytes(
            "bcd02a18bf3f01d19292de30a7a8fdaca4b65e50a6002cc72cd6d2f7c91ac3d5"
            "728f83e0aad2bfcf9abd2d2db58faedd65015dd83fc09b131e271043019e8e0f"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.XCHACHA20_COUNTER1,
            Span(key),
            Span(nonce24),
            Span(zero),
        ),
        hex_bytes(
            "789e9689e5208d7fd9e1f3c5b5341f48ef18a13e418998addadd97a3693a987"
            "f8e82ecd5c1433bfed1af49750c0f1ff29c4174a05b119aa3a9e8333812e0c0fe"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.SALSA20,
            Span(key),
            Span(nonce8),
            Span(zero),
        ),
        hex_bytes(
            "9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee6"
            "3de9c0da2bd7f91ebcb2639bf989c6251b29bf38d39a9bdce7c55f4b2ac12a39"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.SALSA20_12,
            Span(key),
            Span(nonce8),
            Span(zero),
        ),
        hex_bytes(
            "bd78a2f8118a563c761db4f2fbe055da97f90988d27594d9c5dfd13a3efeaa3f"
            "68f0d2564850adf5017433968e4b3405ac49a39532124fcd6f47e415c7028a83"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.SALSA20_8,
            Span(key),
            Span(nonce8),
            Span(zero),
        ),
        hex_bytes(
            "9f591da5f99c235445ea91866ead681b977c4ffa036d770fbca79d41fb014178c"
            "f8ecf3164e5e77d7495dc0195081edb2f45c8a1b17d2bec8df3ef9fb7618075"
        ),
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.XSALSA20,
            Span(key),
            Span(nonce24),
            Span(zero),
        ),
        hex_bytes(
            "ba6e26df4b2ea2cf64d2d3636623b5f45c8636d9998d194d605ac3ba3cff1512"
            "c63ebbfffe85ce2cebdef7dc42f494576d05bdd7b929ebb045f2a793f740277d"
        ),
    )


def test_salsa_roundtrip() raises:
    # This fixed all-zero key and nonce exercise reversibility only; they are
    # intentionally unsafe for production use.
    var key = List[UInt8](length=32, fill=0)
    var nonce = List[UInt8](length=8, fill=0)
    var message = "stream test".as_bytes()
    var encrypted = xor(
        StreamCipherAlgorithm.SALSA20, Span(key), Span(nonce), message
    )
    assert_equal(
        xor(
            StreamCipherAlgorithm.SALSA20,
            Span(key),
            Span(nonce),
            Span(encrypted),
        ),
        List(message),
    )


def test_eight_way_streams_match_independent_messages() raises:
    var key = List[UInt8](length=32, fill=0xA5)
    for algorithm in [
        StreamCipherAlgorithm.CHACHA20,
        StreamCipherAlgorithm.CHACHA20_IETF,
        StreamCipherAlgorithm.CHACHA12,
        StreamCipherAlgorithm.CHACHA8,
        StreamCipherAlgorithm.XCHACHA20,
        StreamCipherAlgorithm.XCHACHA20_COUNTER1,
        StreamCipherAlgorithm.SALSA20,
        StreamCipherAlgorithm.SALSA20_12,
        StreamCipherAlgorithm.SALSA20_8,
        StreamCipherAlgorithm.XSALSA20,
        StreamCipherAlgorithm.SOSEMANUK,
    ]:
        var nonce_size = (
            24 if algorithm == StreamCipherAlgorithm.XCHACHA20
            or algorithm == StreamCipherAlgorithm.XCHACHA20_COUNTER1
            or algorithm
            == StreamCipherAlgorithm.XSALSA20 else (
                16 if algorithm
                == StreamCipherAlgorithm.SOSEMANUK else (
                    12 if algorithm
                    == StreamCipherAlgorithm.CHACHA20_IETF else 8
                )
            )
        )
        var nonces = List[List[UInt8]](capacity=8)
        var inputs = List[List[UInt8]](capacity=8)
        for lane in range(8):
            nonces.append(List[UInt8](length=nonce_size, fill=UInt8(lane)))
            inputs.append(List[UInt8](length=300, fill=UInt8(0x10 + lane)))
        var outputs = xor_eight(algorithm, Span(key), nonces, inputs)
        for lane in range(8):
            assert_equal(
                outputs[lane],
                xor(
                    algorithm,
                    Span(key),
                    Span(nonces[lane]),
                    Span(inputs[lane]),
                ),
            )


def test_eight_way_stream_batch_rejects_invalid_dimensions() raises:
    var key = List[UInt8](length=32, fill=0)
    var nonces = List[List[UInt8]]()
    var inputs = List[List[UInt8]]()
    with assert_raises():
        _ = xor_eight(StreamCipherAlgorithm.CHACHA20, Span(key), nonces, inputs)
    for _ in range(8):
        nonces.append(List[UInt8](length=8, fill=0))
        inputs.append(List[UInt8](length=64, fill=0))
    inputs[7] = List[UInt8](length=63, fill=0)
    with assert_raises():
        _ = xor_eight(StreamCipherAlgorithm.CHACHA20, Span(key), nonces, inputs)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
