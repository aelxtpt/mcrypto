from std.testing import assert_equal, TestSuite
from mcrypto.macs.hmac import authenticate, authenticate_eight
from mcrypto.macs.algorithm import HmacAlgorithm


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high = high - (48 if high <= 57 else 87)
        low = low - (48 if low <= 57 else 87)
        output.append(UInt8((high << 4) | low))
    return output^


def test_rfc4231_vectors() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var data = "Hi There".as_bytes()
    assert_equal(
        authenticate(HmacAlgorithm.SHA256, Span(key), data),
        hex_bytes(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        ),
    )
    assert_equal(
        authenticate(HmacAlgorithm.SHA512, Span(key), data),
        hex_bytes(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        ),
    )


def test_interop_hmac_sha512_256_vector() raises:
    var key = List[UInt8](length=32, fill=0)
    var data = List[UInt8](length=3, fill=0)
    assert_equal(
        authenticate(HmacAlgorithm.SHA512_256, Span(key), Span(data)),
        hex_bytes(
            "faabfc75158bb797242a3ce2953e531de707b0c500aee845921484778863c764"
        ),
    )


def test_rfc2286_ripemd160_vectors() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var data = "Hi There".as_bytes()
    assert_equal(
        authenticate(HmacAlgorithm.RIPEMD160, Span(key), data),
        hex_bytes("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668"),
    )
    var jefe = "Jefe".as_bytes()
    var message = "what do ya want for nothing?".as_bytes()
    assert_equal(
        authenticate(HmacAlgorithm.RIPEMD160, jefe, message),
        hex_bytes("dda6c0213a485a9e24f4742064a7f033b43c4069"),
    )


def test_eight_way_hmac_matches_independent_messages() raises:
    var key = List[UInt8](length=32, fill=0xA5)
    for algorithm in [
        HmacAlgorithm.SHA1,
        HmacAlgorithm.SHA256,
        HmacAlgorithm.SHA512,
        HmacAlgorithm.SHA512_256,
        HmacAlgorithm.RIPEMD160,
    ]:
        var inputs = List[List[UInt8]](capacity=8)
        for lane in range(8):
            inputs.append(List[UInt8](length=300, fill=UInt8(lane)))
        var outputs = authenticate_eight(algorithm, Span(key), inputs)
        for lane in range(8):
            assert_equal(
                outputs[lane],
                authenticate(algorithm, Span(key), Span(inputs[lane])),
            )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
