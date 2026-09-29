from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.secretbox.xchacha20poly1305 import (
    encrypt,
    encrypt_eight,
    decrypt_eight,
    decrypt,
    encrypt_detached,
    decrypt_detached,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var data = text.as_bytes()
    var output = List[UInt8](capacity=len(data) // 2)
    for i in range(0, len(data), 2):
        var high = Int(data[i])
        var low = Int(data[i + 1])
        high -= 48 if high <= 57 else 87
        low -= 48 if low <= 57 else 87
        output.append(UInt8(high * 16 + low))
    return output^


def _check_vector(
    key_hex: StaticString,
    nonce_hex: StaticString,
    message_hex: StaticString,
    expected_hex: StaticString,
) raises:
    var key = hex_bytes(key_hex)
    var nonce = hex_bytes(nonce_hex)
    var message = hex_bytes(message_hex)
    var expected = hex_bytes(expected_hex)
    var combined = encrypt(Span(message), Span(nonce), Span(key))
    assert_equal(combined, expected)
    assert_equal(decrypt(Span(combined), Span(nonce), Span(key)), message)

    var detached = encrypt_detached(Span(message), Span(nonce), Span(key))
    var expected_tag = List[UInt8](capacity=16)
    var expected_body = List[UInt8](capacity=len(message))
    for i in range(16):
        expected_tag.append(expected[i])
    for i in range(16, len(expected)):
        expected_body.append(expected[i])
    assert_equal(detached[0], expected_body)
    assert_equal(detached[1], expected_tag)
    var detached_body = detached[0].copy()
    var detached_tag = detached[1].copy()
    assert_equal(
        decrypt_detached(
            Span(detached_body), Span(detached_tag), Span(nonce), Span(key)
        ),
        message,
    )


def test_interop_empty_message() raises:
    _check_vector(
        "065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34",
        "f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5",
        "",
        "4c72340416339dcdea01b760db5adaf7",
    )


def test_interop_partial_block_message() raises:
    _check_vector(
        "10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189",
        "977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5",
        "518e4a27949812424b2a381c3efea6055ee5e75eff",
        "0c801a037c2ed0500d6ef68e8d195eceb05a15f8edb68b35773e81ac2aca18e9be53416f9a",
    )


def test_interop_long_message() raises:
    _check_vector(
        "9498fdb922e0596e32af7f8108def2068f5a32a5ac70bd33ade371701f3d98d0",
        "a0056f24be0d20106fe750e2ee3684d4457cbdcb3a74e566",
        "b1bc9cfedb340fb06a37eba80439189e48aa0cfd37020eec0afa09165af12864671b3fbddbbb20ac18f586f2f66d13b3ca40c9a7e21c4513a5d87a95319f8ca3c2151e2a1b8b86a35653e77f90b9e63d2a84be9b9603876a89d60fd708edcd64b41be1064b8ad1046553aaeb51dc70b8112c9915d94f2a5dad1e14e7009db6c703c843a4f64b77d44b179b9579ac497dac2d33",
        "4918790d46893fa3dca74d8abc57eef7fca2c6393d1beef5efa845ac20475db38d1a068debf4c5dbd8614eb072877c565dc52bd40941f0b590d2079a5028e426bf50bcbaadcbebf278bddceedc578a5e31379523dee15026ec82d34e56f2871fdf13255db199ac48f163d5ee7e4f4e09a39451356959d9242a39aea33990ab960a4c25346e3d9397fc5e7cb6266c2476411cd331f2bcb4486750c746947ec6401865d5",
    )


def test_tamper_and_parameter_rejection() raises:
    var key = List[UInt8](length=32, fill=7)
    var nonce = List[UInt8](length=24, fill=9)
    var message: List[UInt8] = [1, 2, 3, 4, 5, 6, 7]
    var combined = encrypt(Span(message), Span(nonce), Span(key))
    combined[0] ^= 1
    with assert_raises():
        _ = decrypt(Span(combined), Span(nonce), Span(key))

    var detached = encrypt_detached(Span(message), Span(nonce), Span(key))
    var detached_body = detached[0].copy()
    var detached_tag = detached[1].copy()
    detached_body[0] ^= 1
    with assert_raises():
        _ = decrypt_detached(
            Span(detached_body), Span(detached_tag), Span(nonce), Span(key)
        )
    detached_body[0] ^= 1
    detached_tag[15] ^= 1
    with assert_raises():
        _ = decrypt_detached(
            Span(detached_body), Span(detached_tag), Span(nonce), Span(key)
        )

    var short_key = List[UInt8](length=31, fill=0)
    var short_nonce = List[UInt8](length=23, fill=0)
    var short_tag = List[UInt8](length=15, fill=0)
    with assert_raises():
        _ = encrypt(Span(message), Span(nonce), Span(short_key))
    with assert_raises():
        _ = encrypt(Span(message), Span(short_nonce), Span(key))
    with assert_raises():
        _ = decrypt_detached(
            Span(message), Span(short_tag), Span(nonce), Span(key)
        )


def test_eight_way_xchacha_secretbox_matches_independent_messages() raises:
    var key = List[UInt8](length=32, fill=0xA5)
    var nonces = List[List[UInt8]](capacity=8)
    var messages = List[List[UInt8]](capacity=8)
    for lane in range(8):
        nonces.append(List[UInt8](length=24, fill=UInt8(lane)))
        messages.append(List[UInt8](length=300, fill=UInt8(0x20 + lane)))
    var outputs = encrypt_eight(messages, nonces, Span(key))
    for lane in range(8):
        assert_equal(
            outputs[lane],
            encrypt(Span(messages[lane]), Span(nonces[lane]), Span(key)),
        )
    var recovered = decrypt_eight(outputs, nonces, Span(key))
    for lane in range(8):
        assert_equal(recovered[lane], messages[lane])
    outputs[3][0] ^= 1
    with assert_raises():
        _ = decrypt_eight(outputs, nonces, Span(key))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
