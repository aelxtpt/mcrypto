from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.modes import (
    PreparedCipher,
    process as mode_process,
    process_eight,
    process_speck_cbc_four_into,
)


def hex_bytes(text: StaticString) -> List[UInt8]:
    var b = text.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var h = Int(b[i])
        var l = Int(b[i + 1])
        h -= 48 if h <= 57 else 87
        l -= 48 if l <= 57 else 87
        o.append(UInt8(h * 16 + l))
    return o^


def test_nist_aes_modes() raises:
    var key = hex_bytes("2b7e151628aed2a6abf7158809cf4f3c")
    var iv = hex_bytes("000102030405060708090a0b0c0d0e0f")
    var p = hex_bytes("6bc1bee22e409f96e93d7e117393172a")
    var ecb = hex_bytes("3ad77bb40d7a3660a89ecaf32466ef97")
    var cbc = hex_bytes("7649abac8119b246cee98e9b12e9197d")
    var ctriv = hex_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    var ctr = hex_bytes("874d6191b620e3261bef6864990db6ce")
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.ECB,
            True,
            Span(key),
            Span(iv),
            Span(p),
        ),
        ecb,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.ECB,
            False,
            Span(key),
            Span(iv),
            Span(ecb),
        ),
        p,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC,
            True,
            Span(key),
            Span(iv),
            Span(p),
        ),
        cbc,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC,
            False,
            Span(key),
            Span(iv),
            Span(cbc),
        ),
        p,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CTR,
            True,
            Span(key),
            Span(ctriv),
            Span(p),
        ),
        ctr,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CTR,
            False,
            Span(key),
            Span(ctriv),
            Span(ctr),
        ),
        p,
    )
    var full_plaintext = hex_bytes(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
    var cfb = hex_bytes(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6"
    )
    var ofb = hex_bytes(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc"
        "304c6528f659c77866a510d9c1d6ae5e"
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CFB,
            True,
            Span(key),
            Span(iv),
            Span(full_plaintext),
        ),
        cfb,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CFB,
            False,
            Span(key),
            Span(iv),
            Span(cfb),
        ),
        full_plaintext,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.OFB,
            True,
            Span(key),
            Span(iv),
            Span(full_plaintext),
        ),
        ofb,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.OFB,
            False,
            Span(key),
            Span(iv),
            Span(ofb),
        ),
        full_plaintext,
    )
    var cts_plaintext = hex_bytes(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411"
    )
    var cts = hex_bytes(
        "7649abac8119b246cee98e9b12e9197d"
        "4931b7ebe3959b02a07245ed3eed3d3e"
        "5086cb9b507219ee"
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            True,
            Span(key),
            Span(iv),
            Span(cts_plaintext),
        ),
        cts,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            False,
            Span(key),
            Span(iv),
            Span(cts),
        ),
        cts_plaintext,
    )


def test_half_batch_cham_and_lea_roundtrips() raises:
    var key = List[UInt8](length=16, fill=0xA5)
    var message = List[UInt8](length=64, fill=0)
    for i in range(64):
        message[i] = UInt8(i)
    for algorithm, block_size in [
        (BlockCipherAlgorithm.CHAM64, 8),
        (BlockCipherAlgorithm.CHAM128, 16),
        (BlockCipherAlgorithm.LEA, 16),
    ]:
        var iv = List[UInt8](length=block_size, fill=0x5A)
        var encrypted = process(
            algorithm,
            CipherMode.ECB,
            True,
            Span(key),
            Span(iv),
            Span(message),
        )
        assert_equal(
            process(
                algorithm,
                CipherMode.ECB,
                False,
                Span(key),
                Span(iv),
                Span(encrypted),
            ),
            message,
        )
        var streamed = process(
            algorithm,
            CipherMode.CTR,
            True,
            Span(key),
            Span(iv),
            Span(message),
        )
        assert_equal(
            process(
                algorithm,
                CipherMode.CTR,
                False,
                Span(key),
                Span(iv),
                Span(streamed),
            ),
            message,
        )


def test_four_message_speck_cbc_roundtrips() raises:
    var key = List[UInt8](length=16, fill=0xA5)
    var first = List[UInt8](length=64, fill=0x11)
    var second = List[UInt8](length=64, fill=0x22)
    var third = List[UInt8](length=64, fill=0x33)
    var fourth = List[UInt8](length=64, fill=0x44)
    for cipher in [
        BlockCipherAlgorithm.SPECK64,
        BlockCipherAlgorithm.SPECK128,
    ]:
        var iv = List[UInt8](
            length=8 if cipher == BlockCipherAlgorithm.SPECK64 else 16,
            fill=0x5A,
        )
        var first_output = List[UInt8](length=64, fill=0)
        var second_output = List[UInt8](length=64, fill=0)
        var third_output = List[UInt8](length=64, fill=0)
        var fourth_output = List[UInt8](length=64, fill=0)
        process_speck_cbc_four_into(
            cipher,
            True,
            Span(key),
            Span(iv),
            Span(first),
            Span(second),
            Span(third),
            Span(fourth),
            Span(first_output),
            Span(second_output),
            Span(third_output),
            Span(fourth_output),
        )
        assert_equal(
            first_output,
            process(
                cipher,
                CipherMode.CBC,
                True,
                Span(key),
                Span(iv),
                Span(first),
            ),
        )
        assert_equal(
            second_output,
            process(
                cipher,
                CipherMode.CBC,
                True,
                Span(key),
                Span(iv),
                Span(second),
            ),
        )
        assert_equal(
            third_output,
            process(
                cipher,
                CipherMode.CBC,
                True,
                Span(key),
                Span(iv),
                Span(third),
            ),
        )
        assert_equal(
            fourth_output,
            process(
                cipher,
                CipherMode.CBC,
                True,
                Span(key),
                Span(iv),
                Span(fourth),
            ),
        )
        var first_recovered = List[UInt8](length=64, fill=0)
        var second_recovered = List[UInt8](length=64, fill=0)
        var third_recovered = List[UInt8](length=64, fill=0)
        var fourth_recovered = List[UInt8](length=64, fill=0)
        process_speck_cbc_four_into(
            cipher,
            False,
            Span(key),
            Span(iv),
            Span(first_output),
            Span(second_output),
            Span(third_output),
            Span(fourth_output),
            Span(first_recovered),
            Span(second_recovered),
            Span(third_recovered),
            Span(fourth_recovered),
        )
        assert_equal(first_recovered, first)
        assert_equal(second_recovered, second)
        assert_equal(third_recovered, third)
        assert_equal(fourth_recovered, fourth)


def test_eight_way_modes_match_independent_messages() raises:
    var key = List[UInt8](length=16, fill=0xA5)
    var base_iv = List[UInt8](length=16, fill=0)
    for mode in [
        CipherMode.ECB,
        CipherMode.CBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
    ]:
        var ivs = List[List[UInt8]](capacity=8)
        var inputs = List[List[UInt8]](capacity=8)
        for lane in range(8):
            ivs.append(base_iv.copy())
            inputs.append(List[UInt8](length=64, fill=UInt8(0x20 + lane)))
        var outputs = process_eight(
            BlockCipherAlgorithm.AES, mode, True, Span(key), ivs, inputs
        )
        for lane in range(8):
            assert_equal(
                outputs[lane],
                mode_process(
                    BlockCipherAlgorithm.AES,
                    mode,
                    True,
                    Span(key),
                    Span(ivs[lane]),
                    Span(inputs[lane]),
                ),
            )
    var short_key = List[UInt8](length=8, fill=0x5A)
    var short_iv = List[UInt8](length=8, fill=0)
    var short_ivs = List[List[UInt8]](capacity=8)
    var short_inputs = List[List[UInt8]](capacity=8)
    for lane in range(8):
        short_ivs.append(short_iv.copy())
        short_inputs.append(List[UInt8](length=64, fill=UInt8(lane)))
    var short_outputs = process_eight(
        BlockCipherAlgorithm.BLOWFISH,
        CipherMode.CTR,
        True,
        Span(short_key),
        short_ivs,
        short_inputs,
    )
    for lane in range(8):
        assert_equal(
            short_outputs[lane],
            mode_process(
                BlockCipherAlgorithm.BLOWFISH,
                CipherMode.CTR,
                True,
                Span(short_key),
                Span(short_ivs[lane]),
                Span(short_inputs[lane]),
            ),
        )
    for mode in [CipherMode.CFB, CipherMode.OFB, CipherMode.CTR]:
        var safer_outputs = process_eight(
            BlockCipherAlgorithm.SAFER,
            mode,
            True,
            Span(short_key),
            short_ivs,
            short_inputs,
        )
        for lane in range(8):
            assert_equal(
                safer_outputs[lane],
                mode_process(
                    BlockCipherAlgorithm.SAFER,
                    mode,
                    True,
                    Span(short_key),
                    Span(short_ivs[lane]),
                    Span(short_inputs[lane]),
                ),
            )
        var recovered = process_eight(
            BlockCipherAlgorithm.SAFER,
            mode,
            False,
            Span(short_key),
            short_ivs,
            safer_outputs,
        )
        for lane in range(8):
            assert_equal(recovered[lane], short_inputs[lane])


def test_prepared_cipher_reuses_key_schedule_without_state_leakage() raises:
    var key = List[UInt8](length=16, fill=0xA5)
    var iv = List[UInt8](length=16, fill=0x5A)
    var message = List[UInt8](length=48, fill=0)
    for i in range(len(message)):
        message[i] = UInt8(7 * i + 3)
    var expected = mode_process(
        BlockCipherAlgorithm.AES,
        CipherMode.CBC,
        True,
        Span(key),
        Span(iv),
        Span(message),
    )
    var encryptor = PreparedCipher(
        BlockCipherAlgorithm.AES, CipherMode.CBC, True, Span(key)
    )
    assert_equal(encryptor.process(Span(iv), Span(message)), expected)
    assert_equal(encryptor.process(Span(iv), Span(message)), expected)
    var decryptor = PreparedCipher(
        BlockCipherAlgorithm.AES, CipherMode.CBC, False, Span(key)
    )
    assert_equal(decryptor.process(Span(iv), Span(expected)), message)
    for length in [32, 37]:
        var payload = List[UInt8](capacity=length)
        for i in range(length):
            payload.append(message[i])
        var expected_cts = mode_process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            True,
            Span(key),
            Span(iv),
            Span(payload),
        )
        var cts_encryptor = PreparedCipher(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            True,
            Span(key),
        )
        assert_equal(
            cts_encryptor.process(Span(iv), Span(payload)), expected_cts
        )
        var cts_decryptor = PreparedCipher(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            False,
            Span(key),
        )
        assert_equal(
            cts_decryptor.process(Span(iv), Span(expected_cts)), payload
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
