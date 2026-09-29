from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode
from mcrypto.ciphers.modes import PreparedCipher, process, process_eight


def test_prepared_modes_match_scalar_at_boundaries() raises:
    var key = List[UInt8](length=16, fill=0xA5)
    var iv = List[UInt8](length=16, fill=0x5A)
    for mode in [
        CipherMode.CBC,
        CipherMode.CFB,
        CipherMode.OFB,
        CipherMode.CTR,
    ]:
        var encryptor = PreparedCipher(
            BlockCipherAlgorithm.AES, mode, True, Span(key)
        )
        var decryptor = PreparedCipher(
            BlockCipherAlgorithm.AES, mode, False, Span(key)
        )
        for size in [15, 16, 17, 31, 32, 33, 47, 48, 49]:
            if mode == CipherMode.CBC and size % 16 != 0:
                continue
            var message = List[UInt8](length=size, fill=UInt8(size))
            var expected = process(
                BlockCipherAlgorithm.AES,
                mode,
                True,
                Span(key),
                Span(iv),
                Span(message),
            )
            assert_equal(encryptor.process(Span(iv), Span(message)), expected)
            assert_equal(decryptor.process(Span(iv), Span(expected)), message)
    for size in [17, 31, 32, 33, 47, 48, 49]:
        var message = List[UInt8](length=size, fill=UInt8(size))
        var expected = process(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            True,
            Span(key),
            Span(iv),
            Span(message),
        )
        var encryptor = PreparedCipher(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            True,
            Span(key),
        )
        var decryptor = PreparedCipher(
            BlockCipherAlgorithm.AES,
            CipherMode.CBC_CTS,
            False,
            Span(key),
        )
        assert_equal(encryptor.process(Span(iv), Span(message)), expected)
        assert_equal(decryptor.process(Span(iv), Span(expected)), message)


def test_mode_eight_way_dimensions_and_scalar_equivalence() raises:
    var key = List[UInt8](length=16, fill=7)
    var ivs = List[List[UInt8]](capacity=8)
    var inputs = List[List[UInt8]](capacity=8)
    for lane in range(8):
        ivs.append(List[UInt8](length=16, fill=UInt8(lane)))
        inputs.append(List[UInt8](length=65, fill=UInt8(0x20 + lane)))
    var outputs = process_eight(
        BlockCipherAlgorithm.AES,
        CipherMode.CTR,
        True,
        Span(key),
        ivs,
        inputs,
    )
    for lane in range(8):
        assert_equal(
            outputs[lane],
            process(
                BlockCipherAlgorithm.AES,
                CipherMode.CTR,
                True,
                Span(key),
                Span(ivs[lane]),
                Span(inputs[lane]),
            ),
        )
    var seven_ivs = List[List[UInt8]](capacity=7)
    var seven_inputs = List[List[UInt8]](capacity=7)
    for lane in range(7):
        seven_ivs.append(ivs[lane].copy())
        seven_inputs.append(inputs[lane].copy())
    with assert_raises():
        _ = process_eight(
            BlockCipherAlgorithm.AES,
            CipherMode.CTR,
            True,
            Span(key),
            seven_ivs,
            seven_inputs,
        )
    ivs.append(List[UInt8](length=16, fill=9))
    inputs.append(List[UInt8](length=65, fill=9))
    with assert_raises():
        _ = process_eight(
            BlockCipherAlgorithm.AES,
            CipherMode.CTR,
            True,
            Span(key),
            ivs,
            inputs,
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
