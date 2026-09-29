from std.testing import assert_equal, TestSuite
from mcrypto.ipcrypt.algorithm import IpcryptAlgorithm
from mcrypto.ipcrypt.dispatch import ipcrypt, ipcrypt_eight


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var o = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else 87
        c -= 48 if c <= 57 else 87
        o.append(UInt8(a * 16 + c))
    return o^


def test_official_vectors_and_roundtrips() raises:
    var empty = List[UInt8]()
    var input = h("00000000000000000000ffff00000000")
    var key = h("0123456789abcdeffedcba9876543210")
    var deterministic = ipcrypt(
        IpcryptAlgorithm.IPCRYPT,
        False,
        Span(key),
        Span(empty),
        Span(input),
    )
    assert_equal(deterministic, h("bde96789d353824cd7c6f58a6bd226eb"))
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.IPCRYPT,
            True,
            Span(key),
            Span(empty),
            Span(deterministic),
        ),
        input,
    )
    var tweak = h("08e0c289bff23b7c")
    var nd = ipcrypt(
        IpcryptAlgorithm.ND,
        False,
        Span(key),
        Span(tweak),
        Span(input),
    )
    assert_equal(nd, h("08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"))
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.ND,
            True,
            Span(key),
            Span(empty),
            Span(nd),
        ),
        input,
    )
    var key2 = h(
        "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
    )
    var tweak2 = h("21bd1834bc088cd2b4ecbe30b70898d7")
    var ndx = ipcrypt(
        IpcryptAlgorithm.NDX,
        False,
        Span(key2),
        Span(tweak2),
        Span(input),
    )
    assert_equal(
        ndx,
        h("21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5"),
    )
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.NDX,
            True,
            Span(key2),
            Span(empty),
            Span(ndx),
        ),
        input,
    )
    var pfx = ipcrypt(
        IpcryptAlgorithm.PFX,
        False,
        Span(key2),
        Span(empty),
        Span(input),
    )
    assert_equal(pfx, h("00000000000000000000ffff97529b86"))
    assert_equal(
        ipcrypt(
            IpcryptAlgorithm.PFX,
            True,
            Span(key2),
            Span(empty),
            Span(pfx),
        ),
        input,
    )


def check_eight_way(
    algorithm: IpcryptAlgorithm,
    key: List[UInt8],
    tweak: List[UInt8],
    input: List[UInt8],
) raises:
    var expected = ipcrypt(
        algorithm, False, Span(key), Span(tweak), Span(input)
    )
    var tweaks = List[List[UInt8]](capacity=8)
    var inputs = List[List[UInt8]](capacity=8)
    for _ in range(8):
        tweaks.append(tweak.copy())
        inputs.append(input.copy())
    var encrypted = ipcrypt_eight(algorithm, False, Span(key), tweaks, inputs)
    assert_equal(len(encrypted), 8)
    for output in encrypted:
        assert_equal(output, expected)
    var empty = List[UInt8]()
    var empty_tweaks = List[List[UInt8]](capacity=8)
    var ciphertexts = List[List[UInt8]](capacity=8)
    for _ in range(8):
        empty_tweaks.append(empty.copy())
        ciphertexts.append(expected.copy())
    var decrypted = ipcrypt_eight(
        algorithm, True, Span(key), empty_tweaks, ciphertexts
    )
    for output in decrypted:
        assert_equal(output, input)


def test_eight_way_matches_scalar() raises:
    var input = h("00000000000000000000ffff00000000")
    var key = h("0123456789abcdeffedcba9876543210")
    var key2 = h(
        "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
    )
    var empty = List[UInt8]()
    check_eight_way(IpcryptAlgorithm.IPCRYPT, key, empty, input)
    check_eight_way(IpcryptAlgorithm.ND, key, h("08e0c289bff23b7c"), input)
    check_eight_way(
        IpcryptAlgorithm.NDX,
        key2,
        h("21bd1834bc088cd2b4ecbe30b70898d7"),
        input,
    )
    check_eight_way(IpcryptAlgorithm.PFX, key2, empty, input)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
