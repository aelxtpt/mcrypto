from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.simeck import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm


def h(text: StaticString) -> List[UInt8]:
    var b = text.as_bytes()
    var output = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var high = Int(b[i])
        var low = Int(b[i + 1])
        high -= 48 if high <= 57 else 87
        low -= 48 if low <= 57 else 87
        output.append(UInt8(high * 16 + low))
    return output^


def test_simeck_official_vectors() raises:
    var key32 = h("1918111009080100")
    var plain32 = h("65656877")
    var cipher32 = h("770d2c76")
    assert_equal(
        process(
            BlockCipherAlgorithm.SIMECK32,
            False,
            Span(key32),
            Span(plain32),
        ),
        cipher32,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.SIMECK32,
            True,
            Span(key32),
            Span(cipher32),
        ),
        plain32,
    )
    var key64 = h("1b1a1918131211100b0a090803020100")
    var plain64 = h("656b696c20646e75")
    var cipher64 = h("45ce69025f7ab7ed")
    assert_equal(
        process(
            BlockCipherAlgorithm.SIMECK64,
            False,
            Span(key64),
            Span(plain64),
        ),
        cipher64,
    )
    assert_equal(
        process(
            BlockCipherAlgorithm.SIMECK64,
            True,
            Span(key64),
            Span(cipher64),
        ),
        plain64,
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
