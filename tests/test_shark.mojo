from std.testing import assert_equal, TestSuite
from mcrypto.ciphers.shark import process


def h(t: StaticString) -> List[UInt8]:
    var b = t.as_bytes()
    var output = List[UInt8](capacity=len(b) // 2)
    for i in range(0, len(b), 2):
        var a = Int(b[i])
        var c = Int(b[i + 1])
        a -= 48 if a <= 57 else (87 if a >= 97 else 55)
        c -= 48 if c <= 57 else (87 if c >= 97 else 55)
        output.append(UInt8(a * 16 + c))
    return output^


def test_shark_vectors() raises:
    var keys = [
        h("00000000000000000000000000000000"),
        h("000102030405060708090A0B0C0D0E0F"),
        h("000102030405060708090A0B0C0D0E0F"),
        h("915F4619BE41B2516355A50110A9CE91"),
        h("783348E75AEB0F2FD7B169BB8DC16787"),
        h("DC49DB1375A5584F6485B413B5F12BAF"),
        h("5269F149D41BA0152497574D7F153125"),
    ]
    var plains = [
        h("0000000000000000"),
        h("0000000000000000"),
        h("C76C696289898137"),
        h("21A5DBEE154B8F6D"),
        h("F7C013AC5B2B8952"),
        h("2F42B3B70369FC92"),
        h("65C178B284D197CC"),
    ]
    var ciphers = [
        h("214BCF4E7716420A"),
        h("C76C696289898137"),
        h("077A4A59FAEEEA4D"),
        h("6FF33B98F448E95A"),
        h("E5E554ABE9CED2D2"),
        h("9AE068313F343A7A"),
        h("D3F111A282F17F29"),
    ]
    for i in range(7):
        assert_equal(process(False, Span(keys[i]), Span(plains[i])), ciphers[i])
        assert_equal(process(True, Span(keys[i]), Span(ciphers[i])), plains[i])


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
