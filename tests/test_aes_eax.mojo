from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.aead.aes_eax import encrypt, decrypt


@always_inline("nodebug")
def _nibble(value: UInt8) -> UInt8:
    if value <= 57:
        return value - 48
    if value <= 70:
        return value - 55
    return value - 87


def hex_bytes(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        output.append((_nibble(bytes[i]) << 4) | _nibble(bytes[i + 1]))
    return output^


def _check(
    plaintext_hex: StaticString,
    key_hex: StaticString,
    nonce_hex: StaticString,
    header_hex: StaticString,
    combined_hex: StaticString,
) raises:
    var plaintext = hex_bytes(plaintext_hex)
    var key = hex_bytes(key_hex)
    var nonce = hex_bytes(nonce_hex)
    var header = hex_bytes(header_hex)
    var combined = hex_bytes(combined_hex)
    var expected_ciphertext = List[UInt8](capacity=len(plaintext))
    var expected_tag = List[UInt8](capacity=16)
    for i in range(len(plaintext)):
        expected_ciphertext.append(combined[i])
    for i in range(16):
        expected_tag.append(combined[len(plaintext) + i])
    var sealed = encrypt(Span(key), Span(nonce), Span(header), Span(plaintext))
    assert_equal(sealed[0], expected_ciphertext)
    assert_equal(sealed[1], expected_tag)
    assert_equal(
        decrypt(
            Span(key),
            Span(nonce),
            Span(header),
            Span(expected_ciphertext),
            Span(expected_tag),
        ),
        plaintext,
    )


def test_eax_reference_vectors() raises:
    # Embedded EAX paper vectors.
    _check(
        "",
        "233952DEE4D5ED5F9B9C6D6FF80FF478",
        "62EC67F9C3A4A407FCB2A8C49031A8B3",
        "6BFB914FD07EAE6B",
        "E037830E8389F27B025A2D6527E79D01",
    )
    _check(
        "F7FB",
        "91945D3F4DCBEE0BF45EF52255F095A4",
        "BECAF043B0A23D843194BA972C66DEBD",
        "FA3BFD4806EB53FA",
        "19DD5C4C9331049D0BDAB0277408F67967E5",
    )
    _check(
        "1A47CB4933",
        "01F74AD64077F2E704C0F60ADA3DD523",
        "70C3DB4F0D26368400A10ED05D2BFF5E",
        "234A3463C1264AC6",
        "D851D5BAE03A59F238A23E39199DC9266626C40F80",
    )
    _check(
        "481C9E39B1",
        "D07CF6CBB7F313BDDE66B727AFD3C5E8",
        "8408DFFF3C1A2B1292DC199E46B7D617",
        "33CCE2EABFF5A79D",
        "632A9D131AD4C168A4225D8E1FF755939974A7BEDE",
    )
    _check(
        "40D0C07DA5E4",
        "35B6D0580005BBC12B0587124557D2C2",
        "FDB6B06676EEDC5C61D74276E1F8E816",
        "AEB96EAEBE2970E9",
        "071DFE16C675CB0677E536F73AFE6A14B74EE49844DD",
    )
    _check(
        "4DE3B35C3FC039245BD1FB7D",
        "BD8E6E11475E60B268784C38C62FEB22",
        "6EAC5C93072D8E8513F750935E46DA1B",
        "D4482D1CA78DCE0F",
        "835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F",
    )
    _check(
        "8B0A79306C9CE7ED99DAE4F87F8DD61636",
        "7C77D6E813BED5AC98BAA417477A2E7D",
        "1A8C98DCD73D38393B2BF1569DEEFC19",
        "65D2017990D62528",
        "02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2",
    )
    _check(
        "1BDA122BCE8A8DBAF1877D962B8592DD2D56",
        "5FFF20CAFAB119CA2FC73549E20F5B0D",
        "DDE59B97D722156D4D9AFF2BC7559826",
        "54B9F04E6A09189A",
        "2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A",
    )
    _check(
        "6CF36720872B8513F6EAB1A8A44438D5EF11",
        "A4A4782BCFFD3EC5E7EF6D8C34A56123",
        "B781FCF2F75FA5A8DE97A9CA48E522EC",
        "899A175897561D7E",
        "0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700",
    )
    _check(
        "CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7",
        "8395FCF1E95BEBD697BD010BC766AAC3",
        "22E7ADD93CFC6393C57EC0B3C17D6B44",
        "126735FCC320D25A",
        "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E",
    )


def _check_key_size(key_hex: StaticString) raises:
    var key = hex_bytes(key_hex)
    var nonce = hex_bytes("00112233445566778899AABBCCDDEEFF")
    var aad = hex_bytes("A0A1A2A3A4A5")
    var message = hex_bytes("0001020304050607080910111213141516171819")
    var full = encrypt(Span(key), Span(nonce), Span(aad), Span(message))
    var short = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 8)
    assert_equal(short[0], full[0])
    for i in range(8):
        assert_equal(short[1][i], full[1][i])
    var short_ciphertext = short[0].copy()
    var short_tag = short[1].copy()
    assert_equal(
        decrypt(
            Span(key),
            Span(nonce),
            Span(aad),
            Span(short_ciphertext),
            Span(short_tag),
        ),
        message,
    )


def test_key_sizes_and_truncated_tags() raises:
    _check_key_size("000102030405060708090A0B0C0D0E0F")
    _check_key_size("000102030405060708090A0B0C0D0E0F1011121314151617")
    _check_key_size(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    )


def test_tamper_and_invalid_parameters() raises:
    var key = hex_bytes("8395FCF1E95BEBD697BD010BC766AAC3")
    var nonce = hex_bytes("22E7ADD93CFC6393C57EC0B3C17D6B44")
    var aad = hex_bytes("126735FCC320D25A")
    var message = hex_bytes("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7")
    var sealed = encrypt(Span(key), Span(nonce), Span(aad), Span(message))
    var ciphertext = sealed[0].copy()
    var tag = sealed[1].copy()
    ciphertext[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    ciphertext[0] ^= 1
    tag[0] ^= 1
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(tag)
        )
    var empty_tag = List[UInt8]()
    with assert_raises():
        _ = decrypt(
            Span(key), Span(nonce), Span(aad), Span(ciphertext), Span(empty_tag)
        )
    with assert_raises():
        _ = encrypt(Span(key), Span(nonce), Span(aad), Span(message), 17)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
