from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.kdf.hkdf import derive, extract, expand


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


def test_rfc5869_sha256() raises:
    var secret = List[UInt8](length=22, fill=0x0B)
    var salt = hex_bytes("000102030405060708090a0b0c")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    assert_equal(
        derive(
            HashAlgorithm.SHA256,
            Span(salt),
            Span(secret),
            Span(info),
            42,
        ),
        hex_bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ),
    )


def test_reference_sha512() raises:
    var secret = List[UInt8](length=22, fill=0x0B)
    var salt = hex_bytes("000102030405060708090a0b0c")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    assert_equal(
        derive(
            HashAlgorithm.SHA512,
            Span(salt),
            Span(secret),
            Span(info),
            42,
        ),
        hex_bytes(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
        ),
    )


def test_stages_sha256_rfc_case1() raises:
    # RFC 5869 construction; independent Python hashlib/hmac reference.
    var salt = hex_bytes("000102030405060708090a0b0c")
    var ikm = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    var expected_prk = hex_bytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    var expected = hex_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    var prk = extract(HashAlgorithm.SHA256, Span(salt), Span(ikm))
    assert_equal(prk, expected_prk)
    assert_equal(
        expand(HashAlgorithm.SHA256, Span(prk), Span(info), 42), expected
    )
    assert_equal(
        derive(HashAlgorithm.SHA256, Span(salt), Span(ikm), Span(info), 42),
        expected,
    )


def test_stages_sha256_empty_salt() raises:
    # RFC 5869 construction; independent Python hashlib/hmac reference.
    var salt = hex_bytes("")
    var ikm = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var info = hex_bytes("")
    var expected_prk = hex_bytes(
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    )
    var expected = hex_bytes(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8b2fb61057244b36c6ddd287f634795e7d80d5fe26bfc36def6dc129c29271a0eb7ab14bd2ca88259"
    )
    var prk = extract(HashAlgorithm.SHA256, Span(salt), Span(ikm))
    assert_equal(prk, expected_prk)
    assert_equal(
        expand(HashAlgorithm.SHA256, Span(prk), Span(info), 82), expected
    )
    assert_equal(
        derive(HashAlgorithm.SHA256, Span(salt), Span(ikm), Span(info), 82),
        expected,
    )


def test_stages_sha256_long_inputs() raises:
    # RFC 5869 construction; independent Python hashlib/hmac reference.
    var salt = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    var ikm = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    var info = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    var expected_prk = hex_bytes(
        "1e87ab241b012d6938a2bac15ccc79947d8d95384a9ef2513a04f4e59a9e4595"
    )
    var expected = hex_bytes(
        "75d0be68a614792d6ddb13e9d903cde4171a239005ebff793e8f269c1895436c2cd1e4ce2e345c46ad6e20af6a208daf628e441abe40a1a3f0c9517b62612724f4fd5bb6983be08cf79e9d8645e459d9bc4921c5adc0afa6a7196700676d49d39506b310fa7d40240c884f041afcc641aedb0cdc609222b7616b1b5ef9f0acf543"
    )
    var prk = extract(HashAlgorithm.SHA256, Span(salt), Span(ikm))
    assert_equal(prk, expected_prk)
    assert_equal(
        expand(HashAlgorithm.SHA256, Span(prk), Span(info), 129), expected
    )
    assert_equal(
        derive(HashAlgorithm.SHA256, Span(salt), Span(ikm), Span(info), 129),
        expected,
    )


def test_stages_sha512_rfc_case1() raises:
    # RFC 5869 construction; independent Python hashlib/hmac reference.
    var salt = hex_bytes("000102030405060708090a0b0c")
    var ikm = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var info = hex_bytes("f0f1f2f3f4f5f6f7f8f9")
    var expected_prk = hex_bytes(
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237"
    )
    var expected = hex_bytes(
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
    )
    var prk = extract(HashAlgorithm.SHA512, Span(salt), Span(ikm))
    assert_equal(prk, expected_prk)
    assert_equal(
        expand(HashAlgorithm.SHA512, Span(prk), Span(info), 42), expected
    )
    assert_equal(
        derive(HashAlgorithm.SHA512, Span(salt), Span(ikm), Span(info), 42),
        expected,
    )


def test_stages_sha512_empty_salt() raises:
    # RFC 5869 construction; independent Python hashlib/hmac reference.
    var salt = hex_bytes("")
    var ikm = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var info = hex_bytes("")
    var expected_prk = hex_bytes(
        "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6"
    )
    var expected = hex_bytes(
        "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bacc4e7cb6045faaa698e0e3b3eb91331306def1db8319e8a699b5ee45ab993847dc4df75bde023692c"
    )
    var prk = extract(HashAlgorithm.SHA512, Span(salt), Span(ikm))
    assert_equal(prk, expected_prk)
    assert_equal(
        expand(HashAlgorithm.SHA512, Span(prk), Span(info), 82), expected
    )
    assert_equal(
        derive(HashAlgorithm.SHA512, Span(salt), Span(ikm), Span(info), 82),
        expected,
    )


def test_stages_sha512_long_inputs() raises:
    # RFC 5869 construction; independent Python hashlib/hmac reference.
    var salt = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    var ikm = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    var info = hex_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    )
    var expected_prk = hex_bytes(
        "2cfa9cc6e68fc1ac4837a839b16e8b2a4ed3abbae15047960f7c9d4e30b246d054fb8dca2b92de2a74d7b667052dc84e55a97819dcdcf37cc36784f073f4fb6c"
    )
    var expected = hex_bytes(
        "1614475406a59fc783d87c09ecd401382a40b5a0ac8b4dd8ccf5b39cb9cd6b1d988505e9d68f77385fc5f596e4363608bb3916994923e1a2b7e56a6e703347f2a3e11efeb49a23e8b859248499bae93c9c1dbfe374c5eff89fcea35e8352923f929008b12a0f63154e81f9ee2cc1f9328640bcbcc19a646e19a0646a26efe28dfb"
    )
    var prk = extract(HashAlgorithm.SHA512, Span(salt), Span(ikm))
    assert_equal(prk, expected_prk)
    assert_equal(
        expand(HashAlgorithm.SHA512, Span(prk), Span(info), 129), expected
    )
    assert_equal(
        derive(HashAlgorithm.SHA512, Span(salt), Span(ikm), Span(info), 129),
        expected,
    )


def test_stage_boundaries_and_validation() raises:
    var empty = List[UInt8]()
    var other_empty = List[UInt8]()
    for algorithm, digest_bytes in [
        (HashAlgorithm.SHA256, 32),
        (HashAlgorithm.SHA512, 64),
    ]:
        var key = List[UInt8](length=digest_bytes, fill=0)
        assert_equal(expand(algorithm, Span(key), Span(empty), 0), empty)
        assert_equal(
            len(expand(algorithm, Span(key), Span(empty), 255 * digest_bytes)),
            255 * digest_bytes,
        )
        with assert_raises():
            _ = expand(
                algorithm, Span(key), Span(empty), 255 * digest_bytes + 1
            )
        with assert_raises():
            _ = expand(algorithm, Span(key), Span(empty), -1)
        with assert_raises():
            _ = expand(
                algorithm, Span(key)[0 : digest_bytes - 1], Span(empty), 0
            )
        with assert_raises():
            _ = derive(algorithm, Span(other_empty), Span(key), Span(empty), 0)
    with assert_raises():
        _ = extract(HashAlgorithm.SHA1, Span(other_empty), Span(empty))
    with assert_raises():
        _ = expand(HashAlgorithm.SHA1, Span(other_empty), Span(empty), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
