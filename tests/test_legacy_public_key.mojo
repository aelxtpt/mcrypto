from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from mcrypto.public_key.rabin import (
    signature_keypair as rabin_keypair,
    sign as rabin_sign,
    verify as rabin_verify,
)
from mcrypto.public_key.luc import (
    LUCELGEncryptor,
    LUCELGDecryptor,
    keypair as luc_keypair,
    apply as luc_apply,
    invert as luc_invert,
    lucas,
    lucelg_keypair,
    lucelg_encrypt,
    lucelg_decrypt,
)
from mcrypto.public_key.esign import (
    keypair as esign_keypair,
    sign as esign_sign,
    verify as esign_verify,
    PreparedESIGNSigner,
    PreparedESIGNVerifier,
)
from mcrypto.public_key.dlies import (
    keypair as dlies_keypair,
    encrypt as dlies_encrypt,
    decrypt as dlies_decrypt,
    PreparedDLIESEncryptor,
    PreparedDLIESDecryptor,
)
from mcrypto.public_key._legacy_math import (
    encode_key,
    uint_to_bytes,
    uint_from_bytes,
)
from mcrypto.math.biguint import BigUInt


def bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def hex_bytes(text: StaticString) -> List[UInt8]:
    var encoded = text.as_bytes()
    var output = List[UInt8](capacity=len(encoded) // 2)
    for i in range(0, len(encoded), 2):
        var high = Int(encoded[i])
        var low = Int(encoded[i + 1])
        high = high - 48 if high <= 57 else high - 87
        low = low - 48 if low <= 57 else low - 87
        output.append(UInt8(high * 16 + low))
    return output^


def test_luc_known_sequence_and_roundtrip() raises:
    # V_0=2,V_1=P,V_n=P*V_(n-1)-V_(n-2); V_7(3)=843.
    assert_equal(lucas(BigUInt(7), BigUInt(3), BigUInt(1009)).to_hex(), "34b")
    var keys = luc_keypair(128)
    var value = uint_to_bytes(BigUInt(42))
    var image = luc_apply(Span(keys[0]), Span(value))
    var recovered = luc_invert(Span(keys[1]), Span(image))
    assert_equal(uint_from_bytes(Span(recovered)).to_hex(), "2a")


def test_reference_rabin_williams_emsa2_vector() raises:
    # First 1024-bit Rabin-Williams/EMSA2(SHA-1) vector.
    var modulus = hex_bytes(
        "e5eb47bc1f82db3001faaeabc5bbe71b7d307b431889ac10255262281ec5f5af"
        "8a790bd7bbec5efffa442cf2c3fd5ca4778763b9d15aeac0b9b71bdb13da8272"
        "7f4967ac685975f8ff05a763c864d100b7cc1142102aa2dd343ea1a0ab530255"
        "195c3a6400ecab7b27eff9b01ef6d37381fa6fb5401347f195354396772e8285"
    )
    var magic: List[UInt8] = [82, 87, 86, 49]
    var public_key = encode_key(Span(magic), [uint_from_bytes(Span(modulus))])
    var message = hex_bytes("2ca039854b55688740e3")
    var signature = hex_bytes(
        "1af029cbec9c692ce5096e73e4e9a52ec9a28d207a5511ccec7681e5e3d867a4"
        "ae2e22de4909d89196a272f1b50de6fa3248bca334d46e0d57171a790b6f4697"
        "e7ba7047db79decd47bd21995243debbf25915ddbc93c45875c14de953792257c"
        "5c6825c905aff40109c8cc7e793123d47ac1b5b6304a436cfa9beec8e0054e7"
    )
    assert_true(rabin_verify(Span(public_key), Span(message), Span(signature)))
    message[0] ^= 1
    assert_false(rabin_verify(Span(public_key), Span(message), Span(signature)))
    var out_of_domain = List[UInt8](length=len(signature), fill=0xFF)
    assert_false(
        rabin_verify(Span(public_key), Span(message), Span(out_of_domain))
    )
    assert_false(
        rabin_verify(
            Span(public_key), Span(message), signature[0 : len(signature) - 1]
        )
    )


def test_rabin_sign_verify_tamper() raises:
    var keys = rabin_keypair(384)
    var message = bytes("Rabin-Williams")
    var signature = rabin_sign(Span(keys[1]), Span(message))
    assert_true(rabin_verify(Span(keys[0]), Span(message), Span(signature)))
    message[0] ^= 1
    assert_false(rabin_verify(Span(keys[0]), Span(message), Span(signature)))
    signature[0] ^= 1
    assert_false(rabin_verify(Span(keys[0]), Span(message), Span(signature)))


def test_ntt_esign_emsa5_vector() raises:
    # NTT ESIGN EMSA5 vector 1.
    var modulus = hex_bytes(
        "c5d0b8fac0cc6acc9d52c61200b541f7b4f8ff9f1bda97e0ebf78a3df768ba7"
        "0ade59306d6ae65655bff7c6a94518c91e43dc0003b6f8730acc244799bdacb1"
        "e5070c6ea3089ea83bd5ef0a533adf3d9d63c0e88ce74545cfb21213fc33813f"
        "d913c6a6cf84b5adabc7d74751e9945521ac76a790bba95ad48d9d3fb2fbc4b0"
        "ed2ddee7d5ea6aa61633eccdac6381fab"
    )
    var exponent = hex_bytes("0400")
    var magic: List[UInt8] = [69, 83, 71, 49]
    var public_key = encode_key(
        Span(magic),
        [uint_from_bytes(Span(modulus)), uint_from_bytes(Span(exponent))],
    )
    var message = hex_bytes("86f28c1cb5e640548309b85dc6e64c1a")
    var signature = hex_bytes(
        "348dc9a0943b1e2ba7ef501cbe970a023b37ca4019b9a5cb35ffc3bcdb28dcbd"
        "4193d7817d418bbaf291d97a1eeb918a03ee65caa7ad26c24f9ef807c8798ade"
        "5b70d7328cd36ac0844bf63f511bb63067e8236d084cf8af68e88155ea94b978"
        "aab6bd0339c55d976434423fc779d549779e81f528d028c7343e060544410e528"
        "814fb0874417d1eedf38d6db4b97dd6"
    )
    assert_true(esign_verify(Span(public_key), Span(message), Span(signature)))
    signature[0] ^= 1
    assert_false(esign_verify(Span(public_key), Span(message), Span(signature)))


def test_esign_roundtrip_tamper() raises:
    var keys = esign_keypair(384)
    var message = bytes("ESIGN EMSA5")
    var signature = esign_sign(Span(keys[1]), Span(message))
    assert_true(esign_verify(Span(keys[0]), Span(message), Span(signature)))
    var signer = PreparedESIGNSigner(Span(keys[1]))
    var prepared_signature = signer.sign(Span(message))
    var verifier = PreparedESIGNVerifier(Span(keys[0]))
    assert_true(verifier.verify(Span(message), Span(prepared_signature)))
    var batch = signer.sign_repeated(Span(message), 4)
    assert_equal(len(batch), 4)
    for batched_signature in batch:
        assert_true(verifier.verify(Span(message), Span(batched_signature)))
    message[1] ^= 1
    assert_false(esign_verify(Span(keys[0]), Span(message), Span(signature)))


def test_reference_dlies_sha1_decrypt_vector() raises:
    # First default DLIES decryption vector.
    var p = hex_bytes(
        "ba3ed94110332be99b77a345da72a33146ca960498a6fc2e0e207fdeaadf69c3"
        "e5650df73255475854900b75af7f6aac021de687a1c166ecb2ab6ec6b9da82ad"
        "4fb0f48a966a2b968406e18ba50947d7ee3bb1f13511cb4dde191f0ade1933d0"
        "89c5e82ab8d283943d85ef0102e173abf2635aeac2f84cfc9ec6c4e8f3fbc413"
    )
    var q = hex_bytes(
        "5d1f6ca0881995f4cdbbd1a2ed395198a3654b024c537e1707103fef556fb4e1"
        "f2b286fb992aa3ac2a4805bad7bfb556010ef343d0e0b3765955b7635ced4156"
        "a7d87a454b3515cb420370c5d284a3ebf71dd8f89a88e5a6ef0c8f856f0c99e"
        "844e2f4155c6941ca1ec2f7808170b9d5f931ad75617c267e4f63627479fde209"
    )
    var g = hex_bytes("03")
    var private = hex_bytes("01fdc788cd93f07dba3af2de42ae5aa3ede219919d")
    var magic: List[UInt8] = [68, 76, 83, 49]
    var private_key = encode_key(
        Span(magic),
        [
            uint_from_bytes(Span(p)),
            uint_from_bytes(Span(q)),
            uint_from_bytes(Span(g)),
            uint_from_bytes(Span(private)),
        ],
    )
    var ciphertext = hex_bytes(
        "b11d906cc5a8e71ca8962a8cc0ac4caff2da00dc130c370f42d11fcf5c37de04"
        "6ebc07c7d457ca351ce456a043695d14ed055adad2b58be0df992685ef8b0d215"
        "97a43d7b3d9634a077cb70c4590cd73c20faaacbc5649413eeca0c7b3cbf469e"
        "531299398f61496c51fe9ffe48ae9fe6034f104efc562de9529c776b86add4025"
        "ad6b0c3687b012f92c7b9e82f794e4fbe247d644"
    )
    assert_equal(
        dlies_decrypt(Span(private_key), Span(ciphertext)),
        hex_bytes("76"),
    )
    ciphertext[len(ciphertext) - 1] ^= 1
    with assert_raises():
        _ = dlies_decrypt(Span(private_key), Span(ciphertext))


def test_dlies_roundtrip_and_authentication() raises:
    var keys = dlies_keypair(128)
    var message = bytes("finite-field integrated encryption")
    var label = bytes("context")
    var ciphertext = dlies_encrypt(Span(keys[0]), Span(message), Span(label))
    var plaintext = dlies_decrypt(Span(keys[1]), Span(ciphertext), Span(label))
    assert_equal(plaintext, message)
    var encryptor = PreparedDLIESEncryptor(Span(keys[0]))
    var prepared_ciphertext = encryptor.encrypt(Span(message), Span(label))
    var decryptor = PreparedDLIESDecryptor(Span(keys[1]))
    assert_equal(
        decryptor.decrypt(Span(prepared_ciphertext), Span(label)), message
    )
    ciphertext[len(ciphertext) - 1] ^= 1
    with assert_raises():
        _ = dlies_decrypt(Span(keys[1]), Span(ciphertext), Span(label))


def test_reference_luc_ies_sha1_decrypt_vector() raises:
    # Generated from the canonical lucd512 domain parameters; decrypts under the
    # DHAES/KDF2/HMAC-SHA1 LUC-IES defaults.
    var p = hex_bytes(
        "c339d027e5812ed5d9de044f3697d0273625e5ea9ec4ef3fb89adbfa9cd1fbf"
        "4d8c0ec1118c44609f499ef644eeaece2f38b3f67fac81a075f31a60b5757a87d"
    )
    var q = hex_bytes(
        "619ce813f2c0976aecef02279b4be8139b12f2f54f62779fdc4d6dfd4e68fdfa"
        "6c6076088c622304fa4cf7b22775767179c59fb3fd640d03af98d305ababd43f"
    )
    var magic: List[UInt8] = [76, 85, 88, 49]
    var private_key = encode_key(
        Span(magic),
        [
            uint_from_bytes(Span(p)),
            uint_from_bytes(Span(q)),
            BigUInt(9),
            BigUInt(5),
        ],
    )
    var ciphertext = hex_bytes(
        "0778454f3b8c33d28631e782c6b09b7f3ec74bda225ee27d9674fa5d5ef629bd"
        "7047516742efb2ae700e5bf462333cfcfd64b993ce22255db207701dccc5fc9e"
        "ef800daa12f45516f578f68b1e940c1d189b023d0a1a08ef2c18add2781a78d5"
        "fdaa"
    )
    assert_equal(
        lucelg_decrypt(Span(private_key), Span(ciphertext)),
        bytes("LUC-IES vector"),
    )
    ciphertext[len(ciphertext) - 1] ^= 1
    with assert_raises():
        _ = lucelg_decrypt(Span(private_key), Span(ciphertext))


def test_lucelg_roundtrip_and_authentication() raises:
    var keys = lucelg_keypair(128)
    var message = bytes("LUCELG")
    var ciphertext = lucelg_encrypt(Span(keys[0]), Span(message))
    var plaintext = lucelg_decrypt(Span(keys[1]), Span(ciphertext))
    assert_equal(plaintext, message)
    var label = List[UInt8]()
    var encryptor = LUCELGEncryptor(Span(keys[0]))
    var decryptor = LUCELGDecryptor(Span(keys[1]))
    var prepared_ciphertext = encryptor.encrypt(Span(message), Span(label))
    assert_equal(
        decryptor.decrypt(Span(prepared_ciphertext), Span(label)), message
    )
    ciphertext[len(ciphertext) - 1] ^= 1
    with assert_raises():
        _ = lucelg_decrypt(Span(keys[1]), Span(ciphertext))


def test_malformed_keys_raise() raises:
    var bad: List[UInt8] = [1, 2, 3]
    var message: List[UInt8] = [4]
    var signature: List[UInt8] = [5]
    with assert_raises():
        _ = dlies_encrypt(Span(bad), Span(message))
    with assert_raises():
        _ = rabin_verify(Span(bad), Span(message), Span(signature))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
