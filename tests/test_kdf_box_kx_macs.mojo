from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.hashes.algorithm import HashAlgorithm
from mcrypto.public_key.box import (
    decrypt as box_decrypt,
    encrypt as box_encrypt,
    keypair as box_keypair,
)
from mcrypto.kdf.blake2b import derive as kdf
from mcrypto.kdf.hkdf import derive as hkdf
from mcrypto.key_exchange.kx import (
    keypair as kx_keypair,
    session_keys as kx_session,
)
from mcrypto.macs.poly1305 import authenticate as poly1305
from mcrypto.macs.siphash import hash as shorthash
from mcrypto.macs.algorithm import SipHashAlgorithm


def _hex(text: StaticString) -> List[UInt8]:
    var bytes = text.as_bytes()
    var output = List[UInt8](capacity=len(bytes) // 2)
    for i in range(0, len(bytes), 2):
        var high = Int(bytes[i])
        var low = Int(bytes[i + 1])
        high -= 48 if high <= 57 else (55 if high <= 70 else 87)
        low -= 48 if low <= 57 else (55 if low <= 70 else 87)
        output.append(UInt8(high * 16 + low))
    return output^


def test_kdf_families() raises:
    var context = List[UInt8](length=8, fill=1)
    var key = List[UInt8](length=32, fill=2)
    var salt: List[UInt8] = [3, 4, 5]
    assert_equal(len(kdf(Span(context), Span(key), 7)), 32)
    assert_equal(
        len(
            hkdf(
                HashAlgorithm.SHA256,
                Span(salt),
                Span(key),
                Span(context),
                42,
            )
        ),
        42,
    )
    assert_equal(
        len(
            hkdf(
                HashAlgorithm.SHA512,
                Span(salt),
                Span(key),
                Span(context),
                42,
            )
        ),
        42,
    )


def test_box_roundtrip_and_tamper() raises:
    var alice = box_keypair()
    var bob = box_keypair()
    var alice_public = alice[0].copy()
    var alice_secret = alice[1].copy()
    var bob_public = bob[0].copy()
    var bob_secret = bob[1].copy()
    var nonce = List[UInt8](length=24, fill=9)
    var message: List[UInt8] = [1, 2, 3, 4]
    var ciphertext = box_encrypt(
        Span(message), Span(nonce), Span(bob_public), Span(alice_secret)
    )
    assert_equal(
        box_decrypt(
            Span(ciphertext), Span(nonce), Span(alice_public), Span(bob_secret)
        ),
        message,
    )
    ciphertext[0] ^= 1
    with assert_raises():
        _ = box_decrypt(
            Span(ciphertext), Span(nonce), Span(alice_public), Span(bob_secret)
        )


def test_key_exchange_sessions() raises:
    var client = kx_keypair()
    var server = kx_keypair()
    var client_public = client[0].copy()
    var client_secret = client[1].copy()
    var server_public = server[0].copy()
    var server_secret = server[1].copy()
    var client_keys = kx_session(
        True, Span(client_public), Span(client_secret), Span(server_public)
    )
    var server_keys = kx_session(
        False, Span(server_public), Span(server_secret), Span(client_public)
    )
    assert_equal(client_keys[0], server_keys[1])
    assert_equal(client_keys[1], server_keys[0])


def test_interop_x25519_blake2b_vector() raises:
    var client_secret = List[UInt8](capacity=32)
    var server_secret = List[UInt8](capacity=32)
    for i in range(32):
        client_secret.append(UInt8(i))
        server_secret.append(UInt8(i + 32))
    var client_public = _hex(
        "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
    )
    var server_public = _hex(
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    )
    var client = kx_session(
        True,
        Span(client_public),
        Span(client_secret),
        Span(server_public),
    )
    var server = kx_session(
        False,
        Span(server_public),
        Span(server_secret),
        Span(client_public),
    )
    assert_equal(
        client[0],
        _hex(
            "09fcadb630f490a255a9461619a3a32586c5ec11be9a584832de0aad99099e02"
        ),
    )
    assert_equal(
        client[1],
        _hex(
            "a1c994d365e824f318de66626a225b70a6f3be5b0febe8638882fd8a20d0bf0c"
        ),
    )
    assert_equal(client[0], server[1])
    assert_equal(client[1], server[0])


def test_mac_families() raises:
    var poly_key = List[UInt8](length=32, fill=1)
    var sip_key = List[UInt8](length=16, fill=2)
    var message: List[UInt8] = [1, 2, 3]
    assert_equal(len(poly1305(Span(poly_key), Span(message))), 16)
    assert_equal(
        len(
            shorthash(
                SipHashAlgorithm.SIPHASH_2_4,
                Span(sip_key),
                Span(message),
            )
        ),
        8,
    )
    assert_equal(
        len(
            shorthash(
                SipHashAlgorithm.SIPHASH_X_2_4,
                Span(sip_key),
                Span(message),
            )
        ),
        16,
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
