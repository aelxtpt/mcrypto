from std.testing import TestSuite
from mcrypto.ciphers.dispatch import process
from mcrypto.ciphers.algorithm import BlockCipherAlgorithm, CipherMode


def test_every_block_dispatch_rejects_empty_key() raises:
    var empty = List[UInt8]()
    var accepted = String()
    for name, algorithm, block_size in [
        ("AES", BlockCipherAlgorithm.AES, 16),
        ("ARIA", BlockCipherAlgorithm.ARIA, 16),
        ("Blowfish", BlockCipherAlgorithm.BLOWFISH, 8),
        ("CAST-128", BlockCipherAlgorithm.CAST128, 8),
        ("CAST-256", BlockCipherAlgorithm.CAST256, 16),
        ("CHAM-128", BlockCipherAlgorithm.CHAM128, 16),
        ("CHAM-64", BlockCipherAlgorithm.CHAM64, 8),
        ("Camellia", BlockCipherAlgorithm.CAMELLIA, 16),
        ("DES", BlockCipherAlgorithm.DES, 8),
        ("DES-EDE2", BlockCipherAlgorithm.DES_EDE2, 8),
        ("DES-EDE3", BlockCipherAlgorithm.DES_EDE3, 8),
        ("DES-XEX3", BlockCipherAlgorithm.DES_XEX3, 8),
        ("GOST", BlockCipherAlgorithm.GOST, 8),
        ("HIGHT", BlockCipherAlgorithm.HIGHT, 8),
        ("IDEA", BlockCipherAlgorithm.IDEA, 8),
        ("Kalyna-128", BlockCipherAlgorithm.KALYNA128, 16),
        ("Kalyna-256", BlockCipherAlgorithm.KALYNA256, 32),
        ("Kalyna-512", BlockCipherAlgorithm.KALYNA512, 64),
        ("LEA", BlockCipherAlgorithm.LEA, 16),
        ("MARS", BlockCipherAlgorithm.MARS, 16),
        ("RC2", BlockCipherAlgorithm.RC2, 8),
        ("RC5", BlockCipherAlgorithm.RC5, 8),
        ("RC6", BlockCipherAlgorithm.RC6, 16),
        ("SAFER", BlockCipherAlgorithm.SAFER, 8),
        ("SEED", BlockCipherAlgorithm.SEED, 16),
        ("SHACAL-2", BlockCipherAlgorithm.SHACAL2, 32),
        ("SHARK", BlockCipherAlgorithm.SHARK, 8),
        ("SIMECK-32", BlockCipherAlgorithm.SIMECK32, 4),
        ("SIMECK-64", BlockCipherAlgorithm.SIMECK64, 8),
        ("SIMON-128", BlockCipherAlgorithm.SIMON128, 16),
        ("SIMON-64", BlockCipherAlgorithm.SIMON64, 8),
        ("SKIPJACK", BlockCipherAlgorithm.SKIPJACK, 8),
        ("SM4", BlockCipherAlgorithm.SM4, 16),
        ("SPECK-128", BlockCipherAlgorithm.SPECK128, 16),
        ("SPECK-64", BlockCipherAlgorithm.SPECK64, 8),
        ("Serpent", BlockCipherAlgorithm.SERPENT, 16),
        ("Square", BlockCipherAlgorithm.SQUARE, 16),
        ("TEA", BlockCipherAlgorithm.TEA, 8),
        ("Threefish-1024", BlockCipherAlgorithm.THREEFISH1024, 128),
        ("Threefish-256", BlockCipherAlgorithm.THREEFISH256, 32),
        ("Threefish-512", BlockCipherAlgorithm.THREEFISH512, 64),
        ("Twofish", BlockCipherAlgorithm.TWOFISH, 16),
        ("XTEA", BlockCipherAlgorithm.XTEA, 8),
        ("3-WAY", BlockCipherAlgorithm.THREE_WAY, 12),
    ]:
        var iv = List[UInt8](length=block_size, fill=0)
        var message = List[UInt8](length=block_size, fill=0)
        var rejected = False
        try:
            _ = process(
                algorithm,
                CipherMode.ECB,
                True,
                Span(empty),
                Span(iv),
                Span(message),
            )
        except:
            rejected = True
        if not rejected:
            accepted += String(name) + ","
    if accepted.byte_length() > 0:
        raise Error("accepted empty block key: " + accepted)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
