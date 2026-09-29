"""Typed one-shot block-cipher dispatch and metadata."""

from .algorithm import BlockCipherAlgorithm
from .aes_block import (
    encrypt_block as aes_encrypt,
    decrypt_block as aes_decrypt,
)
from .tea import tea_decrypt, tea_encrypt, xtea_decrypt, xtea_encrypt
from .speck import decrypt as speck_decrypt, encrypt as speck_encrypt
from .simon import decrypt as simon_decrypt, encrypt as simon_encrypt
from .sm4 import process as sm4_process
from .rc import rc5, rc6
from .rc2 import process as rc2_process
from .cham import decrypt as cham_decrypt, encrypt as cham_encrypt
from .hight import decrypt as hight_decrypt, encrypt as hight_encrypt
from .lea import decrypt as lea_decrypt, encrypt as lea_encrypt
from .gost import process as gost_process
from .threeway import process as threeway_process
from .threefish import process as threefish_process
from .simeck import process as simeck_process
from .skipjack import process as skipjack_process
from .shacal2 import process as shacal2_process
from .idea import process as idea_process
from .aria import process as aria_process
from .blowfish import process as blowfish_process
from .camellia import process as camellia_process
from .cast import process as cast_process
from .kalyna import process as kalyna_process
from .safer import safer_k, safer_sk
from .seed import process as seed_process
from .serpent import process as serpent_process
from .shark import process as shark_process
from .square import process as square_process
from .twofish import process as twofish_process
from .des import process as des_process
from .mars import process as mars_process


def _block_size(cipher: BlockCipherAlgorithm) raises -> Int:
    if cipher == BlockCipherAlgorithm.SIMECK32:
        return 4
    if cipher == BlockCipherAlgorithm.THREE_WAY:
        return 12
    if (
        cipher == BlockCipherAlgorithm.AES
        or cipher == BlockCipherAlgorithm.SM4
        or cipher == BlockCipherAlgorithm.SPECK128
        or cipher == BlockCipherAlgorithm.SIMON128
        or cipher == BlockCipherAlgorithm.CHAM128
        or cipher == BlockCipherAlgorithm.LEA
        or cipher == BlockCipherAlgorithm.ARIA
        or cipher == BlockCipherAlgorithm.CAMELLIA
        or cipher == BlockCipherAlgorithm.CAST256
        or cipher == BlockCipherAlgorithm.KALYNA128
        or cipher == BlockCipherAlgorithm.SEED
        or cipher == BlockCipherAlgorithm.SERPENT
        or cipher == BlockCipherAlgorithm.SQUARE
        or cipher == BlockCipherAlgorithm.TWOFISH
        or cipher == BlockCipherAlgorithm.MARS
        or cipher == BlockCipherAlgorithm.RC6
    ):
        return 16
    if (
        cipher == BlockCipherAlgorithm.TEA
        or cipher == BlockCipherAlgorithm.XTEA
        or cipher == BlockCipherAlgorithm.SPECK64
        or cipher == BlockCipherAlgorithm.SIMON64
        or cipher == BlockCipherAlgorithm.RC2
        or cipher == BlockCipherAlgorithm.RC5
        or cipher == BlockCipherAlgorithm.CHAM64
        or cipher == BlockCipherAlgorithm.HIGHT
        or cipher == BlockCipherAlgorithm.GOST
        or cipher == BlockCipherAlgorithm.SIMECK64
        or cipher == BlockCipherAlgorithm.SKIPJACK
        or cipher == BlockCipherAlgorithm.IDEA
        or cipher == BlockCipherAlgorithm.BLOWFISH
        or cipher == BlockCipherAlgorithm.CAST128
        or cipher == BlockCipherAlgorithm.SAFER
        or cipher == BlockCipherAlgorithm.SAFER_K
        or cipher == BlockCipherAlgorithm.SAFER_SK
        or cipher == BlockCipherAlgorithm.SHARK
        or cipher == BlockCipherAlgorithm.SHARK_E
        or cipher == BlockCipherAlgorithm.DES
        or cipher == BlockCipherAlgorithm.DES_XEX3
        or cipher == BlockCipherAlgorithm.DES_EDE2
        or cipher == BlockCipherAlgorithm.DES_EDE3
    ):
        return 8
    if (
        cipher == BlockCipherAlgorithm.SHACAL2
        or cipher == BlockCipherAlgorithm.THREEFISH256
        or cipher == BlockCipherAlgorithm.KALYNA256
    ):
        return 32
    if (
        cipher == BlockCipherAlgorithm.THREEFISH512
        or cipher == BlockCipherAlgorithm.KALYNA512
    ):
        return 64
    if cipher == BlockCipherAlgorithm.THREEFISH1024:
        return 128
    raise Error("invalid block cipher selector")


def _process_block[
    key_origin: Origin, block_origin: Origin
](
    cipher: BlockCipherAlgorithm,
    decrypting: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if cipher == BlockCipherAlgorithm.AES:
        return aes_decrypt(key, block) if decrypting else aes_encrypt(
            key, block
        )
    if cipher == BlockCipherAlgorithm.TEA:
        return tea_decrypt(key, block) if decrypting else tea_encrypt(
            key, block
        )
    if cipher == BlockCipherAlgorithm.XTEA:
        return xtea_decrypt(key, block) if decrypting else xtea_encrypt(
            key, block
        )
    if cipher == BlockCipherAlgorithm.SM4:
        return sm4_process(key, block, decrypting)
    if (
        cipher == BlockCipherAlgorithm.SPECK64
        or cipher == BlockCipherAlgorithm.SPECK128
    ):
        return speck_decrypt(
            cipher, key, block
        ) if decrypting else speck_encrypt(cipher, key, block)
    if (
        cipher == BlockCipherAlgorithm.SIMON64
        or cipher == BlockCipherAlgorithm.SIMON128
    ):
        return simon_decrypt(
            cipher, key, block
        ) if decrypting else simon_encrypt(cipher, key, block)
    if cipher == BlockCipherAlgorithm.RC2:
        return rc2_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.RC5:
        return rc5(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.RC6:
        return rc6(decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.CHAM64
        or cipher == BlockCipherAlgorithm.CHAM128
    ):
        return cham_decrypt(cipher, key, block) if decrypting else cham_encrypt(
            cipher, key, block
        )
    if cipher == BlockCipherAlgorithm.HIGHT:
        return hight_decrypt(key, block) if decrypting else hight_encrypt(
            key, block
        )
    if cipher == BlockCipherAlgorithm.LEA:
        return lea_decrypt(key, block) if decrypting else lea_encrypt(
            key, block
        )
    if cipher == BlockCipherAlgorithm.GOST:
        return gost_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.THREE_WAY:
        return threeway_process(decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.THREEFISH256
        or cipher == BlockCipherAlgorithm.THREEFISH512
        or cipher == BlockCipherAlgorithm.THREEFISH1024
    ):
        var tweak = List[UInt8](length=16, fill=0)
        return threefish_process(decrypting, key, Span(tweak), block)
    if (
        cipher == BlockCipherAlgorithm.SIMECK32
        or cipher == BlockCipherAlgorithm.SIMECK64
    ):
        return simeck_process(cipher, decrypting, key, block)
    if cipher == BlockCipherAlgorithm.SKIPJACK:
        return skipjack_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.SHACAL2:
        return shacal2_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.IDEA:
        return idea_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.ARIA:
        return aria_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.BLOWFISH:
        return blowfish_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.CAMELLIA:
        return camellia_process(decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.CAST128
        or cipher == BlockCipherAlgorithm.CAST256
    ):
        return cast_process(cipher, decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.KALYNA128
        or cipher == BlockCipherAlgorithm.KALYNA256
        or cipher == BlockCipherAlgorithm.KALYNA512
    ):
        return kalyna_process(cipher, decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.SAFER
        or cipher == BlockCipherAlgorithm.SAFER_K
    ):
        return safer_k(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.SAFER_SK:
        return safer_sk(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.SEED:
        return seed_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.SERPENT:
        return serpent_process(decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.SHARK
        or cipher == BlockCipherAlgorithm.SHARK_E
    ):
        return shark_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.SQUARE:
        return square_process(decrypting, key, block)
    if cipher == BlockCipherAlgorithm.TWOFISH:
        return twofish_process(decrypting, key, block)
    if (
        cipher == BlockCipherAlgorithm.DES
        or cipher == BlockCipherAlgorithm.DES_XEX3
        or cipher == BlockCipherAlgorithm.DES_EDE2
        or cipher == BlockCipherAlgorithm.DES_EDE3
    ):
        return des_process(cipher, decrypting, key, block)
    if cipher == BlockCipherAlgorithm.MARS:
        return mars_process(decrypting, key, block)
    raise Error("invalid block cipher selector")


def _prepared_kind(algorithm: BlockCipherAlgorithm) raises -> UInt8:
    if algorithm == BlockCipherAlgorithm.THREE_WAY:
        return 1
    if algorithm == BlockCipherAlgorithm.GOST:
        return 2
    if algorithm == BlockCipherAlgorithm.RC2:
        return 3
    if algorithm == BlockCipherAlgorithm.TEA:
        return 4
    if algorithm == BlockCipherAlgorithm.XTEA:
        return 5
    if algorithm == BlockCipherAlgorithm.SIMON64:
        return 6
    if algorithm == BlockCipherAlgorithm.SIMON128:
        return 7
    if algorithm == BlockCipherAlgorithm.SPECK64:
        return 8
    if algorithm == BlockCipherAlgorithm.SPECK128:
        return 9
    if algorithm == BlockCipherAlgorithm.SIMECK32:
        return 10
    if algorithm == BlockCipherAlgorithm.SIMECK64:
        return 11
    if algorithm == BlockCipherAlgorithm.CHAM64:
        return 12
    if algorithm == BlockCipherAlgorithm.CHAM128:
        return 13
    if algorithm == BlockCipherAlgorithm.ARIA:
        return 14
    if (
        algorithm == BlockCipherAlgorithm.KALYNA128
        or algorithm == BlockCipherAlgorithm.KALYNA256
        or algorithm == BlockCipherAlgorithm.KALYNA512
    ):
        return 15
    if algorithm == BlockCipherAlgorithm.LEA:
        return 16
    if (
        algorithm == BlockCipherAlgorithm.SAFER
        or algorithm == BlockCipherAlgorithm.SAFER_K
        or algorithm == BlockCipherAlgorithm.SAFER_SK
    ):
        return 17
    if (
        algorithm == BlockCipherAlgorithm.SHARK
        or algorithm == BlockCipherAlgorithm.SHARK_E
    ):
        return 18
    if algorithm == BlockCipherAlgorithm.SQUARE:
        return 19
    if algorithm == BlockCipherAlgorithm.TWOFISH:
        return 20
    if algorithm == BlockCipherAlgorithm.CAMELLIA:
        return 21
    if algorithm == BlockCipherAlgorithm.HIGHT:
        return 22
    if algorithm == BlockCipherAlgorithm.CAST128:
        return 23
    if algorithm == BlockCipherAlgorithm.CAST256:
        return 24
    if algorithm == BlockCipherAlgorithm.SERPENT:
        return 25
    if algorithm == BlockCipherAlgorithm.SHACAL2:
        return 26
    if (
        algorithm == BlockCipherAlgorithm.DES
        or algorithm == BlockCipherAlgorithm.DES_EDE2
        or algorithm == BlockCipherAlgorithm.DES_EDE3
        or algorithm == BlockCipherAlgorithm.DES_XEX3
    ):
        return 27
    if algorithm == BlockCipherAlgorithm.SM4:
        return 28
    if algorithm == BlockCipherAlgorithm.BLOWFISH:
        return 29
    if algorithm == BlockCipherAlgorithm.MARS:
        return 30
    if algorithm == BlockCipherAlgorithm.RC5:
        return 31
    if algorithm == BlockCipherAlgorithm.RC6:
        return 32
    if (
        algorithm == BlockCipherAlgorithm.THREEFISH256
        or algorithm == BlockCipherAlgorithm.THREEFISH512
        or algorithm == BlockCipherAlgorithm.THREEFISH1024
    ):
        return 33
    if algorithm == BlockCipherAlgorithm.IDEA:
        return 34
    if algorithm == BlockCipherAlgorithm.SKIPJACK:
        return 35
    if algorithm == BlockCipherAlgorithm.SEED:
        return 36
    if algorithm == BlockCipherAlgorithm.AES:
        return 37
    raise Error("invalid block cipher selector")
