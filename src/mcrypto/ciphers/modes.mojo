"""ECB, CBC, CFB, OFB, and CTR modes over pure-Mojo block ciphers."""

from std.memory import bitcast

from std.sys import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic

from ..internal.bytes import load_le64
from .algorithm import BlockCipherAlgorithm, CipherMode
from .block_dispatch import _block_size, _prepared_kind, _process_block
from .modes_batch import (
    _process_aria_cbc_four_into,
    _process_speck_cbc_four_into,
)

from .prepared_aes import _PreparedAES
from .tea import (
    prepare as tea_prepare,
    process_eight as tea_process_eight,
    process_prepared_into as tea_process_into,
)
from .speck import (
    decrypt_prepared32 as speck_decrypt_prepared32,
    decrypt_prepared64 as speck_decrypt_prepared64,
    encrypt_prepared32 as speck_encrypt_prepared32,
    encrypt_prepared64 as speck_encrypt_prepared64,
    prepare32 as speck_prepare32,
    prepare64 as speck_prepare64,
    process_four64 as speck_process_four64,
    process_eight32 as speck_process_eight32,
    process_prepared32_into as speck_process_into32,
    process_prepared64_into as speck_process_into64,
)
from .simon import (
    decrypt_prepared32 as simon_decrypt_prepared32,
    decrypt_prepared64 as simon_decrypt_prepared64,
    encrypt_prepared32 as simon_encrypt_prepared32,
    encrypt_prepared64 as simon_encrypt_prepared64,
    prepare32 as simon_prepare32,
    prepare64 as simon_prepare64,
    process_four64 as simon_process_four64,
    process_eight32 as simon_process_eight32,
    process_prepared32_into as simon_process_into32,
    process_prepared64_into as simon_process_into64,
)
from .sm4 import (
    prepare as sm4_prepare,
    process_prepared as sm4_process_prepared,
    prepare_tables as sm4_prepare_tables,
    process_prepared_tables_into as sm4_process_tables_into,
)
from .rc import (
    prepare5 as rc5_prepare,
    prepare6 as rc6_prepare,
    process_prepared5 as rc5_process_prepared,
    process_prepared6 as rc6_process_prepared,
    process_prepared5_into as rc5_process_into,
    process_eight5_into as rc5_process_eight,
    process_prepared6_into as rc6_process_into,
    process_eight6_into as rc6_process_eight,
)
from .rc2 import (
    prepare as rc2_prepare,
    process_prepared as rc2_process_prepared,
    process_prepared_into as rc2_process_into,
)
from .cham import (
    decrypt_prepared16 as cham_decrypt_prepared16,
    decrypt_prepared32 as cham_decrypt_prepared32,
    encrypt_prepared16 as cham_encrypt_prepared16,
    encrypt_prepared32 as cham_encrypt_prepared32,
    prepare16 as cham_prepare16,
    prepare32 as cham_prepare32,
    process_eight32 as cham_process_eight32,
    process_sixteen16 as cham_process_sixteen16,
    process_prepared16_into as cham_process_into16,
    process_prepared32_into as cham_process_into32,
)
from .hight import (
    prepare as hight_prepare,
    process_prepared as hight_process_prepared,
    process_prepared_into as hight_process_into,
)
from .lea import (
    decrypt_prepared as lea_decrypt_prepared,
    encrypt_prepared as lea_encrypt_prepared,
    prepare as lea_prepare,
    process_eight as lea_process_eight,
    process_prepared_into as lea_process_into,
)
from .gost import (
    prepare as gost_prepare,
    process_prepared as gost_process_prepared,
    process_prepared_into as gost_process_into,
)
from .threeway import (
    prepare as threeway_prepare,
    process_prepared as threeway_process_prepared,
    process_prepared_into as threeway_process_into,
)
from .threefish import (
    process_prepared as threefish_process_prepared,
    process_prepared_into as threefish_process_into,
)
from .simeck import (
    prepare16 as simeck_prepare16,
    prepare32 as simeck_prepare32,
    process_eight32 as simeck_process_eight32,
    process_prepared16 as simeck_process_prepared16,
    process_prepared32 as simeck_process_prepared32,
    process_prepared16_into as simeck_process_into16,
    process_prepared32_into as simeck_process_into32,
    process_sixteen16 as simeck_process_sixteen16,
)
from .skipjack import (
    prepare as skipjack_prepare,
    process_prepared_into as skipjack_process_into,
)
from .shacal2 import (
    prepare as shacal2_prepare,
    process_prepared as shacal2_process_prepared,
    process_prepared_into as shacal2_process_into,
)
from .idea import (
    prepare as idea_prepare,
    process_prepared_into as idea_process_into,
)
from .aria import (
    prepare as aria_prepare,
    prepare_tables as aria_prepare_tables,
    process_prepared_tables as aria_process_prepared,
    process_prepared_tables_into as aria_process_into,
    process_four_tables_into as aria_process_four_into,
)
from .blowfish import (
    prepare as blowfish_prepare,
    process_prepared as blowfish_process_prepared,
    process_prepared_into as blowfish_process_into,
)
from .camellia import (
    prepare as camellia_prepare,
    prepare_tables as camellia_prepare_tables,
    process_prepared_tables as camellia_process_prepared,
    process_prepared_tables_into as camellia_process_into,
)
from .cast import (
    cast128_process_into,
    cast128_process_prepared,
    cast256_process_into,
    cast256_process_prepared,
    prepare128 as cast128_prepare,
    prepare256 as cast256_prepare,
)
from .kalyna import (
    prepare as kalyna_prepare,
    prepare_transform_tables as kalyna_prepare_tables,
    process_prepared_tables as kalyna_process_prepared_tables,
    process_prepared_tables_into as kalyna_process_into,
)
from .safer import (
    prepare as safer_prepare,
    process_prepared as safer_process_prepared,
    process_prepared_into as safer_process_into,
    process_eight_encrypt as safer_process_eight_encrypt,
)
from .seed import (
    prepare as seed_prepare,
    process_prepared_into as seed_process_into,
)
from .serpent import (
    prepare as serpent_prepare,
    process_eight as serpent_process_eight,
    process_prepared as serpent_process_prepared,
)
from .des import (
    prepare as des_prepare,
    process_prepared as des_process_prepared,
    process_prepared_into as des_process_into,
)
from .shark import (
    prepare as shark_prepare,
    prepare_tables as shark_prepare_tables,
    process_prepared_tables as shark_process_prepared_tables,
    process_prepared_tables_into as shark_process_into,
)
from .square import (
    prepare as square_prepare,
    prepare_tables as square_prepare_tables,
    process_prepared_tables as square_process_prepared_tables,
    process_prepared_tables_into as square_process_into,
)
from .twofish import (
    prepare as twofish_prepare,
    prepare_tables as twofish_prepare_tables,
    process_prepared_tables as twofish_process_prepared_tables,
    process_prepared_tables_into as twofish_process_into,
)
from .mars import (
    prepare as mars_prepare,
    process_prepared as mars_process_prepared,
    process_prepared_into as mars_process_into,
)


@always_inline("nodebug")
def _byte_swap32(value: UInt32) -> UInt32:
    return llvm_intrinsic["llvm.bswap.i32", UInt32, has_side_effect=False](
        value
    )


@always_inline("nodebug")
def _byte_swap64(value: UInt64) -> UInt64:
    return llvm_intrinsic["llvm.bswap.i64", UInt64, has_side_effect=False](
        value
    )


def block_size(cipher: BlockCipherAlgorithm) raises -> Int:
    return _block_size(cipher)


def encrypt_block[
    key_origin: Origin, block_origin: Origin
](
    cipher: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    return _process_block(cipher, False, key, block)


def decrypt_block[
    key_origin: Origin, block_origin: Origin
](
    cipher: BlockCipherAlgorithm,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    return _process_block(cipher, True, key, block)


struct _PreparedCipher(Movable):
    var algorithm: BlockCipherAlgorithm
    var kind: UInt8
    var aes: _PreparedAES
    var twofish_round_keys: List[UInt32]
    var twofish_tables: List[UInt32]
    var camellia_encrypt_kw: List[UInt64]
    var camellia_encrypt_rounds: List[UInt64]
    var camellia_encrypt_extra: List[UInt64]
    var camellia_decrypt_kw: List[UInt64]
    var camellia_decrypt_rounds: List[UInt64]
    var camellia_decrypt_extra: List[UInt64]
    var camellia_tables: List[UInt64]
    var kalyna_keys: List[UInt64]
    var kalyna_rounds: Int
    var kalyna_tables: List[UInt64]
    var kalyna_inverse_sboxes: List[UInt8]
    var kalyna_words: Int
    var blowfish_p: List[UInt32]
    var blowfish_s: List[UInt32]
    var lea_keys: List[UInt32]
    var lea_rounds: Int
    var hight_keys: List[UInt8]
    var cast_keys: List[UInt32]
    var cast_rounds: Int
    var serpent_keys: List[UInt32]
    var shacal2_keys: List[UInt32]
    var aria_encrypt_keys: List[List[UInt8]]
    var aria_decrypt_keys: List[List[UInt8]]
    var aria_rounds: Int
    var aria_tables: List[SIMD[DType.uint8, 16]]
    var simon32_keys: List[UInt32]
    var tea_keys: List[UInt32]
    var simon64_keys: List[UInt64]
    var simeck16_keys: List[UInt16]
    var simeck32_keys: List[UInt32]
    var des_first: List[UInt64]
    var des_second: List[UInt64]
    var des_third: List[UInt64]
    var des_whitening0: UInt64
    var des_whitening1: UInt64
    var sm4_schedule: List[UInt32]
    var sm4_tables: List[UInt32]
    var rc5_schedule: List[UInt32]
    var rc6_schedule: List[UInt32]
    var rc2_schedule: List[UInt16]
    var gost_keys: List[UInt32]
    var gost_tables: List[UInt32]
    var threeway_encrypt_keys: List[UInt32]
    var threeway_decrypt_keys: List[UInt32]
    var seed_keys: List[UInt32]
    var seed_tables: List[UInt32]
    var mars_keys: List[UInt32]
    var mars_sbox: List[UInt32]
    var idea_encrypt_keys: List[UInt16]
    var idea_decrypt_keys: List[UInt16]
    var safer_keys: List[UInt8]
    var safer_rounds: Int
    var skipjack_key: List[UInt8]
    var skipjack_table: List[UInt8]
    var shark_encrypt_keys: List[UInt64]
    var shark_decrypt_keys: List[UInt64]
    var shark_encrypt_tables: List[UInt64]
    var shark_decrypt_tables: List[UInt64]
    var square_encrypt_keys: List[UInt32]
    var square_decrypt_keys: List[UInt32]
    var square_encrypt_tables: List[UInt32]
    var square_decrypt_tables: List[UInt32]
    var cham16_keys: InlineArray[UInt16, 16]
    var cham32_keys: InlineArray[UInt32, 16]
    var cham32_rounds: Int
    var speck32_keys: List[UInt32]
    var speck64_keys: List[UInt64]
    var threefish_key: InlineArray[UInt64, 17]
    var threefish_tweak: InlineArray[UInt64, 3]
    var threefish_words: Int

    def __init__[
        key_origin: Origin
    ](
        out self,
        algorithm: BlockCipherAlgorithm,
        key: Span[UInt8, key_origin],
        decrypting: Bool = False,
    ) raises:
        self.algorithm = algorithm
        self.kind = _prepared_kind(algorithm)
        self.aes = _PreparedAES()
        if self.kind == 37:
            self.aes = _PreparedAES(key)
        self.twofish_round_keys = List[UInt32]()
        self.twofish_tables = List[UInt32]()
        self.camellia_encrypt_kw = List[UInt64]()
        self.camellia_encrypt_rounds = List[UInt64]()
        self.camellia_encrypt_extra = List[UInt64]()
        self.camellia_decrypt_kw = List[UInt64]()
        self.camellia_decrypt_rounds = List[UInt64]()
        self.camellia_decrypt_extra = List[UInt64]()
        self.camellia_tables = List[UInt64]()
        self.kalyna_keys = List[UInt64]()
        self.kalyna_rounds = 0
        self.kalyna_words = 0
        self.kalyna_tables = List[UInt64]()
        self.kalyna_inverse_sboxes = List[UInt8]()
        self.blowfish_p = List[UInt32]()
        self.blowfish_s = List[UInt32]()
        self.lea_keys = List[UInt32]()
        self.lea_rounds = 0
        self.hight_keys = List[UInt8]()
        self.cast_keys = List[UInt32]()
        self.cast_rounds = 0
        self.serpent_keys = List[UInt32]()
        self.shacal2_keys = List[UInt32]()
        self.aria_encrypt_keys = List[List[UInt8]]()
        self.aria_decrypt_keys = List[List[UInt8]]()
        self.aria_rounds = 0
        self.aria_tables = List[SIMD[DType.uint8, 16]]()
        self.simon32_keys = List[UInt32]()
        self.tea_keys = List[UInt32]()
        self.simon64_keys = List[UInt64]()
        self.simeck16_keys = List[UInt16]()
        self.simeck32_keys = List[UInt32]()
        self.des_first = List[UInt64]()
        self.des_second = List[UInt64]()
        self.des_third = List[UInt64]()
        self.des_whitening0 = 0
        self.des_whitening1 = 0
        self.sm4_schedule = List[UInt32]()
        self.sm4_tables = List[UInt32]()
        self.rc5_schedule = List[UInt32]()
        self.rc6_schedule = List[UInt32]()
        self.rc2_schedule = List[UInt16]()
        self.gost_keys = List[UInt32]()
        self.gost_tables = List[UInt32]()
        self.threeway_encrypt_keys = List[UInt32]()
        self.threeway_decrypt_keys = List[UInt32]()
        self.mars_keys = List[UInt32]()
        self.mars_sbox = List[UInt32]()
        self.idea_encrypt_keys = List[UInt16]()
        self.idea_decrypt_keys = List[UInt16]()
        self.safer_keys = List[UInt8]()
        self.safer_rounds = 0
        self.seed_keys = List[UInt32]()
        self.seed_tables = List[UInt32]()
        self.skipjack_key = List[UInt8]()
        self.skipjack_table = List[UInt8]()
        self.shark_encrypt_keys = List[UInt64]()
        self.shark_decrypt_keys = List[UInt64]()
        self.shark_encrypt_tables = List[UInt64]()
        self.shark_decrypt_tables = List[UInt64]()
        self.square_encrypt_keys = List[UInt32]()
        self.square_decrypt_keys = List[UInt32]()
        self.square_encrypt_tables = List[UInt32]()
        self.square_decrypt_tables = List[UInt32]()
        self.cham16_keys = InlineArray[UInt16, 16](uninitialized=True)
        self.cham32_keys = InlineArray[UInt32, 16](uninitialized=True)
        self.cham32_rounds = 0
        self.speck32_keys = List[UInt32]()
        self.speck64_keys = List[UInt64]()
        self.threefish_key = InlineArray[UInt64, 17](uninitialized=True)
        self.threefish_tweak = InlineArray[UInt64, 3](uninitialized=True)
        self.threefish_words = 0
        if self.kind == 20:
            var schedule = twofish_prepare(key)
            self.twofish_round_keys = schedule[0].copy()
            self.twofish_tables = twofish_prepare_tables(
                schedule[1], schedule[2]
            )
        if self.kind == 21:
            if decrypting:
                var schedule = camellia_prepare(key, True)
                self.camellia_decrypt_kw = schedule[0].copy()
                self.camellia_decrypt_rounds = schedule[1].copy()
                self.camellia_decrypt_extra = schedule[2].copy()
            else:
                var schedule = camellia_prepare(key, False)
                self.camellia_encrypt_kw = schedule[0].copy()
                self.camellia_encrypt_rounds = schedule[1].copy()
                self.camellia_encrypt_extra = schedule[2].copy()
            self.camellia_tables = camellia_prepare_tables()
        if self.kind == 15:
            var kalyna_schedule = kalyna_prepare(algorithm, key)
            self.kalyna_keys = kalyna_schedule[0].copy()
            self.kalyna_rounds = kalyna_schedule[1]
            self.kalyna_words = kalyna_schedule[2]
            var kalyna_tables = kalyna_prepare_tables()
            self.kalyna_tables = kalyna_tables[0].copy()
            self.kalyna_inverse_sboxes = kalyna_tables[1].copy()
        if self.kind == 29:
            var blowfish_schedule = blowfish_prepare(key)
            self.blowfish_p = blowfish_schedule[0].copy()
            self.blowfish_s = blowfish_schedule[1].copy()
        if self.kind == 16:
            var lea_schedule = lea_prepare(key)
            self.lea_keys = lea_schedule[0].copy()
            self.lea_rounds = lea_schedule[1]
        if self.kind == 22:
            self.hight_keys = hight_prepare(key)
        if self.kind == 23:
            var cast_schedule = cast128_prepare(key)
            self.cast_keys = cast_schedule[0].copy()
            self.cast_rounds = cast_schedule[1]
        if self.kind == 24:
            self.cast_keys = cast256_prepare(key)
        if self.kind == 25:
            self.serpent_keys = serpent_prepare(key)
        if self.kind == 26:
            self.shacal2_keys = shacal2_prepare(key)
        if self.kind == 14:
            var schedule = aria_prepare(key, decrypting)
            if decrypting:
                self.aria_decrypt_keys = schedule[0].copy()
            else:
                self.aria_encrypt_keys = schedule[0].copy()
            self.aria_rounds = schedule[1]
            self.aria_tables = aria_prepare_tables()
        if self.kind == 4 or self.kind == 5:
            self.tea_keys = tea_prepare(key)

        if self.kind == 10:
            self.simeck16_keys = simeck_prepare16(key)
        if self.kind == 11:
            self.simeck32_keys = simeck_prepare32(key)
        if self.kind == 6:
            self.simon32_keys = simon_prepare32(key)
        if self.kind == 7:
            self.simon64_keys = simon_prepare64(key)
        if self.kind == 27:
            var des_schedule = des_prepare(algorithm, key)
            self.des_first = des_schedule[0].copy()
            self.des_second = des_schedule[1].copy()
            self.des_third = des_schedule[2].copy()
            self.des_whitening0 = des_schedule[3]
            self.des_whitening1 = des_schedule[4]
        if self.kind == 28:
            self.sm4_schedule = sm4_prepare(key)
            self.sm4_tables = sm4_prepare_tables()
        if self.kind == 31:
            self.rc5_schedule = rc5_prepare(key)
        if self.kind == 32:
            self.rc6_schedule = rc6_prepare(key)
        if self.kind == 3:
            self.rc2_schedule = rc2_prepare(key)
        if self.kind == 2:
            var gost_schedule = gost_prepare(key)
            self.gost_keys = gost_schedule[0].copy()
            self.gost_tables = gost_schedule[1].copy()
        if self.kind == 1:
            if decrypting:
                self.threeway_decrypt_keys = threeway_prepare(key, True)
            else:
                self.threeway_encrypt_keys = threeway_prepare(key, False)
        if self.kind == 30:
            var mars_schedule = mars_prepare(key)
            self.mars_keys = mars_schedule[0].copy()
            self.mars_sbox = mars_schedule[1].copy()
        if self.kind == 36:
            var seed_schedule = seed_prepare(key)
            self.seed_keys = seed_schedule[0].copy()
            self.seed_tables = seed_schedule[1].copy()
        if self.kind == 34:
            if decrypting:
                self.idea_decrypt_keys = idea_prepare(key, True)
            else:
                self.idea_encrypt_keys = idea_prepare(key, False)
        if self.kind == 17:
            var safer_schedule = safer_prepare(
                key, algorithm == BlockCipherAlgorithm.SAFER_SK
            )
            self.safer_keys = safer_schedule[0].copy()
            self.safer_rounds = safer_schedule[1]
        if self.kind == 35:
            var skipjack_schedule = skipjack_prepare(key)
            self.skipjack_key = skipjack_schedule[0].copy()
            self.skipjack_table = skipjack_schedule[1].copy()
        if self.kind == 18:
            if decrypting:
                self.shark_decrypt_keys = shark_prepare(key, True)
                self.shark_decrypt_tables = shark_prepare_tables(True)
            else:
                self.shark_encrypt_keys = shark_prepare(key, False)
                self.shark_encrypt_tables = shark_prepare_tables(False)
        if self.kind == 19:
            if decrypting:
                self.square_decrypt_keys = square_prepare(key, True)
                self.square_decrypt_tables = square_prepare_tables(True)
            else:
                self.square_encrypt_keys = square_prepare(key, False)
                self.square_encrypt_tables = square_prepare_tables(False)
        if self.kind == 12:
            self.cham16_keys = cham_prepare16(key)
        if self.kind == 13:
            var cham_schedule = cham_prepare32(key)
            self.cham32_keys = cham_schedule[0].copy()
            self.cham32_rounds = cham_schedule[1]
        if self.kind == 8:
            self.speck32_keys = speck_prepare32(key)
        if self.kind == 9:
            self.speck64_keys = speck_prepare64(key)
        if self.kind == 33:
            self.threefish_words = len(key) // 8
            if (
                self.threefish_words != 4
                and self.threefish_words != 8
                and self.threefish_words != 16
            ):
                raise Error("Threefish key must be 32, 64, or 128 bytes")
            var parity = UInt64(0x1BD11BDAA9FC1A22)
            for i in range(self.threefish_words):
                var word = load_le64(key, i * 8)
                self.threefish_key[i] = word
                parity ^= word
            self.threefish_key[self.threefish_words] = parity
            self.threefish_tweak[0] = 0
            self.threefish_tweak[1] = 0
            self.threefish_tweak[2] = 0

    def __init__(out self, *, deinit move: Self):
        self.algorithm = move.algorithm
        self.kind = move.kind
        self.aes = move.aes^
        self.twofish_round_keys = move.twofish_round_keys^
        self.twofish_tables = move.twofish_tables^
        self.camellia_encrypt_kw = move.camellia_encrypt_kw^
        self.camellia_encrypt_rounds = move.camellia_encrypt_rounds^
        self.camellia_encrypt_extra = move.camellia_encrypt_extra^
        self.camellia_decrypt_kw = move.camellia_decrypt_kw^
        self.camellia_decrypt_rounds = move.camellia_decrypt_rounds^
        self.camellia_decrypt_extra = move.camellia_decrypt_extra^
        self.camellia_tables = move.camellia_tables^
        self.kalyna_keys = move.kalyna_keys^
        self.kalyna_rounds = move.kalyna_rounds
        self.kalyna_words = move.kalyna_words
        self.kalyna_tables = move.kalyna_tables^
        self.kalyna_inverse_sboxes = move.kalyna_inverse_sboxes^
        self.blowfish_p = move.blowfish_p^
        self.blowfish_s = move.blowfish_s^
        self.lea_keys = move.lea_keys^
        self.lea_rounds = move.lea_rounds
        self.hight_keys = move.hight_keys^
        self.cast_keys = move.cast_keys^
        self.cast_rounds = move.cast_rounds
        self.serpent_keys = move.serpent_keys^
        self.shacal2_keys = move.shacal2_keys^
        self.aria_encrypt_keys = move.aria_encrypt_keys^
        self.aria_decrypt_keys = move.aria_decrypt_keys^
        self.aria_rounds = move.aria_rounds
        self.aria_tables = move.aria_tables^
        self.simon32_keys = move.simon32_keys^
        self.tea_keys = move.tea_keys^
        self.simon64_keys = move.simon64_keys^
        self.simeck16_keys = move.simeck16_keys^
        self.simeck32_keys = move.simeck32_keys^
        self.des_first = move.des_first^
        self.des_second = move.des_second^
        self.des_third = move.des_third^
        self.des_whitening0 = move.des_whitening0
        self.des_whitening1 = move.des_whitening1
        self.sm4_schedule = move.sm4_schedule^
        self.sm4_tables = move.sm4_tables^
        self.rc5_schedule = move.rc5_schedule^
        self.rc6_schedule = move.rc6_schedule^
        self.rc2_schedule = move.rc2_schedule^
        self.gost_keys = move.gost_keys^
        self.gost_tables = move.gost_tables^
        self.threeway_encrypt_keys = move.threeway_encrypt_keys^
        self.threeway_decrypt_keys = move.threeway_decrypt_keys^
        self.mars_keys = move.mars_keys^
        self.mars_sbox = move.mars_sbox^
        self.idea_encrypt_keys = move.idea_encrypt_keys^
        self.idea_decrypt_keys = move.idea_decrypt_keys^
        self.safer_keys = move.safer_keys^
        self.safer_rounds = move.safer_rounds
        self.cham16_keys = move.cham16_keys^
        self.cham32_keys = move.cham32_keys^
        self.seed_keys = move.seed_keys^
        self.seed_tables = move.seed_tables^
        self.skipjack_key = move.skipjack_key^
        self.skipjack_table = move.skipjack_table^
        self.shark_encrypt_keys = move.shark_encrypt_keys^
        self.shark_decrypt_keys = move.shark_decrypt_keys^
        self.shark_encrypt_tables = move.shark_encrypt_tables^
        self.shark_decrypt_tables = move.shark_decrypt_tables^
        self.square_encrypt_keys = move.square_encrypt_keys^
        self.square_decrypt_keys = move.square_decrypt_keys^
        self.square_encrypt_tables = move.square_encrypt_tables^
        self.square_decrypt_tables = move.square_decrypt_tables^
        self.cham32_rounds = move.cham32_rounds
        self.speck32_keys = move.speck32_keys^
        self.speck64_keys = move.speck64_keys^
        self.threefish_key = move.threefish_key^
        self.threefish_tweak = move.threefish_tweak^
        self.threefish_words = move.threefish_words

    @always_inline("nodebug")
    def decrypt_aes_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        self.aes.decrypt_into(block, output, output_offset)

    @always_inline("nodebug")
    def encrypt_aes_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        self.aes.encrypt_into(block, output, output_offset)

    @always_inline("nodebug")
    def process_threefish_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        decrypt: Bool,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        if self.threefish_words == 4:
            threefish_process_into[4](
                decrypt,
                self.threefish_key,
                self.threefish_tweak,
                block,
                output,
                output_offset,
            )
        elif self.threefish_words == 8:
            threefish_process_into[8](
                decrypt,
                self.threefish_key,
                self.threefish_tweak,
                block,
                output,
                output_offset,
            )
        else:
            threefish_process_into[16](
                decrypt,
                self.threefish_key,
                self.threefish_tweak,
                block,
                output,
                output_offset,
            )

    def encrypt_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        comptime if CompilationTarget.is_x86():
            if self.kind == 37:
                if len(block) != 16:
                    raise Error("AES block must be 16 bytes")
                if output_offset < 0 or output_offset + 16 > len(output):
                    raise Error("cipher output span is too short")
                self.encrypt_aes_into(block, output, output_offset)
                return
        if self.kind == 1:
            threeway_process_into[False](
                self.threeway_encrypt_keys, block, output, output_offset
            )
            return
        if self.kind == 2:
            gost_process_into[False](
                self.gost_keys,
                self.gost_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 3:
            rc2_process_into[False](
                self.rc2_schedule, block, output, output_offset
            )
            return
        if self.kind == 4:
            tea_process_into[False, False](
                self.tea_keys, block, output, output_offset
            )
            return
        if self.kind == 5:
            tea_process_into[True, False](
                self.tea_keys, block, output, output_offset
            )
            return
        if self.kind == 6:
            simon_process_into32[False](
                self.simon32_keys, block, output, output_offset
            )
            return
        if self.kind == 7:
            simon_process_into64[False](
                self.simon64_keys, block, output, output_offset
            )
            return
        if self.kind == 8:
            speck_process_into32[False](
                self.speck32_keys, block, output, output_offset
            )
            return
        if self.kind == 9:
            speck_process_into64[False](
                self.speck64_keys, block, output, output_offset
            )
            return
        if self.kind == 10:
            simeck_process_into16[False](
                self.simeck16_keys, block, output, output_offset
            )
            return
        if self.kind == 11:
            simeck_process_into32[False](
                self.simeck32_keys, block, output, output_offset
            )
            return
        if self.kind == 12:
            cham_process_into16[False](
                self.cham16_keys, block, output, output_offset
            )
            return
        if self.kind == 13 and self.cham32_rounds == 80:
            cham_process_into32[False, 80](
                self.cham32_keys, block, output, output_offset
            )
            return
        if self.kind == 13 and self.cham32_rounds == 96:
            cham_process_into32[False, 96](
                self.cham32_keys, block, output, output_offset
            )
            return
        if self.kind == 14:
            aria_process_into(
                self.aria_encrypt_keys,
                self.aria_rounds,
                self.aria_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 15:
            kalyna_process_into(
                False,
                self.kalyna_keys,
                self.kalyna_rounds,
                self.kalyna_words,
                self.kalyna_tables,
                self.kalyna_inverse_sboxes,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 16:
            lea_process_into[False](
                self.lea_keys,
                self.lea_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 17:
            safer_process_into(
                False,
                self.safer_keys,
                self.safer_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 18:
            shark_process_into(
                self.shark_encrypt_keys,
                self.shark_encrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 19:
            square_process_into(
                False,
                self.square_encrypt_keys,
                self.square_encrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 20:
            twofish_process_into(
                False,
                self.twofish_round_keys,
                self.twofish_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 21:
            camellia_process_into(
                self.camellia_encrypt_kw,
                self.camellia_encrypt_rounds,
                self.camellia_encrypt_extra,
                self.camellia_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kalyna_words != 0:
            kalyna_process_into(
                False,
                self.kalyna_keys,
                self.kalyna_rounds,
                self.kalyna_words,
                self.kalyna_tables,
                self.kalyna_inverse_sboxes,
                block,
                output,
                output_offset,
            )
            return
        if self.lea_rounds != 0:
            lea_process_into[False](
                self.lea_keys,
                self.lea_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 22:
            hight_process_into[False](
                self.hight_keys, block, output, output_offset
            )
            return
        if self.kind == 23:
            cast128_process_into(
                False,
                self.cast_keys,
                self.cast_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 24:
            cast256_process_into[False](
                self.cast_keys, block, output, output_offset
            )
            return
        if self.aria_rounds != 0:
            aria_process_into(
                self.aria_encrypt_keys,
                self.aria_rounds,
                self.aria_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 27:
            des_process_into(
                self.algorithm,
                False,
                self.des_first,
                self.des_second,
                self.des_third,
                self.des_whitening0,
                self.des_whitening1,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 28:
            sm4_process_tables_into[False](
                self.sm4_schedule,
                self.sm4_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 29:
            blowfish_process_into[False](
                self.blowfish_p,
                self.blowfish_s,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 30:
            mars_process_into(
                False,
                self.mars_keys,
                self.mars_sbox,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 31:
            rc5_process_into[False](
                self.rc5_schedule, block, output, output_offset
            )
            return
        if self.kind == 32:
            rc6_process_into[False](
                self.rc6_schedule, block, output, output_offset
            )
            return
        if self.kind == 33:
            self.process_threefish_into(False, block, output, output_offset)
            return
        if self.kind == 34:
            idea_process_into(
                self.idea_encrypt_keys,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 26:
            shacal2_process_into[False](
                self.shacal2_keys, block, output, output_offset
            )
            return
        if self.safer_rounds != 0:
            safer_process_into(
                False,
                self.safer_keys,
                self.safer_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 18:
            shark_process_into(
                self.shark_encrypt_keys,
                self.shark_encrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 19:
            square_process_into(
                False,
                self.square_encrypt_keys,
                self.square_encrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        var size = _block_size(self.algorithm)
        if self.kind == 35:
            skipjack_process_into[False](
                self.skipjack_key,
                self.skipjack_table,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 36:
            seed_process_into[False](
                self.seed_keys,
                self.seed_tables,
                block,
                output,
                output_offset,
            )
            return
        if len(block) != size:
            raise Error("block has invalid length")
        if output_offset < 0 or output_offset + size > len(output):
            raise Error("cipher output span is too short")
        var transformed = self.encrypt(block)
        for i in range(size):
            output[output_offset + i] = transformed[i]

    def decrypt_into[
        block_origin: Origin, output_origin: MutOrigin
    ](
        self,
        block: Span[UInt8, block_origin],
        output: Span[mut=True, UInt8, output_origin],
        output_offset: Int,
    ) raises:
        comptime if CompilationTarget.is_x86():
            if self.kind == 37:
                if len(block) != 16:
                    raise Error("AES block must be 16 bytes")
                if output_offset < 0 or output_offset + 16 > len(output):
                    raise Error("cipher output span is too short")
                self.decrypt_aes_into(block, output, output_offset)
                return
        if self.kind == 1:
            threeway_process_into[True](
                self.threeway_decrypt_keys, block, output, output_offset
            )
            return
        if self.kind == 2:
            gost_process_into[True](
                self.gost_keys,
                self.gost_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 3:
            rc2_process_into[True](
                self.rc2_schedule, block, output, output_offset
            )
            return
        if self.kind == 4:
            tea_process_into[False, True](
                self.tea_keys, block, output, output_offset
            )
            return
        if self.kind == 5:
            tea_process_into[True, True](
                self.tea_keys, block, output, output_offset
            )
            return
        if self.kind == 6:
            simon_process_into32[True](
                self.simon32_keys, block, output, output_offset
            )
            return
        if self.kind == 7:
            simon_process_into64[True](
                self.simon64_keys, block, output, output_offset
            )
            return
        if self.kind == 8:
            speck_process_into32[True](
                self.speck32_keys, block, output, output_offset
            )
            return
        if self.kind == 9:
            speck_process_into64[True](
                self.speck64_keys, block, output, output_offset
            )
            return
        if self.kind == 10:
            simeck_process_into16[True](
                self.simeck16_keys, block, output, output_offset
            )
            return
        if self.kind == 11:
            simeck_process_into32[True](
                self.simeck32_keys, block, output, output_offset
            )
            return
        if self.kind == 12:
            cham_process_into16[True](
                self.cham16_keys, block, output, output_offset
            )
            return
        if self.kind == 13 and self.cham32_rounds == 80:
            cham_process_into32[True, 80](
                self.cham32_keys, block, output, output_offset
            )
            return
        if self.kind == 13 and self.cham32_rounds == 96:
            cham_process_into32[True, 96](
                self.cham32_keys, block, output, output_offset
            )
            return
        if self.kind == 14:
            aria_process_into(
                self.aria_decrypt_keys,
                self.aria_rounds,
                self.aria_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 15:
            kalyna_process_into(
                True,
                self.kalyna_keys,
                self.kalyna_rounds,
                self.kalyna_words,
                self.kalyna_tables,
                self.kalyna_inverse_sboxes,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 16:
            lea_process_into[True](
                self.lea_keys,
                self.lea_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 17:
            safer_process_into(
                True,
                self.safer_keys,
                self.safer_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 18:
            shark_process_into(
                self.shark_decrypt_keys,
                self.shark_decrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 19:
            square_process_into(
                True,
                self.square_decrypt_keys,
                self.square_decrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 20:
            twofish_process_into(
                True,
                self.twofish_round_keys,
                self.twofish_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 21:
            camellia_process_into(
                self.camellia_decrypt_kw,
                self.camellia_decrypt_rounds,
                self.camellia_decrypt_extra,
                self.camellia_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kalyna_words != 0:
            kalyna_process_into(
                True,
                self.kalyna_keys,
                self.kalyna_rounds,
                self.kalyna_words,
                self.kalyna_tables,
                self.kalyna_inverse_sboxes,
                block,
                output,
                output_offset,
            )
            return
        if self.lea_rounds != 0:
            lea_process_into[True](
                self.lea_keys,
                self.lea_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 22:
            hight_process_into[True](
                self.hight_keys, block, output, output_offset
            )
            return
        if self.kind == 23:
            cast128_process_into(
                True,
                self.cast_keys,
                self.cast_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 24:
            cast256_process_into[True](
                self.cast_keys, block, output, output_offset
            )
            return
        if self.aria_rounds != 0:
            aria_process_into(
                self.aria_decrypt_keys,
                self.aria_rounds,
                self.aria_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 27:
            des_process_into(
                self.algorithm,
                True,
                self.des_first,
                self.des_second,
                self.des_third,
                self.des_whitening0,
                self.des_whitening1,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 28:
            sm4_process_tables_into[True](
                self.sm4_schedule,
                self.sm4_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 29:
            blowfish_process_into[True](
                self.blowfish_p,
                self.blowfish_s,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 30:
            mars_process_into(
                True,
                self.mars_keys,
                self.mars_sbox,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 31:
            rc5_process_into[True](
                self.rc5_schedule, block, output, output_offset
            )
            return
        if self.kind == 32:
            rc6_process_into[True](
                self.rc6_schedule, block, output, output_offset
            )
            return
        if self.kind == 33:
            self.process_threefish_into(True, block, output, output_offset)
            return
        if self.kind == 34:
            idea_process_into(
                self.idea_decrypt_keys, block, output, output_offset
            )
            return
        if self.kind == 26:
            shacal2_process_into[True](
                self.shacal2_keys, block, output, output_offset
            )
            return
        if self.safer_rounds != 0:
            safer_process_into(
                True,
                self.safer_keys,
                self.safer_rounds,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 18:
            shark_process_into(
                self.shark_decrypt_keys,
                self.shark_decrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 19:
            square_process_into(
                True,
                self.square_decrypt_keys,
                self.square_decrypt_tables,
                block,
                output,
                output_offset,
            )
            return
        var size = _block_size(self.algorithm)
        if self.kind == 35:
            skipjack_process_into[True](
                self.skipjack_key,
                self.skipjack_table,
                block,
                output,
                output_offset,
            )
            return
        if self.kind == 36:
            seed_process_into[True](
                self.seed_keys,
                self.seed_tables,
                block,
                output,
                output_offset,
            )
            return
        if len(block) != size:
            raise Error("block has invalid length")
        if output_offset < 0 or output_offset + size > len(output):
            raise Error("cipher output span is too short")
        var transformed = self.decrypt(block)
        for i in range(size):
            output[output_offset + i] = transformed[i]

    def encrypt[
        block_origin: Origin
    ](self, block: Span[UInt8, block_origin]) raises -> List[UInt8]:
        if self.kind == 37:
            var output = List[UInt8](length=16, fill=0)
            self.encrypt_aes_into(block, Span(output), 0)
            return output^
        if self.kind == 4 or self.kind == 5:
            var output = List[UInt8](length=8, fill=0)
            if self.kind == 4:
                tea_process_into[False, False](
                    self.tea_keys, block, Span(output), 0
                )
            else:
                tea_process_into[True, False](
                    self.tea_keys, block, Span(output), 0
                )
            return output^
        if self.kind == 20:
            return twofish_process_prepared_tables(
                False, self.twofish_round_keys, self.twofish_tables, block
            )
        if self.kind == 21:
            return camellia_process_prepared(
                self.camellia_encrypt_kw,
                self.camellia_encrypt_rounds,
                self.camellia_encrypt_extra,
                self.camellia_tables,
                block,
            )
        if self.kalyna_words != 0:
            return kalyna_process_prepared_tables(
                False,
                self.kalyna_keys,
                self.kalyna_rounds,
                self.kalyna_words,
                self.kalyna_tables,
                self.kalyna_inverse_sboxes,
                block,
            )
        if self.kind == 29:
            return blowfish_process_prepared(
                False, self.blowfish_p, self.blowfish_s, block
            )
        if self.lea_rounds != 0:
            return lea_encrypt_prepared(self.lea_keys, self.lea_rounds, block)
        if self.kind == 22:
            return hight_process_prepared[False](self.hight_keys, block)
        if self.kind == 23:
            return cast128_process_prepared(
                False, self.cast_keys, self.cast_rounds, block
            )
        if self.kind == 24:
            return cast256_process_prepared(False, self.cast_keys, block)
        if self.kind == 25:
            return serpent_process_prepared(False, self.serpent_keys, block)
        if self.kind == 26:
            return shacal2_process_prepared(False, self.shacal2_keys, block)
        if self.aria_rounds != 0:
            return aria_process_prepared(
                self.aria_encrypt_keys,
                self.aria_rounds,
                self.aria_tables,
                block,
            )
        if self.kind == 6:
            return simon_encrypt_prepared32(self.simon32_keys, block)
        if self.kind == 7:
            return simon_encrypt_prepared64(self.simon64_keys, block)
        if self.kind == 10:
            return simeck_process_prepared16(False, self.simeck16_keys, block)
        if self.kind == 11:
            return simeck_process_prepared32(False, self.simeck32_keys, block)
        if self.kind == 27:
            return des_process_prepared(
                self.algorithm,
                False,
                self.des_first,
                self.des_second,
                self.des_third,
                self.des_whitening0,
                self.des_whitening1,
                block,
            )
        if self.kind == 28:
            return sm4_process_prepared(self.sm4_schedule, block, False)
        if self.kind == 1:
            return threeway_process_prepared(
                False, self.threeway_encrypt_keys, block
            )
        if self.kind == 2:
            return gost_process_prepared(
                False, self.gost_keys, self.gost_tables, block
            )
        if self.kind == 3:
            return rc2_process_prepared(False, self.rc2_schedule, block)
        if self.kind == 31:
            return rc5_process_prepared(False, self.rc5_schedule, block)
        if self.kind == 32:
            return rc6_process_prepared(False, self.rc6_schedule, block)
        if self.kind == 30:
            return mars_process_prepared(
                False, self.mars_keys, self.mars_sbox, block
            )
        if self.kind == 34:
            var output = List[UInt8](length=8, fill=0)
            idea_process_into(self.idea_encrypt_keys, block, Span(output), 0)
            return output^
        if self.kind == 35:
            var output = List[UInt8](length=8, fill=0)
            skipjack_process_into[False](
                self.skipjack_key,
                self.skipjack_table,
                block,
                Span(output),
                0,
            )
            return output^
        if self.kind == 12:
            return cham_encrypt_prepared16(self.cham16_keys, block)
        if self.cham32_rounds == 80:
            return cham_encrypt_prepared32[80](self.cham32_keys, block)
        if self.cham32_rounds == 96:
            return cham_encrypt_prepared32[96](self.cham32_keys, block)
        if self.kind == 36:
            var output = List[UInt8](length=16, fill=0)
            seed_process_into[False](
                self.seed_keys,
                self.seed_tables,
                block,
                Span(output),
                0,
            )
            return output^
        if self.kind == 8:
            return speck_encrypt_prepared32(self.speck32_keys, block)
        if self.kind == 9:
            return speck_encrypt_prepared64(self.speck64_keys, block)
        if self.threefish_words == 4:
            return threefish_process_prepared[4](
                False, self.threefish_key, self.threefish_tweak, block
            )
        if self.threefish_words == 8:
            return threefish_process_prepared[8](
                False, self.threefish_key, self.threefish_tweak, block
            )
        if self.threefish_words == 16:
            return threefish_process_prepared[16](
                False, self.threefish_key, self.threefish_tweak, block
            )
        if self.safer_rounds != 0:
            return safer_process_prepared(
                False, self.safer_keys, self.safer_rounds, block
            )
        if self.kind == 18:
            return shark_process_prepared_tables(
                self.shark_encrypt_keys, self.shark_encrypt_tables, block
            )
        if self.kind == 19:
            return square_process_prepared_tables(
                False,
                self.square_encrypt_keys,
                self.square_encrypt_tables,
                block,
            )
        raise Error("unknown prepared cipher")

    def decrypt[
        block_origin: Origin
    ](self, block: Span[UInt8, block_origin]) raises -> List[UInt8]:
        if self.kind == 37:
            var output = List[UInt8](length=16, fill=0)
            self.decrypt_aes_into(block, Span(output), 0)
            return output^
        if self.kind == 4 or self.kind == 5:
            var output = List[UInt8](length=8, fill=0)
            if self.kind == 4:
                tea_process_into[False, True](
                    self.tea_keys, block, Span(output), 0
                )
            else:
                tea_process_into[True, True](
                    self.tea_keys, block, Span(output), 0
                )
            return output^
        if self.kind == 20:
            return twofish_process_prepared_tables(
                True, self.twofish_round_keys, self.twofish_tables, block
            )
        if self.kind == 21:
            return camellia_process_prepared(
                self.camellia_decrypt_kw,
                self.camellia_decrypt_rounds,
                self.camellia_decrypt_extra,
                self.camellia_tables,
                block,
            )
        if self.kalyna_words != 0:
            return kalyna_process_prepared_tables(
                True,
                self.kalyna_keys,
                self.kalyna_rounds,
                self.kalyna_words,
                self.kalyna_tables,
                self.kalyna_inverse_sboxes,
                block,
            )
        if self.kind == 29:
            return blowfish_process_prepared(
                True, self.blowfish_p, self.blowfish_s, block
            )
        if self.lea_rounds != 0:
            return lea_decrypt_prepared(self.lea_keys, self.lea_rounds, block)
        if self.kind == 22:
            return hight_process_prepared[True](self.hight_keys, block)
        if self.kind == 23:
            return cast128_process_prepared(
                True, self.cast_keys, self.cast_rounds, block
            )
        if self.kind == 24:
            return cast256_process_prepared(True, self.cast_keys, block)
        if self.kind == 25:
            return serpent_process_prepared(True, self.serpent_keys, block)
        if self.kind == 26:
            return shacal2_process_prepared(True, self.shacal2_keys, block)
        if self.aria_rounds != 0:
            return aria_process_prepared(
                self.aria_decrypt_keys,
                self.aria_rounds,
                self.aria_tables,
                block,
            )
        if self.kind == 6:
            return simon_decrypt_prepared32(self.simon32_keys, block)
        if self.kind == 7:
            return simon_decrypt_prepared64(self.simon64_keys, block)
        if self.kind == 10:
            return simeck_process_prepared16(True, self.simeck16_keys, block)
        if self.kind == 11:
            return simeck_process_prepared32(True, self.simeck32_keys, block)
        if self.kind == 27:
            return des_process_prepared(
                self.algorithm,
                True,
                self.des_first,
                self.des_second,
                self.des_third,
                self.des_whitening0,
                self.des_whitening1,
                block,
            )
        if self.kind == 28:
            return sm4_process_prepared(self.sm4_schedule, block, True)
        if self.kind == 1:
            return threeway_process_prepared(
                True, self.threeway_decrypt_keys, block
            )
        if self.kind == 2:
            return gost_process_prepared(
                True, self.gost_keys, self.gost_tables, block
            )
        if self.kind == 3:
            return rc2_process_prepared(True, self.rc2_schedule, block)
        if self.kind == 31:
            return rc5_process_prepared(True, self.rc5_schedule, block)
        if self.kind == 32:
            return rc6_process_prepared(True, self.rc6_schedule, block)
        if self.kind == 30:
            return mars_process_prepared(
                True, self.mars_keys, self.mars_sbox, block
            )
        if self.kind == 34:
            var output = List[UInt8](length=8, fill=0)
            idea_process_into(self.idea_decrypt_keys, block, Span(output), 0)
            return output^
        if self.kind == 12:
            return cham_decrypt_prepared16(self.cham16_keys, block)
        if self.kind == 35:
            var output = List[UInt8](length=8, fill=0)
            skipjack_process_into[True](
                self.skipjack_key,
                self.skipjack_table,
                block,
                Span(output),
                0,
            )
            return output^
        if self.cham32_rounds == 80:
            return cham_decrypt_prepared32[80](self.cham32_keys, block)
        if self.cham32_rounds == 96:
            return cham_decrypt_prepared32[96](self.cham32_keys, block)
        if self.kind == 36:
            var output = List[UInt8](length=16, fill=0)
            seed_process_into[True](
                self.seed_keys,
                self.seed_tables,
                block,
                Span(output),
                0,
            )
            return output^
        if self.kind == 8:
            return speck_decrypt_prepared32(self.speck32_keys, block)
        if self.kind == 9:
            return speck_decrypt_prepared64(self.speck64_keys, block)
        if self.threefish_words == 4:
            return threefish_process_prepared[4](
                True, self.threefish_key, self.threefish_tweak, block
            )
        if self.threefish_words == 8:
            return threefish_process_prepared[8](
                True, self.threefish_key, self.threefish_tweak, block
            )
        if self.threefish_words == 16:
            return threefish_process_prepared[16](
                True, self.threefish_key, self.threefish_tweak, block
            )
        if self.safer_rounds != 0:
            return safer_process_prepared(
                True, self.safer_keys, self.safer_rounds, block
            )
        if self.kind == 18:
            return shark_process_prepared_tables(
                self.shark_decrypt_keys, self.shark_decrypt_tables, block
            )
        if self.kind == 19:
            return square_process_prepared_tables(
                True,
                self.square_decrypt_keys,
                self.square_decrypt_tables,
                block,
            )
        raise Error("unknown prepared cipher")


@always_inline("nodebug")
def _increment(mut counter: List[UInt8]):
    for offset in range(len(counter)):
        var i = len(counter) - 1 - offset
        counter[i] += 1
        if counter[i] != 0:
            return


@always_inline("nodebug")
def _fill_counters4[
    blocks: Int
](mut feedback: List[UInt8], mut counters: List[UInt8]):
    var feedback_pointer = Span(feedback).unsafe_ptr()
    var counters_pointer = Span(counters).unsafe_ptr()
    var word = bitcast[DType.uint32, 1](
        feedback_pointer.unsafe_load[width=4](0)
    )
    var counter = _byte_swap32(UInt32(word[0]))
    comptime for block in range(blocks):
        word[0] = _byte_swap32(counter)
        counters_pointer.unsafe_store[width=4](
            block * 4, bitcast[DType.uint8, 4](word)
        )
        counter += 1
    word[0] = _byte_swap32(counter)
    feedback_pointer.unsafe_store[width=4](0, bitcast[DType.uint8, 4](word))


@always_inline("nodebug")
def _fill_counters8[
    blocks: Int
](mut feedback: List[UInt8], mut counters: List[UInt8]):
    var feedback_pointer = Span(feedback).unsafe_ptr()
    var counters_pointer = Span(counters).unsafe_ptr()
    var word = bitcast[DType.uint64, 1](
        feedback_pointer.unsafe_load[width=8](0)
    )
    var counter = _byte_swap64(UInt64(word[0]))
    comptime for block in range(blocks):
        word[0] = _byte_swap64(counter)
        counters_pointer.unsafe_store[width=8](
            block * 8, bitcast[DType.uint8, 8](word)
        )
        counter += 1
    word[0] = _byte_swap64(counter)
    feedback_pointer.unsafe_store[width=8](0, bitcast[DType.uint8, 8](word))


@always_inline("nodebug")
def _fill_counters16[
    blocks: Int
](mut feedback: List[UInt8], mut counters: List[UInt8]):
    var feedback_pointer = Span(feedback).unsafe_ptr()
    var counters_pointer = Span(counters).unsafe_ptr()
    var words = bitcast[DType.uint64, 2](
        feedback_pointer.unsafe_load[width=16](0)
    )
    var counter_high = _byte_swap64(UInt64(words[0]))
    var counter_low = _byte_swap64(UInt64(words[1]))
    comptime for block in range(blocks):
        words[0] = _byte_swap64(counter_high)
        words[1] = _byte_swap64(counter_low)
        counters_pointer.unsafe_store[width=16](
            block * 16, bitcast[DType.uint8, 16](words)
        )
        counter_low += 1
        if counter_low == 0:
            counter_high += 1
    words[0] = _byte_swap64(counter_high)
    words[1] = _byte_swap64(counter_low)
    feedback_pointer.unsafe_store[width=16](0, bitcast[DType.uint8, 16](words))


def _process_mode[
    key_origin: Origin, iv_origin: Origin, input_origin: Origin
](
    algorithm: BlockCipherAlgorithm,
    mode: CipherMode,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    var cipher = algorithm
    var size = _block_size(algorithm)
    if (
        mode != CipherMode.ECB
        and mode != CipherMode.CBC
        and mode != CipherMode.CBC_CTS
        and mode != CipherMode.CFB
        and mode != CipherMode.OFB
        and mode != CipherMode.CTR
    ):
        raise Error("unknown block mode")
    if mode == CipherMode.CBC_CTS:
        if len(iv) != size:
            raise Error("mode IV has invalid length")
        if len(input) <= size:
            raise Error("CBC-CTS requires more than one block")
        if len(input) % size == 0:
            var swapped = List[UInt8](capacity=len(input))
            if encrypt:
                swapped = _process_mode(
                    algorithm, CipherMode.CBC, True, key, iv, input
                )
            else:
                for byte in input:
                    swapped.append(byte)
            var penultimate_offset = len(swapped) - 2 * size
            var last_offset = len(swapped) - size
            for i in range(size):
                var temporary = swapped[penultimate_offset + i]
                swapped[penultimate_offset + i] = swapped[last_offset + i]
                swapped[last_offset + i] = temporary
            if encrypt:
                return swapped^
            return _process_mode(
                algorithm, CipherMode.CBC, False, key, iv, Span(swapped)
            )
        var needs_inverse = not encrypt
        var prepared = _PreparedCipher(algorithm, key, needs_inverse)
        var prefix_bytes = ((len(input) - 1) // size - 1) * size
        var output = List[UInt8](length=len(input), fill=0)
        var output_span = Span(output)
        var feedback = List[UInt8](capacity=size)
        for byte in iv:
            feedback.append(byte)
        var block = List[UInt8](length=size, fill=0)
        if encrypt:
            for offset in range(0, prefix_bytes, size):
                for i in range(size):
                    block[i] = input[offset + i] ^ feedback[i]
                prepared.encrypt_into(Span(block), output_span, offset)
                for i in range(size):
                    feedback[i] = output[offset + i]
            var remainder = len(input) - prefix_bytes - size
            for i in range(size):
                block[i] = input[prefix_bytes + i] ^ feedback[i]
            var penultimate = List[UInt8](length=size, fill=0)
            prepared.encrypt_into(Span(block), Span(penultimate), 0)
            for i in range(size):
                block[i] = penultimate[i]
            for i in range(remainder):
                block[i] ^= input[prefix_bytes + size + i]
            prepared.encrypt_into(Span(block), output_span, prefix_bytes)
            for i in range(remainder):
                output[prefix_bytes + size + i] = penultimate[i]
            return output^
        var decrypted = List[UInt8](length=size, fill=0)
        for offset in range(0, prefix_bytes, size):
            for i in range(size):
                block[i] = input[offset + i]
            prepared.decrypt_into(Span(block), Span(decrypted), 0)
            for i in range(size):
                output[offset + i] = decrypted[i] ^ feedback[i]
                feedback[i] = block[i]
        var remainder = len(input) - prefix_bytes - size
        for i in range(size):
            block[i] = input[prefix_bytes + i]
        prepared.decrypt_into(Span(block), Span(decrypted), 0)
        var stolen = List[UInt8](length=size, fill=0)
        for i in range(remainder):
            stolen[i] = input[prefix_bytes + size + i]
        for i in range(remainder, size):
            stolen[i] = decrypted[i]
        prepared.decrypt_into(Span(stolen), Span(block), 0)
        for i in range(size):
            output[prefix_bytes + i] = block[i] ^ feedback[i]
        for i in range(remainder):
            output[prefix_bytes + size + i] = decrypted[i] ^ stolen[i]
        return output^
    if mode == CipherMode.ECB or mode == CipherMode.CBC:
        if len(input) % size != 0:
            raise Error("ECB and CBC require complete blocks")
    if mode != CipherMode.ECB and len(iv) != size:
        raise Error("mode IV has invalid length")
    var needs_inverse = not encrypt and (
        mode == CipherMode.ECB or mode == CipherMode.CBC
    )
    var prepared = _PreparedCipher(algorithm, key, needs_inverse)
    var output = List[UInt8](length=len(input), fill=0)
    var feedback = List[UInt8](capacity=size)
    for byte in iv:
        feedback.append(byte)
    var input_pointer = input.unsafe_ptr()
    var output_span = Span(output)
    var output_pointer = output_span.unsafe_ptr()
    var feedback_pointer = Span(feedback).unsafe_ptr()
    comptime if CompilationTarget.is_x86():
        if cipher == BlockCipherAlgorithm.AES and mode == CipherMode.CTR:
            var counters = List[UInt8](length=128, fill=0)
            var counters_pointer = Span(counters).unsafe_ptr()
            var words = bitcast[DType.uint64, 2](
                feedback_pointer.unsafe_load[width=16](0)
            )
            var counter_high = _byte_swap64(UInt64(words[0]))
            var counter_low = _byte_swap64(UInt64(words[1]))
            var offset = 0
            while offset + 128 <= len(input):
                comptime for block in range(8):
                    words[0] = _byte_swap64(counter_high)
                    words[1] = _byte_swap64(counter_low)
                    counters_pointer.unsafe_store[width=16](
                        block * 16, bitcast[DType.uint8, 16](words)
                    )
                    counter_low += 1
                    if counter_low == 0:
                        counter_high += 1
                prepared.aes.encrypt_eight(
                    Span(counters),
                    0,
                    input,
                    offset,
                    output_span,
                    offset,
                )
                offset += 128
            while offset + 64 <= len(input):
                comptime for block in range(4):
                    words[0] = _byte_swap64(counter_high)
                    words[1] = _byte_swap64(counter_low)
                    counters_pointer.unsafe_store[width=16](
                        block * 16, bitcast[DType.uint8, 16](words)
                    )
                    counter_low += 1
                    if counter_low == 0:
                        counter_high += 1
                prepared.aes.encrypt_four(
                    Span(counters),
                    0,
                    input,
                    offset,
                    output_span,
                    offset,
                )
                offset += 64
            while offset < len(input):
                words[0] = _byte_swap64(counter_high)
                words[1] = _byte_swap64(counter_low)
                counters_pointer.unsafe_store[width=16](
                    0, bitcast[DType.uint8, 16](words)
                )
                var stream = bitcast[DType.uint8, 16](
                    prepared.aes.encrypt_state(Span(counters), 0)
                )
                var count = min(16, len(input) - offset)
                for i in range(count):
                    output_pointer.unsafe_store(
                        offset + i,
                        input_pointer.unsafe_load(offset + i) ^ stream[i],
                    )
                counter_low += 1
                if counter_low == 0:
                    counter_high += 1
                offset += 16
            return output^
        if cipher == BlockCipherAlgorithm.AES and mode == CipherMode.OFB:
            for offset in range(0, len(input), 16):
                var stream = bitcast[DType.uint8, 16](
                    prepared.aes.encrypt_state(Span(feedback), 0)
                )
                feedback_pointer.unsafe_store[width=16](0, stream)
                var count = min(16, len(input) - offset)
                if count == 16:
                    output_pointer.unsafe_store[width=16](
                        offset,
                        input_pointer.unsafe_load[width=16](offset) ^ stream,
                    )
                else:
                    for i in range(count):
                        output_pointer.unsafe_store(
                            offset + i,
                            input_pointer.unsafe_load(offset + i) ^ stream[i],
                        )
            return output^
        if cipher == BlockCipherAlgorithm.AES and mode == CipherMode.CFB:
            for offset in range(0, len(input), 16):
                var stream = bitcast[DType.uint8, 16](
                    prepared.aes.encrypt_state(Span(feedback), 0)
                )
                var count = min(16, len(input) - offset)
                if count == 16:
                    var source = input_pointer.unsafe_load[width=16](offset)
                    var result = source ^ stream
                    output_pointer.unsafe_store[width=16](offset, result)
                    feedback_pointer.unsafe_store[width=16](
                        0, result if encrypt else source
                    )
                else:
                    for i in range(count):
                        output_pointer.unsafe_store(
                            offset + i,
                            input_pointer.unsafe_load(offset + i) ^ stream[i],
                        )
            return output^
        if (
            cipher == BlockCipherAlgorithm.AES
            and mode == CipherMode.ECB
            and encrypt
        ):
            var zeros = List[UInt8](length=128, fill=0)
            var offset = 0
            while offset + 128 <= len(input):
                prepared.aes.encrypt_eight(
                    input,
                    offset,
                    Span(zeros),
                    0,
                    output_span,
                    offset,
                )
                offset += 128
            while offset + 64 <= len(input):
                prepared.aes.encrypt_four(
                    input,
                    offset,
                    Span(zeros),
                    0,
                    output_span,
                    offset,
                )
                offset += 64
            while offset < len(input):
                output_pointer.unsafe_store[width=16](
                    offset,
                    bitcast[DType.uint8, 16](
                        prepared.aes.encrypt_state(input, offset)
                    ),
                )
                offset += 16
            return output^
        if (
            cipher == BlockCipherAlgorithm.AES
            and mode == CipherMode.CBC
            and encrypt
        ):
            for offset in range(0, len(input), 16):
                feedback_pointer.unsafe_store[width=16](
                    0,
                    feedback_pointer.unsafe_load[width=16](0)
                    ^ input_pointer.unsafe_load[width=16](offset),
                )
                var encrypted = bitcast[DType.uint8, 16](
                    prepared.aes.encrypt_state(Span(feedback), 0)
                )
                feedback_pointer.unsafe_store[width=16](0, encrypted)
                output_pointer.unsafe_store[width=16](offset, encrypted)
            return output^
        if (
            cipher == BlockCipherAlgorithm.AES
            and mode == CipherMode.ECB
            and not encrypt
        ):
            var offset = 0
            while offset + 64 <= len(input):
                prepared.aes.decrypt_four_into(
                    input,
                    offset,
                    output_span,
                    offset,
                )
                offset += 64
            while offset < len(input):
                output_pointer.unsafe_store[width=16](
                    offset,
                    bitcast[DType.uint8, 16](
                        prepared.aes.decrypt_state(input, offset)
                    ),
                )
                offset += 16
            return output^
        if (
            cipher == BlockCipherAlgorithm.AES
            and mode == CipherMode.CBC
            and not encrypt
        ):
            var offset = 0
            while offset + 64 <= len(input):
                prepared.aes.decrypt_four_into(
                    input,
                    offset,
                    output_span,
                    offset,
                )
                output_pointer.unsafe_store[width=16](
                    offset,
                    output_pointer.unsafe_load[width=16](offset)
                    ^ feedback_pointer.unsafe_load[width=16](0),
                )
                output_pointer.unsafe_store[width=16](
                    offset + 16,
                    output_pointer.unsafe_load[width=16](offset + 16)
                    ^ input_pointer.unsafe_load[width=16](offset),
                )
                output_pointer.unsafe_store[width=16](
                    offset + 32,
                    output_pointer.unsafe_load[width=16](offset + 32)
                    ^ input_pointer.unsafe_load[width=16](offset + 16),
                )
                output_pointer.unsafe_store[width=16](
                    offset + 48,
                    output_pointer.unsafe_load[width=16](offset + 48)
                    ^ input_pointer.unsafe_load[width=16](offset + 32),
                )
                feedback_pointer.unsafe_store[width=16](
                    0, input_pointer.unsafe_load[width=16](offset + 48)
                )
                offset += 64
            while offset < len(input):
                var source = input_pointer.unsafe_load[width=16](offset)
                var decrypted = bitcast[DType.uint8, 16](
                    prepared.aes.decrypt_state(input, offset)
                )
                output_pointer.unsafe_store[width=16](
                    offset,
                    decrypted ^ feedback_pointer.unsafe_load[width=16](0),
                )
                feedback_pointer.unsafe_store[width=16](0, source)
                offset += 16
            return output^
    if prepared.threefish_words != 0:
        if mode == CipherMode.ECB:
            for offset in range(0, len(input), size):
                prepared.process_threefish_into(
                    not encrypt,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            return output^
        if mode == CipherMode.CTR:
            var stream = List[UInt8](length=size, fill=0)
            var stream_pointer = Span(stream).unsafe_ptr()
            var offset = 0
            while offset + size <= len(input):
                prepared.process_threefish_into(
                    False, Span(feedback), Span(stream), 0
                )
                for chunk in range(0, size, 16):
                    output_pointer.unsafe_store[width=16](
                        offset + chunk,
                        input_pointer.unsafe_load[width=16](offset + chunk)
                        ^ stream_pointer.unsafe_load[width=16](chunk),
                    )
                _increment(feedback)
                offset += size
            if offset < len(input):
                prepared.process_threefish_into(
                    False, Span(feedback), Span(stream), 0
                )
                for i in range(len(input) - offset):
                    output_pointer.unsafe_store(
                        offset + i,
                        input_pointer.unsafe_load(offset + i)
                        ^ stream_pointer.unsafe_load(i),
                    )
            return output^
        if mode == CipherMode.CBC:
            if encrypt:
                for offset in range(0, len(input), size):
                    for chunk in range(0, size, 16):
                        feedback_pointer.unsafe_store[width=16](
                            chunk,
                            feedback_pointer.unsafe_load[width=16](chunk)
                            ^ input_pointer.unsafe_load[width=16](
                                offset + chunk
                            ),
                        )
                    prepared.process_threefish_into(
                        False, Span(feedback), output_span, offset
                    )
                    for chunk in range(0, size, 16):
                        feedback_pointer.unsafe_store[width=16](
                            chunk,
                            output_pointer.unsafe_load[width=16](
                                offset + chunk
                            ),
                        )
            else:
                for offset in range(0, len(input), size):
                    prepared.process_threefish_into(
                        True,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
                    for chunk in range(0, size, 16):
                        output_pointer.unsafe_store[width=16](
                            offset + chunk,
                            output_pointer.unsafe_load[width=16](offset + chunk)
                            ^ feedback_pointer.unsafe_load[width=16](chunk),
                        )
                        feedback_pointer.unsafe_store[width=16](
                            chunk,
                            input_pointer.unsafe_load[width=16](offset + chunk),
                        )
            return output^
        if mode == CipherMode.OFB or mode == CipherMode.CFB:
            var stream = List[UInt8](length=size, fill=0)
            for offset in range(0, len(input), size):
                prepared.process_threefish_into(
                    False, Span(feedback), Span(stream), 0
                )
                var count = min(size, len(input) - offset)
                for i in range(count):
                    output[offset + i] = input[offset + i] ^ stream[i]
                if mode == CipherMode.OFB:
                    for i in range(size):
                        feedback[i] = stream[i]
                elif count == size:
                    for i in range(size):
                        feedback[i] = output[offset + i] if encrypt else input[
                            offset + i
                        ]
            return output^
    if (
        cipher == BlockCipherAlgorithm.DES
        or cipher == BlockCipherAlgorithm.DES_XEX3
        or cipher == BlockCipherAlgorithm.DES_EDE2
        or cipher == BlockCipherAlgorithm.DES_EDE3
    ):
        if mode == CipherMode.ECB:
            for offset in range(0, len(input), 8):
                des_process_into(
                    algorithm,
                    not encrypt,
                    prepared.des_first,
                    prepared.des_second,
                    prepared.des_third,
                    prepared.des_whitening0,
                    prepared.des_whitening1,
                    input[offset : offset + 8],
                    output_span,
                    offset,
                )
            return output^
        if mode == CipherMode.CBC:
            if encrypt:
                for offset in range(0, len(input), 8):
                    comptime for i in range(8):
                        feedback[i] ^= input[offset + i]
                    des_process_into(
                        algorithm,
                        False,
                        prepared.des_first,
                        prepared.des_second,
                        prepared.des_third,
                        prepared.des_whitening0,
                        prepared.des_whitening1,
                        Span(feedback),
                        output_span,
                        offset,
                    )
                    comptime for i in range(8):
                        feedback[i] = output[offset + i]
            else:
                for offset in range(0, len(input), 8):
                    des_process_into(
                        algorithm,
                        True,
                        prepared.des_first,
                        prepared.des_second,
                        prepared.des_third,
                        prepared.des_whitening0,
                        prepared.des_whitening1,
                        input[offset : offset + 8],
                        output_span,
                        offset,
                    )
                    comptime for i in range(8):
                        output[offset + i] ^= feedback[i]
                        feedback[i] = input[offset + i]
            return output^
        if mode == CipherMode.CTR:
            var offset = 0
            while offset + 8 <= len(input):
                des_process_into(
                    algorithm,
                    False,
                    prepared.des_first,
                    prepared.des_second,
                    prepared.des_third,
                    prepared.des_whitening0,
                    prepared.des_whitening1,
                    Span(feedback),
                    output_span,
                    offset,
                )
                comptime for i in range(8):
                    output[offset + i] ^= input[offset + i]
                _increment(feedback)
                offset += 8
            if offset < len(input):
                var stream = List[UInt8](length=8, fill=0)
                des_process_into(
                    algorithm,
                    False,
                    prepared.des_first,
                    prepared.des_second,
                    prepared.des_third,
                    prepared.des_whitening0,
                    prepared.des_whitening1,
                    Span(feedback),
                    Span(stream),
                    0,
                )
                for i in range(len(input) - offset):
                    output[offset + i] = input[offset + i] ^ stream[i]
            return output^
    if (
        cipher == BlockCipherAlgorithm.CAST128
        or cipher == BlockCipherAlgorithm.CAST256
    ) and mode == CipherMode.ECB:
        for offset in range(0, len(input), size):
            if cipher == BlockCipherAlgorithm.CAST128:
                cast128_process_into(
                    not encrypt,
                    prepared.cast_keys,
                    prepared.cast_rounds,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            elif encrypt:
                cast256_process_into[False](
                    prepared.cast_keys,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            else:
                cast256_process_into[True](
                    prepared.cast_keys,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
        return output^
    if (
        cipher == BlockCipherAlgorithm.CAST128
        or cipher == BlockCipherAlgorithm.CAST256
    ) and mode == CipherMode.CTR:
        var stream = List[UInt8](length=size, fill=0)
        for offset in range(0, len(input), size):
            if cipher == BlockCipherAlgorithm.CAST128:
                cast128_process_into(
                    False,
                    prepared.cast_keys,
                    prepared.cast_rounds,
                    Span(feedback),
                    Span(stream),
                    0,
                )
            else:
                cast256_process_into[False](
                    prepared.cast_keys,
                    Span(feedback),
                    Span(stream),
                    0,
                )
            var count = min(size, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
        return output^
    if cipher == BlockCipherAlgorithm.HIGHT and mode == CipherMode.ECB:
        for offset in range(0, len(input), 8):
            if encrypt:
                hight_process_into[False](
                    prepared.hight_keys,
                    input[offset : offset + 8],
                    output_span,
                    offset,
                )
            else:
                hight_process_into[True](
                    prepared.hight_keys,
                    input[offset : offset + 8],
                    output_span,
                    offset,
                )
        return output^
    if cipher == BlockCipherAlgorithm.HIGHT and mode == CipherMode.CTR:
        var stream = List[UInt8](length=8, fill=0)
        for offset in range(0, len(input), 8):
            hight_process_into[False](
                prepared.hight_keys,
                Span(feedback),
                Span(stream),
                0,
            )
            var count = min(8, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
        return output^
    if cipher == BlockCipherAlgorithm.HIGHT and mode == CipherMode.CBC:
        if encrypt:
            for offset in range(0, len(input), 8):
                comptime for i in range(8):
                    feedback[i] ^= input[offset + i]
                hight_process_into[False](
                    prepared.hight_keys,
                    Span(feedback),
                    output_span,
                    offset,
                )
                comptime for i in range(8):
                    feedback[i] = output[offset + i]
        else:
            for offset in range(0, len(input), 8):
                hight_process_into[True](
                    prepared.hight_keys,
                    input[offset : offset + 8],
                    output_span,
                    offset,
                )
                comptime for i in range(8):
                    output[offset + i] ^= feedback[i]
                    feedback[i] = input[offset + i]
        return output^
    if cipher == BlockCipherAlgorithm.HIGHT and (
        mode == CipherMode.OFB or mode == CipherMode.CFB
    ):
        var stream = List[UInt8](length=8, fill=0)
        for offset in range(0, len(input), 8):
            hight_process_into[False](
                prepared.hight_keys,
                Span(feedback),
                Span(stream),
                0,
            )
            var count = min(8, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            if mode == CipherMode.OFB:
                comptime for i in range(8):
                    feedback[i] = stream[i]
            elif count == 8:
                comptime for i in range(8):
                    feedback[i] = output[offset + i] if encrypt else input[
                        offset + i
                    ]
        return output^
    if cipher == BlockCipherAlgorithm.ARIA and mode == CipherMode.ECB:
        var offset = 0
        if encrypt:
            while offset + 64 <= len(input):
                aria_process_four_into(
                    prepared.aria_encrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    input[offset : offset + 64],
                    output_span,
                    offset,
                )
                offset += 64
            while offset < len(input):
                aria_process_into(
                    prepared.aria_encrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
                offset += 16
        else:
            while offset + 64 <= len(input):
                aria_process_four_into(
                    prepared.aria_decrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    input[offset : offset + 64],
                    output_span,
                    offset,
                )
                offset += 64
            while offset < len(input):
                aria_process_into(
                    prepared.aria_decrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
                offset += 16
        return output^
    if cipher == BlockCipherAlgorithm.CAMELLIA and mode == CipherMode.ECB:
        for offset in range(0, len(input), 16):
            if encrypt:
                camellia_process_into(
                    prepared.camellia_encrypt_kw,
                    prepared.camellia_encrypt_rounds,
                    prepared.camellia_encrypt_extra,
                    prepared.camellia_tables,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
            else:
                camellia_process_into(
                    prepared.camellia_decrypt_kw,
                    prepared.camellia_decrypt_rounds,
                    prepared.camellia_decrypt_extra,
                    prepared.camellia_tables,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
        return output^
    if cipher == BlockCipherAlgorithm.ARIA and mode == CipherMode.CTR:
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            _fill_counters16[4](feedback, counters)
            aria_process_four_into(
                prepared.aria_encrypt_keys,
                prepared.aria_rounds,
                prepared.aria_tables,
                Span(counters),
                output_span,
                offset,
            )
            output_pointer.unsafe_store[width=64](
                offset,
                output_pointer.unsafe_load[width=64](offset)
                ^ input_pointer.unsafe_load[width=64](offset),
            )
            offset += 64
        var stream = List[UInt8](length=16, fill=0)
        while offset < len(input):
            aria_process_into(
                prepared.aria_encrypt_keys,
                prepared.aria_rounds,
                prepared.aria_tables,
                Span(feedback),
                Span(stream),
                0,
            )
            var count = min(16, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += 16
        return output^
    if cipher == BlockCipherAlgorithm.CAMELLIA and mode == CipherMode.CTR:
        var stream = List[UInt8](length=16, fill=0)
        for offset in range(0, len(input), 16):
            camellia_process_into(
                prepared.camellia_encrypt_kw,
                prepared.camellia_encrypt_rounds,
                prepared.camellia_encrypt_extra,
                prepared.camellia_tables,
                Span(feedback),
                Span(stream),
                0,
            )
            var count = min(16, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
        return output^
    if prepared.kalyna_words != 0:
        if mode == CipherMode.ECB:
            for offset in range(0, len(input), size):
                kalyna_process_into(
                    not encrypt,
                    prepared.kalyna_keys,
                    prepared.kalyna_rounds,
                    prepared.kalyna_words,
                    prepared.kalyna_tables,
                    prepared.kalyna_inverse_sboxes,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            return output^
        var stream = List[UInt8](length=size, fill=0)
        var stream_span = Span(stream)
        if mode == CipherMode.CBC:
            if encrypt:
                for offset in range(0, len(input), size):
                    for i in range(size):
                        stream[i] = input[offset + i] ^ feedback[i]
                    kalyna_process_into(
                        False,
                        prepared.kalyna_keys,
                        prepared.kalyna_rounds,
                        prepared.kalyna_words,
                        prepared.kalyna_tables,
                        prepared.kalyna_inverse_sboxes,
                        stream_span,
                        output_span,
                        offset,
                    )
                    for i in range(size):
                        feedback[i] = output[offset + i]
            else:
                for offset in range(0, len(input), size):
                    kalyna_process_into(
                        True,
                        prepared.kalyna_keys,
                        prepared.kalyna_rounds,
                        prepared.kalyna_words,
                        prepared.kalyna_tables,
                        prepared.kalyna_inverse_sboxes,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
                    for i in range(size):
                        output[offset + i] ^= feedback[i]
                        feedback[i] = input[offset + i]
            return output^
        if mode == CipherMode.CTR:
            for offset in range(0, len(input), size):
                kalyna_process_into(
                    False,
                    prepared.kalyna_keys,
                    prepared.kalyna_rounds,
                    prepared.kalyna_words,
                    prepared.kalyna_tables,
                    prepared.kalyna_inverse_sboxes,
                    Span(feedback),
                    stream_span,
                    0,
                )
                var count = min(size, len(input) - offset)
                for i in range(count):
                    output[offset + i] = input[offset + i] ^ stream[i]
                _increment(feedback)
            return output^
        if mode == CipherMode.OFB:
            for offset in range(0, len(input), size):
                kalyna_process_into(
                    False,
                    prepared.kalyna_keys,
                    prepared.kalyna_rounds,
                    prepared.kalyna_words,
                    prepared.kalyna_tables,
                    prepared.kalyna_inverse_sboxes,
                    Span(feedback),
                    stream_span,
                    0,
                )
                for i in range(size):
                    feedback[i] = stream[i]
                var count = min(size, len(input) - offset)
                for i in range(count):
                    output[offset + i] = input[offset + i] ^ stream[i]
            return output^
        if mode == CipherMode.CFB:
            for offset in range(0, len(input), size):
                kalyna_process_into(
                    False,
                    prepared.kalyna_keys,
                    prepared.kalyna_rounds,
                    prepared.kalyna_words,
                    prepared.kalyna_tables,
                    prepared.kalyna_inverse_sboxes,
                    Span(feedback),
                    stream_span,
                    0,
                )
                var count = min(size, len(input) - offset)
                for i in range(count):
                    output[offset + i] = input[offset + i] ^ stream[i]
                if count == size:
                    for i in range(size):
                        feedback[i] = output[offset + i] if encrypt else input[
                            offset + i
                        ]
            return output^
    if cipher == BlockCipherAlgorithm.TWOFISH:
        if mode == CipherMode.ECB:
            for offset in range(0, len(input), 16):
                twofish_process_into(
                    not encrypt,
                    prepared.twofish_round_keys,
                    prepared.twofish_tables,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
            return output^
        if mode == CipherMode.CBC:
            if encrypt:
                for offset in range(0, len(input), 16):
                    feedback_pointer.unsafe_store[width=16](
                        0,
                        input_pointer.unsafe_load[width=16](offset)
                        ^ feedback_pointer.unsafe_load[width=16](0),
                    )
                    twofish_process_into(
                        False,
                        prepared.twofish_round_keys,
                        prepared.twofish_tables,
                        Span(feedback),
                        output_span,
                        offset,
                    )
                    feedback_pointer.unsafe_store[width=16](
                        0, output_pointer.unsafe_load[width=16](offset)
                    )
            else:
                for offset in range(0, len(input), 16):
                    twofish_process_into(
                        True,
                        prepared.twofish_round_keys,
                        prepared.twofish_tables,
                        input[offset : offset + 16],
                        output_span,
                        offset,
                    )
                    output_pointer.unsafe_store[width=16](
                        offset,
                        output_pointer.unsafe_load[width=16](offset)
                        ^ feedback_pointer.unsafe_load[width=16](0),
                    )
                    feedback_pointer.unsafe_store[width=16](
                        0, input_pointer.unsafe_load[width=16](offset)
                    )
            return output^
        var stream = List[UInt8](length=16, fill=0)
        var stream_span = Span(stream)
        var stream_pointer = stream_span.unsafe_ptr()
        if mode == CipherMode.CTR:
            for offset in range(0, len(input), 16):
                twofish_process_into(
                    False,
                    prepared.twofish_round_keys,
                    prepared.twofish_tables,
                    Span(feedback),
                    stream_span,
                    0,
                )
                var count = min(16, len(input) - offset)
                for i in range(count):
                    output_pointer.unsafe_store(
                        offset + i,
                        input_pointer.unsafe_load(offset + i)
                        ^ stream_pointer.unsafe_load(i),
                    )
                _increment(feedback)
            return output^
        if mode == CipherMode.OFB:
            for offset in range(0, len(input), 16):
                twofish_process_into(
                    False,
                    prepared.twofish_round_keys,
                    prepared.twofish_tables,
                    Span(feedback),
                    stream_span,
                    0,
                )
                feedback_pointer.unsafe_store[width=16](
                    0, stream_pointer.unsafe_load[width=16](0)
                )
                var count = min(16, len(input) - offset)
                for i in range(count):
                    output_pointer.unsafe_store(
                        offset + i,
                        input_pointer.unsafe_load(offset + i)
                        ^ feedback_pointer.unsafe_load(i),
                    )
            return output^
        if mode == CipherMode.CFB:
            for offset in range(0, len(input), 16):
                twofish_process_into(
                    False,
                    prepared.twofish_round_keys,
                    prepared.twofish_tables,
                    Span(feedback),
                    stream_span,
                    0,
                )
                var count = min(16, len(input) - offset)
                for i in range(count):
                    var transformed = input_pointer.unsafe_load(
                        offset + i
                    ) ^ stream_pointer.unsafe_load(i)
                    output_pointer.unsafe_store(offset + i, transformed)
                    if count == 16:
                        feedback_pointer.unsafe_store(
                            i,
                            transformed if encrypt else input_pointer.unsafe_load(
                                offset + i
                            ),
                        )
            return output^
    if cipher == BlockCipherAlgorithm.SERPENT and mode == CipherMode.ECB:
        var offset = 0
        while offset + 128 <= len(input):
            serpent_process_eight(
                not encrypt,
                prepared.serpent_keys,
                input[offset : offset + 128],
                output_span,
                offset,
            )
            offset += 128
        while offset < len(input):
            var transformed = prepared.encrypt(
                input[offset : offset + 16]
            ) if encrypt else prepared.decrypt(input[offset : offset + 16])
            for i in range(16):
                output[offset + i] = transformed[i]
            offset += 16
        return output^
    if cipher == BlockCipherAlgorithm.SERPENT and mode == CipherMode.CTR:
        var counters = List[UInt8](length=128, fill=0)
        var offset = 0
        while offset + 128 <= len(input):
            _fill_counters16[8](feedback, counters)
            serpent_process_eight(
                False,
                prepared.serpent_keys,
                Span(counters),
                output_span,
                offset,
            )
            comptime for chunk in range(8):
                output_pointer.unsafe_store[width=16](
                    offset + chunk * 16,
                    output_pointer.unsafe_load[width=16](offset + chunk * 16)
                    ^ input_pointer.unsafe_load[width=16](offset + chunk * 16),
                )
            offset += 128
        while offset < len(input):
            var stream = prepared.encrypt(Span(feedback))
            var count = min(16, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += 16
        return output^
    if (
        cipher == BlockCipherAlgorithm.TEA
        or cipher == BlockCipherAlgorithm.XTEA
    ) and mode == CipherMode.ECB:
        var offset = 0
        while offset + 64 <= len(input):
            tea_process_eight(
                algorithm,
                not encrypt,
                prepared.tea_keys,
                input[offset : offset + 64],
                Span(output),
                offset,
            )
            offset += 64
        while offset < len(input):
            var transformed = prepared.encrypt(
                input[offset : offset + 8]
            ) if encrypt else prepared.decrypt(input[offset : offset + 8])
            for i in range(8):
                output[offset + i] = transformed[i]
            offset += 8
        return output^
    if (
        cipher == BlockCipherAlgorithm.TEA
        or cipher == BlockCipherAlgorithm.XTEA
    ) and mode == CipherMode.CTR:
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            _fill_counters8[8](feedback, counters)
            tea_process_eight(
                algorithm,
                False,
                prepared.tea_keys,
                Span(counters),
                Span(output),
                offset,
            )
            comptime for chunk in range(4):
                output_pointer.unsafe_store[width=16](
                    offset + chunk * 16,
                    output_pointer.unsafe_load[width=16](offset + chunk * 16)
                    ^ input_pointer.unsafe_load[width=16](offset + chunk * 16),
                )
            offset += 64
        while offset < len(input):
            var stream = prepared.encrypt(Span(feedback))
            var count = min(8, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += 8
        return output^
    if (
        cipher == BlockCipherAlgorithm.SPECK64
        or cipher == BlockCipherAlgorithm.SPECK128
    ) and mode == CipherMode.ECB:
        var offset = 0
        while offset + 64 <= len(input):
            if cipher == BlockCipherAlgorithm.SPECK64:
                speck_process_eight32(
                    not encrypt,
                    prepared.speck32_keys,
                    input[offset : offset + 64],
                    Span(output),
                    offset,
                )
            else:
                speck_process_four64(
                    not encrypt,
                    prepared.speck64_keys,
                    input[offset : offset + 64],
                    Span(output),
                    offset,
                )
            offset += 64
        while offset < len(input):
            if cipher == BlockCipherAlgorithm.SPECK64:
                if encrypt:
                    speck_process_into32[False](
                        prepared.speck32_keys,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
                else:
                    speck_process_into32[True](
                        prepared.speck32_keys,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
            elif encrypt:
                speck_process_into64[False](
                    prepared.speck64_keys,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            else:
                speck_process_into64[True](
                    prepared.speck64_keys,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            offset += size
        return output^
    if (
        cipher == BlockCipherAlgorithm.SPECK64
        or cipher == BlockCipherAlgorithm.SPECK128
    ) and mode == CipherMode.CBC:
        if encrypt:
            for offset in range(0, len(input), size):
                for i in range(size):
                    feedback[i] ^= input[offset + i]
                if cipher == BlockCipherAlgorithm.SPECK64:
                    speck_process_into32[False](
                        prepared.speck32_keys,
                        Span(feedback),
                        output_span,
                        offset,
                    )
                else:
                    speck_process_into64[False](
                        prepared.speck64_keys,
                        Span(feedback),
                        output_span,
                        offset,
                    )
                for i in range(size):
                    feedback[i] = output[offset + i]
        else:
            for offset in range(0, len(input), size):
                if cipher == BlockCipherAlgorithm.SPECK64:
                    speck_process_into32[True](
                        prepared.speck32_keys,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
                else:
                    speck_process_into64[True](
                        prepared.speck64_keys,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
                for i in range(size):
                    output[offset + i] ^= feedback[i]
                    feedback[i] = input[offset + i]
        return output^
    if (
        cipher == BlockCipherAlgorithm.SPECK64
        or cipher == BlockCipherAlgorithm.SPECK128
    ) and mode == CipherMode.CTR:
        var counters = List[UInt8](length=64, fill=0)
        var counters_pointer = Span(counters).unsafe_ptr()
        var offset = 0
        if cipher == BlockCipherAlgorithm.SPECK64:
            var word = bitcast[DType.uint64, 1](
                feedback_pointer.unsafe_load[width=8](0)
            )
            var counter = _byte_swap64(UInt64(word[0]))
            while offset + 64 <= len(input):
                comptime for block in range(8):
                    word[0] = _byte_swap64(counter)
                    counters_pointer.unsafe_store[width=8](
                        block * 8, bitcast[DType.uint8, 8](word)
                    )
                    counter += 1
                speck_process_eight32(
                    False,
                    prepared.speck32_keys,
                    Span(counters),
                    output_span,
                    offset,
                )
                comptime for chunk in range(4):
                    output_pointer.unsafe_store[width=16](
                        offset + chunk * 16,
                        output_pointer.unsafe_load[width=16](
                            offset + chunk * 16
                        )
                        ^ input_pointer.unsafe_load[width=16](
                            offset + chunk * 16
                        ),
                    )
                offset += 64
            word[0] = _byte_swap64(counter)
            feedback_pointer.unsafe_store[width=8](
                0, bitcast[DType.uint8, 8](word)
            )
        else:
            var words = bitcast[DType.uint64, 2](
                feedback_pointer.unsafe_load[width=16](0)
            )
            var counter_high = _byte_swap64(UInt64(words[0]))
            var counter_low = _byte_swap64(UInt64(words[1]))
            while offset + 64 <= len(input):
                comptime for block in range(4):
                    words[0] = _byte_swap64(counter_high)
                    words[1] = _byte_swap64(counter_low)
                    counters_pointer.unsafe_store[width=16](
                        block * 16, bitcast[DType.uint8, 16](words)
                    )
                    counter_low += 1
                    if counter_low == 0:
                        counter_high += 1
                speck_process_four64(
                    False,
                    prepared.speck64_keys,
                    Span(counters),
                    output_span,
                    offset,
                )
                comptime for chunk in range(4):
                    output_pointer.unsafe_store[width=16](
                        offset + chunk * 16,
                        output_pointer.unsafe_load[width=16](
                            offset + chunk * 16
                        )
                        ^ input_pointer.unsafe_load[width=16](
                            offset + chunk * 16
                        ),
                    )
                offset += 64
            words[0] = _byte_swap64(counter_high)
            words[1] = _byte_swap64(counter_low)
            feedback_pointer.unsafe_store[width=16](
                0, bitcast[DType.uint8, 16](words)
            )
        while offset + size <= len(input):
            if cipher == BlockCipherAlgorithm.SPECK64:
                speck_process_into32[False](
                    prepared.speck32_keys,
                    Span(feedback),
                    output_span,
                    offset,
                )
            else:
                speck_process_into64[False](
                    prepared.speck64_keys,
                    Span(feedback),
                    output_span,
                    offset,
                )
            for i in range(size):
                output[offset + i] ^= input[offset + i]
            _increment(feedback)
            offset += size
        if offset < len(input):
            var stream = List[UInt8](length=size, fill=0)
            if cipher == BlockCipherAlgorithm.SPECK64:
                speck_process_into32[False](
                    prepared.speck32_keys,
                    Span(feedback),
                    Span(stream),
                    0,
                )
            else:
                speck_process_into64[False](
                    prepared.speck64_keys,
                    Span(feedback),
                    Span(stream),
                    0,
                )
            for i in range(len(input) - offset):
                output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if (
        cipher == BlockCipherAlgorithm.SIMON64
        or cipher == BlockCipherAlgorithm.SIMON128
    ) and mode == CipherMode.ECB:
        var offset = 0
        while offset + 64 <= len(input):
            if cipher == BlockCipherAlgorithm.SIMON64:
                simon_process_eight32(
                    not encrypt,
                    prepared.simon32_keys,
                    input[offset : offset + 64],
                    Span(output),
                    offset,
                )
            else:
                simon_process_four64(
                    not encrypt,
                    prepared.simon64_keys,
                    input[offset : offset + 64],
                    Span(output),
                    offset,
                )
            offset += 64
        while offset < len(input):
            var transformed = prepared.encrypt(
                input[offset : offset + size]
            ) if encrypt else prepared.decrypt(input[offset : offset + size])
            for i in range(size):
                output[offset + i] = transformed[i]
            offset += size
        return output^
    if (
        cipher == BlockCipherAlgorithm.SIMON64
        or cipher == BlockCipherAlgorithm.SIMON128
    ) and mode == CipherMode.CTR:
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            if cipher == BlockCipherAlgorithm.SIMON64:
                _fill_counters8[8](feedback, counters)
            else:
                _fill_counters16[4](feedback, counters)
            if cipher == BlockCipherAlgorithm.SIMON64:
                simon_process_eight32(
                    False,
                    prepared.simon32_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            else:
                simon_process_four64(
                    False,
                    prepared.simon64_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            comptime for chunk in range(4):
                output_pointer.unsafe_store[width=16](
                    offset + chunk * 16,
                    output_pointer.unsafe_load[width=16](offset + chunk * 16)
                    ^ input_pointer.unsafe_load[width=16](offset + chunk * 16),
                )
            offset += 64
        while offset < len(input):
            var stream = prepared.encrypt(Span(feedback))
            var count = min(size, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += size
        return output^
    if (
        cipher == BlockCipherAlgorithm.CHAM64
        or cipher == BlockCipherAlgorithm.CHAM128
    ) and mode == CipherMode.ECB:
        var offset = 0
        while offset + 128 <= len(input):
            if cipher == BlockCipherAlgorithm.CHAM64:
                cham_process_sixteen16(
                    not encrypt,
                    prepared.cham16_keys,
                    input[offset : offset + 128],
                    Span(output),
                    offset,
                )
            elif prepared.cham32_rounds == 80:
                cham_process_eight32[80](
                    not encrypt,
                    prepared.cham32_keys,
                    input[offset : offset + 128],
                    Span(output),
                    offset,
                )
            else:
                cham_process_eight32[96](
                    not encrypt,
                    prepared.cham32_keys,
                    input[offset : offset + 128],
                    Span(output),
                    offset,
                )
            offset += 128
        if offset + 64 <= len(input):
            var padded_blocks = InlineArray[UInt8, 128](fill=0)
            var padded_output = InlineArray[UInt8, 128](fill=0)
            Span(padded_blocks).unsafe_ptr().unsafe_store[width=64](
                0, input_pointer.unsafe_load[width=64](offset)
            )
            if cipher == BlockCipherAlgorithm.CHAM64:
                cham_process_sixteen16(
                    not encrypt,
                    prepared.cham16_keys,
                    Span(padded_blocks),
                    Span(padded_output),
                    0,
                )
            elif prepared.cham32_rounds == 80:
                cham_process_eight32[80](
                    not encrypt,
                    prepared.cham32_keys,
                    Span(padded_blocks),
                    Span(padded_output),
                    0,
                )
            else:
                cham_process_eight32[96](
                    not encrypt,
                    prepared.cham32_keys,
                    Span(padded_blocks),
                    Span(padded_output),
                    0,
                )
            output_pointer.unsafe_store[width=64](
                offset,
                Span(padded_output).unsafe_ptr().unsafe_load[width=64](0),
            )
            offset += 64
        while offset < len(input):
            var transformed = prepared.encrypt(
                input[offset : offset + size]
            ) if encrypt else prepared.decrypt(input[offset : offset + size])
            for i in range(size):
                output[offset + i] = transformed[i]
            offset += size
        return output^
    if (
        cipher == BlockCipherAlgorithm.CHAM64
        or cipher == BlockCipherAlgorithm.CHAM128
    ) and mode == CipherMode.CTR:
        var counters = List[UInt8](length=128, fill=0)
        var offset = 0
        while offset + 128 <= len(input):
            if cipher == BlockCipherAlgorithm.CHAM64:
                _fill_counters8[16](feedback, counters)
            else:
                _fill_counters16[8](feedback, counters)
            if cipher == BlockCipherAlgorithm.CHAM64:
                cham_process_sixteen16(
                    False,
                    prepared.cham16_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            elif prepared.cham32_rounds == 80:
                cham_process_eight32[80](
                    False,
                    prepared.cham32_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            else:
                cham_process_eight32[96](
                    False,
                    prepared.cham32_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            comptime for chunk in range(8):
                output_pointer.unsafe_store[width=16](
                    offset + chunk * 16,
                    output_pointer.unsafe_load[width=16](offset + chunk * 16)
                    ^ input_pointer.unsafe_load[width=16](offset + chunk * 16),
                )
            offset += 128
        if offset + 64 <= len(input):
            var batch_output = InlineArray[UInt8, 128](fill=0)
            if cipher == BlockCipherAlgorithm.CHAM64:
                _fill_counters8[8](feedback, counters)
                cham_process_sixteen16(
                    False,
                    prepared.cham16_keys,
                    Span(counters),
                    Span(batch_output),
                    0,
                )
            elif prepared.cham32_rounds == 80:
                _fill_counters16[4](feedback, counters)
                cham_process_eight32[80](
                    False,
                    prepared.cham32_keys,
                    Span(counters),
                    Span(batch_output),
                    0,
                )
            else:
                _fill_counters16[4](feedback, counters)
                cham_process_eight32[96](
                    False,
                    prepared.cham32_keys,
                    Span(counters),
                    Span(batch_output),
                    0,
                )
            output_pointer.unsafe_store[width=64](
                offset,
                Span(batch_output).unsafe_ptr().unsafe_load[width=64](0)
                ^ input_pointer.unsafe_load[width=64](offset),
            )
            offset += 64
        while offset < len(input):
            var stream = prepared.encrypt(Span(feedback))
            var count = min(size, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += size
        return output^
    if (
        cipher == BlockCipherAlgorithm.SIMECK32
        or cipher == BlockCipherAlgorithm.SIMECK64
    ) and mode == CipherMode.ECB:
        var offset = 0
        while offset + 64 <= len(input):
            if cipher == BlockCipherAlgorithm.SIMECK32:
                simeck_process_sixteen16(
                    not encrypt,
                    prepared.simeck16_keys,
                    input[offset : offset + 64],
                    Span(output),
                    offset,
                )
            else:
                simeck_process_eight32(
                    not encrypt,
                    prepared.simeck32_keys,
                    input[offset : offset + 64],
                    Span(output),
                    offset,
                )
            offset += 64
        while offset < len(input):
            var transformed = prepared.encrypt(
                input[offset : offset + size]
            ) if encrypt else prepared.decrypt(input[offset : offset + size])
            for i in range(size):
                output[offset + i] = transformed[i]
            offset += size
        return output^
    if (
        cipher == BlockCipherAlgorithm.SIMECK32
        or cipher == BlockCipherAlgorithm.SIMECK64
    ) and mode == CipherMode.CTR:
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            if cipher == BlockCipherAlgorithm.SIMECK32:
                _fill_counters4[16](feedback, counters)
            else:
                _fill_counters8[8](feedback, counters)
            if cipher == BlockCipherAlgorithm.SIMECK32:
                simeck_process_sixteen16(
                    False,
                    prepared.simeck16_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            else:
                simeck_process_eight32(
                    False,
                    prepared.simeck32_keys,
                    Span(counters),
                    Span(output),
                    offset,
                )
            comptime for chunk in range(4):
                output_pointer.unsafe_store[width=16](
                    offset + chunk * 16,
                    output_pointer.unsafe_load[width=16](offset + chunk * 16)
                    ^ input_pointer.unsafe_load[width=16](offset + chunk * 16),
                )
            offset += 64
        while offset < len(input):
            var stream = prepared.encrypt(Span(feedback))
            var count = min(size, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += size
        return output^
    if cipher == BlockCipherAlgorithm.LEA and mode == CipherMode.ECB:
        var offset = 0
        while offset + 128 <= len(input):
            lea_process_eight(
                not encrypt,
                prepared.lea_keys,
                prepared.lea_rounds,
                input[offset : offset + 128],
                Span(output),
                offset,
            )
            offset += 128
        if offset + 64 <= len(input):
            var padded_blocks = InlineArray[UInt8, 128](fill=0)
            var padded_output = InlineArray[UInt8, 128](fill=0)
            Span(padded_blocks).unsafe_ptr().unsafe_store[width=64](
                0, input_pointer.unsafe_load[width=64](offset)
            )
            lea_process_eight(
                not encrypt,
                prepared.lea_keys,
                prepared.lea_rounds,
                Span(padded_blocks),
                Span(padded_output),
                0,
            )
            output_pointer.unsafe_store[width=64](
                offset,
                Span(padded_output).unsafe_ptr().unsafe_load[width=64](0),
            )
            offset += 64
        while offset < len(input):
            if encrypt:
                lea_process_into[False](
                    prepared.lea_keys,
                    prepared.lea_rounds,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
            else:
                lea_process_into[True](
                    prepared.lea_keys,
                    prepared.lea_rounds,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
            offset += 16
        return output^
    if cipher == BlockCipherAlgorithm.LEA and mode == CipherMode.CBC:
        if encrypt:
            for offset in range(0, len(input), 16):
                comptime for i in range(16):
                    feedback[i] ^= input[offset + i]
                lea_process_into[False](
                    prepared.lea_keys,
                    prepared.lea_rounds,
                    Span(feedback),
                    output_span,
                    offset,
                )
                comptime for i in range(16):
                    feedback[i] = output[offset + i]
        else:
            for offset in range(0, len(input), 16):
                lea_process_into[True](
                    prepared.lea_keys,
                    prepared.lea_rounds,
                    input[offset : offset + 16],
                    output_span,
                    offset,
                )
                comptime for i in range(16):
                    output[offset + i] ^= feedback[i]
                    feedback[i] = input[offset + i]
        return output^
    if cipher == BlockCipherAlgorithm.LEA and mode == CipherMode.CTR:
        var counters = List[UInt8](length=128, fill=0)
        var offset = 0
        while offset + 128 <= len(input):
            _fill_counters16[8](feedback, counters)
            lea_process_eight(
                False,
                prepared.lea_keys,
                prepared.lea_rounds,
                Span(counters),
                Span(output),
                offset,
            )
            comptime for chunk in range(8):
                output_pointer.unsafe_store[width=16](
                    offset + chunk * 16,
                    output_pointer.unsafe_load[width=16](offset + chunk * 16)
                    ^ input_pointer.unsafe_load[width=16](offset + chunk * 16),
                )
            offset += 128
        if offset + 64 <= len(input):
            var batch_output = InlineArray[UInt8, 128](fill=0)
            _fill_counters16[4](feedback, counters)
            lea_process_eight(
                False,
                prepared.lea_keys,
                prepared.lea_rounds,
                Span(counters),
                Span(batch_output),
                0,
            )
            output_pointer.unsafe_store[width=64](
                offset,
                Span(batch_output).unsafe_ptr().unsafe_load[width=64](0)
                ^ input_pointer.unsafe_load[width=64](offset),
            )
            offset += 64
        while offset + 16 <= len(input):
            lea_process_into[False](
                prepared.lea_keys,
                prepared.lea_rounds,
                Span(feedback),
                output_span,
                offset,
            )
            comptime for i in range(16):
                output[offset + i] ^= input[offset + i]
            _increment(feedback)
            offset += 16
        if offset < len(input):
            var stream = List[UInt8](length=16, fill=0)
            lea_process_into[False](
                prepared.lea_keys,
                prepared.lea_rounds,
                Span(feedback),
                Span(stream),
                0,
            )
            for i in range(len(input) - offset):
                output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if cipher == BlockCipherAlgorithm.MARS and mode == CipherMode.ECB:
        for offset in range(0, len(input), 16):
            mars_process_into(
                not encrypt,
                prepared.mars_keys,
                prepared.mars_sbox,
                input[offset : offset + 16],
                output_span,
                offset,
            )
        return output^
    if (
        cipher == BlockCipherAlgorithm.RC5 or cipher == BlockCipherAlgorithm.RC6
    ) and mode == CipherMode.ECB:
        for offset in range(0, len(input), size):
            if cipher == BlockCipherAlgorithm.RC5:
                if encrypt:
                    rc5_process_into[False](
                        prepared.rc5_schedule,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
                else:
                    rc5_process_into[True](
                        prepared.rc5_schedule,
                        input[offset : offset + size],
                        output_span,
                        offset,
                    )
            elif encrypt:
                rc6_process_into[False](
                    prepared.rc6_schedule,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            else:
                rc6_process_into[True](
                    prepared.rc6_schedule,
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
        return output^
    if cipher == BlockCipherAlgorithm.SM4:
        if mode == CipherMode.ECB:
            for offset in range(0, len(input), 16):
                if encrypt:
                    sm4_process_tables_into[False](
                        prepared.sm4_schedule,
                        prepared.sm4_tables,
                        input[offset : offset + 16],
                        output_span,
                        offset,
                    )
                else:
                    sm4_process_tables_into[True](
                        prepared.sm4_schedule,
                        prepared.sm4_tables,
                        input[offset : offset + 16],
                        output_span,
                        offset,
                    )
            return output^
        if mode == CipherMode.CBC:
            if encrypt:
                for offset in range(0, len(input), 16):
                    comptime for i in range(16):
                        feedback[i] ^= input[offset + i]
                    sm4_process_tables_into[False](
                        prepared.sm4_schedule,
                        prepared.sm4_tables,
                        Span(feedback),
                        output_span,
                        offset,
                    )
                    comptime for i in range(16):
                        feedback[i] = output[offset + i]
            else:
                for offset in range(0, len(input), 16):
                    sm4_process_tables_into[True](
                        prepared.sm4_schedule,
                        prepared.sm4_tables,
                        input[offset : offset + 16],
                        output_span,
                        offset,
                    )
                    comptime for i in range(16):
                        output[offset + i] ^= feedback[i]
                        feedback[i] = input[offset + i]
            return output^
        if mode == CipherMode.CTR:
            var offset = 0
            while offset + 16 <= len(input):
                sm4_process_tables_into[False](
                    prepared.sm4_schedule,
                    prepared.sm4_tables,
                    Span(feedback),
                    output_span,
                    offset,
                )
                comptime for i in range(16):
                    output[offset + i] ^= input[offset + i]
                _increment(feedback)
                offset += 16
            if offset < len(input):
                var stream = List[UInt8](length=16, fill=0)
                sm4_process_tables_into[False](
                    prepared.sm4_schedule,
                    prepared.sm4_tables,
                    Span(feedback),
                    Span(stream),
                    0,
                )
                for i in range(len(input) - offset):
                    output[offset + i] = input[offset + i] ^ stream[i]
            return output^
    if cipher == BlockCipherAlgorithm.RC5 and mode == CipherMode.CTR:
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            _fill_counters8[8](feedback, counters)
            rc5_process_eight(
                prepared.rc5_schedule,
                Span(counters),
                output_span,
                offset,
            )
            output_pointer.unsafe_store[width=64](
                offset,
                output_pointer.unsafe_load[width=64](offset)
                ^ input_pointer.unsafe_load[width=64](offset),
            )
            offset += 64
        while offset + 8 <= len(input):
            rc5_process_into[False](
                prepared.rc5_schedule,
                Span(feedback),
                output_span,
                offset,
            )
            output_pointer.unsafe_store[width=8](
                offset,
                output_pointer.unsafe_load[width=8](offset)
                ^ input_pointer.unsafe_load[width=8](offset),
            )
            _increment(feedback)
            offset += 8
        if offset < len(input):
            var stream = List[UInt8](length=8, fill=0)
            rc5_process_into[False](
                prepared.rc5_schedule,
                Span(feedback),
                Span(stream),
                0,
            )
            for i in range(len(input) - offset):
                output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if cipher == BlockCipherAlgorithm.RC6 and mode == CipherMode.CTR:
        var counters = List[UInt8](length=128, fill=0)
        var offset = 0
        while offset + 128 <= len(input):
            _fill_counters16[8](feedback, counters)
            rc6_process_eight(
                prepared.rc6_schedule,
                Span(counters),
                output_span,
                offset,
            )
            output_pointer.unsafe_store[width=128](
                offset,
                output_pointer.unsafe_load[width=128](offset)
                ^ input_pointer.unsafe_load[width=128](offset),
            )
            offset += 128
        while offset + 16 <= len(input):
            rc6_process_into[False](
                prepared.rc6_schedule,
                Span(feedback),
                output_span,
                offset,
            )
            output_pointer.unsafe_store[width=16](
                offset,
                output_pointer.unsafe_load[width=16](offset)
                ^ input_pointer.unsafe_load[width=16](offset),
            )
            _increment(feedback)
            offset += 16
        if offset < len(input):
            var stream = List[UInt8](length=16, fill=0)
            rc6_process_into[False](
                prepared.rc6_schedule,
                Span(feedback),
                Span(stream),
                0,
            )
            for i in range(len(input) - offset):
                output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if mode == CipherMode.CTR:
        var offset = 0
        while offset + size <= len(input):
            prepared.encrypt_into(Span(feedback), output_span, offset)
            _xor_mode_block_in_place(output_span, offset, input, offset, size)
            _increment(feedback)
            offset += size
        if offset < len(input):
            var stream = List[UInt8](length=size, fill=0)
            prepared.encrypt_into(Span(feedback), Span(stream), 0)
            for i in range(len(input) - offset):
                output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if mode == CipherMode.OFB:
        var stream = List[UInt8](length=size, fill=0)
        for offset in range(0, len(input), size):
            prepared.encrypt_into(Span(feedback), Span(stream), 0)
            var count = min(size, len(input) - offset)
            _copy_mode_block(Span(stream), 0, Span(feedback), 0, size)
            if count == size:
                _xor_mode_block(
                    input, offset, Span(stream), 0, output_span, offset, size
                )
            else:
                for i in range(count):
                    output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if mode == CipherMode.CFB:
        var stream = List[UInt8](length=size, fill=0)
        for offset in range(0, len(input), size):
            prepared.encrypt_into(Span(feedback), Span(stream), 0)
            var count = min(size, len(input) - offset)
            if count == size:
                _xor_mode_block(
                    input, offset, Span(stream), 0, output_span, offset, size
                )
                if encrypt:
                    _copy_mode_block(
                        output_span, offset, Span(feedback), 0, size
                    )
                else:
                    _copy_mode_block(input, offset, Span(feedback), 0, size)
            else:
                for i in range(count):
                    output[offset + i] = input[offset + i] ^ stream[i]
        return output^
    if mode == CipherMode.ECB:
        for offset in range(0, len(input), size):
            if encrypt:
                prepared.encrypt_into(
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
            else:
                prepared.decrypt_into(
                    input[offset : offset + size],
                    output_span,
                    offset,
                )
        return output^
    var block = List[UInt8](length=size, fill=0)
    for offset in range(0, len(input), size):
        if encrypt:
            _xor_mode_block(
                input,
                offset,
                Span(feedback),
                0,
                Span(block),
                0,
                size,
            )
            prepared.encrypt_into(Span(block), output_span, offset)
            _copy_mode_block(output_span, offset, Span(feedback), 0, size)
            continue
        else:
            _copy_mode_block(input, offset, Span(block), 0, size)
            prepared.decrypt_into(Span(block), output_span, offset)
            _xor_mode_block_in_place(
                output_span,
                offset,
                Span(feedback),
                0,
                size,
            )
            _copy_mode_block(Span(block), 0, Span(feedback), 0, size)
            continue
    return output^


def process[
    key_origin: Origin, iv_origin: Origin, input_origin: Origin
](
    cipher: BlockCipherAlgorithm,
    mode: CipherMode,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    return _process_mode(cipher, mode, encrypt, key, iv, input)


@always_inline("nodebug")
def _copy_mode_block[
    source_origin: Origin,
    output_origin: MutOrigin,
](
    source: Span[UInt8, source_origin],
    source_offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    size: Int,
):
    var source_pointer = source.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    if size == 4:
        output_pointer.unsafe_store[width=4](
            output_offset, source_pointer.unsafe_load[width=4](source_offset)
        )
        return
    if size == 8:
        output_pointer.unsafe_store[width=8](
            output_offset, source_pointer.unsafe_load[width=8](source_offset)
        )
        return
    if size == 12:
        output_pointer.unsafe_store[width=8](
            output_offset, source_pointer.unsafe_load[width=8](source_offset)
        )
        output_pointer.unsafe_store[width=4](
            output_offset + 8,
            source_pointer.unsafe_load[width=4](source_offset + 8),
        )
        return
    for offset in range(0, size, 16):
        output_pointer.unsafe_store[width=16](
            output_offset + offset,
            source_pointer.unsafe_load[width=16](source_offset + offset),
        )


@always_inline("nodebug")
def _xor_mode_block[
    left_origin: Origin,
    right_origin: Origin,
    output_origin: MutOrigin,
](
    left: Span[UInt8, left_origin],
    left_offset: Int,
    right: Span[UInt8, right_origin],
    right_offset: Int,
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    size: Int,
):
    var left_pointer = left.unsafe_ptr()
    var right_pointer = right.unsafe_ptr()
    var output_pointer = output.unsafe_ptr()
    if size == 4:
        output_pointer.unsafe_store[width=4](
            output_offset,
            left_pointer.unsafe_load[width=4](left_offset)
            ^ right_pointer.unsafe_load[width=4](right_offset),
        )
        return
    if size == 8:
        output_pointer.unsafe_store[width=8](
            output_offset,
            left_pointer.unsafe_load[width=8](left_offset)
            ^ right_pointer.unsafe_load[width=8](right_offset),
        )
        return
    if size == 12:
        output_pointer.unsafe_store[width=8](
            output_offset,
            left_pointer.unsafe_load[width=8](left_offset)
            ^ right_pointer.unsafe_load[width=8](right_offset),
        )
        output_pointer.unsafe_store[width=4](
            output_offset + 8,
            left_pointer.unsafe_load[width=4](left_offset + 8)
            ^ right_pointer.unsafe_load[width=4](right_offset + 8),
        )
        return
    for offset in range(0, size, 16):
        output_pointer.unsafe_store[width=16](
            output_offset + offset,
            left_pointer.unsafe_load[width=16](left_offset + offset)
            ^ right_pointer.unsafe_load[width=16](right_offset + offset),
        )


@always_inline("nodebug")
def _xor_mode_block_in_place[
    output_origin: MutOrigin,
    right_origin: Origin,
](
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
    right: Span[UInt8, right_origin],
    right_offset: Int,
    size: Int,
):
    var output_pointer = output.unsafe_ptr()
    var right_pointer = right.unsafe_ptr()
    if size == 4:
        output_pointer.unsafe_store[width=4](
            output_offset,
            output_pointer.unsafe_load[width=4](output_offset)
            ^ right_pointer.unsafe_load[width=4](right_offset),
        )
        return
    if size == 8:
        output_pointer.unsafe_store[width=8](
            output_offset,
            output_pointer.unsafe_load[width=8](output_offset)
            ^ right_pointer.unsafe_load[width=8](right_offset),
        )
        return
    if size == 12:
        output_pointer.unsafe_store[width=8](
            output_offset,
            output_pointer.unsafe_load[width=8](output_offset)
            ^ right_pointer.unsafe_load[width=8](right_offset),
        )
        output_pointer.unsafe_store[width=4](
            output_offset + 8,
            output_pointer.unsafe_load[width=4](output_offset + 8)
            ^ right_pointer.unsafe_load[width=4](right_offset + 8),
        )
        return
    for offset in range(0, size, 16):
        output_pointer.unsafe_store[width=16](
            output_offset + offset,
            output_pointer.unsafe_load[width=16](output_offset + offset)
            ^ right_pointer.unsafe_load[width=16](right_offset + offset),
        )


def _process_prepared_basic[
    iv_origin: Origin, input_origin: Origin
](
    prepared: _PreparedCipher,
    size: Int,
    mode: CipherMode,
    encrypt: Bool,
    iv: Span[UInt8, iv_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if (mode == CipherMode.ECB or mode == CipherMode.CBC) and len(
        input
    ) % size != 0:
        raise Error("ECB and CBC require complete blocks")
    if mode != CipherMode.ECB and len(iv) != size:
        raise Error("mode IV has invalid length")
    var output = List[UInt8](length=len(input), fill=0)
    var output_span = Span(output)
    comptime if CompilationTarget.is_x86():
        if mode == CipherMode.ECB and prepared.kind == 37:
            var offset = 0
            if encrypt:
                var zeros = List[UInt8](length=128, fill=0)
                while offset + 128 <= len(input):
                    prepared.aes.encrypt_eight(
                        input,
                        offset,
                        Span(zeros),
                        0,
                        output_span,
                        offset,
                    )
                    offset += 128
                while offset + 64 <= len(input):
                    prepared.aes.encrypt_four(
                        input,
                        offset,
                        Span(zeros),
                        0,
                        output_span,
                        offset,
                    )
                    offset += 64
                while offset < len(input):
                    output_span.unsafe_ptr().unsafe_store[width=16](
                        offset,
                        bitcast[DType.uint8, 16](
                            prepared.aes.encrypt_state(input, offset)
                        ),
                    )
                    offset += 16
            else:
                while offset + 64 <= len(input):
                    prepared.aes.decrypt_four_into(
                        input,
                        offset,
                        output_span,
                        offset,
                    )
                    offset += 64
                while offset < len(input):
                    output_span.unsafe_ptr().unsafe_store[width=16](
                        offset,
                        bitcast[DType.uint8, 16](
                            prepared.aes.decrypt_state(input, offset)
                        ),
                    )
                    offset += 16
            return output^
    if mode == CipherMode.ECB and (prepared.kind == 8 or prepared.kind == 9):
        var offset = 0
        while offset + 64 <= len(input):
            if prepared.kind == 8:
                speck_process_eight32(
                    not encrypt,
                    prepared.speck32_keys,
                    input[offset : offset + 64],
                    output_span,
                    offset,
                )
            else:
                speck_process_four64(
                    not encrypt,
                    prepared.speck64_keys,
                    input[offset : offset + 64],
                    output_span,
                    offset,
                )
            offset += 64
        while offset < len(input):
            if encrypt:
                prepared.encrypt_into(
                    input[offset : offset + size], output_span, offset
                )
            else:
                prepared.decrypt_into(
                    input[offset : offset + size], output_span, offset
                )
            offset += size
        return output^
    if mode == CipherMode.ECB and prepared.kind == 14:
        var offset = 0
        while offset + 64 <= len(input):
            if encrypt:
                aria_process_four_into(
                    prepared.aria_encrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    input[offset : offset + 64],
                    output_span,
                    offset,
                )
            else:
                aria_process_four_into(
                    prepared.aria_decrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    input[offset : offset + 64],
                    output_span,
                    offset,
                )
            offset += 64
        while offset < len(input):
            if encrypt:
                prepared.encrypt_into(
                    input[offset : offset + size], output_span, offset
                )
            else:
                prepared.decrypt_into(
                    input[offset : offset + size], output_span, offset
                )
            offset += size
        return output^
    if mode == CipherMode.ECB:
        for offset in range(0, len(input), size):
            if encrypt:
                prepared.encrypt_into(
                    input[offset : offset + size], output_span, offset
                )
            else:
                prepared.decrypt_into(
                    input[offset : offset + size], output_span, offset
                )
        return output^
    var feedback = List[UInt8](capacity=size)
    for byte in iv:
        feedback.append(byte)
    var block = List[UInt8](length=size, fill=0)
    var stream = List[UInt8](length=size, fill=0)
    if mode == CipherMode.CTR and prepared.kind == 31:
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            _fill_counters8[8](feedback, counters)
            rc5_process_eight(
                prepared.rc5_schedule,
                Span(counters),
                output_span,
                offset,
            )
            output_span.unsafe_ptr().unsafe_store[width=64](
                offset,
                output_span.unsafe_ptr().unsafe_load[width=64](offset)
                ^ input.unsafe_ptr().unsafe_load[width=64](offset),
            )
            offset += 64
        while offset < len(input):
            prepared.encrypt_into(Span(feedback), Span(stream), 0)
            var count = min(size, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += count
        return output^
    if mode == CipherMode.CTR and (
        prepared.kind == 8 or prepared.kind == 9 or prepared.kind == 14
    ):
        var counters = List[UInt8](length=64, fill=0)
        var offset = 0
        while offset + 64 <= len(input):
            if prepared.kind == 8:
                _fill_counters8[8](feedback, counters)
                speck_process_eight32(
                    False,
                    prepared.speck32_keys,
                    Span(counters),
                    output_span,
                    offset,
                )
            elif prepared.kind == 9:
                _fill_counters16[4](feedback, counters)
                speck_process_four64(
                    False,
                    prepared.speck64_keys,
                    Span(counters),
                    output_span,
                    offset,
                )
            else:
                _fill_counters16[4](feedback, counters)
                aria_process_four_into(
                    prepared.aria_encrypt_keys,
                    prepared.aria_rounds,
                    prepared.aria_tables,
                    Span(counters),
                    output_span,
                    offset,
                )
            output_span.unsafe_ptr().unsafe_store[width=64](
                offset,
                output_span.unsafe_ptr().unsafe_load[width=64](offset)
                ^ input.unsafe_ptr().unsafe_load[width=64](offset),
            )
            offset += 64
        while offset < len(input):
            prepared.encrypt_into(Span(feedback), Span(stream), 0)
            var count = min(size, len(input) - offset)
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
            _increment(feedback)
            offset += count
        return output^
    var offset = 0
    while offset < len(input):
        if mode == CipherMode.CBC:
            if encrypt:
                _xor_mode_block(
                    input,
                    offset,
                    Span(feedback),
                    0,
                    Span(block),
                    0,
                    size,
                )
                prepared.encrypt_into(Span(block), output_span, offset)
                _copy_mode_block(output_span, offset, Span(feedback), 0, size)
            else:
                _copy_mode_block(input, offset, Span(block), 0, size)
                prepared.decrypt_into(Span(block), output_span, offset)
                _xor_mode_block_in_place(
                    output_span,
                    offset,
                    Span(feedback),
                    0,
                    size,
                )
                _copy_mode_block(Span(block), 0, Span(feedback), 0, size)
            offset += size
            continue
        prepared.encrypt_into(Span(feedback), Span(stream), 0)
        var count = min(size, len(input) - offset)
        if count == size:
            _xor_mode_block(
                input, offset, Span(stream), 0, output_span, offset, size
            )
        else:
            for i in range(count):
                output[offset + i] = input[offset + i] ^ stream[i]
        if mode == CipherMode.CTR:
            _increment(feedback)
        elif mode == CipherMode.OFB:
            _copy_mode_block(Span(stream), 0, Span(feedback), 0, size)
        elif mode == CipherMode.CFB:
            if count == size:
                if encrypt:
                    _copy_mode_block(
                        output_span, offset, Span(feedback), 0, size
                    )
                else:
                    _copy_mode_block(input, offset, Span(feedback), 0, size)
        else:
            raise Error("unknown batched block mode")
        offset += count
    return output^


def _process_prepared_cbc_cts[
    iv_origin: Origin, input_origin: Origin
](
    prepared: _PreparedCipher,
    size: Int,
    encrypt: Bool,
    iv: Span[UInt8, iv_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(iv) != size:
        raise Error("mode IV has invalid length")
    if len(input) <= size:
        raise Error("CBC-CTS requires more than one block")
    if len(input) % size == 0:
        var swapped = List[UInt8]()
        if encrypt:
            swapped = _process_prepared_basic(
                prepared, size, CipherMode.CBC, True, iv, input
            )
        else:
            for byte in input:
                swapped.append(byte)
        var penultimate_offset = len(swapped) - 2 * size
        var last_offset = len(swapped) - size
        var temporary = List[UInt8](length=size, fill=0)
        _copy_mode_block(
            Span(swapped),
            penultimate_offset,
            Span(temporary),
            0,
            size,
        )
        for i in range(size):
            swapped[penultimate_offset + i] = swapped[last_offset + i]
        _copy_mode_block(Span(temporary), 0, Span(swapped), last_offset, size)
        if encrypt:
            return swapped^
        return _process_prepared_basic(
            prepared, size, CipherMode.CBC, False, iv, Span(swapped)
        )
    var prefix_bytes = ((len(input) - 1) // size - 1) * size
    var output = List[UInt8](length=len(input), fill=0)
    var output_span = Span(output)
    var feedback = List[UInt8](capacity=size)
    for byte in iv:
        feedback.append(byte)
    var block = List[UInt8](length=size, fill=0)
    if encrypt:
        for offset in range(0, prefix_bytes, size):
            _xor_mode_block(
                input,
                offset,
                Span(feedback),
                0,
                Span(block),
                0,
                size,
            )
            prepared.encrypt_into(Span(block), output_span, offset)
            _copy_mode_block(output_span, offset, Span(feedback), 0, size)
        _xor_mode_block(
            input,
            prefix_bytes,
            Span(feedback),
            0,
            Span(block),
            0,
            size,
        )
        var penultimate = List[UInt8](length=size, fill=0)
        prepared.encrypt_into(Span(block), Span(penultimate), 0)
        _copy_mode_block(Span(penultimate), 0, Span(block), 0, size)
        var remainder = len(input) - prefix_bytes - size
        for i in range(remainder):
            block[i] ^= input[prefix_bytes + size + i]
        prepared.encrypt_into(Span(block), output_span, prefix_bytes)
        for i in range(remainder):
            output[prefix_bytes + size + i] = penultimate[i]
        return output^
    var decrypted = List[UInt8](length=size, fill=0)
    for offset in range(0, prefix_bytes, size):
        _copy_mode_block(input, offset, Span(block), 0, size)
        prepared.decrypt_into(Span(block), Span(decrypted), 0)
        _xor_mode_block(
            Span(decrypted),
            0,
            Span(feedback),
            0,
            output_span,
            offset,
            size,
        )
        _copy_mode_block(Span(block), 0, Span(feedback), 0, size)
    var remainder = len(input) - prefix_bytes - size
    _copy_mode_block(input, prefix_bytes, Span(block), 0, size)
    prepared.decrypt_into(Span(block), Span(decrypted), 0)
    var stolen = List[UInt8](length=size, fill=0)
    for i in range(remainder):
        stolen[i] = input[prefix_bytes + size + i]
    for i in range(remainder, size):
        stolen[i] = decrypted[i]
    prepared.decrypt_into(Span(stolen), Span(block), 0)
    _xor_mode_block(
        Span(block),
        0,
        Span(feedback),
        0,
        output_span,
        prefix_bytes,
        size,
    )
    for i in range(remainder):
        output[prefix_bytes + size + i] = decrypted[i] ^ stolen[i]
    return output^


struct PreparedCipher(Movable):
    """Reusable prepared block cipher for ECB, CBC, CBC-CTS, CFB, OFB, and CTR.
    """

    var _prepared: _PreparedCipher
    var _size: Int
    var _mode: CipherMode
    var _encrypt: Bool

    def __init__[
        key_origin: Origin
    ](
        out self,
        cipher: BlockCipherAlgorithm,
        mode: CipherMode,
        encrypt: Bool,
        key: Span[UInt8, key_origin],
    ) raises:
        if (
            mode != CipherMode.ECB
            and mode != CipherMode.CBC
            and mode != CipherMode.CBC_CTS
            and mode != CipherMode.CFB
            and mode != CipherMode.OFB
            and mode != CipherMode.CTR
        ):
            raise Error("invalid cipher mode selector")
        self._size = _block_size(cipher)
        self._mode = mode
        self._encrypt = encrypt
        var needs_inverse = not encrypt and (
            mode == CipherMode.ECB
            or mode == CipherMode.CBC
            or mode == CipherMode.CBC_CTS
        )
        self._prepared = _PreparedCipher(cipher, key, needs_inverse)

    def __init__(out self, *, deinit move: Self):
        self._prepared = move._prepared^
        self._size = move._size
        self._mode = move._mode
        self._encrypt = move._encrypt

    def process[
        iv_origin: Origin, input_origin: Origin
    ](
        self,
        iv: Span[UInt8, iv_origin],
        input: Span[UInt8, input_origin],
    ) raises -> List[UInt8]:
        if self._mode == CipherMode.CBC_CTS:
            return _process_prepared_cbc_cts(
                self._prepared,
                self._size,
                self._encrypt,
                iv,
                input,
            )
        return _process_prepared_basic(
            self._prepared,
            self._size,
            self._mode,
            self._encrypt,
            iv,
            input,
        )


def _process_safer_stream_eight[
    key_origin: Origin
](
    mode: CipherMode,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    ivs: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    var schedule = safer_prepare(key, False)
    var keys = schedule[0].copy()
    var rounds = schedule[1]
    var input_length = len(inputs[0])
    var outputs = List[List[UInt8]](capacity=8)
    var feedback = List[UInt8](length=64, fill=0)
    for lane in range(8):
        if len(ivs[lane]) != 8 or len(inputs[lane]) != input_length:
            raise Error("SAFER stream batch dimensions do not match")
        outputs.append(List[UInt8](length=input_length, fill=0))
        for i in range(8):
            feedback[lane * 8 + i] = ivs[lane][i]
    var streams = List[UInt8](length=64, fill=0)
    for offset in range(0, input_length, 8):
        safer_process_eight_encrypt(
            keys, rounds, Span(feedback), Span(streams), 0
        )
        var count = min(8, input_length - offset)
        for lane in range(8):
            for i in range(count):
                outputs[lane][offset + i] = (
                    inputs[lane][offset + i] ^ streams[lane * 8 + i]
                )
            if mode == CipherMode.CTR:
                var position = lane * 8 + 7
                while position >= lane * 8:
                    feedback[position] += 1
                    if feedback[position] != 0:
                        break
                    position -= 1
            elif mode == CipherMode.OFB:
                for i in range(8):
                    feedback[lane * 8 + i] = streams[lane * 8 + i]
            elif mode == CipherMode.CFB:
                if count == 8:
                    for i in range(8):
                        feedback[lane * 8 + i] = outputs[lane][
                            offset + i
                        ] if encrypt else inputs[lane][offset + i]
            else:
                raise Error("unknown SAFER batched stream mode")
    return outputs^


def process_eight[
    key_origin: Origin
](
    cipher: BlockCipherAlgorithm,
    mode: CipherMode,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    ivs: List[List[UInt8]],
    inputs: List[List[UInt8]],
) raises -> List[List[UInt8]]:
    """Process eight independent messages while sharing one key schedule."""
    if len(ivs) != 8 or len(inputs) != 8:
        raise Error("eight-way block-cipher batch has invalid dimensions")
    if cipher == BlockCipherAlgorithm.SAFER and (
        mode == CipherMode.CFB
        or mode == CipherMode.OFB
        or mode == CipherMode.CTR
    ):
        var same_size = True
        for lane in range(1, 8):
            same_size = same_size and len(inputs[lane]) == len(inputs[0])
        if same_size:
            return _process_safer_stream_eight(mode, encrypt, key, ivs, inputs)
    var outputs = List[List[UInt8]](capacity=8)
    if mode == CipherMode.CBC_CTS:
        for lane in range(8):
            outputs.append(
                process(
                    cipher,
                    mode,
                    encrypt,
                    key,
                    Span(ivs[lane]),
                    Span(inputs[lane]),
                )
            )
        return outputs^
    var size = _block_size(cipher)
    var needs_inverse = not encrypt and (
        mode == CipherMode.ECB or mode == CipherMode.CBC
    )
    var prepared = _PreparedCipher(cipher, key, needs_inverse)
    for lane in range(8):
        outputs.append(
            _process_prepared_basic(
                prepared,
                size,
                mode,
                encrypt,
                Span(ivs[lane]),
                Span(inputs[lane]),
            )
        )
    return outputs^


def process_aria_cbc_four_into[
    key_origin: Origin,
    iv_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    _process_aria_cbc_four_into(
        encrypt,
        key,
        iv,
        first,
        second,
        third,
        fourth,
        first_output,
        second_output,
        third_output,
        fourth_output,
    )


def process_speck_cbc_four_into[
    key_origin: Origin,
    iv_origin: Origin,
    first_origin: Origin,
    second_origin: Origin,
    third_origin: Origin,
    fourth_origin: Origin,
    first_output_origin: MutOrigin,
    second_output_origin: MutOrigin,
    third_output_origin: MutOrigin,
    fourth_output_origin: MutOrigin,
](
    cipher: BlockCipherAlgorithm,
    encrypt: Bool,
    key: Span[UInt8, key_origin],
    iv: Span[UInt8, iv_origin],
    first: Span[UInt8, first_origin],
    second: Span[UInt8, second_origin],
    third: Span[UInt8, third_origin],
    fourth: Span[UInt8, fourth_origin],
    first_output: Span[mut=True, UInt8, first_output_origin],
    second_output: Span[mut=True, UInt8, second_output_origin],
    third_output: Span[mut=True, UInt8, third_output_origin],
    fourth_output: Span[mut=True, UInt8, fourth_output_origin],
) raises:
    _process_speck_cbc_four_into(
        cipher,
        encrypt,
        key,
        iv,
        first,
        second,
        third,
        fourth,
        first_output,
        second_output,
        third_output,
        fourth_output,
    )
