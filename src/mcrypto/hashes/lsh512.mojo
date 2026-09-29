"""LSH-224, LSH-256, LSH-384, and LSH-512 in pure Mojo."""

from std.collections import InlineArray
from std.bit import rotate_bits_left
from std.memory import bitcast


def _constants() -> InlineArray[UInt64, 224]:
    return [
        0x97884283C938982A,
        0xBA1FCA93533E2355,
        0xC519A2E87AEB1C03,
        0x9A0FC95462AF17B1,
        0xFC3DDA8AB019A82B,
        0x02825D079A895407,
        0x79F2D0A7EE06A6F7,
        0xD76D15EED9FDF5FE,
        0x1FCAC64D01D0C2C1,
        0xD9EA5DE69161790F,
        0xDEBC8B6366071FC8,
        0xA9D91DB711C6C94B,
        0x3A18653AC9C1D427,
        0x84DF64A223DD5B09,
        0x6CC37895F4AD9E70,
        0x448304C8D7F3F4D5,
        0xEA91134ED29383E0,
        0xC4484477F2DA88E8,
        0x9B47EEC96D26E8A6,
        0x82F6D4C8D89014F4,
        0x527DA0048B95FB61,
        0x644406C60138648D,
        0x303C0E8AA24C0EDC,
        0xC787CDA0CBE8CA19,
        0x7BA46221661764CA,
        0x0C8CBC6ACD6371AC,
        0xE336B836940F8F41,
        0x79CB9DA168A50976,
        0xD01DA49021915CB3,
        0xA84ACCC7399CF1F1,
        0x6C4A992CEE5AEB0C,
        0x4F556E6CB4B2E3E0,
        0x200683877D7C2F45,
        0x9949273830D51DB8,
        0x19EEEECAA39ED124,
        0x45693F0A0DAE7FEF,
        0xEDC234B1B2EE1083,
        0xF3179400D68EE399,
        0xB6E3C61B4945F778,
        0xA4C3DB216796C42F,
        0x268A0B04F9AB7465,
        0xE2705F6905F2D651,
        0x08DDB96E426FF53D,
        0xAEA84917BC2E6F34,
        0xAFF6E664A0FE9470,
        0x0AAB94D765727D8C,
        0x9AA9E1648F3D702E,
        0x689EFC88FE5AF3D3,
        0xB0950FFEA51FD98B,
        0x52CFC86EF8C92833,
        0xE69727B0B2653245,
        0x56F160D3EA9DA3E2,
        0xA6DD4B059F93051F,
        0xB6406C3CD7F00996,
        0x448B45F3CCAD9EC8,
        0x079B8587594EC73B,
        0x45A50EA3C4F9653B,
        0x22983767C1F15B85,
        0x7DBED8631797782B,
        0x485234BE88418638,
        0x842850A5329824C5,
        0xF6ACA914C7F9A04C,
        0xCFD139C07A4C670C,
        0xA3210CE0A8160242,
        0xEAB3B268BE5EA080,
        0xBACF9F29B34CE0A7,
        0x3C973B7AAF0FA3A8,
        0x9A86F346C9C7BE80,
        0xAC78F5D7CABCEA49,
        0xA355BDDCC199ED42,
        0xA10AFA3AC6B373DB,
        0xC42DED88BE1844E5,
        0x9E661B271CFF216A,
        0x8A6EC8DD002D8861,
        0xD3D2B629BEB34BE4,
        0x217A3A1091863F1A,
        0x256ECDA287A733F5,
        0xF9139A9E5B872FE5,
        0xAC0535017A274F7C,
        0xF21B7646D65D2AA9,
        0x048142441C208C08,
        0xF937A5DD2DB5E9EB,
        0xA688DFE871FF30B7,
        0x9BB44AA217C5593B,
        0x943C702A2EDB291A,
        0x0CAE38F9E2B715DE,
        0xB13A367BA176CC28,
        0x0D91BD1D3387D49B,
        0x85C386603CAC940C,
        0x30DD830AE39FD5E4,
        0x2F68C85A712FE85D,
        0x4FFEECB9DD1E94D6,
        0xD0AC9A590A0443AE,
        0xBAE732DC99CCF3EA,
        0xEB70B21D1842F4D9,
        0x9F4EDA50BB5C6FA8,
        0x4949E69CE940A091,
        0x0E608DEE8375BA14,
        0x983122CBA118458C,
        0x4EEBA696FBB36B25,
        0x7D46F3630E47F27E,
        0xA21A0F7666C0DEA4,
        0x5C22CF355B37CEC4,
        0xEE292B0C17CC1847,
        0x9330838629E131DA,
        0x6EEE7C71F92FCE22,
        0xC953EE6CB95DD224,
        0x3A923D92AF1E9073,
        0xC43A5671563A70FB,
        0xBC2985DD279F8346,
        0x7EF2049093069320,
        0x17543723E3E46035,
        0xC3B409B00B130C6D,
        0x5D6AEE6B28FDF090,
        0x1D425B26172FF6ED,
        0xCCCFD041CDAF03AD,
        0xFE90C7C790AB6CBF,
        0xE5AF6304C722CA02,
        0x70F695239999B39E,
        0x6B8B5B07C844954C,
        0x77BDB9BB1E1F7A30,
        0xC859599426EE80ED,
        0x5F9D813D4726E40A,
        0x9CA0120F7CB2B179,
        0x8F588F583C182CBD,
        0x951267CBE9ECCCE7,
        0x678BB8BD334D520E,
        0xF6E662D00CD9E1B7,
        0x357774D93D99AAA7,
        0x21B2EDBB156F6EB5,
        0xFD1EBE846E0AEE69,
        0x3CB2218C2F642B15,
        0xE7E7E7945444EA4C,
        0xA77A33B5D6B9B47C,
        0xF34475F0809F6075,
        0xDD4932DCE6BB99AD,
        0xACEC4E16D74451DC,
        0xD4A0A8D084DE23D6,
        0x1BDD42F278F95866,
        0xEED3ADBB938F4051,
        0xCFCF7BE8992F3733,
        0x21ADE98C906E3123,
        0x37BA66711FFFD668,
        0x267C0FC3A255478A,
        0x993A64EE1B962E88,
        0x754979556301FAAA,
        0xF920356B7251BE81,
        0xC281694F22CF923F,
        0x9F4B6481C8666B02,
        0xCF97761CFE9F5444,
        0xF220D7911FD63E9F,
        0xA28BD365F79CD1B0,
        0xD39F5309B1C4B721,
        0xBEC2CEB864FCA51F,
        0x1955A0DDC410407A,
        0x43EAB871F261D201,
        0xEAAFE64A2ED16DA1,
        0x670D931B9DF39913,
        0x12F868B0F614DE91,
        0x2E5F395D946E8252,
        0x72F25CBB767BD8F4,
        0x8191871D61A1C4DD,
        0x6EF67EA1D450BA93,
        0x2EA32A645433D344,
        0x9A963079003F0F8B,
        0x74A0AEB9918CAC7A,
        0x0B6119A70AF36FA3,
        0x8D9896F202F0D480,
        0x654F1831F254CD66,
        0x1318A47F0366A25E,
        0x65752076250B4E01,
        0xD1CD8EB888071772,
        0x30C6A9793F4E9B25,
        0x154F684B1E3926EE,
        0x6C7AC0B1FE6312AE,
        0x262F88F4F3C5550D,
        0xB4674A24472233CB,
        0x2BBD23826A090071,
        0xDA95969B30594F66,
        0x9F5C47408F1E8A43,
        0xF77022B88DE9C055,
        0x64B7B36957601503,
        0xE73B72B06175C11A,
        0x55B87DE8B91A6233,
        0x1BB16E6B6955FF7F,
        0xE8E0A5EC7309719C,
        0x702C31CB89A8B640,
        0xFBA387CFADA8CDE2,
        0x6792DB4677AA164C,
        0x1C6B1CC0B7751867,
        0x22AE2311D736DC01,
        0x0E3666A1D37C9588,
        0xCD1FD9D4BF557E9A,
        0xC986925F7C7B0E84,
        0x9C5DFD55325EF6B0,
        0x9F2B577D5676B0DD,
        0xFA6E21BE21C062B3,
        0x8787DD782C8D7F83,
        0xD0D134E90E12DD23,
        0x449D087550121D96,
        0xECF9AE9414D41967,
        0x5018F1DBF789934D,
        0xFA5B52879155A74C,
        0xCA82D4D3CD278E7C,
        0x688FDFDFE22316AD,
        0x0F6555A4BA0D030A,
        0xA2061DF720F000F3,
        0xE1A57DC5622FB3DA,
        0xE6A842A8E8ED8153,
        0x690ACDD3811CE09D,
        0x55ADDA18E6FCF446,
        0x4D57A8A0F4B60B46,
        0xF86FBFC20539C415,
        0x74BAFA5EC7100D19,
        0xA824151810F0F495,
        0x8723432791E38EBB,
        0x8EEAEB91D66ED539,
        0x73D8A1549DFD7E06,
        0x0387F2FFE3F13A9B,
        0xA5004995AAC15193,
        0x682F81C73EFDDA0D,
        0x2FB55925D71D268D,
        0xCC392D2901E58A3D,
        0xAA666AB975724A42,
    ]


def _iv(bits: Int) raises -> InlineArray[UInt64, 16]:
    if bits == 224:
        return [
            0x0C401E9FE8813A55,
            0x4A5F446268FD3D35,
            0xFF13E452334F612A,
            0xF8227661037E354A,
            0xA5F223723C9CA29D,
            0x95D965A11AED3979,
            0x01E23835B9AB02CC,
            0x52D49CBAD5B30616,
            0x9E5C2027773F4ED3,
            0x66A5C8801925B701,
            0x22BBC85B4C6779D9,
            0xC13171A42C559C23,
            0x31E2B67D25BE3813,
            0xD522C4DEED8E4D83,
            0xA79F5509B43FBAFE,
            0xE00D2CD88B4B6C6A,
        ]
    if bits == 256:
        return [
            0x6DC57C33DF989423,
            0xD8EA7F6E8342C199,
            0x76DF8356F8603AC4,
            0x40F1B44DE838223A,
            0x39FFE7CFC31484CD,
            0x39C4326CC5281548,
            0x8A2FF85A346045D8,
            0xFF202AA46DBDD61E,
            0xCF785B3CD5FCDB8B,
            0x1F0323B64A8150BF,
            0xFF75D972F29EA355,
            0x2E567F30BF1CA9E1,
            0xB596875BF8FF6DBA,
            0xFCCA39B089EF4615,
            0xECFF4017D020B4B6,
            0x7E77384C772ED802,
        ]
    if bits == 384:
        return [
            0x53156A66292808F6,
            0xB2C4F362B204C2BC,
            0xB84B7213BFA05C4E,
            0x976CEB7C1B299F73,
            0xDF0CC63C0570AE97,
            0xDA4441BAA486CE3F,
            0x6559F5D9B5F2ACC2,
            0x22DACF19B4B52A16,
            0xBBCDACEFDE80953A,
            0xC9891A2879725B3E,
            0x7C9FE6330237E440,
            0xA30BA550553F7431,
            0xBB08043FB34E3E30,
            0xA0DEC48D54618EAD,
            0x150317267464BC57,
            0x32D1501FDE63DC93,
        ]
    if bits == 512:
        return [
            0xADD50F3C7F07094E,
            0xE3F3CEE8F9418A4F,
            0xB527ECDE5B3D0AE9,
            0x2EF6DEC68076F501,
            0x8CB994CAE5ACA216,
            0xFBB9EAE4BBA48CC7,
            0x650A526174725FEA,
            0x1F9A61A73F8D8085,
            0xB6607378173B539B,
            0x1BC99853B0C0B9ED,
            0xDF727FC19B182D47,
            0xDBEF360CF893A457,
            0x4981F5E570147E80,
            0xD00C4490CA7D3E30,
            0x5D73940C0E4AE1EC,
            0x894085E2EDB2D819,
        ]
    raise Error("LSH-512 family size must be 224, 256, 384, or 512")


@always_inline("nodebug")
def _permute(mut left: SIMD[DType.uint64, 8], mut right: SIMD[DType.uint64, 8]):
    var lower_mask = SIMD[DType.uint64, 8](
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        0,
        0,
    )
    var old_left = left
    var old_right = right
    left = (old_left.shuffle[6, 4, 5, 7, 6, 4, 5, 7]() & lower_mask) | (
        old_right.shuffle[4, 7, 6, 5, 4, 7, 6, 5]() & ~lower_mask
    )
    right = (old_left.shuffle[2, 0, 1, 3, 2, 0, 1, 3]() & lower_mask) | (
        old_right.shuffle[0, 3, 2, 1, 0, 3, 2, 1]() & ~lower_mask
    )


@always_inline("nodebug")
def _mix[
    alpha: Int, beta: Int
](
    mut left: SIMD[DType.uint64, 8],
    mut right: SIMD[DType.uint64, 8],
    constant: SIMD[DType.uint64, 8],
):
    left += right
    left = rotate_bits_left[alpha](left) ^ constant
    right += left
    right = rotate_bits_left[beta](right)
    left += right
    right = bitcast[DType.uint64, 8](
        bitcast[DType.uint8, 64](right).shuffle[
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            14,
            15,
            8,
            9,
            10,
            11,
            12,
            13,
            20,
            21,
            22,
            23,
            16,
            17,
            18,
            19,
            26,
            27,
            28,
            29,
            30,
            31,
            24,
            25,
            39,
            32,
            33,
            34,
            35,
            36,
            37,
            38,
            45,
            46,
            47,
            40,
            41,
            42,
            43,
            44,
            51,
            52,
            53,
            54,
            55,
            48,
            49,
            50,
            57,
            58,
            59,
            60,
            61,
            62,
            63,
            56,
        ]()
    )


@always_inline("nodebug")
def _compress[
    block_origin: Origin, constants_origin: Origin
](
    mut chaining_left: SIMD[DType.uint64, 8],
    mut chaining_right: SIMD[DType.uint64, 8],
    block: Span[UInt8, block_origin],
    block_offset: Int,
    constants: Span[UInt64, constants_origin],
):
    var block_pointer = block.unsafe_ptr()
    var constants_pointer = constants.unsafe_ptr()
    var message0 = bitcast[DType.uint64, 8](
        block_pointer.unsafe_load[width=64](block_offset)
    )
    var message1 = bitcast[DType.uint64, 8](
        block_pointer.unsafe_load[width=64](block_offset + 64)
    )
    var message2 = bitcast[DType.uint64, 8](
        block_pointer.unsafe_load[width=64](block_offset + 128)
    )
    var message3 = bitcast[DType.uint64, 8](
        block_pointer.unsafe_load[width=64](block_offset + 192)
    )
    var left = chaining_left ^ message0
    var right = chaining_right ^ message1
    _mix[23, 59](left, right, constants_pointer.unsafe_load[width=8](0))
    _permute(left, right)
    left ^= message2
    right ^= message3
    _mix[7, 3](left, right, constants_pointer.unsafe_load[width=8](8))
    _permute(left, right)
    comptime for step in range(1, 14):
        message0 = message2 + message0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        message1 = message3 + message1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        left ^= message0
        right ^= message1
        _mix[23, 59](
            left,
            right,
            constants_pointer.unsafe_load[width=8](16 * step),
        )
        _permute(left, right)
        message2 = message0 + message2.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        message3 = message1 + message3.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
        left ^= message2
        right ^= message3
        _mix[7, 3](
            left,
            right,
            constants_pointer.unsafe_load[width=8](16 * step + 8),
        )
        _permute(left, right)
    message0 = message2 + message0.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    message1 = message3 + message1.shuffle[3, 2, 0, 1, 7, 4, 5, 6]()
    chaining_left = left ^ message0
    chaining_right = right ^ message1


def lsh512_into[
    input_origin: Origin,
    output_origin: MutOrigin,
](
    bits: Int,
    data: Span[UInt8, input_origin],
    output: Span[mut=True, UInt8, output_origin],
) raises:
    if len(output) != bits // 8:
        raise Error("LSH-512 output span has invalid length")
    var cv = _iv(bits)
    var cv_pointer = Span(cv).unsafe_ptr()
    var chaining_left = cv_pointer.unsafe_load[width=8](0)
    var chaining_right = cv_pointer.unsafe_load[width=8](8)
    var constants = _constants()
    var constants_span = Span(constants)
    var offset = 0
    var data_length = len(data)
    while offset + 256 <= data_length:
        _compress(chaining_left, chaining_right, data, offset, constants_span)
        offset += 256
    var block = InlineArray[UInt8, 256](fill=0)
    var remainder = data_length - offset
    for i in range(remainder):
        block[i] = data[offset + i]
    block[remainder] = 0x80
    _compress(chaining_left, chaining_right, Span(block), 0, constants_span)
    var output_pointer = output.unsafe_ptr()
    var remaining = len(output)
    var output_offset = 0
    for i in range(8):
        if remaining == 0:
            break
        var word = chaining_left[i] ^ chaining_right[i]
        var word_bytes = min(8, remaining)
        if word_bytes == 8:
            output_pointer.unsafe_store[width=8](
                output_offset,
                bitcast[DType.uint8, 8](SIMD[DType.uint64, 1](word)),
            )
        else:
            for j in range(word_bytes):
                output_pointer.unsafe_store(
                    output_offset + j, UInt8(word >> UInt64(j * 8))
                )
        output_offset += word_bytes
        remaining -= word_bytes


def lsh512[
    origin: Origin
](bits: Int, data: Span[UInt8, origin]) raises -> List[UInt8]:
    var output = List[UInt8](length=bits // 8, fill=0)
    lsh512_into(bits, data, Span(output))
    return output^


def lsh512_224[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    return lsh512(224, data)


def lsh512_256[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    return lsh512(256, data)


def lsh384[origin: Origin](data: Span[UInt8, origin]) raises -> List[UInt8]:
    return lsh512(384, data)
