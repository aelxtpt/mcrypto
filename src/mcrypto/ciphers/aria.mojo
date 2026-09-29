"""RFC 5794 ARIA block cipher for 128-, 192-, and 256-bit keys."""

from std.builtin.globals import global_constant

comptime _S1: InlineArray[UInt8, 256] = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

comptime _S2: InlineArray[UInt8, 256] = [
    0xE2,
    0x4E,
    0x54,
    0xFC,
    0x94,
    0xC2,
    0x4A,
    0xCC,
    0x62,
    0x0D,
    0x6A,
    0x46,
    0x3C,
    0x4D,
    0x8B,
    0xD1,
    0x5E,
    0xFA,
    0x64,
    0xCB,
    0xB4,
    0x97,
    0xBE,
    0x2B,
    0xBC,
    0x77,
    0x2E,
    0x03,
    0xD3,
    0x19,
    0x59,
    0xC1,
    0x1D,
    0x06,
    0x41,
    0x6B,
    0x55,
    0xF0,
    0x99,
    0x69,
    0xEA,
    0x9C,
    0x18,
    0xAE,
    0x63,
    0xDF,
    0xE7,
    0xBB,
    0x00,
    0x73,
    0x66,
    0xFB,
    0x96,
    0x4C,
    0x85,
    0xE4,
    0x3A,
    0x09,
    0x45,
    0xAA,
    0x0F,
    0xEE,
    0x10,
    0xEB,
    0x2D,
    0x7F,
    0xF4,
    0x29,
    0xAC,
    0xCF,
    0xAD,
    0x91,
    0x8D,
    0x78,
    0xC8,
    0x95,
    0xF9,
    0x2F,
    0xCE,
    0xCD,
    0x08,
    0x7A,
    0x88,
    0x38,
    0x5C,
    0x83,
    0x2A,
    0x28,
    0x47,
    0xDB,
    0xB8,
    0xC7,
    0x93,
    0xA4,
    0x12,
    0x53,
    0xFF,
    0x87,
    0x0E,
    0x31,
    0x36,
    0x21,
    0x58,
    0x48,
    0x01,
    0x8E,
    0x37,
    0x74,
    0x32,
    0xCA,
    0xE9,
    0xB1,
    0xB7,
    0xAB,
    0x0C,
    0xD7,
    0xC4,
    0x56,
    0x42,
    0x26,
    0x07,
    0x98,
    0x60,
    0xD9,
    0xB6,
    0xB9,
    0x11,
    0x40,
    0xEC,
    0x20,
    0x8C,
    0xBD,
    0xA0,
    0xC9,
    0x84,
    0x04,
    0x49,
    0x23,
    0xF1,
    0x4F,
    0x50,
    0x1F,
    0x13,
    0xDC,
    0xD8,
    0xC0,
    0x9E,
    0x57,
    0xE3,
    0xC3,
    0x7B,
    0x65,
    0x3B,
    0x02,
    0x8F,
    0x3E,
    0xE8,
    0x25,
    0x92,
    0xE5,
    0x15,
    0xDD,
    0xFD,
    0x17,
    0xA9,
    0xBF,
    0xD4,
    0x9A,
    0x7E,
    0xC5,
    0x39,
    0x67,
    0xFE,
    0x76,
    0x9D,
    0x43,
    0xA7,
    0xE1,
    0xD0,
    0xF5,
    0x68,
    0xF2,
    0x1B,
    0x34,
    0x70,
    0x05,
    0xA3,
    0x8A,
    0xD5,
    0x79,
    0x86,
    0xA8,
    0x30,
    0xC6,
    0x51,
    0x4B,
    0x1E,
    0xA6,
    0x27,
    0xF6,
    0x35,
    0xD2,
    0x6E,
    0x24,
    0x16,
    0x82,
    0x5F,
    0xDA,
    0xE6,
    0x75,
    0xA2,
    0xEF,
    0x2C,
    0xB2,
    0x1C,
    0x9F,
    0x5D,
    0x6F,
    0x80,
    0x0A,
    0x72,
    0x44,
    0x9B,
    0x6C,
    0x90,
    0x0B,
    0x5B,
    0x33,
    0x7D,
    0x5A,
    0x52,
    0xF3,
    0x61,
    0xA1,
    0xF7,
    0xB0,
    0xD6,
    0x3F,
    0x7C,
    0x6D,
    0xED,
    0x14,
    0xE0,
    0xA5,
    0x3D,
    0x22,
    0xB3,
    0xF8,
    0x89,
    0xDE,
    0x71,
    0x1A,
    0xAF,
    0xBA,
    0xB5,
    0x81,
]

comptime _X1: InlineArray[UInt8, 256] = [
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
]

comptime _X2: InlineArray[UInt8, 256] = [
    0x30,
    0x68,
    0x99,
    0x1B,
    0x87,
    0xB9,
    0x21,
    0x78,
    0x50,
    0x39,
    0xDB,
    0xE1,
    0x72,
    0x09,
    0x62,
    0x3C,
    0x3E,
    0x7E,
    0x5E,
    0x8E,
    0xF1,
    0xA0,
    0xCC,
    0xA3,
    0x2A,
    0x1D,
    0xFB,
    0xB6,
    0xD6,
    0x20,
    0xC4,
    0x8D,
    0x81,
    0x65,
    0xF5,
    0x89,
    0xCB,
    0x9D,
    0x77,
    0xC6,
    0x57,
    0x43,
    0x56,
    0x17,
    0xD4,
    0x40,
    0x1A,
    0x4D,
    0xC0,
    0x63,
    0x6C,
    0xE3,
    0xB7,
    0xC8,
    0x64,
    0x6A,
    0x53,
    0xAA,
    0x38,
    0x98,
    0x0C,
    0xF4,
    0x9B,
    0xED,
    0x7F,
    0x22,
    0x76,
    0xAF,
    0xDD,
    0x3A,
    0x0B,
    0x58,
    0x67,
    0x88,
    0x06,
    0xC3,
    0x35,
    0x0D,
    0x01,
    0x8B,
    0x8C,
    0xC2,
    0xE6,
    0x5F,
    0x02,
    0x24,
    0x75,
    0x93,
    0x66,
    0x1E,
    0xE5,
    0xE2,
    0x54,
    0xD8,
    0x10,
    0xCE,
    0x7A,
    0xE8,
    0x08,
    0x2C,
    0x12,
    0x97,
    0x32,
    0xAB,
    0xB4,
    0x27,
    0x0A,
    0x23,
    0xDF,
    0xEF,
    0xCA,
    0xD9,
    0xB8,
    0xFA,
    0xDC,
    0x31,
    0x6B,
    0xD1,
    0xAD,
    0x19,
    0x49,
    0xBD,
    0x51,
    0x96,
    0xEE,
    0xE4,
    0xA8,
    0x41,
    0xDA,
    0xFF,
    0xCD,
    0x55,
    0x86,
    0x36,
    0xBE,
    0x61,
    0x52,
    0xF8,
    0xBB,
    0x0E,
    0x82,
    0x48,
    0x69,
    0x9A,
    0xE0,
    0x47,
    0x9E,
    0x5C,
    0x04,
    0x4B,
    0x34,
    0x15,
    0x79,
    0x26,
    0xA7,
    0xDE,
    0x29,
    0xAE,
    0x92,
    0xD7,
    0x84,
    0xE9,
    0xD2,
    0xBA,
    0x5D,
    0xF3,
    0xC5,
    0xB0,
    0xBF,
    0xA4,
    0x3B,
    0x71,
    0x44,
    0x46,
    0x2B,
    0xFC,
    0xEB,
    0x6F,
    0xD5,
    0xF6,
    0x14,
    0xFE,
    0x7C,
    0x70,
    0x5A,
    0x7D,
    0xFD,
    0x2F,
    0x18,
    0x83,
    0x16,
    0xA5,
    0x91,
    0x1F,
    0x05,
    0x95,
    0x74,
    0xA9,
    0xC1,
    0x5B,
    0x4A,
    0x85,
    0x6D,
    0x13,
    0x07,
    0x4F,
    0x4E,
    0x45,
    0xB2,
    0x0F,
    0xC9,
    0x1C,
    0xA6,
    0xBC,
    0xEC,
    0x73,
    0x90,
    0x7B,
    0xCF,
    0x59,
    0x8F,
    0xA1,
    0xF9,
    0x2D,
    0xF2,
    0xB1,
    0x00,
    0x94,
    0x37,
    0x9F,
    0xD0,
    0x2E,
    0x9C,
    0x6E,
    0x28,
    0x3F,
    0x80,
    0xF0,
    0x3D,
    0xD3,
    0x25,
    0x8A,
    0xB5,
    0xE7,
    0x42,
    0xB3,
    0xC7,
    0xEA,
    0xF7,
    0x4C,
    0x11,
    0x33,
    0x03,
    0xA2,
    0xAC,
    0x60,
]

comptime _C: InlineArray[UInt8, 48] = [
    0x51,
    0x7C,
    0xC1,
    0xB7,
    0x27,
    0x22,
    0x0A,
    0x94,
    0xFE,
    0x13,
    0xAB,
    0xE8,
    0xFA,
    0x9A,
    0x6E,
    0xE0,
    0x6D,
    0xB1,
    0x4A,
    0xCC,
    0x9E,
    0x21,
    0xC8,
    0x20,
    0xFF,
    0x28,
    0xB1,
    0xD5,
    0xEF,
    0x5D,
    0xE2,
    0xB0,
    0xDB,
    0x92,
    0x37,
    0x1D,
    0x21,
    0x26,
    0xE9,
    0x70,
    0x03,
    0x24,
    0x97,
    0x75,
    0x04,
    0xE8,
    0xC9,
    0x0E,
]


def _combined_sboxes() -> InlineArray[UInt8, 1024]:
    var s1 = materialize[_S1]()
    var s2 = materialize[_S2]()
    var x1 = materialize[_X1]()
    var x2 = materialize[_X2]()
    var boxes = InlineArray[UInt8, 1024](fill=0)
    comptime for i in range(256):
        boxes[i] = s1[i]
        boxes[256 + i] = s2[i]
        boxes[512 + i] = x1[i]
        boxes[768 + i] = x2[i]
    return boxes^


comptime _BOXES: InlineArray[UInt8, 1024] = _combined_sboxes()


def _diffuse(state: List[UInt8]) -> List[UInt8]:
    return [
        state[3]
        ^ state[4]
        ^ state[6]
        ^ state[8]
        ^ state[9]
        ^ state[13]
        ^ state[14],
        state[2]
        ^ state[5]
        ^ state[7]
        ^ state[8]
        ^ state[9]
        ^ state[12]
        ^ state[15],
        state[1]
        ^ state[4]
        ^ state[6]
        ^ state[10]
        ^ state[11]
        ^ state[12]
        ^ state[15],
        state[0]
        ^ state[5]
        ^ state[7]
        ^ state[10]
        ^ state[11]
        ^ state[13]
        ^ state[14],
        state[0]
        ^ state[2]
        ^ state[5]
        ^ state[8]
        ^ state[11]
        ^ state[14]
        ^ state[15],
        state[1]
        ^ state[3]
        ^ state[4]
        ^ state[9]
        ^ state[10]
        ^ state[14]
        ^ state[15],
        state[0]
        ^ state[2]
        ^ state[7]
        ^ state[9]
        ^ state[10]
        ^ state[12]
        ^ state[13],
        state[1]
        ^ state[3]
        ^ state[6]
        ^ state[8]
        ^ state[11]
        ^ state[12]
        ^ state[13],
        state[0]
        ^ state[1]
        ^ state[4]
        ^ state[7]
        ^ state[10]
        ^ state[13]
        ^ state[15],
        state[0]
        ^ state[1]
        ^ state[5]
        ^ state[6]
        ^ state[11]
        ^ state[12]
        ^ state[14],
        state[2]
        ^ state[3]
        ^ state[5]
        ^ state[6]
        ^ state[8]
        ^ state[13]
        ^ state[15],
        state[2]
        ^ state[3]
        ^ state[4]
        ^ state[7]
        ^ state[9]
        ^ state[12]
        ^ state[14],
        state[1]
        ^ state[2]
        ^ state[6]
        ^ state[7]
        ^ state[9]
        ^ state[11]
        ^ state[12],
        state[0]
        ^ state[3]
        ^ state[6]
        ^ state[7]
        ^ state[8]
        ^ state[10]
        ^ state[13],
        state[0]
        ^ state[3]
        ^ state[4]
        ^ state[5]
        ^ state[9]
        ^ state[11]
        ^ state[14],
        state[1]
        ^ state[2]
        ^ state[4]
        ^ state[5]
        ^ state[8]
        ^ state[10]
        ^ state[15],
    ]


@always_inline("nodebug")
def _schedule_round[
    kind: Int, constants_origin: Origin, boxes_origin: Origin
](
    state: InlineArray[UInt8, 16],
    constants: Span[UInt8, constants_origin],
    constant_offset: Int,
    boxes: Span[UInt8, boxes_origin],
) -> InlineArray[UInt8, 16]:
    var output = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        output[i] = state[i] ^ constants[constant_offset + i]
        comptime box = (i + (0 if kind == 1 else 2)) % 4
        output[i] = boxes[box * 256 + Int(output[i])]
    return _diffuse_inline(output)


@always_inline("nodebug")
def _gsrk[
    amount: Int
](x: InlineArray[UInt8, 16], y: InlineArray[UInt8, 16]) -> List[UInt8]:
    comptime q = amount // 8
    comptime r = amount % 8
    var output = List[UInt8](capacity=16)
    comptime for i in range(16):
        comptime hi = (i - q + 16) % 16
        comptime lo = (i - q - 1 + 32) % 16
        var a = UInt16(y[hi]) >> UInt16(r)
        var b = UInt16(y[lo]) << UInt16(8 - r)
        output.append(x[i] ^ UInt8((a | b) & 255))
    return output^


def _keys[
    key_origin: Origin
](key: Span[UInt8, key_origin], rounds: Int) -> List[List[UInt8]]:
    var q = 0 if len(key) == 16 else (1 if len(key) == 24 else 2)
    var constants = materialize[_C]()
    var boxes = materialize[_BOXES]()
    var w0 = InlineArray[UInt8, 16](fill=0)
    var kr = InlineArray[UInt8, 16](fill=0)
    comptime for i in range(16):
        w0[i] = key[i]
    for i in range(len(key) - 16):
        kr[i] = key[16 + i]
    var w1 = _schedule_round[1](
        w0, Span(constants), ((q + 0) % 3) * 16, Span(boxes)
    )
    comptime for i in range(16):
        w1[i] ^= kr[i]
    var w2 = _schedule_round[2](
        w1, Span(constants), ((q + 1) % 3) * 16, Span(boxes)
    )
    comptime for i in range(16):
        w2[i] ^= w0[i]
    var w3 = _schedule_round[1](
        w2, Span(constants), ((q + 2) % 3) * 16, Span(boxes)
    )
    comptime for i in range(16):
        w3[i] ^= w1[i]
    var keys = List[List[UInt8]](capacity=rounds + 1)
    keys.append(_gsrk[19](w0, w1))
    keys.append(_gsrk[19](w1, w2))
    keys.append(_gsrk[19](w2, w3))
    keys.append(_gsrk[19](w3, w0))
    keys.append(_gsrk[31](w0, w1))
    keys.append(_gsrk[31](w1, w2))
    keys.append(_gsrk[31](w2, w3))
    keys.append(_gsrk[31](w3, w0))
    keys.append(_gsrk[67](w0, w1))
    keys.append(_gsrk[67](w1, w2))
    keys.append(_gsrk[67](w2, w3))
    keys.append(_gsrk[67](w3, w0))
    keys.append(_gsrk[97](w0, w1))
    if rounds >= 14:
        keys.append(_gsrk[97](w1, w2))
        keys.append(_gsrk[97](w2, w3))
    if rounds == 16:
        keys.append(_gsrk[97](w3, w0))
        keys.append(_gsrk[109](w0, w1))
    return keys^


def prepare[
    key_origin: Origin
](key: Span[UInt8, key_origin], decrypt: Bool) raises -> Tuple[
    List[List[UInt8]], Int
]:
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise Error("ARIA key must be 16, 24, or 32 bytes")
    var rounds = 12 if len(key) == 16 else (14 if len(key) == 24 else 16)
    var encryption_keys = _keys(key, rounds)
    if not decrypt:
        return (encryption_keys^, rounds)
    var keys = List[List[UInt8]](capacity=rounds + 1)
    keys.append(encryption_keys[rounds].copy())
    for i in range(1, rounds):
        keys.append(_diffuse(encryption_keys[rounds - i]))
    keys.append(encryption_keys[0].copy())
    return (keys^, rounds)


@always_inline("nodebug")
def _sub_inline[
    kind: Int, boxes_origin: Origin
](mut state: InlineArray[UInt8, 16], boxes: Span[UInt8, boxes_origin]):
    comptime for i in range(16):
        comptime box = (i + (0 if kind == 1 else 2)) % 4
        state[i] = boxes[box * 256 + Int(state[i])]


@always_inline("nodebug")
def _diffuse_inline(state: InlineArray[UInt8, 16]) -> InlineArray[UInt8, 16]:
    return InlineArray[UInt8, 16](
        state[3]
        ^ state[4]
        ^ state[6]
        ^ state[8]
        ^ state[9]
        ^ state[13]
        ^ state[14],
        state[2]
        ^ state[5]
        ^ state[7]
        ^ state[8]
        ^ state[9]
        ^ state[12]
        ^ state[15],
        state[1]
        ^ state[4]
        ^ state[6]
        ^ state[10]
        ^ state[11]
        ^ state[12]
        ^ state[15],
        state[0]
        ^ state[5]
        ^ state[7]
        ^ state[10]
        ^ state[11]
        ^ state[13]
        ^ state[14],
        state[0]
        ^ state[2]
        ^ state[5]
        ^ state[8]
        ^ state[11]
        ^ state[14]
        ^ state[15],
        state[1]
        ^ state[3]
        ^ state[4]
        ^ state[9]
        ^ state[10]
        ^ state[14]
        ^ state[15],
        state[0]
        ^ state[2]
        ^ state[7]
        ^ state[9]
        ^ state[10]
        ^ state[12]
        ^ state[13],
        state[1]
        ^ state[3]
        ^ state[6]
        ^ state[8]
        ^ state[11]
        ^ state[12]
        ^ state[13],
        state[0]
        ^ state[1]
        ^ state[4]
        ^ state[7]
        ^ state[10]
        ^ state[13]
        ^ state[15],
        state[0]
        ^ state[1]
        ^ state[5]
        ^ state[6]
        ^ state[11]
        ^ state[12]
        ^ state[14],
        state[2]
        ^ state[3]
        ^ state[5]
        ^ state[6]
        ^ state[8]
        ^ state[13]
        ^ state[15],
        state[2]
        ^ state[3]
        ^ state[4]
        ^ state[7]
        ^ state[9]
        ^ state[12]
        ^ state[14],
        state[1]
        ^ state[2]
        ^ state[6]
        ^ state[7]
        ^ state[9]
        ^ state[11]
        ^ state[12],
        state[0]
        ^ state[3]
        ^ state[6]
        ^ state[7]
        ^ state[8]
        ^ state[10]
        ^ state[13],
        state[0]
        ^ state[3]
        ^ state[4]
        ^ state[5]
        ^ state[9]
        ^ state[11]
        ^ state[14],
        state[1]
        ^ state[2]
        ^ state[4]
        ^ state[5]
        ^ state[8]
        ^ state[10]
        ^ state[15],
        __list_literal__=None,
    )


def _diffusion_masks() -> InlineArray[SIMD[DType.uint8, 16], 16]:
    var masks = InlineArray[SIMD[DType.uint8, 16], 16](
        fill=SIMD[DType.uint8, 16](0)
    )
    comptime for position in range(16):
        var contribution = InlineArray[UInt8, 16](fill=0)
        contribution[position] = 0xFF
        var diffused = _diffuse_inline(contribution)
        var mask = SIMD[DType.uint8, 16](0)
        comptime for i in range(16):
            mask[i] = diffused[i]
        masks[position] = mask
    return masks^


def _precomputed_tables() -> InlineArray[SIMD[DType.uint8, 16], 1024]:
    var boxes = materialize[_BOXES]()
    var tables = InlineArray[SIMD[DType.uint8, 16], 1024](
        fill=SIMD[DType.uint8, 16](0)
    )
    comptime for box in range(4):
        comptime for value in range(256):
            tables[box * 256 + value] = SIMD[DType.uint8, 16](
                boxes[box * 256 + value]
            )
    return tables^


comptime _ROUND_TABLES = _precomputed_tables()


def prepare_tables() -> List[SIMD[DType.uint8, 16]]:
    # Rounds read the immutable table directly from constant storage.
    return List[SIMD[DType.uint8, 16]]()


@always_inline("nodebug")
def _round_table[
    kind: Int
](
    state: SIMD[DType.uint8, 16],
    key: List[UInt8],
    tables: List[SIMD[DType.uint8, 16]],
) -> SIMD[DType.uint8, 16]:
    ref constant_tables = global_constant[_ROUND_TABLES]()
    comptime masks = _diffusion_masks()
    var output = SIMD[DType.uint8, 16](0)
    var key_pointer = Span(key).unsafe_ptr()
    var table_pointer = Span(constant_tables).unsafe_ptr()
    comptime for position in range(16):
        comptime box = (position + (0 if kind == 1 else 2)) % 4
        comptime mask = masks[position]
        output ^= (
            table_pointer[
                unsafe_offset=(
                    box * 256
                    + Int(state[position] ^ key_pointer.unsafe_load(position))
                )
            ]
            & mask
        )
    return output


def _process_prepared_tables_into[
    round_count: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[List[UInt8]],
    tables: List[SIMD[DType.uint8, 16]],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var state = block.unsafe_ptr().unsafe_load[width=16](0)
    comptime for round in range(round_count - 1):
        state = _round_table[1 if round % 2 == 0 else 2](
            state, keys[round], tables
        )
    var penultimate_key = Span(keys[round_count - 1]).unsafe_ptr()
    state ^= penultimate_key.unsafe_load[width=16](0)
    ref constant_tables = global_constant[_ROUND_TABLES]()
    var table_pointer = Span(constant_tables).unsafe_ptr()
    comptime for position in range(16):
        comptime box = (position + 2) % 4
        state[position] = table_pointer[
            unsafe_offset=box * 256 + Int(state[position])
        ][0]
    var final_key = Span(keys[round_count]).unsafe_ptr()
    state ^= final_key.unsafe_load[width=16](0)
    output.unsafe_ptr().unsafe_store[width=16](output_offset, state)


@always_inline("nodebug")
def _round_table_four[
    kind: Int
](
    mut first: SIMD[DType.uint8, 16],
    mut second: SIMD[DType.uint8, 16],
    mut third: SIMD[DType.uint8, 16],
    mut fourth: SIMD[DType.uint8, 16],
    key: List[UInt8],
):
    ref constant_tables = global_constant[_ROUND_TABLES]()
    comptime masks = _diffusion_masks()
    var first_output = SIMD[DType.uint8, 16](0)
    var second_output = SIMD[DType.uint8, 16](0)
    var third_output = SIMD[DType.uint8, 16](0)
    var fourth_output = SIMD[DType.uint8, 16](0)
    var key_pointer = Span(key).unsafe_ptr()
    var table_pointer = Span(constant_tables).unsafe_ptr()
    comptime for position in range(16):
        comptime box = (position + (0 if kind == 1 else 2)) % 4
        comptime mask = masks[position]
        var key_byte = key_pointer.unsafe_load(position)
        first_output ^= (
            table_pointer[
                unsafe_offset=box * 256 + Int(first[position] ^ key_byte)
            ]
            & mask
        )
        second_output ^= (
            table_pointer[
                unsafe_offset=box * 256 + Int(second[position] ^ key_byte)
            ]
            & mask
        )
        third_output ^= (
            table_pointer[
                unsafe_offset=box * 256 + Int(third[position] ^ key_byte)
            ]
            & mask
        )
        fourth_output ^= (
            table_pointer[
                unsafe_offset=box * 256 + Int(fourth[position] ^ key_byte)
            ]
            & mask
        )
    first = first_output
    second = second_output
    third = third_output
    fourth = fourth_output


@always_inline("nodebug")
def _process_four_tables_into[
    round_count: Int,
    block_origin: Origin,
    output_origin: MutOrigin,
](
    keys: List[List[UInt8]],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
):
    var block_pointer = blocks.unsafe_ptr()
    var first = block_pointer.unsafe_load[width=16](0)
    var second = block_pointer.unsafe_load[width=16](16)
    var third = block_pointer.unsafe_load[width=16](32)
    var fourth = block_pointer.unsafe_load[width=16](48)
    comptime for round in range(round_count - 1):
        _round_table_four[1 if round % 2 == 0 else 2](
            first, second, third, fourth, keys[round]
        )
    var penultimate_key = Span(keys[round_count - 1]).unsafe_ptr()
    var key = penultimate_key.unsafe_load[width=16](0)
    first ^= key
    second ^= key
    third ^= key
    fourth ^= key
    ref constant_tables = global_constant[_ROUND_TABLES]()
    var table_pointer = Span(constant_tables).unsafe_ptr()
    comptime for position in range(16):
        comptime box = (position + 2) % 4
        first[position] = table_pointer[
            unsafe_offset=box * 256 + Int(first[position])
        ][0]
        second[position] = table_pointer[
            unsafe_offset=box * 256 + Int(second[position])
        ][0]
        third[position] = table_pointer[
            unsafe_offset=box * 256 + Int(third[position])
        ][0]
        fourth[position] = table_pointer[
            unsafe_offset=box * 256 + Int(fourth[position])
        ][0]
    var final_key = (
        Span(keys[round_count]).unsafe_ptr().unsafe_load[width=16](0)
    )
    first ^= final_key
    second ^= final_key
    third ^= final_key
    fourth ^= final_key
    var output_pointer = output.unsafe_ptr()
    output_pointer.unsafe_store[width=16](output_offset, first)
    output_pointer.unsafe_store[width=16](output_offset + 16, second)
    output_pointer.unsafe_store[width=16](output_offset + 32, third)
    output_pointer.unsafe_store[width=16](output_offset + 48, fourth)


def process_four_tables_into[
    block_origin: Origin, output_origin: MutOrigin
](
    keys: List[List[UInt8]],
    rounds: Int,
    tables: List[SIMD[DType.uint8, 16]],
    blocks: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(blocks) < 64:
        raise Error("four-way ARIA input span is too short")
    if output_offset < 0 or output_offset + 64 > len(output):
        raise Error("four-way ARIA output span is too short")
    if rounds == 12:
        _process_four_tables_into[12](keys, blocks, output, output_offset)
        return
    if rounds == 14:
        _process_four_tables_into[14](keys, blocks, output, output_offset)
        return
    if rounds == 16:
        _process_four_tables_into[16](keys, blocks, output, output_offset)
        return
    raise Error("invalid ARIA round count")


def process_prepared_tables_into[
    block_origin: Origin, output_origin: MutOrigin
](
    keys: List[List[UInt8]],
    rounds: Int,
    tables: List[SIMD[DType.uint8, 16]],
    block: Span[UInt8, block_origin],
    output: Span[mut=True, UInt8, output_origin],
    output_offset: Int,
) raises:
    if len(block) != 16:
        raise Error("ARIA block must be 16 bytes")
    if output_offset < 0 or output_offset + 16 > len(output):
        raise Error("ARIA output span is too short")
    if rounds == 12:
        _process_prepared_tables_into[12](
            keys, tables, block, output, output_offset
        )
        return
    if rounds == 14:
        _process_prepared_tables_into[14](
            keys, tables, block, output, output_offset
        )
        return
    if rounds == 16:
        _process_prepared_tables_into[16](
            keys, tables, block, output, output_offset
        )
        return
    raise Error("invalid ARIA round count")


def process_prepared_tables[
    block_origin: Origin
](
    keys: List[List[UInt8]],
    rounds: Int,
    tables: List[SIMD[DType.uint8, 16]],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var output = List[UInt8](length=16, fill=0)
    process_prepared_tables_into(keys, rounds, tables, block, Span(output), 0)
    return output^


@always_inline("nodebug")
def _round_inline[
    kind: Int, boxes_origin: Origin
](
    state: InlineArray[UInt8, 16],
    key: List[UInt8],
    boxes: Span[UInt8, boxes_origin],
) -> InlineArray[UInt8, 16]:
    var output = InlineArray[UInt8, 16](fill=0)
    var key_pointer = Span(key).unsafe_ptr()
    comptime for i in range(16):
        output[i] = state[i] ^ key_pointer.unsafe_load(i)
    _sub_inline[kind](output, boxes)
    return _diffuse_inline(output)


def _process_prepared[
    round_count: Int, block_origin: Origin
](keys: List[List[UInt8]], block: Span[UInt8, block_origin]) -> List[UInt8]:
    var state = InlineArray[UInt8, 16](fill=0)
    var boxes = materialize[_BOXES]()
    comptime for i in range(16):
        state[i] = block[i]
    comptime for round in range(round_count - 1):
        state = _round_inline[1 if round % 2 == 0 else 2](
            state, keys[round], Span(boxes)
        )
    var penultimate_key = Span(keys[round_count - 1]).unsafe_ptr()
    comptime for i in range(16):
        state[i] ^= penultimate_key.unsafe_load(i)
    _sub_inline[2](state, Span(boxes))
    var output = List[UInt8](capacity=16)
    var final_key = Span(keys[round_count]).unsafe_ptr()
    comptime for i in range(16):
        output.append(state[i] ^ final_key.unsafe_load(i))
    return output^


def process_prepared[
    block_origin: Origin
](
    keys: List[List[UInt8]],
    rounds: Int,
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    if len(block) != 16:
        raise Error("ARIA block must be 16 bytes")
    if rounds == 12:
        return _process_prepared[12](keys, block)
    if rounds == 14:
        return _process_prepared[14](keys, block)
    if rounds == 16:
        return _process_prepared[16](keys, block)
    raise Error("invalid ARIA round count")


def process[
    key_origin: Origin, block_origin: Origin
](
    decrypt: Bool,
    key: Span[UInt8, key_origin],
    block: Span[UInt8, block_origin],
) raises -> List[UInt8]:
    var schedule = prepare(key, decrypt)
    return process_prepared(schedule[0], schedule[1], block)
