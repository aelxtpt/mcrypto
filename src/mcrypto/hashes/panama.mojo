"""Panama hash in pure Mojo."""

from std.collections import InlineArray
from std.memory import bitcast


@always_inline("nodebug")
def _rotl[amount: Int](value: UInt32) -> UInt32:
    comptime if amount == 0:
        return value
    else:
        return (value << UInt32(amount)) | (value >> UInt32(32 - amount))


struct _Panama(Movable):
    var state: InlineArray[UInt32, 17]
    var buffer: InlineArray[InlineArray[UInt32, 8], 32]
    var position: Int

    def __init__(out self):
        self.state = InlineArray[UInt32, 17](fill=0)
        var stage = InlineArray[UInt32, 8](fill=0)
        self.buffer = InlineArray[InlineArray[UInt32, 8], 32](fill=stage)
        self.position = 0

    def __init__(out self, *, deinit move: Self):
        self.state = move.state^
        self.buffer = move.buffer^
        self.position = move.position

    @always_inline("nodebug")
    def step[pushing: Bool](mut self, words: SIMD[DType.uint32, 8]):
        var stage16 = (self.position + 16) & 31
        var stage4 = (self.position + 28) & 31
        self.position = (self.position + 1) & 31
        var stage0 = self.position
        var stage25 = (self.position + 7) & 31
        comptime for i in range(8):
            var old = self.buffer[stage0][i]
            comptime if pushing:
                self.buffer[stage0][i] = old ^ words[i]
            else:
                self.buffer[stage0][i] = old ^ self.state[i + 1]
            self.buffer[stage25][(i + 6) % 8] ^= old
        var transformed = InlineArray[UInt32, 17](fill=0)
        comptime for i in range(17):
            comptime target = (5 * i) % 17
            transformed[target] = _rotl[(target * (target + 1) // 2) % 32](
                self.state[i]
                ^ (self.state[(i + 1) % 17] | ~self.state[(i + 2) % 17])
            )
        var next = InlineArray[UInt32, 17](fill=0)
        next[0] = transformed[0] ^ transformed[1] ^ transformed[4] ^ 1
        comptime for i in range(8):
            next[i + 1] = (
                transformed[i + 1]
                ^ transformed[(i + 2) % 17]
                ^ transformed[(i + 5) % 17]
            )
            comptime if pushing:
                next[i + 1] ^= words[i]
            else:
                next[i + 1] ^= self.buffer[stage4][i]
            next[i + 9] = (
                transformed[i + 9]
                ^ transformed[(i + 10) % 17]
                ^ transformed[(i + 13) % 17]
                ^ self.buffer[stage16][i]
            )
        self.state = next^


def panama[origin: Origin](data: Span[UInt8, origin]) -> List[UInt8]:
    var engine = _Panama()
    var data_pointer = data.unsafe_ptr()
    var offset = 0
    while offset + 32 <= len(data):
        var words = bitcast[DType.uint32, 8](
            data_pointer.unsafe_load[width=32](offset)
        )
        engine.step[True](words)
        offset += 32
    var final_block = InlineArray[UInt8, 32](fill=0)
    var remaining = len(data) - offset
    for i in range(remaining):
        final_block[i] = data[offset + i]
    final_block[remaining] = 1
    var final_words = bitcast[DType.uint32, 8](
        Span(final_block).unsafe_ptr().unsafe_load[width=32](0)
    )
    engine.step[True](final_words)
    var zeros = SIMD[DType.uint32, 8](0)
    for _ in range(32):
        engine.step[False](zeros)
    var output = List[UInt8](capacity=32)
    for i in range(8):
        var word = engine.state[i + 9]
        for j in range(4):
            output.append(UInt8(word >> UInt32(j * 8)))
    return output^
