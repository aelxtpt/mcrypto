"""HC-128 stream cipher."""
from std.memory import bitcast


from ..internal.bytes import load_le32


@always_inline("nodebug")
def _ror(x: UInt32, n: Int) -> UInt32:
    return (x >> UInt32(n)) | (x << UInt32(32 - n))


@always_inline("nodebug")
def _f1(x: UInt32) -> UInt32:
    return _ror(x, 7) ^ _ror(x, 18) ^ (x >> 3)


@always_inline("nodebug")
def _f2(x: UInt32) -> UInt32:
    return _ror(x, 17) ^ _ror(x, 19) ^ (x >> 10)


@always_inline("nodebug")
def _step(
    mut table: InlineArray[UInt32, 1024],
    mut x: InlineArray[UInt32, 16],
    mut y: InlineArray[UInt32, 16],
    counter: Int,
    initialize: Bool,
) -> UInt32:
    var cc = counter & 511
    var d = counter & 15
    if counter < 512:
        var h = (
            table[512 + Int(x[(d + 4) & 15] & 255)]
            + table[768 + Int((x[(d + 4) & 15] >> 16) & 255)]
        )
        var value = (
            table[cc]
            + _ror(x[(d + 6) & 15], 8)
            + (_ror(table[(cc + 1) & 511], 23) ^ _ror(x[(d + 13) & 15], 10))
        )
        if initialize:
            value ^= h
        x[d] = value
        table[cc] = value
        return value if initialize else value ^ h
    var h = (
        table[Int(y[(d + 4) & 15] & 255)]
        + table[256 + Int((y[(d + 4) & 15] >> 16) & 255)]
    )
    var value = (
        table[512 + cc]
        + _ror(y[(d + 6) & 15], 24)
        + (_ror(table[512 + ((cc + 1) & 511)], 9) ^ _ror(y[(d + 13) & 15], 22))
    )
    if initialize:
        value ^= h
    y[d] = value
    table[512 + cc] = value
    return value if initialize else value ^ h


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 16 or len(nonce) != 16:
        raise Error("HC-128 requires 16-byte key and IV")
    var table = InlineArray[UInt32, 1024](uninitialized=True)
    comptime for i in range(4):
        table[i] = load_le32(key, i * 4)
        table[i + 4] = table[i]
        table[i + 8] = load_le32(nonce, i * 4)
        table[i + 12] = table[i + 8]
    for i in range(16, 272):
        table[i] = (
            _f2(table[i - 2])
            + table[i - 7]
            + _f1(table[i - 15])
            + table[i - 16]
            + UInt32(i)
        )
    comptime for i in range(16):
        table[i] = table[256 + i]
    for i in range(16, 1024):
        table[i] = (
            _f2(table[i - 2])
            + table[i - 7]
            + _f1(table[i - 15])
            + table[i - 16]
            + UInt32(256 + i)
        )
    var x = InlineArray[UInt32, 16](uninitialized=True)
    var y = InlineArray[UInt32, 16](uninitialized=True)
    comptime for i in range(16):
        x[i] = table[496 + i]
        y[i] = table[1008 + i]
    var counter = 0
    for _ in range(1024):
        _ = _step(table, x, y, counter, True)
        counter = (counter + 1) & 1023
    var output = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    var offset = 0
    while offset + 16 <= len(input):
        var words = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            words[lane] = _step(table, x, y, counter, False)
            counter = (counter + 1) & 1023
        output_pointer.unsafe_store[width=16](
            offset,
            input_pointer.unsafe_load[width=16](offset)
            ^ bitcast[DType.uint8, 16](words),
        )
        offset += 16
    while offset < len(input):
        var word = _step(table, x, y, counter, False)
        counter = (counter + 1) & 1023
        var count = min(4, len(input) - offset)
        for i in range(count):
            output_pointer.unsafe_store(
                offset + i,
                input_pointer.unsafe_load(offset + i)
                ^ UInt8(word >> UInt32(8 * i)),
            )
        offset += 4
    return output^
