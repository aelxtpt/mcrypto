"""HC-256 stream cipher."""
from std.memory import bitcast


@always_inline("nodebug")
def _ror(x: UInt32, n: Int) -> UInt32:
    return (x >> UInt32(n)) | (x << UInt32(32 - n))


@always_inline("nodebug")
def _rol(x: UInt32, n: Int) -> UInt32:
    return (x << UInt32(n)) | (x >> UInt32(32 - n))


def _load_word[
    origin: Origin
](data: Span[UInt8, origin], offset: Int) -> UInt32:
    var value = UInt32(0)
    for i in range(4):
        value |= UInt32(data[offset + i])
        value = _rol(value, 8)
    return value


@always_inline("nodebug")
def _f1(x: UInt32) -> UInt32:
    return _ror(x, 7) ^ _ror(x, 18) ^ (x >> 3)


@always_inline("nodebug")
def _f2(x: UInt32) -> UInt32:
    return _ror(x, 17) ^ _ror(x, 19) ^ (x >> 10)


@always_inline("nodebug")
def _generate(
    mut p: InlineArray[UInt32, 1024],
    mut q: InlineArray[UInt32, 1024],
    counter: Int,
) -> UInt32:
    var i = counter & 1023
    var i3 = (i - 3) & 1023
    var i10 = (i - 10) & 1023
    var i12 = (i - 12) & 1023
    var i1023 = (i - 1023) & 1023
    if counter < 1024:
        p[i] += (
            p[i10]
            + (_ror(p[i3], 10) ^ _ror(p[i1023], 23))
            + q[Int((p[i3] ^ p[i1023]) & 1023)]
        )
        var u = p[i12]
        return (
            q[Int(u & 255)]
            + q[256 + Int((u >> 8) & 255)]
            + q[512 + Int((u >> 16) & 255)]
            + q[768 + Int(u >> 24)]
        ) ^ p[i]
    q[i] += (
        q[i10]
        + (_ror(q[i3], 10) ^ _ror(q[i1023], 23))
        + p[Int((q[i3] ^ q[i1023]) & 1023)]
    )
    var u = q[i12]
    return (
        p[Int(u & 255)]
        + p[256 + Int((u >> 8) & 255)]
        + p[512 + Int((u >> 16) & 255)]
        + p[768 + Int(u >> 24)]
    ) ^ q[i]


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 32 or len(nonce) != 32:
        raise Error("HC-256 requires 32-byte key and IV")
    var w = InlineArray[UInt32, 2560](uninitialized=True)
    comptime for i in range(8):
        w[i] = _load_word(key, i * 4)
        w[i + 8] = _load_word(nonce, i * 4)
    for i in range(16, 2560):
        w[i] = _f2(w[i - 2]) + w[i - 7] + _f1(w[i - 15]) + w[i - 16] + UInt32(i)
    var p = InlineArray[UInt32, 1024](uninitialized=True)
    var q = InlineArray[UInt32, 1024](uninitialized=True)
    for i in range(1024):
        p[i] = w[i + 512]
        q[i] = w[i + 1536]
    var counter = 0
    for _ in range(4096):
        _ = _generate(p, q, counter)
        counter = (counter + 1) & 2047
    var output = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    var offset = 0
    while offset + 16 <= len(input):
        var words = SIMD[DType.uint32, 4](0)
        comptime for lane in range(4):
            words[lane] = _generate(p, q, counter)
            counter = (counter + 1) & 2047
        output_pointer.unsafe_store[width=16](
            offset,
            input_pointer.unsafe_load[width=16](offset)
            ^ bitcast[DType.uint8, 16](words),
        )
        offset += 16
    while offset < len(input):
        var word = _generate(p, q, counter)
        counter = (counter + 1) & 2047
        var count = min(4, len(input) - offset)
        for i in range(count):
            output_pointer.unsafe_store(
                offset + i,
                input_pointer.unsafe_load(offset + i)
                ^ UInt8(word >> UInt32(8 * i)),
            )
        offset += 4
    return output^
