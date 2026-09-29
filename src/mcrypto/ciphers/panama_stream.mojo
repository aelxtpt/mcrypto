"""Panama stream cipher in pure Mojo."""
from std.memory import bitcast


from ..hashes.panama import _Panama


@always_inline("nodebug")
def _swap_words(words: SIMD[DType.uint32, 8]) -> SIMD[DType.uint32, 8]:
    return (
        ((words & 0x000000FF) << 24)
        | ((words & 0x0000FF00) << 8)
        | ((words & 0x00FF0000) >> 8)
        | ((words & 0xFF000000) >> 24)
    )


@always_inline("nodebug")
def _words[
    origin: Origin
](data: Span[UInt8, origin], big_endian: Bool) -> SIMD[DType.uint32, 8]:
    var output = bitcast[DType.uint32, 8](
        data.unsafe_ptr().unsafe_load[width=32](0)
    )
    return _swap_words(output) if big_endian else output


def xor[
    key_origin: Origin, nonce_origin: Origin, input_origin: Origin
](
    big_endian: Bool,
    key: Span[UInt8, key_origin],
    nonce: Span[UInt8, nonce_origin],
    input: Span[UInt8, input_origin],
) raises -> List[UInt8]:
    if len(key) != 32 or len(nonce) != 32:
        raise Error("Panama requires a 32-byte key and nonce")
    var engine = _Panama()
    engine.step[True](_words(key, big_endian))
    engine.step[True](_words(nonce, big_endian))
    var zeros = SIMD[DType.uint32, 8](0)
    for _ in range(32):
        engine.step[False](zeros)
    var output = List[UInt8](length=len(input), fill=0)
    var input_pointer = input.unsafe_ptr()
    var output_pointer = Span(output).unsafe_ptr()
    var offset = 0
    while offset < len(input):
        var words = SIMD[DType.uint32, 8](
            engine.state[9],
            engine.state[10],
            engine.state[11],
            engine.state[12],
            engine.state[13],
            engine.state[14],
            engine.state[15],
            engine.state[16],
        )
        if big_endian:
            words = _swap_words(words)
        var stream = bitcast[DType.uint8, 32](words)
        var count = min(32, len(input) - offset)
        if count == 32:
            output_pointer.unsafe_store[width=32](
                offset,
                input_pointer.unsafe_load[width=32](offset) ^ stream,
            )
        else:
            for i in range(count):
                output_pointer.unsafe_store(
                    offset + i,
                    input_pointer.unsafe_load(offset + i) ^ stream[i],
                )
        offset += 32
        if offset < len(input):
            engine.step[False](zeros)
    return output^
