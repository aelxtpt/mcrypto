"""Type-safe compression transform selection."""


@fieldwise_init
struct _CompressionTransformToken[value: UInt8](ImplicitlyCopyable):
    pass


struct CompressionTransform(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime DEFLATE = CompressionTransform(_CompressionTransformToken[0]())
    comptime INFLATE = CompressionTransform(_CompressionTransformToken[1]())
    comptime GZIP = CompressionTransform(_CompressionTransformToken[2]())
    comptime GUNZIP = CompressionTransform(_CompressionTransformToken[3]())
    comptime ZLIB_COMPRESS = CompressionTransform(
        _CompressionTransformToken[4]()
    )
    comptime ZLIB_DECOMPRESS = CompressionTransform(
        _CompressionTransformToken[5]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _CompressionTransformToken[value]):
        comptime assert value < 6, "invalid CompressionTransform value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_compression_transform(name: String) raises -> CompressionTransform:
    if name == "Deflate":
        return CompressionTransform.DEFLATE
    if name == "Inflate":
        return CompressionTransform.INFLATE
    if name == "Gzip":
        return CompressionTransform.GZIP
    if name == "Gunzip":
        return CompressionTransform.GUNZIP
    if name == "ZlibCompress":
        return CompressionTransform.ZLIB_COMPRESS
    if name == "ZlibDecompress":
        return CompressionTransform.ZLIB_DECOMPRESS
    raise Error("unknown compression transform")
