"""Type-safe binary-to-text transform selection."""


@fieldwise_init
struct _EncodingTransformToken[value: UInt8](ImplicitlyCopyable):
    pass


struct EncodingTransform(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime HEX_ENCODE = EncodingTransform(_EncodingTransformToken[0]())
    comptime HEX_DECODE = EncodingTransform(_EncodingTransformToken[1]())
    comptime BASE32_ENCODE = EncodingTransform(_EncodingTransformToken[2]())
    comptime BASE32_DECODE = EncodingTransform(_EncodingTransformToken[3]())
    comptime BASE64_ENCODE = EncodingTransform(_EncodingTransformToken[4]())
    comptime BASE64_DECODE = EncodingTransform(_EncodingTransformToken[5]())
    comptime BASE64URL_ENCODE = EncodingTransform(_EncodingTransformToken[6]())
    comptime BASE64URL_DECODE = EncodingTransform(_EncodingTransformToken[7]())

    def __init__[value: UInt8](out self, token: _EncodingTransformToken[value]):
        comptime assert value < 8, "invalid EncodingTransform value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_encoding_transform(name: String) raises -> EncodingTransform:
    if name == "HexEncode":
        return EncodingTransform.HEX_ENCODE
    if name == "HexDecode":
        return EncodingTransform.HEX_DECODE
    if name == "Base32Encode":
        return EncodingTransform.BASE32_ENCODE
    if name == "Base32Decode":
        return EncodingTransform.BASE32_DECODE
    if name == "Base64Encode":
        return EncodingTransform.BASE64_ENCODE
    if name == "Base64Decode":
        return EncodingTransform.BASE64_DECODE
    if name == "Base64URLEncode":
        return EncodingTransform.BASE64URL_ENCODE
    if name == "Base64URLDecode":
        return EncodingTransform.BASE64URL_DECODE
    raise Error("unknown encoding transform")
