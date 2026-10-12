from std.testing import assert_equal, assert_raises, TestSuite
from mcrypto.compression.transforms import (
    inflate,
    zlib_decompress,
    gzip_decompress,
    transform,
    _inflate_codes,
    _fixed_lengths,
)
from mcrypto.compression.algorithm import CompressionTransform
from mcrypto.encoding.transforms import transform as decode
from mcrypto.encoding.algorithm import EncodingTransform


def _hex(text: String) raises -> List[UInt8]:
    return decode(EncodingTransform.HEX_DECODE, text.as_bytes())


def test_stored_block_budget() raises:
    # Independent Python zlib fixture, BTYPE=0.
    var compressed: List[UInt8] = [1, 80, 199, 175, 56]
    var expected = List[UInt8]()
    for _ in range(10000):
        for byte in "abcde".as_bytes():
            expected.append(byte)
    for _ in range(4):
        for byte in range(256):
            expected.append(UInt8(byte))
    for byte in expected:
        compressed.append(byte)
    assert_equal(inflate(Span(compressed), max_output_bytes=51024), expected)
    assert_equal(inflate(Span(compressed)), expected)
    with assert_raises():
        _ = inflate(Span(compressed), max_output_bytes=51023)
    with assert_raises():
        _ = inflate(Span(compressed), max_output_bytes=0)


def test_fixed_block_budget() raises:
    # Independent Python zlib fixture, BTYPE=1.
    var compressed = _hex(
        "4b4c4a4e494d1c25468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825468951629418254689516294182546895162941825860bc1c0c8c4ccc2cac6cec1c9c5cdc3cbc72f2028242c222a262e2129252d232b27afa0a8a4aca2aaa6aea1a9a5ada3aba76f6068646c626a666e6169656d636b67efe0e8e4ece2eae6eee1e9e5ede3ebe71f1018141c121a161e1119151d131b179f00b6252d3d23332b3b27372fbfa0b0a8b8a4b4acbca2b2aabaa6b6aebea1b1a9b9a5b5adbda3b3abbba7b7af7fc2c44993a74c9d367dc6cc59b3e7cc9d377fc1c2458b972c5db67cc5ca55abd7ac5db77ec3c64d9bb76cddb67dc7ce5dbbf7ecddb7ffc0c143878f1c3d76fcc4c953a7cf9c3d77fec2c54b97af5cbd76fdc6cd5bb7efdcbd77ffc1c3478f9f3c7df6fcc5cb57afdfbc7df7fec3c74f9fbf7cfdf6fdc7cf5fbffffcfdf77fd4ffa3fe1fc9fe0700"
    )
    var expected = List[UInt8]()
    for _ in range(10000):
        for byte in "abcde".as_bytes():
            expected.append(byte)
    for _ in range(4):
        for byte in range(256):
            expected.append(UInt8(byte))
    assert_equal(inflate(Span(compressed), max_output_bytes=51024), expected)
    assert_equal(inflate(Span(compressed)), expected)
    with assert_raises():
        _ = inflate(Span(compressed), max_output_bytes=51023)
    with assert_raises():
        _ = inflate(Span(compressed), max_output_bytes=0)


def test_dynamic_block_budget() raises:
    # Independent Python zlib fixture, BTYPE=2.
    var compressed = _hex(
        "edcfd31210080040d16cdbdccdb6cd45b66ddbb6dd86cdb66ddbb66dbb66fa8c3a2fe7f5cead5da76ebdfab5010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f0ab102060a0c04182060b1e2264a8d061c2860b1f2162a4c851a2468b1e2366acd871e2c68b9f2061a2c47ffc992469b2e42952a64a9d266dbaf4193266ca9c256bb6ec3972e6ca9d276fbefc050a162a5ca468b1e27ffdfdcfbf254a962a5da66cb9f2152a56aa5ca56ab5ea356ad6fa5969d0b051e3264d9b356fd1b255eb366ddbb5efd0b153e72e5dbb75efd1b357ef3e7dfbf51f3070d0e02143870d1f3172d4e83163c78d9f30f1bf4993a74cfd7fdaf4193367cd9e3377defc050b172d5eb274d9f2152b57ad5eb376ddfa0d1b376ddeb275dbf61d3b77eddeb377dffe03070f1d3e72f4d8f113274f9d3e73f6dcf90b172f5dbe72f5daf51b376fddbe73f7defd070f1f3d7ef2f4d9f3172f5fbd7ef3f6ddfb0f1f3f7dfef2f5db77fffe7fe7ff1f"
    )
    var expected = List[UInt8]()
    for _ in range(10000):
        for byte in "abcde".as_bytes():
            expected.append(byte)
    for _ in range(4):
        for byte in range(256):
            expected.append(UInt8(byte))
    assert_equal(inflate(Span(compressed), max_output_bytes=51024), expected)
    assert_equal(inflate(Span(compressed)), expected)
    with assert_raises():
        _ = inflate(Span(compressed), max_output_bytes=51023)
    with assert_raises():
        _ = inflate(Span(compressed), max_output_bytes=0)


def test_wrapper_budgets_and_concatenated_gzip() raises:
    var zlib_data = _hex("789ccb48cdc9c90700062c0215")
    var gzip_data = _hex("1f8b08000000000002ffcb48cdc9c9070086a6103605000000")
    var expected = List("hello".as_bytes())
    assert_equal(zlib_decompress(Span(zlib_data), max_output_bytes=5), expected)
    assert_equal(gzip_decompress(Span(gzip_data), max_output_bytes=5), expected)
    with assert_raises():
        _ = zlib_decompress(Span(zlib_data), max_output_bytes=4)
    with assert_raises():
        _ = gzip_decompress(Span(gzip_data), max_output_bytes=4)
    var combined = _hex(
        "1f8b08000000000002ffcb48cdc9c9070086a61036050000001f8b08000000000002ffcb48cdc9c9070086a6103605000000"
    )
    assert_equal(
        gzip_decompress(Span(combined), max_output_bytes=10),
        List("hellohello".as_bytes()),
    )
    with assert_raises():
        _ = gzip_decompress(Span(combined), max_output_bytes=9)
    var empty_zlib = _hex("789c030000000001")
    var empty_gzip = _hex("1f8b08000000000002ff03000000000000000000")
    var empty_raw = _hex("0300")
    assert_equal(len(zlib_decompress(Span(empty_zlib), max_output_bytes=0)), 0)
    assert_equal(len(gzip_decompress(Span(empty_gzip), max_output_bytes=0)), 0)
    assert_equal(len(inflate(Span(empty_raw), max_output_bytes=0)), 0)
    with assert_raises():
        _ = inflate(Span(empty_raw), max_output_bytes=-1)
    with assert_raises():
        _ = zlib_decompress(Span(empty_zlib), max_output_bytes=-1)
    with assert_raises():
        _ = gzip_decompress(Span(empty_gzip), max_output_bytes=-1)
    zlib_data[len(zlib_data) - 1] ^= 1
    gzip_data[len(gzip_data) - 8] ^= 1
    with assert_raises():
        _ = zlib_decompress(Span(zlib_data), max_output_bytes=5)
    with assert_raises():
        _ = gzip_decompress(Span(gzip_data), max_output_bytes=5)


def test_dispatcher_propagates_budget_and_rejects_compressors() raises:
    for algorithm in [
        CompressionTransform.DEFLATE,
        CompressionTransform.ZLIB_COMPRESS,
        CompressionTransform.GZIP,
    ]:
        with assert_raises():
            _ = transform(algorithm, "hello".as_bytes(), max_output_bytes=0)
    for algorithm, encoded in [
        (CompressionTransform.INFLATE, "cb48cdc9c90700"),
        (CompressionTransform.ZLIB_DECOMPRESS, "789ccb48cdc9c90700062c0215"),
        (
            CompressionTransform.GUNZIP,
            "1f8b08000000000002ffcb48cdc9c9070086a6103605000000",
        ),
    ]:
        var data = _hex(encoded)
        assert_equal(
            transform(algorithm, Span(data), max_output_bytes=5),
            List("hello".as_bytes()),
        )
        with assert_raises():
            _ = transform(algorithm, Span(data), max_output_bytes=4)


def test_decoder_stops_before_backreference_growth() raises:
    # Fixed-Huffman stream for a long run, from Python zlib. Inspect the
    # internal output after the error to prove enforcement precedes expansion.
    var data = _hex(
        "4b4c1c05a360148c8251300a46c1281805a360148c8251300a46c1281805a360148c8251300a46c1281805a360148c8251300a46c1281805a360148c8251300a863e0000"
    )
    var position = 1
    var bits = UInt64(data[0] >> 3)
    var bit_count = 5
    var output = List[UInt8]()
    var literal = _fixed_lengths()
    var distance = List[Int](length=32, fill=5)
    with assert_raises():
        _inflate_codes(
            Span(data),
            position,
            bits,
            bit_count,
            output,
            literal,
            distance,
            32768,
            3,
        )
    assert_equal(output, List("aa".as_bytes()))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
