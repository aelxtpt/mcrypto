"""NIST SP 800-90A Hash_DRBG and HMAC_DRBG one-shot generation."""

from ..hashes.sha256 import SHA256
from ..hashes.algorithm import HashAlgorithm
from ..hashes.sha512 import SHA512
from ..macs.algorithm import HmacAlgorithm
from ..macs.hmac import (
    _HMACKey,
    _finalize_sha256_into,
    _finalize_sha512_into,
)


@always_inline("nodebug")
def _hash_into[
    origin: Origin
](
    algorithm: HashAlgorithm,
    data: Span[UInt8, origin],
    mut output: InlineArray[UInt8, 64],
) raises:
    if algorithm == HashAlgorithm.SHA256:
        var state = SHA256()
        state.update(data)
        _finalize_sha256_into(state, output)
        return
    if algorithm == HashAlgorithm.SHA512:
        var state = SHA512()
        state.update(data)
        _finalize_sha512_into(state, output)
        return
    raise Error("unsupported DRBG hash")


@always_inline("nodebug")
def _hash_working_into[
    origin: Origin
](
    algorithm: HashAlgorithm,
    data: Span[UInt8, origin],
    mut output: InlineArray[UInt8, 64],
) raises:
    var source = data.unsafe_ptr()
    if algorithm == HashAlgorithm.SHA256:
        var state = SHA256()
        var destination = Span(state._buffer).unsafe_ptr()
        destination.unsafe_store[width=32](0, source.unsafe_load[width=32](0))
        destination.unsafe_store[width=16](32, source.unsafe_load[width=16](32))
        destination.unsafe_store[width=4](48, source.unsafe_load[width=4](48))
        destination.unsafe_store[width=2](52, source.unsafe_load[width=2](52))
        destination.unsafe_store(54, source.unsafe_load(54))
        state._buffer_len = 55
        state._total_len = 55
        _finalize_sha256_into(state, output)
        return
    if algorithm == HashAlgorithm.SHA512:
        var state = SHA512()
        var destination = Span(state._buffer).unsafe_ptr()
        destination.unsafe_store[width=64](0, source.unsafe_load[width=64](0))
        destination.unsafe_store[width=32](64, source.unsafe_load[width=32](64))
        destination.unsafe_store[width=8](96, source.unsafe_load[width=8](96))
        destination.unsafe_store[width=4](104, source.unsafe_load[width=4](104))
        destination.unsafe_store[width=2](108, source.unsafe_load[width=2](108))
        destination.unsafe_store(110, source.unsafe_load(110))
        state._buffer_len = 111
        state._total_len = 111
        _finalize_sha512_into(state, output)
        return
    raise Error("unsupported DRBG hash")


def _hmac(
    algorithm: HmacAlgorithm, key: List[UInt8], data: List[UInt8]
) raises -> List[UInt8]:
    var prepared = _HMACKey(algorithm, Span(key))
    return prepared.authenticate(Span(data))


def _append(mut target: List[UInt8], source: List[UInt8]):
    for byte in source:
        target.append(byte)


def _increment(mut value: List[UInt8]):
    for offset in range(len(value)):
        var i = len(value) - 1 - offset
        value[i] += 1
        if value[i] != 0:
            return


def _add[origin: Origin](mut value: List[UInt8], addition: Span[UInt8, origin]):
    var carry = 0
    var i = len(value) - 1
    var j = len(addition) - 1
    while i >= 0:
        var total = Int(value[i]) + carry + (Int(addition[j]) if j >= 0 else 0)
        value[i] = UInt8(total)
        carry = total >> 8
        i -= 1
        j -= 1


def _hash_df(
    algorithm: HashAlgorithm, data: List[UInt8], output_bytes: Int
) raises -> List[UInt8]:
    var output = List[UInt8](length=output_bytes, fill=0)
    var input = List[UInt8](length=5 + len(data), fill=0)
    var bits = UInt32(output_bytes * 8)
    input[1] = UInt8(bits >> 24)
    input[2] = UInt8(bits >> 16)
    input[3] = UInt8(bits >> 8)
    input[4] = UInt8(bits)
    for i in range(len(data)):
        input[5 + i] = data[i]
    var digest = InlineArray[UInt8, 64](uninitialized=True)
    var digest_bytes = 32 if algorithm == HashAlgorithm.SHA256 else 64
    var produced = 0
    var counter: UInt8 = 1
    while produced < output_bytes:
        input[0] = counter
        _hash_into(algorithm, Span(input), digest)
        var take = min(digest_bytes, output_bytes - produced)
        for i in range(take):
            output[produced + i] = digest[i]
        produced += take
        counter += 1
    return output^


def hash_drbg[
    entropy_origin: Origin,
    nonce_origin: Origin,
    personalization_origin: Origin,
    additional_origin: Origin,
](
    algorithm: HashAlgorithm,
    entropy: Span[UInt8, entropy_origin],
    nonce: Span[UInt8, nonce_origin],
    personalization: Span[UInt8, personalization_origin],
    additional: Span[UInt8, additional_origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    if algorithm != HashAlgorithm.SHA256 and algorithm != HashAlgorithm.SHA512:
        raise Error("Hash_DRBG requires SHA-256 or SHA-512")
    var seed_length = 55 if algorithm == HashAlgorithm.SHA256 else 111
    var seed = List[UInt8](
        length=len(entropy) + len(nonce) + len(personalization), fill=0
    )
    var seed_offset = 0
    for byte in entropy:
        seed[seed_offset] = byte
        seed_offset += 1
    for byte in nonce:
        seed[seed_offset] = byte
        seed_offset += 1
    for byte in personalization:
        seed[seed_offset] = byte
        seed_offset += 1
    var v = _hash_df(algorithm, seed, seed_length)
    var c_input = List[UInt8](length=1 + len(v), fill=0)
    for i in range(len(v)):
        c_input[1 + i] = v[i]
    var c = _hash_df(algorithm, c_input, seed_length)
    var digest_bytes = 32 if algorithm == HashAlgorithm.SHA256 else 64
    if len(additional) != 0:
        var w_input = List[UInt8](length=1 + len(v) + len(additional), fill=0)
        w_input[0] = 2
        for i in range(len(v)):
            w_input[1 + i] = v[i]
        for i in range(len(additional)):
            w_input[1 + len(v) + i] = additional[i]
        var w = InlineArray[UInt8, 64](uninitialized=True)
        _hash_into(algorithm, Span(w_input), w)
        _add(v, Span(w)[0:digest_bytes])
    var working = v.copy()
    var output = List[UInt8](length=output_bytes, fill=0)
    var digest = InlineArray[UInt8, 64](uninitialized=True)
    var produced = 0
    while produced < output_bytes:
        _hash_working_into(algorithm, Span(working), digest)
        var take = min(digest_bytes, output_bytes - produced)
        if take == digest_bytes:
            if digest_bytes == 32:
                Span(output).unsafe_ptr().unsafe_store[width=32](
                    produced, Span(digest).unsafe_ptr().unsafe_load[width=32](0)
                )
            else:
                Span(output).unsafe_ptr().unsafe_store[width=64](
                    produced, Span(digest).unsafe_ptr().unsafe_load[width=64](0)
                )
        else:
            for i in range(take):
                output[produced + i] = digest[i]
        produced += take
        _increment(working)
    var h_input = List[UInt8](length=1 + len(v), fill=0)
    h_input[0] = 3
    for i in range(len(v)):
        h_input[1 + i] = v[i]
    _hash_into(algorithm, Span(h_input), digest)
    _add(v, Span(digest)[0:digest_bytes])
    _add(v, Span(c))
    var reseed = List[UInt8](length=8, fill=0)
    reseed[7] = 1
    _add(v, Span(reseed))
    return output^


def _hmac_update(
    algorithm: HmacAlgorithm,
    mut key: List[UInt8],
    mut value: List[UInt8],
    provided: List[UInt8],
) raises:
    var input = value.copy()
    input.append(0)
    _append(input, provided)
    key = _hmac(algorithm, key, input)
    value = _hmac(algorithm, key, value)
    if len(provided) != 0:
        input = value.copy()
        input.append(1)
        _append(input, provided)
        key = _hmac(algorithm, key, input)
        value = _hmac(algorithm, key, value)


def hmac_drbg[
    entropy_origin: Origin,
    nonce_origin: Origin,
    personalization_origin: Origin,
    additional_origin: Origin,
](
    algorithm: HmacAlgorithm,
    entropy: Span[UInt8, entropy_origin],
    nonce: Span[UInt8, nonce_origin],
    personalization: Span[UInt8, personalization_origin],
    additional: Span[UInt8, additional_origin],
    output_bytes: Int,
) raises -> List[UInt8]:
    if algorithm != HmacAlgorithm.SHA256 and algorithm != HmacAlgorithm.SHA512:
        raise Error("HMAC_DRBG requires HMAC-SHA256 or HMAC-SHA512")
    var digest_bytes = 32 if algorithm == HmacAlgorithm.SHA256 else 64
    var key = List[UInt8](length=digest_bytes, fill=0)
    var value = List[UInt8](length=digest_bytes, fill=1)
    var seed = List[UInt8]()
    for byte in entropy:
        seed.append(byte)
    for byte in nonce:
        seed.append(byte)
    for byte in personalization:
        seed.append(byte)
    _hmac_update(algorithm, key, value, seed)
    var extra = List[UInt8]()
    for byte in additional:
        extra.append(byte)
    if len(extra) != 0:
        _hmac_update(algorithm, key, value, extra)
    var output = List[UInt8](length=output_bytes, fill=0)
    var prepared = _HMACKey(algorithm, Span(key))
    var digest = InlineArray[UInt8, 64](uninitialized=True)
    var produced = 0
    while produced < output_bytes:
        prepared.authenticate_into(Span(value), digest)
        var take = min(digest_bytes, output_bytes - produced)
        for i in range(digest_bytes):
            value[i] = digest[i]
        for i in range(take):
            output[produced + i] = digest[i]
        produced += take
    _hmac_update(algorithm, key, value, extra)
    return output^
