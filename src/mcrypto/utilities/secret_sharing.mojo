"""Shamir secret sharing and Rabin information dispersal over GF(256).

Shares are self-describing byte strings.  The fixed 28-byte header contains a
magic value, version, scheme, threshold, non-zero share ID, original length,
and the first 16 bytes of SHA-256(secret).  The digest is an integrity check,
not a substitute for an application-level MAC when shares cross a trust
boundary.
"""

from ..hashes.sha256 import sha256
from ..math.fields import GF256
from ..random.entropy import system_entropy


comptime _HEADER_BYTES = 28
comptime _SHAMIR = UInt8(1)
comptime _IDA = UInt8(2)


@always_inline("nodebug")
def _gf_mul(a: UInt8, b: UInt8) -> UInt8:
    return GF256().multiply(a, b)


@always_inline("nodebug")
def _gf_div(numerator: UInt8, denominator: UInt8) raises -> UInt8:
    if denominator == 0:
        raise Error("division by zero in GF(256)")
    if numerator == 0:
        return 0
    return _gf_mul(numerator, GF256().inverse(denominator))


def _interpolate_at(
    xs: List[UInt8], ys: List[UInt8], target: UInt8
) raises -> UInt8:
    for i in range(len(xs)):
        if target == xs[i]:
            return ys[i]
    var value = UInt8(0)
    for i in range(len(xs)):
        var numerator = UInt8(1)
        var denominator = UInt8(1)
        for j in range(len(xs)):
            if i != j:
                numerator = _gf_mul(numerator, target ^ xs[j])
                denominator = _gf_mul(denominator, xs[i] ^ xs[j])
        value ^= _gf_mul(ys[i], _gf_div(numerator, denominator))
    return value


@always_inline("nodebug")
def _append_u32(mut output: List[UInt8], value: Int):
    var word = UInt32(value)
    output.append(UInt8(word >> 24))
    output.append(UInt8(word >> 16))
    output.append(UInt8(word >> 8))
    output.append(UInt8(word))


@always_inline("nodebug")
def _read_u32[origin: Origin](data: Span[UInt8, origin], offset: Int) -> Int:
    return Int(
        (UInt32(data[offset]) << 24)
        | (UInt32(data[offset + 1]) << 16)
        | (UInt32(data[offset + 2]) << 8)
        | UInt32(data[offset + 3])
    )


def _validate_parameters[
    ids_origin: Origin
](threshold: Int, ids: Span[UInt8, ids_origin]) raises:
    if threshold < 1 or threshold > 255:
        raise Error("sharing threshold must be 1..255")
    if len(ids) < threshold or len(ids) > 255:
        raise Error("share count must be between threshold and 255")
    for i in range(len(ids)):
        if ids[i] == 0:
            raise Error("share IDs must be non-zero")
        for j in range(i):
            if ids[i] == ids[j]:
                raise Error("share IDs must be distinct")


def _validate_secret_length[origin: Origin](secret: Span[UInt8, origin]) raises:
    if len(secret) > 0xFFFFFFFF:
        raise Error("secret is too large for the share format")


def _new_share[
    secret_origin: Origin
](
    scheme: UInt8,
    threshold: Int,
    share_id: UInt8,
    secret: Span[UInt8, secret_origin],
    digest: List[UInt8],
    payload_bytes: Int,
) raises -> List[UInt8]:
    if len(secret) > 0xFFFFFFFF:
        raise Error("secret is too large for the share format")
    var output = List[UInt8](capacity=_HEADER_BYTES + payload_bytes)
    output.append(UInt8(0x4D))
    output.append(UInt8(0x43))
    output.append(UInt8(0x53))
    output.append(UInt8(0x53))
    output.append(UInt8(1))
    output.append(scheme)
    output.append(UInt8(threshold))
    output.append(share_id)
    _append_u32(output, len(secret))
    for i in range(16):
        output.append(digest[i])
    return output^


def shamir_split_deterministic[
    secret_origin: Origin, ids_origin: Origin, random_origin: Origin
](
    secret: Span[UInt8, secret_origin],
    threshold: Int,
    ids: Span[UInt8, ids_origin],
    randomness: Span[UInt8, random_origin],
) raises -> List[List[UInt8]]:
    """Split using caller-supplied coefficient bytes for reproducible output.

    Randomness must contain exactly ``len(secret) * (threshold - 1)`` bytes,
    ordered by secret byte and then by increasing polynomial degree.
    """
    _validate_parameters(threshold, ids)
    _validate_secret_length(secret)
    var required = len(secret) * (threshold - 1)
    if len(randomness) != required:
        raise Error("incorrect Shamir randomness length")
    var digest = sha256(secret)
    var shares = List[List[UInt8]](capacity=len(ids))
    for share_id in ids:
        shares.append(
            _new_share(
                _SHAMIR, threshold, share_id, secret, digest, len(secret)
            )
        )
    for offset in range(len(secret)):
        for share_index in range(len(ids)):
            var x = ids[share_index]
            var y = secret[offset]
            var power = x
            for degree in range(threshold - 1):
                y ^= _gf_mul(
                    randomness[offset * (threshold - 1) + degree], power
                )
                power = _gf_mul(power, x)
            shares[share_index].append(y)
    return shares^


def shamir_split[
    secret_origin: Origin, ids_origin: Origin
](
    secret: Span[UInt8, secret_origin],
    threshold: Int,
    ids: Span[UInt8, ids_origin],
) raises -> List[List[UInt8]]:
    """Split a secret with coefficients drawn from the operating system CSPRNG.
    """
    _validate_parameters(threshold, ids)
    _validate_secret_length(secret)
    var randomness = system_entropy(len(secret) * (threshold - 1))
    return shamir_split_deterministic(secret, threshold, ids, Span(randomness))


def ida_split[
    secret_origin: Origin, ids_origin: Origin
](
    secret: Span[UInt8, secret_origin],
    threshold: Int,
    ids: Span[UInt8, ids_origin],
) raises -> List[List[UInt8]]:
    """Disperse data with a threshold-sized Reed-Solomon/Rabin transform."""
    _validate_parameters(threshold, ids)
    _validate_secret_length(secret)
    var payload_bytes = (len(secret) + threshold - 1) // threshold
    var digest = sha256(secret)
    var shares = List[List[UInt8]](capacity=len(ids))
    for share_id in ids:
        shares.append(
            _new_share(_IDA, threshold, share_id, secret, digest, payload_bytes)
        )
    var base_xs = List[UInt8](capacity=threshold)
    for i in range(threshold):
        base_xs.append(UInt8(i + 1))
    var values = List[UInt8](length=threshold, fill=0)
    for stripe in range(payload_bytes):
        for i in range(threshold):
            var input_offset = stripe * threshold + i
            values[i] = (
                secret[input_offset] if input_offset < len(secret) else 0
            )
        for share_index in range(len(ids)):
            shares[share_index].append(
                _interpolate_at(base_xs, values, ids[share_index])
            )
    return shares^


def _same_digest(a: List[UInt8], b: List[UInt8]) -> Bool:
    var difference = UInt8(0)
    for i in range(16):
        difference |= a[_HEADER_BYTES - 16 + i] ^ b[_HEADER_BYTES - 16 + i]
    return difference == 0


def _validate_shares(
    shares: List[List[UInt8]], scheme: UInt8
) raises -> Tuple[Int, Int, Int]:
    if len(shares) == 0:
        raise Error("no shares supplied")
    if len(shares[0]) < _HEADER_BYTES:
        raise Error("truncated share")
    var first = Span(shares[0])
    if (
        first[0] != 0x4D
        or first[1] != 0x43
        or first[2] != 0x53
        or first[3] != 0x53
    ):
        raise Error("invalid share magic")
    if first[4] != 1 or first[5] != scheme:
        raise Error("unsupported share version or scheme")
    var threshold = Int(first[6])
    var original_bytes = _read_u32(first, 8)
    var payload_bytes = len(first) - _HEADER_BYTES
    if threshold < 1 or len(shares) < threshold:
        raise Error("insufficient shares")
    var expected_payload = original_bytes
    if scheme == _IDA:
        expected_payload = (original_bytes + threshold - 1) // threshold
    if payload_bytes != expected_payload:
        raise Error("invalid share payload length")
    for i in range(len(shares)):
        if len(shares[i]) != _HEADER_BYTES + payload_bytes:
            raise Error("shares have inconsistent lengths")
        var current = Span(shares[i])
        if (
            current[0] != 0x4D
            or current[1] != 0x43
            or current[2] != 0x53
            or current[3] != 0x53
        ):
            raise Error("invalid share magic")
        if (
            current[4] != 1
            or current[5] != scheme
            or current[6] != UInt8(threshold)
        ):
            raise Error("shares have inconsistent metadata")
        if current[7] == 0 or _read_u32(current, 8) != original_bytes:
            raise Error("shares have invalid metadata")
        if not _same_digest(shares[0], shares[i]):
            raise Error("shares have inconsistent integrity digests")
        for j in range(i):
            if current[7] == shares[j][7]:
                raise Error("duplicate share ID")
    return (threshold, original_bytes, payload_bytes)


def _verify_extra_shares(
    shares: List[List[UInt8]],
    threshold: Int,
    payload_bytes: Int,
    xs: List[UInt8],
    mut ys: List[UInt8],
) raises:
    for extra in range(threshold, len(shares)):
        for offset in range(payload_bytes):
            for i in range(threshold):
                ys[i] = shares[i][_HEADER_BYTES + offset]
            var expected = _interpolate_at(xs, ys, shares[extra][7])
            if expected != shares[extra][_HEADER_BYTES + offset]:
                raise Error("share payloads are inconsistent")


def _verify_digest(output: List[UInt8], first_share: List[UInt8]) raises:
    var actual = sha256(Span(output))
    var difference = UInt8(0)
    for i in range(16):
        difference |= actual[i] ^ first_share[_HEADER_BYTES - 16 + i]
    if difference != 0:
        raise Error("share integrity check failed")


def shamir_recover(shares: List[List[UInt8]]) raises -> List[UInt8]:
    """Recover a Shamir secret from any threshold distinct shares."""
    var metadata = _validate_shares(shares, _SHAMIR)
    var threshold = metadata[0]
    var original_bytes = metadata[1]
    var xs = List[UInt8](capacity=threshold)
    for i in range(threshold):
        xs.append(shares[i][7])
    var ys = List[UInt8](length=threshold, fill=0)
    var output = List[UInt8](capacity=original_bytes)
    for offset in range(original_bytes):
        for i in range(threshold):
            ys[i] = shares[i][_HEADER_BYTES + offset]
        output.append(_interpolate_at(xs, ys, 0))
    _verify_extra_shares(shares, threshold, original_bytes, xs, ys)
    _verify_digest(output, shares[0])
    return output^


def ida_recover(shares: List[List[UInt8]]) raises -> List[UInt8]:
    """Recover dispersed data from any threshold distinct IDA shares."""
    var metadata = _validate_shares(shares, _IDA)
    var threshold = metadata[0]
    var original_bytes = metadata[1]
    var payload_bytes = metadata[2]
    var xs = List[UInt8](capacity=threshold)
    for i in range(threshold):
        xs.append(shares[i][7])
    var ys = List[UInt8](length=threshold, fill=0)
    var output = List[UInt8](capacity=original_bytes)
    for stripe in range(payload_bytes):
        for i in range(threshold):
            ys[i] = shares[i][_HEADER_BYTES + stripe]
        for base_index in range(threshold):
            if len(output) < original_bytes:
                output.append(_interpolate_at(xs, ys, UInt8(base_index + 1)))
    _verify_extra_shares(shares, threshold, payload_bytes, xs, ys)
    _verify_digest(output, shares[0])
    return output^
