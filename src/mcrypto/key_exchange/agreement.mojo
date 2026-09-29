"""Typed facade for the pure-Mojo key-agreement implementations."""

from .finite_field import (
    DHGroup,
    rfc3526_group14,
    public_key as finite_public,
    dh as finite_dh,
    dh2 as finite_dh2,
    authenticated_agree as finite_authenticated,
)
from .lucdif import (
    LUCDomain,
    lucd512_domain,
    public_key as lucdif_public,
    agree as lucdif_agree,
)
from .xtr_dh import (
    XTRDomain,
    xtr171_domain,
    public_key as xtr_public,
    agree as xtr_agree,
)
from .elliptic import (
    P256Domain,
    p256,
    public_key as elliptic_public,
    encode_point as elliptic_encode_point,
    decode_point as elliptic_decode_point,
    ecdh,
    authenticated_agree as elliptic_authenticated,
)
from .x25519 import public_key as x25519_public, agree as x25519_agree
from ._common import from_be, to_be
from ..math.biguint import BigUInt, FixedBaseLucasPower
from ..math.ec import FixedBaseMultiplier
from ..random.entropy import system_entropy
from ..hashes.sha256 import sha256
from .algorithm import AgreementAlgorithm


comptime _KEY_HEADER_BYTES = 6
comptime _KEY_TAG_BYTES = 16


def _family_id(name: AgreementAlgorithm) raises -> UInt8:
    if name == AgreementAlgorithm.DH:
        return 1
    if name == AgreementAlgorithm.DH2:
        return 2
    if name == AgreementAlgorithm.MQV:
        return 3
    if name == AgreementAlgorithm.HMQV:
        return 4
    if name == AgreementAlgorithm.FHMQV:
        return 5
    if name == AgreementAlgorithm.LUCDIF:
        return 6
    if name == AgreementAlgorithm.XTR_DH:
        return 7
    if name == AgreementAlgorithm.ECDH_P256:
        return 8
    if name == AgreementAlgorithm.ECMQV_P256:
        return 9
    if name == AgreementAlgorithm.ECHMQV_P256:
        return 10
    if name == AgreementAlgorithm.ECFHMQV_P256:
        return 11
    if name == AgreementAlgorithm.X25519:
        return 12
    raise Error("unknown agreement family")


def _domain_id(name: AgreementAlgorithm) raises -> UInt8:
    var family = _family_id(name)
    if family <= 5:
        return 1
    if family == 6:
        return 2
    if family == 7:
        return 3
    if family <= 11:
        return 4
    return 5


def _dual_key(name: AgreementAlgorithm) -> Bool:
    return (
        name == AgreementAlgorithm.DH2
        or name == AgreementAlgorithm.MQV
        or name == AgreementAlgorithm.HMQV
        or name == AgreementAlgorithm.FHMQV
        or name == AgreementAlgorithm.ECMQV_P256
        or name == AgreementAlgorithm.ECHMQV_P256
        or name == AgreementAlgorithm.ECFHMQV_P256
    )


def _payload_sizes(name: AgreementAlgorithm) raises -> Tuple[Int, Int]:
    _ = _family_id(name)
    if (
        name == AgreementAlgorithm.DH
        or name == AgreementAlgorithm.DH2
        or name == AgreementAlgorithm.MQV
        or name == AgreementAlgorithm.HMQV
        or name == AgreementAlgorithm.FHMQV
    ):
        return (
            256 * (2 if _dual_key(name) else 1),
            256 * (2 if _dual_key(name) else 1),
        )
    if name == AgreementAlgorithm.LUCDIF:
        var domain = lucd512_domain()
        return (domain.private_bytes, domain.bytes)
    if name == AgreementAlgorithm.XTR_DH:
        var domain = xtr171_domain()
        return (domain.private_bytes, 2 * domain.field_bytes)
    if (
        name == AgreementAlgorithm.ECDH_P256
        or name == AgreementAlgorithm.ECMQV_P256
        or name == AgreementAlgorithm.ECHMQV_P256
        or name == AgreementAlgorithm.ECFHMQV_P256
    ):
        return (
            32 * (2 if _dual_key(name) else 1),
            65 * (2 if _dual_key(name) else 1),
        )
    return (32, 32)


def _parameters(name: AgreementAlgorithm) raises -> List[UInt8]:
    return [
        UInt8(0x4D),
        UInt8(0x43),
        UInt8(0x41),
        UInt8(1),
        _family_id(name),
        _domain_id(name),
    ]


def _validate_parameters[
    origin: Origin
](name: AgreementAlgorithm, parameters: Span[UInt8, origin],) raises:
    var expected = _parameters(name)
    if len(parameters) != len(expected):
        raise Error("agreement parameter block has the wrong length")
    for i in range(len(expected)):
        if parameters[i] != expected[i]:
            raise Error(
                "agreement parameter block does not identify this family"
            )


def _wrap[
    origin: Origin
](
    name: AgreementAlgorithm,
    private_key: Bool,
    client_role: Bool,
    payload: Span[UInt8, origin],
) raises -> List[UInt8]:
    var body_bytes = _KEY_HEADER_BYTES + len(payload)
    var output = List[UInt8](unsafe_uninit_length=body_bytes + _KEY_TAG_BYTES)
    output[0] = UInt8(0x4D)
    output[1] = UInt8(0x43)
    output[2] = UInt8(0x53 if private_key else 0x50)
    output[3] = UInt8(1)
    output[4] = _family_id(name)
    output[5] = UInt8(1 if client_role else 2)
    for i in range(len(payload)):
        output[_KEY_HEADER_BYTES + i] = payload[i]
    var digest = sha256(Span(output)[0:body_bytes])
    for i in range(_KEY_TAG_BYTES):
        output[body_bytes + i] = digest[i]
    return output^


def _unwrap[
    origin: Origin
](
    name: AgreementAlgorithm,
    private_key: Bool,
    client_role: Bool,
    encoded: Span[UInt8, origin],
    payload_bytes: Int,
) raises -> List[UInt8]:
    var body_bytes = _KEY_HEADER_BYTES + payload_bytes
    if len(encoded) != body_bytes + _KEY_TAG_BYTES:
        raise Error("agreement key has the wrong length")
    if (
        encoded[0] != UInt8(0x4D)
        or encoded[1] != UInt8(0x43)
        or encoded[2] != UInt8(0x53 if private_key else 0x50)
        or encoded[3] != UInt8(1)
        or encoded[4] != _family_id(name)
        or encoded[5] != UInt8(1 if client_role else 2)
    ):
        raise Error("agreement key header has the wrong family, kind, or role")
    var digest = sha256(encoded[0:body_bytes])
    var difference = UInt8(0)
    for i in range(_KEY_TAG_BYTES):
        difference |= encoded[body_bytes + i] ^ digest[i]
    if difference != UInt8(0):
        raise Error("agreement key integrity check failed")
    var payload = List[UInt8](unsafe_uninit_length=payload_bytes)
    for i in range(payload_bytes):
        payload[i] = encoded[_KEY_HEADER_BYTES + i]
    return payload^


def _part[
    origin: Origin
](payload: Span[UInt8, origin], offset: Int, size: Int,) raises -> List[UInt8]:
    if offset < 0 or size < 0 or offset + size > len(payload):
        raise Error("malformed compound agreement key")
    var output = List[UInt8](unsafe_uninit_length=size)
    for i in range(size):
        output[i] = payload[offset + i]
    return output^


def _random_range(
    upper_exclusive: BigUInt, minimum: BigUInt, size: Int
) raises -> List[UInt8]:
    if upper_exclusive.compare(minimum) <= 0:
        raise Error("empty private-key range")
    var width = upper_exclusive.subtract(minimum)
    var bits = width.bit_length()
    var random_bytes = max(1, (bits + 7) // 8)
    if random_bytes > size:
        raise Error("private-key encoding is too short for the domain")
    var excess = random_bytes * 8 - bits
    while True:
        var random = system_entropy(random_bytes)
        if excess > 0:
            random[0] &= UInt8(0xFF >> excess)
        var candidate = from_be(Span(random))
        if candidate.compare(width) < 0:
            return to_be(candidate.add(minimum), size)


def _random_finite_field_secret() raises -> List[UInt8]:
    """Generate a 256-bit group-14 exponent in its fixed-width encoding."""
    while True:
        var random = system_entropy(32)
        var nonzero = UInt8(0)
        for byte in random:
            nonzero |= byte
        if nonzero != 0:
            var encoded = List[UInt8](length=256, fill=0)
            for i in range(32):
                encoded[224 + i] = random[i]
            return encoded^


def _generate_payload(
    name: AgreementAlgorithm,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    var private_payload = List[UInt8]()
    var public_payload = List[UInt8]()
    if (
        name == AgreementAlgorithm.DH
        or name == AgreementAlgorithm.DH2
        or name == AgreementAlgorithm.MQV
        or name == AgreementAlgorithm.HMQV
        or name == AgreementAlgorithm.FHMQV
    ):
        var domain = rfc3526_group14()
        var count = 2 if _dual_key(name) else 1
        for _ in range(count):
            var secret = _random_finite_field_secret()
            var public = finite_public(domain, Span(secret))
            for byte in secret:
                private_payload.append(byte)
            for byte in public:
                public_payload.append(byte)
    elif name == AgreementAlgorithm.LUCDIF:
        var domain = lucd512_domain()
        var secret = _random_range(
            domain.order, BigUInt(1), domain.private_bytes
        )
        private_payload = secret.copy()
        public_payload = lucdif_public(domain, Span(secret))
    elif name == AgreementAlgorithm.XTR_DH:
        var domain = xtr171_domain()
        var secret = _random_range(domain.q, BigUInt(1), domain.private_bytes)
        private_payload = secret.copy()
        public_payload = xtr_public(domain, Span(secret))
    elif (
        name == AgreementAlgorithm.ECDH_P256
        or name == AgreementAlgorithm.ECMQV_P256
        or name == AgreementAlgorithm.ECHMQV_P256
        or name == AgreementAlgorithm.ECFHMQV_P256
    ):
        var domain = p256()
        var count = 2 if _dual_key(name) else 1
        for _ in range(count):
            var secret = _random_range(domain.order, BigUInt(1), 32)
            var public = elliptic_public(domain, Span(secret))
            for byte in secret:
                private_payload.append(byte)
            for byte in public:
                public_payload.append(byte)
    elif name == AgreementAlgorithm.X25519:
        var secret = system_entropy(32)
        private_payload = secret.copy()
        public_payload = x25519_public(Span(secret))
    else:
        raise Error("unknown agreement family")
    return (private_payload^, public_payload^)


def info(
    name: AgreementAlgorithm, key_bits: Int = 2048
) raises -> Tuple[Int, Int, Int]:
    if key_bits < 512:
        raise Error("agreement key size is too small")
    var sizes = _payload_sizes(name)
    var overhead = _KEY_HEADER_BYTES + _KEY_TAG_BYTES
    return (sizes[0] + overhead, sizes[1] + overhead, 32)


def generate_keypair(
    name: AgreementAlgorithm,
    key_bits: Int = 2048,
) raises -> Tuple[List[UInt8], List[UInt8], List[UInt8]]:
    _ = info(name, key_bits)
    var generated = _generate_payload(name)
    var private_key = _wrap(name, True, True, Span(generated[0]))
    var public_key = _wrap(name, False, True, Span(generated[1]))
    var parameters = _parameters(name)
    return (private_key^, public_key^, parameters^)


struct PreparedLUCDIFKeyGenerator(Movable):
    """Canonical LUCDIF domain with a reusable fixed-base Lucas table."""

    var domain: LUCDomain
    var power: FixedBaseLucasPower
    var parameters: List[UInt8]

    def __init__(out self, key_bits: Int = 512) raises:
        _ = info(AgreementAlgorithm.LUCDIF, key_bits)
        self.domain = lucd512_domain()
        self.power = FixedBaseLucasPower(
            self.domain.seed,
            self.domain.modulus,
            self.domain.order.bit_length(),
        )
        self.parameters = _parameters(AgreementAlgorithm.LUCDIF)

    def __init__(out self, *, deinit move: Self):
        self.domain = move.domain^
        self.power = move.power^
        self.parameters = move.parameters^

    def generate(
        mut self,
    ) raises -> Tuple[List[UInt8], List[UInt8], List[UInt8]]:
        var secret = _random_range(
            self.domain.order, BigUInt(1), self.domain.private_bytes
        )
        var public = to_be(
            self.power.power_reusing(from_be(Span(secret))),
            self.domain.bytes,
        )
        return (
            _wrap(AgreementAlgorithm.LUCDIF, True, True, Span(secret)),
            _wrap(AgreementAlgorithm.LUCDIF, False, True, Span(public)),
            self.parameters.copy(),
        )


struct PreparedEllipticKeyGenerator(Movable):
    """P-256 agreement key generator with reusable base-point tables."""

    var name: AgreementAlgorithm
    var domain: P256Domain
    var multiplier: FixedBaseMultiplier
    var count: Int
    var parameters: List[UInt8]

    def __init__(
        out self, name: AgreementAlgorithm, key_bits: Int = 256
    ) raises:
        if (
            name != AgreementAlgorithm.ECDH_P256
            and name != AgreementAlgorithm.ECMQV_P256
            and name != AgreementAlgorithm.ECHMQV_P256
            and name != AgreementAlgorithm.ECFHMQV_P256
        ):
            raise Error("prepared elliptic generator requires a P-256 family")
        _ = info(name, key_bits)
        self.name = name
        self.domain = p256()
        self.multiplier = FixedBaseMultiplier(
            self.domain.curve,
            self.domain.generator,
            self.domain.order.bit_length(),
        )
        self.count = 2 if _dual_key(self.name) else 1
        self.parameters = _parameters(self.name)

    def __init__(out self, *, deinit move: Self):
        self.name = move.name
        self.domain = move.domain^
        self.multiplier = move.multiplier^
        self.count = move.count
        self.parameters = move.parameters^

    def generate(
        self,
    ) raises -> Tuple[List[UInt8], List[UInt8], List[UInt8]]:
        var private_payload = List[UInt8](capacity=self.count * 32)
        var public_payload = List[UInt8](capacity=self.count * 65)
        for _ in range(self.count):
            var secret = _random_range(self.domain.order, BigUInt(1), 32)
            var public = elliptic_encode_point(
                self.domain,
                self.multiplier.multiply(from_be(Span(secret))),
            )
            for byte in secret:
                private_payload.append(byte)
            for byte in public:
                public_payload.append(byte)
        return (
            _wrap(self.name, True, True, Span(private_payload)),
            _wrap(self.name, False, True, Span(public_payload)),
            self.parameters.copy(),
        )


def generate_peer[
    parameters_origin: Origin
](
    name: AgreementAlgorithm,
    parameters: Span[UInt8, parameters_origin],
    private_bytes: Int,
    public_bytes: Int,
    client_role: Bool,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    _validate_parameters(name, parameters)
    var sizes = info(name)
    if private_bytes != sizes[0] or public_bytes != sizes[1]:
        raise Error("agreement key sizes do not match the selected family")
    var generated = _generate_payload(name)
    var private_key = _wrap(name, True, client_role, Span(generated[0]))
    var public_key = _wrap(name, False, client_role, Span(generated[1]))
    return (private_key^, public_key^)


def _raw_agree[
    private_origin: Origin, public_origin: Origin
](
    name: AgreementAlgorithm,
    private_payload: Span[UInt8, private_origin],
    peer_payload: Span[UInt8, public_origin],
    client_role: Bool,
) raises -> List[UInt8]:
    if name == AgreementAlgorithm.DH:
        return finite_dh(rfc3526_group14(), private_payload, peer_payload)
    if name == AgreementAlgorithm.DH2:
        var own_static = _part(private_payload, 0, 256)
        var own_ephemeral = _part(private_payload, 256, 256)
        var peer_static = _part(peer_payload, 0, 256)
        var peer_ephemeral = _part(peer_payload, 256, 256)
        return finite_dh2(
            rfc3526_group14(),
            Span(own_static),
            Span(own_ephemeral),
            Span(peer_static),
            Span(peer_ephemeral),
        )
    if (
        name == AgreementAlgorithm.MQV
        or name == AgreementAlgorithm.HMQV
        or name == AgreementAlgorithm.FHMQV
    ):
        var domain = rfc3526_group14()
        var own_static = _part(private_payload, 0, 256)
        var own_ephemeral = _part(private_payload, 256, 256)
        var peer_static = _part(peer_payload, 0, 256)
        var peer_ephemeral = _part(peer_payload, 256, 256)
        var local_static = finite_public(domain, Span(own_static))
        var local_ephemeral = finite_public(domain, Span(own_ephemeral))
        return finite_authenticated(
            domain,
            name,
            Span(own_static),
            Span(own_ephemeral),
            Span(local_static),
            Span(local_ephemeral),
            Span(peer_static),
            Span(peer_ephemeral),
            client_role,
        )
    if name == AgreementAlgorithm.LUCDIF:
        return lucdif_agree(lucd512_domain(), private_payload, peer_payload)
    if name == AgreementAlgorithm.XTR_DH:
        return xtr_agree(xtr171_domain(), private_payload, peer_payload)
    if name == AgreementAlgorithm.ECDH_P256:
        return ecdh(p256(), private_payload, peer_payload)
    if (
        name == AgreementAlgorithm.ECMQV_P256
        or name == AgreementAlgorithm.ECHMQV_P256
        or name == AgreementAlgorithm.ECFHMQV_P256
    ):
        var domain = p256()
        var own_static = _part(private_payload, 0, 32)
        var own_ephemeral = _part(private_payload, 32, 32)
        var peer_static = _part(peer_payload, 0, 65)
        var peer_ephemeral = _part(peer_payload, 65, 65)
        var local_static = elliptic_public(domain, Span(own_static))
        var local_ephemeral = elliptic_public(domain, Span(own_ephemeral))
        return elliptic_authenticated(
            domain,
            name,
            Span(own_static),
            Span(own_ephemeral),
            Span(local_static),
            Span(local_ephemeral),
            Span(peer_static),
            Span(peer_ephemeral),
            client_role,
        )
    if name == AgreementAlgorithm.X25519:
        return x25519_agree(private_payload, peer_payload)
    raise Error("unknown agreement family")


struct PreparedAgreement(Movable):
    """Validated agreement keys and fixed domains reusable across operations."""

    var name: AgreementAlgorithm
    var shared_bytes: Int
    var client_role: Bool
    var private_primary: List[UInt8]
    var private_secondary: List[UInt8]
    var peer_primary: List[UInt8]
    var peer_secondary: List[UInt8]
    var local_primary: List[UInt8]
    var local_secondary: List[UInt8]
    var finite_domain: DHGroup
    var luc_domain: LUCDomain
    var xtr_domain: XTRDomain
    var elliptic_domain: P256Domain
    var luc_power: List[FixedBaseLucasPower]
    var elliptic_power: List[FixedBaseMultiplier]

    def __init__[
        parameters_origin: Origin,
        private_origin: Origin,
        public_origin: Origin,
    ](
        out self,
        name: AgreementAlgorithm,
        parameters: Span[UInt8, parameters_origin],
        private_key: Span[UInt8, private_origin],
        peer_public_key: Span[UInt8, public_origin],
        shared_bytes: Int,
        client_role: Bool,
    ) raises:
        _validate_parameters(name, parameters)
        var sizes = _payload_sizes(name)
        self.name = name
        self.shared_bytes = shared_bytes
        self.client_role = client_role
        var private_payload = _unwrap(
            self.name,
            True,
            client_role,
            private_key,
            sizes[0],
        )
        var peer_payload = _unwrap(
            self.name,
            False,
            not client_role,
            peer_public_key,
            sizes[1],
        )
        if _dual_key(self.name):
            self.private_primary = _part(
                Span(private_payload), 0, sizes[0] // 2
            )
            self.private_secondary = _part(
                Span(private_payload), sizes[0] // 2, sizes[0] // 2
            )
            self.peer_primary = _part(Span(peer_payload), 0, sizes[1] // 2)
            self.peer_secondary = _part(
                Span(peer_payload), sizes[1] // 2, sizes[1] // 2
            )
        else:
            self.private_primary = private_payload^
            self.private_secondary = List[UInt8]()
            self.peer_primary = peer_payload^
            self.peer_secondary = List[UInt8]()
        self.finite_domain = rfc3526_group14()
        self.luc_domain = lucd512_domain()
        self.xtr_domain = xtr171_domain()
        self.elliptic_domain = p256()
        self.local_primary = List[UInt8]()
        self.local_secondary = List[UInt8]()
        self.luc_power = List[FixedBaseLucasPower]()
        self.elliptic_power = List[FixedBaseMultiplier]()
        if self.name == AgreementAlgorithm.LUCDIF:
            _ = lucdif_agree(
                self.luc_domain,
                Span(self.private_primary),
                Span(self.peer_primary),
            )
            self.luc_power.append(
                FixedBaseLucasPower(
                    from_be(Span(self.peer_primary)),
                    self.luc_domain.modulus,
                    self.luc_domain.order.bit_length(),
                )
            )
        elif self.name == AgreementAlgorithm.ECDH_P256:
            _ = ecdh(
                self.elliptic_domain,
                Span(self.private_primary),
                Span(self.peer_primary),
            )
            self.elliptic_power.append(
                FixedBaseMultiplier(
                    self.elliptic_domain.curve,
                    elliptic_decode_point(
                        self.elliptic_domain, Span(self.peer_primary)
                    ),
                    self.elliptic_domain.order.bit_length(),
                )
            )
        if (
            self.name == AgreementAlgorithm.MQV
            or self.name == AgreementAlgorithm.HMQV
            or self.name == AgreementAlgorithm.FHMQV
        ):
            self.local_primary = finite_public(
                self.finite_domain, Span(self.private_primary)
            )
            self.local_secondary = finite_public(
                self.finite_domain, Span(self.private_secondary)
            )
        elif (
            self.name == AgreementAlgorithm.ECMQV_P256
            or self.name == AgreementAlgorithm.ECHMQV_P256
            or self.name == AgreementAlgorithm.ECFHMQV_P256
        ):
            self.local_primary = elliptic_public(
                self.elliptic_domain, Span(self.private_primary)
            )
            self.local_secondary = elliptic_public(
                self.elliptic_domain, Span(self.private_secondary)
            )

    def __init__(out self, *, deinit move: Self):
        self.name = move.name
        self.shared_bytes = move.shared_bytes
        self.client_role = move.client_role
        self.private_primary = move.private_primary^
        self.private_secondary = move.private_secondary^
        self.peer_primary = move.peer_primary^
        self.peer_secondary = move.peer_secondary^
        self.local_primary = move.local_primary^
        self.local_secondary = move.local_secondary^
        self.finite_domain = move.finite_domain^
        self.luc_domain = move.luc_domain^
        self.xtr_domain = move.xtr_domain^
        self.elliptic_domain = move.elliptic_domain^
        self.luc_power = move.luc_power^
        self.elliptic_power = move.elliptic_power^

    def agree(mut self) raises -> List[UInt8]:
        var raw: List[UInt8]
        if self.name == AgreementAlgorithm.DH:
            raw = finite_dh(
                self.finite_domain,
                Span(self.private_primary),
                Span(self.peer_primary),
            )
        elif self.name == AgreementAlgorithm.DH2:
            raw = finite_dh2(
                self.finite_domain,
                Span(self.private_primary),
                Span(self.private_secondary),
                Span(self.peer_primary),
                Span(self.peer_secondary),
            )
        elif (
            self.name == AgreementAlgorithm.MQV
            or self.name == AgreementAlgorithm.HMQV
            or self.name == AgreementAlgorithm.FHMQV
        ):
            raw = finite_authenticated(
                self.finite_domain,
                self.name,
                Span(self.private_primary),
                Span(self.private_secondary),
                Span(self.local_primary),
                Span(self.local_secondary),
                Span(self.peer_primary),
                Span(self.peer_secondary),
                self.client_role,
            )
        elif self.name == AgreementAlgorithm.LUCDIF:
            raw = to_be(
                self.luc_power[0].power_reusing(
                    from_be(Span(self.private_primary))
                ),
                self.luc_domain.bytes,
            )
        elif self.name == AgreementAlgorithm.XTR_DH:
            raw = xtr_agree(
                self.xtr_domain,
                Span(self.private_primary),
                Span(self.peer_primary),
            )
        elif self.name == AgreementAlgorithm.ECDH_P256:
            var shared = self.elliptic_power[0].multiply(
                from_be(Span(self.private_primary))
            )
            if shared.infinity:
                raise Error("ECDH produced the point at infinity")
            raw = to_be(shared.x, 32)
        elif (
            self.name == AgreementAlgorithm.ECMQV_P256
            or self.name == AgreementAlgorithm.ECHMQV_P256
            or self.name == AgreementAlgorithm.ECFHMQV_P256
        ):
            raw = elliptic_authenticated(
                self.elliptic_domain,
                self.name,
                Span(self.private_primary),
                Span(self.private_secondary),
                Span(self.local_primary),
                Span(self.local_secondary),
                Span(self.peer_primary),
                Span(self.peer_secondary),
                self.client_role,
            )
        elif self.name == AgreementAlgorithm.X25519:
            raw = x25519_agree(
                Span(self.private_primary), Span(self.peer_primary)
            )
        else:
            raise Error("unknown agreement family")
        return _resize(Span(raw), self.shared_bytes)


def _resize[
    origin: Origin
](raw: Span[UInt8, origin], shared_bytes: Int,) raises -> List[UInt8]:
    if shared_bytes <= 0:
        raise Error("shared secret size must be positive")
    if shared_bytes == len(raw):
        var exact = List[UInt8](capacity=len(raw))
        for byte in raw:
            exact.append(byte)
        return exact^
    var output = List[UInt8](capacity=shared_bytes)
    var counter = UInt32(0)
    while len(output) < shared_bytes:
        var block = List[UInt8](capacity=len(raw) + 4)
        for byte in raw:
            block.append(byte)
        for i in range(4):
            block.append(UInt8(counter >> UInt32(8 * i)))
        var digest = sha256(Span(block))
        for byte in digest:
            if len(output) < shared_bytes:
                output.append(byte)
        counter += 1
    return output^


def agree[
    parameters_origin: Origin,
    private_origin: Origin,
    public_origin: Origin,
](
    name: AgreementAlgorithm,
    parameters: Span[UInt8, parameters_origin],
    private_key: Span[UInt8, private_origin],
    peer_public_key: Span[UInt8, public_origin],
    shared_bytes: Int,
    client_role: Bool,
) raises -> List[UInt8]:
    _validate_parameters(name, parameters)
    var payload_sizes = _payload_sizes(name)
    var private_payload = _unwrap(
        name,
        True,
        client_role,
        private_key,
        payload_sizes[0],
    )
    var peer_payload = _unwrap(
        name,
        False,
        not client_role,
        peer_public_key,
        payload_sizes[1],
    )
    var raw = _raw_agree(
        name,
        Span(private_payload),
        Span(peer_payload),
        client_role,
    )
    return _resize(Span(raw), shared_bytes)
