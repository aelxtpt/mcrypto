"""Type-safe group family and operation selection."""


@fieldwise_init
struct _GroupFamilyToken[value: UInt8](ImplicitlyCopyable):
    pass


struct GroupFamily(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime X25519 = GroupFamily(_GroupFamilyToken[0]())
    comptime ED25519 = GroupFamily(_GroupFamilyToken[1]())
    comptime RISTRETTO255 = GroupFamily(_GroupFamilyToken[2]())

    def __init__[value: UInt8](out self, token: _GroupFamilyToken[value]):
        comptime assert value < 3, "invalid GroupFamily value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _GroupOperationToken[value: UInt8](ImplicitlyCopyable):
    pass


struct GroupOperation(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ADD = GroupOperation(_GroupOperationToken[0]())
    comptime SUB = GroupOperation(_GroupOperationToken[1]())
    comptime FROM_HASH = GroupOperation(_GroupOperationToken[2]())
    comptime IS_VALID = GroupOperation(_GroupOperationToken[3]())
    comptime SCALAR_REDUCE = GroupOperation(_GroupOperationToken[4]())
    comptime SCALAR_INVERT = GroupOperation(_GroupOperationToken[5]())
    comptime SCALAR_NEGATE = GroupOperation(_GroupOperationToken[6]())
    comptime SCALAR_COMPLEMENT = GroupOperation(_GroupOperationToken[7]())
    comptime SCALAR_ADD = GroupOperation(_GroupOperationToken[8]())
    comptime SCALAR_SUB = GroupOperation(_GroupOperationToken[9]())
    comptime SCALAR_MUL = GroupOperation(_GroupOperationToken[10]())

    def __init__[value: UInt8](out self, token: _GroupOperationToken[value]):
        comptime assert value < 11, "invalid GroupOperation value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _CoreAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct CoreAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime HCHACHA20 = CoreAlgorithm(_CoreAlgorithmToken[0]())
    comptime HSALSA20 = CoreAlgorithm(_CoreAlgorithmToken[1]())
    comptime SALSA20 = CoreAlgorithm(_CoreAlgorithmToken[2]())
    comptime SALSA20_12 = CoreAlgorithm(_CoreAlgorithmToken[3]())
    comptime SALSA20_8 = CoreAlgorithm(_CoreAlgorithmToken[4]())
    comptime KECCAK_F1600 = CoreAlgorithm(_CoreAlgorithmToken[5]())

    def __init__[value: UInt8](out self, token: _CoreAlgorithmToken[value]):
        comptime assert value < 6, "invalid CoreAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _BatchedCoreAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct BatchedCoreAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime HCHACHA20 = BatchedCoreAlgorithm(_BatchedCoreAlgorithmToken[0]())
    comptime HSALSA20 = BatchedCoreAlgorithm(_BatchedCoreAlgorithmToken[1]())
    comptime SALSA20 = BatchedCoreAlgorithm(_BatchedCoreAlgorithmToken[2]())
    comptime SALSA20_12 = BatchedCoreAlgorithm(_BatchedCoreAlgorithmToken[3]())
    comptime SALSA20_8 = BatchedCoreAlgorithm(_BatchedCoreAlgorithmToken[4]())

    def __init__[
        value: UInt8
    ](out self, token: _BatchedCoreAlgorithmToken[value]):
        comptime assert value < 5, "invalid BatchedCoreAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


@fieldwise_init
struct _EdwardsGroupAlgorithmToken[value: UInt8](ImplicitlyCopyable):
    pass


struct EdwardsGroupAlgorithm(Equatable, ImplicitlyCopyable):
    var _value: UInt8

    comptime ED25519 = EdwardsGroupAlgorithm(_EdwardsGroupAlgorithmToken[0]())
    comptime RISTRETTO255 = EdwardsGroupAlgorithm(
        _EdwardsGroupAlgorithmToken[1]()
    )

    def __init__[
        value: UInt8
    ](out self, token: _EdwardsGroupAlgorithmToken[value]):
        comptime assert value < 2, "invalid EdwardsGroupAlgorithm value"
        self._value = value

    @always_inline
    def __eq__(self, other: Self) -> Bool:
        return self._value == other._value

    @always_inline
    def __ne__(self, other: Self) -> Bool:
        return not self == other


def parse_core_algorithm(name: String) raises -> CoreAlgorithm:
    if name == "HChaCha20":
        return CoreAlgorithm.HCHACHA20
    if name == "HSalsa20":
        return CoreAlgorithm.HSALSA20
    if name == "Salsa20":
        return CoreAlgorithm.SALSA20
    if name == "Salsa20-12":
        return CoreAlgorithm.SALSA20_12
    if name == "Salsa20-8":
        return CoreAlgorithm.SALSA20_8
    if name == "Keccak-f1600":
        return CoreAlgorithm.KECCAK_F1600
    raise Error("unknown core algorithm")


def parse_batched_core_algorithm(name: String) raises -> BatchedCoreAlgorithm:
    if name == "HChaCha20":
        return BatchedCoreAlgorithm.HCHACHA20
    if name == "HSalsa20":
        return BatchedCoreAlgorithm.HSALSA20
    if name == "Salsa20":
        return BatchedCoreAlgorithm.SALSA20
    if name == "Salsa20-12":
        return BatchedCoreAlgorithm.SALSA20_12
    if name == "Salsa20-8":
        return BatchedCoreAlgorithm.SALSA20_8
    raise Error("unknown batched core algorithm")


def parse_edwards_group_algorithm(
    name: String,
) raises -> EdwardsGroupAlgorithm:
    if name == "Ed25519":
        return EdwardsGroupAlgorithm.ED25519
    if name == "Ristretto255":
        return EdwardsGroupAlgorithm.RISTRETTO255
    raise Error("unknown Edwards-group algorithm")


def parse_group_family(name: String) raises -> GroupFamily:
    if name == "X25519":
        return GroupFamily.X25519
    if name == "Ed25519":
        return GroupFamily.ED25519
    if name == "Ristretto255":
        return GroupFamily.RISTRETTO255
    raise Error("unknown group family")


def parse_group_operation(name: String) raises -> GroupOperation:
    if name == "add" or name == "point-add":
        return GroupOperation.ADD
    if name == "sub" or name == "point-sub":
        return GroupOperation.SUB
    if name == "from-hash":
        return GroupOperation.FROM_HASH
    if name == "is-valid":
        return GroupOperation.IS_VALID
    if name == "scalar-reduce":
        return GroupOperation.SCALAR_REDUCE
    if name == "scalar-invert":
        return GroupOperation.SCALAR_INVERT
    if name == "scalar-negate":
        return GroupOperation.SCALAR_NEGATE
    if name == "scalar-complement":
        return GroupOperation.SCALAR_COMPLEMENT
    if name == "scalar-add":
        return GroupOperation.SCALAR_ADD
    if name == "scalar-sub":
        return GroupOperation.SCALAR_SUB
    if name == "scalar-mul":
        return GroupOperation.SCALAR_MUL
    raise Error("unknown group operation")
