"""Small prime and binary fields used by block ciphers and coding schemes."""


struct PrimeField64:
    var modulus: UInt64

    def __init__(out self, modulus: UInt64) raises:
        if modulus < 2:
            raise Error("field modulus must be at least two")
        self.modulus = modulus

    @always_inline("nodebug")
    def reduce(self, value: UInt64) -> UInt64:
        return value % self.modulus

    @always_inline("nodebug")
    def add(self, a: UInt64, b: UInt64) -> UInt64:
        var left = a % self.modulus
        var right = b % self.modulus
        if right >= self.modulus - left:
            return right - (self.modulus - left)
        return left + right

    @always_inline("nodebug")
    def subtract(self, a: UInt64, b: UInt64) -> UInt64:
        var left = a % self.modulus
        var right = b % self.modulus
        if left >= right:
            return left - right
        return self.modulus - (right - left)

    @always_inline("nodebug")
    def multiply(self, a: UInt64, b: UInt64) -> UInt64:
        return UInt64(
            (UInt128(a % self.modulus) * UInt128(b % self.modulus))
            % UInt128(self.modulus)
        )

    def power(self, base: UInt64, exponent: UInt64) -> UInt64:
        var factor = base % self.modulus
        var remaining = exponent
        var result = UInt64(1)
        while remaining != 0:
            if remaining & 1 != 0:
                result = self.multiply(result, factor)
            factor = self.multiply(factor, factor)
            remaining >>= 1
        return result

    def inverse(self, value: UInt64) raises -> UInt64:
        var reduced = value % self.modulus
        if reduced == 0:
            raise Error("zero has no multiplicative inverse")
        var old_r = Int128(reduced)
        var r = Int128(self.modulus)
        var old_t = Int128(1)
        var t = Int128(0)
        while r != 0:
            var quotient = old_r // r
            var next_r = old_r - quotient * r
            old_r = r
            r = next_r
            var next_t = old_t - quotient * t
            old_t = t
            t = next_t
        if old_r != 1:
            raise Error("element is not invertible modulo the modulus")
        if old_t < 0:
            old_t += Int128(self.modulus)
        return UInt64(old_t)


struct GF256:
    var modulus: UInt8

    def __init__(out self, modulus: UInt8 = 0x1B):
        self.modulus = modulus

    @always_inline("nodebug")
    def add(self, a: UInt8, b: UInt8) -> UInt8:
        return a ^ b

    @always_inline("nodebug")
    def multiply(self, a: UInt8, b: UInt8) -> UInt8:
        var factor = a
        var multiplier = b
        var product = UInt8(0)
        for _ in range(8):
            var bit_mask = UInt8(0) - (multiplier & 1)
            product ^= factor & bit_mask
            var high_mask = UInt8(0) - UInt8((factor >> 7) & 1)
            factor = (factor << 1) ^ (self.modulus & high_mask)
            multiplier >>= 1
        return product

    def power(self, base: UInt8, exponent: UInt16) -> UInt8:
        var factor = base
        var remaining = exponent
        var result = UInt8(1)
        while remaining != 0:
            if remaining & 1 != 0:
                result = self.multiply(result, factor)
            factor = self.multiply(factor, factor)
            remaining >>= 1
        return result

    def inverse(self, value: UInt8) raises -> UInt8:
        if value == 0:
            raise Error("zero has no multiplicative inverse")
        return self.power(value, 254)


struct GF2_32:
    var modulus: UInt32

    def __init__(out self, modulus: UInt32 = 0x8D):
        self.modulus = modulus

    @always_inline("nodebug")
    def add(self, a: UInt32, b: UInt32) -> UInt32:
        return a ^ b

    def multiply(self, a: UInt32, b: UInt32) -> UInt32:
        var factor = a
        var multiplier = b
        var product = UInt32(0)
        for _ in range(32):
            var bit_mask = UInt32(0) - (multiplier & 1)
            product ^= factor & bit_mask
            var high_mask = UInt32(0) - ((factor >> 31) & 1)
            factor = (factor << 1) ^ (self.modulus & high_mask)
            multiplier >>= 1
        return product

    def power(self, base: UInt32, exponent: UInt64) -> UInt32:
        var factor = base
        var remaining = exponent
        var result = UInt32(1)
        while remaining != 0:
            if remaining & 1 != 0:
                result = self.multiply(result, factor)
            factor = self.multiply(factor, factor)
            remaining >>= 1
        return result

    def inverse(self, value: UInt32) raises -> UInt32:
        if value == 0:
            raise Error("zero has no multiplicative inverse")
        return self.power(value, UInt64(0xFFFFFFFE))
