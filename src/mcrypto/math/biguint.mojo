"""Unsigned multiprecision arithmetic with little-endian 32-bit limbs."""

comptime LIMB_BITS = 32
comptime LIMB_BASE = UInt64(1) << LIMB_BITS
comptime LIMB_MASK = LIMB_BASE - 1


struct BigUInt(Copyable, Movable):
    var limbs: List[UInt32]

    def __init__(out self):
        self.limbs = List[UInt32](length=1, fill=0)

    def __init__(out self, value: UInt64):
        self.limbs = List[UInt32](capacity=2)
        self.limbs.append(UInt32(value))
        if value >> LIMB_BITS != 0:
            self.limbs.append(UInt32(value >> LIMB_BITS))

    def __init__(out self, *, copy: Self):
        self.limbs = copy.limbs.copy()

    def __init__(out self, *, deinit move: Self):
        self.limbs = move.limbs^

    @staticmethod
    def from_limbs[origin: Origin](values: Span[UInt32, origin]) -> Self:
        var result = BigUInt()
        result.limbs.clear()
        for value in values:
            result.limbs.append(value)
        if len(result.limbs) == 0:
            result.limbs.append(0)
        result._normalize()
        return result^

    def _normalize(mut self):
        while len(self.limbs) > 1 and self.limbs[len(self.limbs) - 1] == 0:
            _ = self.limbs.pop()

    def is_zero(self) -> Bool:
        return len(self.limbs) == 1 and self.limbs[0] == 0

    def bit_length(self) -> Int:
        if self.is_zero():
            return 0
        var top = self.limbs[len(self.limbs) - 1]
        var bits = (len(self.limbs) - 1) * LIMB_BITS
        while top != 0:
            bits += 1
            top >>= 1
        return bits

    def bit(self, index: Int) -> UInt32:
        if index < 0 or index // LIMB_BITS >= len(self.limbs):
            return 0
        return (self.limbs[index // LIMB_BITS] >> UInt32(index % LIMB_BITS)) & 1

    def compare(self, other: Self) -> Int:
        if len(self.limbs) < len(other.limbs):
            return -1
        if len(self.limbs) > len(other.limbs):
            return 1
        for i in range(len(self.limbs) - 1, -1, -1):
            if self.limbs[i] < other.limbs[i]:
                return -1
            if self.limbs[i] > other.limbs[i]:
                return 1
        return 0

    def add(self, other: Self) -> Self:
        var count = max(len(self.limbs), len(other.limbs))
        var result = BigUInt()
        result.limbs = List[UInt32](capacity=count + 1)
        var carry = UInt64(0)
        for i in range(count):
            var left = UInt64(self.limbs[i]) if i < len(self.limbs) else 0
            var right = UInt64(other.limbs[i]) if i < len(other.limbs) else 0
            var total = left + right + carry
            result.limbs.append(UInt32(total & LIMB_MASK))
            carry = total >> LIMB_BITS
        if carry != 0:
            result.limbs.append(UInt32(carry))
        return result^

    def subtract(self, other: Self) raises -> Self:
        if self.compare(other) < 0:
            raise Error("unsigned subtraction underflow")
        var result = BigUInt()
        result.limbs = List[UInt32](capacity=len(self.limbs))
        var borrow = UInt64(0)
        for i in range(len(self.limbs)):
            var left = UInt64(self.limbs[i])
            var right = (
                UInt64(other.limbs[i]) if i < len(other.limbs) else 0
            ) + borrow
            if left >= right:
                result.limbs.append(UInt32(left - right))
                borrow = 0
            else:
                result.limbs.append(UInt32(LIMB_BASE + left - right))
                borrow = 1
        result._normalize()
        return result^

    @always_inline("nodebug")
    def multiply(self, other: Self) -> Self:
        var result = BigUInt()
        result.limbs = List[UInt32](
            length=len(self.limbs) + len(other.limbs), fill=0
        )
        var left_pointer = Span(self.limbs).unsafe_ptr()
        var right_pointer = Span(other.limbs).unsafe_ptr()
        var result_pointer = Span(result.limbs).unsafe_ptr()
        for i in range(len(self.limbs)):
            var left = UInt64(left_pointer.unsafe_load(i))
            var carry = UInt64(0)
            for j in range(len(other.limbs)):
                var index = i + j
                var total = (
                    UInt64(result_pointer.unsafe_load(index))
                    + left * UInt64(right_pointer.unsafe_load(j))
                    + carry
                )
                result_pointer.unsafe_store(index, UInt32(total))
                carry = total >> LIMB_BITS
            var index = i + len(other.limbs)
            while carry != 0:
                var total = UInt64(result_pointer.unsafe_load(index)) + carry
                result_pointer.unsafe_store(index, UInt32(total))
                carry = total >> LIMB_BITS
                index += 1
        result._normalize()
        return result^

    def shift_left_one(mut self):
        var carry = UInt32(0)
        for i in range(len(self.limbs)):
            var next = self.limbs[i] >> 31
            self.limbs[i] = (self.limbs[i] << 1) | carry
            carry = next
        if carry != 0:
            self.limbs.append(carry)

    def shift_right_one(mut self):
        var carry = UInt32(0)
        for i in range(len(self.limbs) - 1, -1, -1):
            var next = self.limbs[i] & 1
            self.limbs[i] = (self.limbs[i] >> 1) | (carry << 31)
            carry = next
        self._normalize()

    def add_small(mut self, value: UInt32):
        var carry = UInt64(value)
        var index = 0
        while carry != 0:
            if index == len(self.limbs):
                self.limbs.append(0)
            var total = UInt64(self.limbs[index]) + carry
            self.limbs[index] = UInt32(total & LIMB_MASK)
            carry = total >> LIMB_BITS
            index += 1

    def modulo(self, modulus: Self) raises -> Self:
        """Remainder using normalized base-2^32 long division (Knuth D)."""
        if modulus.is_zero():
            raise Error("modulo by zero")
        if self.compare(modulus) < 0:
            return self.copy()
        if len(modulus.limbs) == 1:
            var divisor = UInt64(modulus.limbs[0])
            var remainder = UInt64(0)
            for i in range(len(self.limbs) - 1, -1, -1):
                remainder = (
                    (remainder << LIMB_BITS) + UInt64(self.limbs[i])
                ) % divisor
            return BigUInt(remainder)
        var shift = 0
        var top = modulus.limbs[len(modulus.limbs) - 1]
        while (top & 0x80000000) == 0:
            top <<= 1
            shift += 1
        var n = len(modulus.limbs)
        var normalized_modulus = List[UInt32](length=n, fill=0)
        var carry = UInt64(0)
        for i in range(n):
            var value = (UInt64(modulus.limbs[i]) << UInt64(shift)) | carry
            normalized_modulus[i] = UInt32(value)
            carry = value >> LIMB_BITS
        var normalized_value = List[UInt32](length=len(self.limbs) + 1, fill=0)
        carry = 0
        for i in range(len(self.limbs)):
            var value = (UInt64(self.limbs[i]) << UInt64(shift)) | carry
            normalized_value[i] = UInt32(value)
            carry = value >> LIMB_BITS
        normalized_value[len(self.limbs)] = UInt32(carry)
        var modulus_pointer = Span(normalized_modulus).unsafe_ptr()
        var value_pointer = Span(normalized_value).unsafe_ptr()
        var quotient_limbs = len(self.limbs) - n
        var divisor_top = UInt64(modulus_pointer.unsafe_load(n - 1))
        for j in range(quotient_limbs, -1, -1):
            var numerator = (
                UInt64(value_pointer.unsafe_load(j + n)) << LIMB_BITS
            ) | UInt64(value_pointer.unsafe_load(j + n - 1))
            var estimate = numerator // divisor_top
            var estimate_remainder = numerator % divisor_top
            if estimate >= LIMB_BASE:
                estimate = LIMB_BASE - 1
                estimate_remainder += divisor_top
            while estimate_remainder < LIMB_BASE and estimate * UInt64(
                modulus_pointer.unsafe_load(n - 2)
            ) > (
                (estimate_remainder << LIMB_BITS)
                + UInt64(value_pointer.unsafe_load(j + n - 2))
            ):
                estimate -= 1
                estimate_remainder += divisor_top
            var product_carry = UInt64(0)
            var borrow = UInt64(0)
            for i in range(n):
                var product = (
                    estimate * UInt64(modulus_pointer.unsafe_load(i))
                    + product_carry
                )
                product_carry = product >> LIMB_BITS
                var subtrahend = (product & LIMB_MASK) + borrow
                var index = j + i
                var current = UInt64(value_pointer.unsafe_load(index))
                if current < subtrahend:
                    value_pointer.unsafe_store(
                        index, UInt32(LIMB_BASE + current - subtrahend)
                    )
                    borrow = 1
                else:
                    value_pointer.unsafe_store(
                        index, UInt32(current - subtrahend)
                    )
                    borrow = 0
            var top_subtrahend = product_carry + borrow
            var top_index = j + n
            var current_top = UInt64(value_pointer.unsafe_load(top_index))
            var negative = current_top < top_subtrahend
            value_pointer.unsafe_store(
                top_index,
                UInt32(
                    LIMB_BASE
                    + current_top
                    - top_subtrahend if negative else current_top
                    - top_subtrahend
                ),
            )
            if negative:
                var addition_carry = UInt64(0)
                for i in range(n):
                    var index = j + i
                    var total = (
                        UInt64(value_pointer.unsafe_load(index))
                        + UInt64(modulus_pointer.unsafe_load(i))
                        + addition_carry
                    )
                    value_pointer.unsafe_store(index, UInt32(total))
                    addition_carry = total >> LIMB_BITS
                value_pointer.unsafe_store(
                    top_index,
                    UInt32(
                        UInt64(value_pointer.unsafe_load(top_index))
                        + addition_carry
                    ),
                )
        var remainder_limbs = List[UInt32](length=n, fill=0)
        var remainder_pointer = Span(remainder_limbs).unsafe_ptr()
        if shift == 0:
            for i in range(n):
                remainder_pointer.unsafe_store(i, value_pointer.unsafe_load(i))
        else:
            for i in range(n):
                remainder_pointer.unsafe_store(
                    i,
                    (value_pointer.unsafe_load(i) >> UInt32(shift))
                    | (
                        value_pointer.unsafe_load(i + 1)
                        << UInt32(LIMB_BITS - shift)
                    ),
                )
        return BigUInt.from_limbs(Span(remainder_limbs))

    def divide(self, divisor_value: Self) raises -> Self:
        """Quotient using normalized base-2^32 long division (Knuth D)."""
        if divisor_value.is_zero():
            raise Error("division by zero")
        if self.compare(divisor_value) < 0:
            return BigUInt()
        if len(divisor_value.limbs) == 1:
            var divisor = UInt64(divisor_value.limbs[0])
            var remainder = UInt64(0)
            var quotient = List[UInt32](length=len(self.limbs), fill=0)
            for i in range(len(self.limbs) - 1, -1, -1):
                var numerator = (remainder << LIMB_BITS) | UInt64(self.limbs[i])
                quotient[i] = UInt32(numerator // divisor)
                remainder = numerator % divisor
            return BigUInt.from_limbs(Span(quotient))
        var shift = 0
        var top = divisor_value.limbs[len(divisor_value.limbs) - 1]
        while (top & 0x80000000) == 0:
            top <<= 1
            shift += 1
        var n = len(divisor_value.limbs)
        var normalized_divisor = List[UInt32](length=n, fill=0)
        var carry = UInt64(0)
        for i in range(n):
            var value = (
                UInt64(divisor_value.limbs[i]) << UInt64(shift)
            ) | carry
            normalized_divisor[i] = UInt32(value)
            carry = value >> LIMB_BITS
        var normalized_value = List[UInt32](length=len(self.limbs) + 1, fill=0)
        carry = 0
        for i in range(len(self.limbs)):
            var value = (UInt64(self.limbs[i]) << UInt64(shift)) | carry
            normalized_value[i] = UInt32(value)
            carry = value >> LIMB_BITS
        normalized_value[len(self.limbs)] = UInt32(carry)
        var quotient_count = len(self.limbs) - n
        var quotient = List[UInt32](length=quotient_count + 1, fill=0)
        var divisor_top = UInt64(normalized_divisor[n - 1])
        for j in range(quotient_count, -1, -1):
            var numerator = (
                UInt64(normalized_value[j + n]) << LIMB_BITS
            ) | UInt64(normalized_value[j + n - 1])
            var estimate = numerator // divisor_top
            var estimate_remainder = numerator % divisor_top
            if estimate >= LIMB_BASE:
                estimate = LIMB_BASE - 1
                estimate_remainder += divisor_top
            while estimate_remainder < LIMB_BASE and estimate * UInt64(
                normalized_divisor[n - 2]
            ) > (
                (estimate_remainder << LIMB_BITS)
                + UInt64(normalized_value[j + n - 2])
            ):
                estimate -= 1
                estimate_remainder += divisor_top
            var product_carry = UInt64(0)
            var borrow = UInt64(0)
            for i in range(n):
                var product = (
                    estimate * UInt64(normalized_divisor[i]) + product_carry
                )
                product_carry = product >> LIMB_BITS
                var subtrahend = (product & LIMB_MASK) + borrow
                var current = UInt64(normalized_value[j + i])
                if current < subtrahend:
                    normalized_value[j + i] = UInt32(
                        LIMB_BASE + current - subtrahend
                    )
                    borrow = 1
                else:
                    normalized_value[j + i] = UInt32(current - subtrahend)
                    borrow = 0
            var top_subtrahend = product_carry + borrow
            var current_top = UInt64(normalized_value[j + n])
            var negative = current_top < top_subtrahend
            normalized_value[j + n] = UInt32(
                (
                    LIMB_BASE
                    + current_top
                    - top_subtrahend if negative else current_top
                    - top_subtrahend
                )
            )
            if negative:
                estimate -= 1
                var addition_carry = UInt64(0)
                for i in range(n):
                    var total = (
                        UInt64(normalized_value[j + i])
                        + UInt64(normalized_divisor[i])
                        + addition_carry
                    )
                    normalized_value[j + i] = UInt32(total)
                    addition_carry = total >> LIMB_BITS
                normalized_value[j + n] = UInt32(
                    UInt64(normalized_value[j + n]) + addition_carry
                )
            quotient[j] = UInt32(estimate)
        return BigUInt.from_limbs(Span(quotient))

    def _modular_multiply_six(self, other: Self, modulus: Self) raises -> Self:
        """Allocation-light product reduction for operands of at most six limbs.
        """
        var product = InlineArray[UInt32, 12](fill=0)
        comptime for i in range(6):
            var left = UInt64(0)
            if i < len(self.limbs):
                left = UInt64(self.limbs[i])
            var carry = UInt64(0)
            comptime for j in range(6):
                var right = UInt64(0)
                if j < len(other.limbs):
                    right = UInt64(other.limbs[j])
                comptime index = i + j
                var total = UInt64(product[index]) + left * right + carry
                product[index] = UInt32(total)
                carry = total >> LIMB_BITS
            var index = i + 6
            while carry != 0 and index < 12:
                var total = UInt64(product[index]) + carry
                product[index] = UInt32(total)
                carry = total >> LIMB_BITS
                index += 1
        var product_count = 12
        while product_count > 1 and product[product_count - 1] == 0:
            product_count -= 1
        comptime n = 6
        var below_modulus = product_count < n
        if product_count == n:
            below_modulus = True
            comptime for offset in range(6):
                var index = n - 1 - offset
                if product[index] > modulus.limbs[index]:
                    below_modulus = False
                    break
                if product[index] < modulus.limbs[index]:
                    break
                if index == 0:
                    below_modulus = False
        if below_modulus:
            var result = BigUInt()
            result.limbs = List[UInt32](unsafe_uninit_length=product_count)
            for i in range(product_count):
                result.limbs[i] = product[i]
            return result^
        var shift = 0
        var top = modulus.limbs[n - 1]
        while (top & 0x80000000) == 0:
            top <<= 1
            shift += 1
        var normalized_modulus = InlineArray[UInt32, 6](fill=0)
        var carry = UInt64(0)
        comptime for i in range(6):
            var value = (UInt64(modulus.limbs[i]) << UInt64(shift)) | carry
            normalized_modulus[i] = UInt32(value)
            carry = value >> LIMB_BITS
        var normalized_value = InlineArray[UInt32, 13](fill=0)
        carry = 0
        for i in range(product_count):
            var value = (UInt64(product[i]) << UInt64(shift)) | carry
            normalized_value[i] = UInt32(value)
            carry = value >> LIMB_BITS
        normalized_value[product_count] = UInt32(carry)
        var quotient_limbs = product_count - n
        var divisor_top = UInt64(normalized_modulus[n - 1])
        for offset in range(quotient_limbs + 1):
            var j = quotient_limbs - offset
            var numerator = (
                UInt64(normalized_value[j + n]) << LIMB_BITS
            ) | UInt64(normalized_value[j + n - 1])
            var estimate = numerator // divisor_top
            var estimate_remainder = numerator % divisor_top
            if estimate >= LIMB_BASE:
                estimate = LIMB_BASE - 1
                estimate_remainder += divisor_top
            while estimate_remainder < LIMB_BASE and estimate * UInt64(
                normalized_modulus[n - 2]
            ) > (
                (estimate_remainder << LIMB_BITS)
                + UInt64(normalized_value[j + n - 2])
            ):
                estimate -= 1
                estimate_remainder += divisor_top
            var product_carry = UInt64(0)
            var borrow = UInt64(0)
            comptime for i in range(6):
                var partial = (
                    estimate * UInt64(normalized_modulus[i]) + product_carry
                )
                product_carry = partial >> LIMB_BITS
                var subtrahend = (partial & LIMB_MASK) + borrow
                var index = j + i
                var current = UInt64(normalized_value[index])
                if current < subtrahend:
                    normalized_value[index] = UInt32(
                        LIMB_BASE + current - subtrahend
                    )
                    borrow = 1
                else:
                    normalized_value[index] = UInt32(current - subtrahend)
                    borrow = 0
            var top_subtrahend = product_carry + borrow
            var top_index = j + n
            var current_top = UInt64(normalized_value[top_index])
            var negative = current_top < top_subtrahend
            normalized_value[top_index] = UInt32(
                (
                    LIMB_BASE
                    + current_top
                    - top_subtrahend if negative else current_top
                    - top_subtrahend
                )
            )
            if negative:
                var addition_carry = UInt64(0)
                comptime for i in range(6):
                    var index = j + i
                    var total = (
                        UInt64(normalized_value[index])
                        + UInt64(normalized_modulus[i])
                        + addition_carry
                    )
                    normalized_value[index] = UInt32(total)
                    addition_carry = total >> LIMB_BITS
                normalized_value[top_index] = UInt32(
                    UInt64(normalized_value[top_index]) + addition_carry
                )
        var result = BigUInt()
        result.limbs = List[UInt32](unsafe_uninit_length=n)
        if shift == 0:
            comptime for i in range(6):
                result.limbs[i] = normalized_value[i]
        else:
            comptime for i in range(6):
                result.limbs[i] = (normalized_value[i] >> UInt32(shift)) | (
                    normalized_value[i + 1] << UInt32(LIMB_BITS - shift)
                )
        result._normalize()
        return result^

    def modular_multiply(self, other: Self, modulus: Self) raises -> Self:
        if (
            len(modulus.limbs) == 6
            and len(self.limbs) <= 6
            and len(other.limbs) <= 6
        ):
            return self._modular_multiply_six(other, modulus)
        return self.multiply(other).modulo(modulus)

    def _montgomery_square_into(
        self,
        modulus: Self,
        modulus_words: List[UInt64],
        negated_inverse: UInt64,
        word_count: Int,
        mut output: Self,
        mut work: List[UInt64],
        mut right_words: List[UInt64],
    ):
        self._montgomery_multiply_into(
            self,
            modulus,
            modulus_words,
            negated_inverse,
            word_count,
            output,
            work,
            right_words,
        )

    def _montgomery_multiply_cios_fixed[
        word_count: Int
    ](
        self,
        other: Self,
        modulus_words: List[UInt64],
        negated_inverse: UInt64,
        mut output: Self,
        mut work: List[UInt64],
        mut right_words: List[UInt64],
    ):
        """Integrated fixed-width Montgomery product for full-width inputs."""
        var work_pointer = Span(work).unsafe_ptr()
        var left_pointer = Span(self.limbs).unsafe_ptr()
        var right_pointer = Span(other.limbs).unsafe_ptr()
        var modulus_pointer = Span(modulus_words).unsafe_ptr()
        var output_pointer = Span(output.limbs).unsafe_ptr()
        var right_words_pointer = Span(right_words).unsafe_ptr()
        comptime for i in range(word_count + 2):
            work_pointer.unsafe_store(i, 0)
        comptime for j in range(word_count):
            right_words_pointer.unsafe_store(
                j,
                UInt64(right_pointer.unsafe_load(2 * j))
                | (UInt64(right_pointer.unsafe_load(2 * j + 1)) << 32),
            )
        comptime for i in range(word_count):
            var left_word = UInt64(left_pointer.unsafe_load(2 * i)) | (
                UInt64(left_pointer.unsafe_load(2 * i + 1)) << 32
            )
            var carry = UInt64(0)
            comptime for j in range(word_count):
                var total = (
                    UInt128(work_pointer.unsafe_load(j))
                    + UInt128(left_word)
                    * UInt128(right_words_pointer.unsafe_load(j))
                    + UInt128(carry)
                )
                work_pointer.unsafe_store(j, UInt64(total))
                carry = UInt64(total >> 64)
            var edge = UInt128(work_pointer.unsafe_load(word_count)) + UInt128(
                carry
            )
            work_pointer.unsafe_store(word_count, UInt64(edge))
            work_pointer.unsafe_store(word_count + 1, UInt64(edge >> 64))
            var multiplier = work_pointer.unsafe_load(0) * negated_inverse
            carry = 0
            comptime for j in range(word_count):
                var total = (
                    UInt128(work_pointer.unsafe_load(j))
                    + UInt128(multiplier)
                    * UInt128(modulus_pointer.unsafe_load(j))
                    + UInt128(carry)
                )
                if j != 0:
                    work_pointer.unsafe_store(j - 1, UInt64(total))
                carry = UInt64(total >> 64)
            edge = UInt128(work_pointer.unsafe_load(word_count)) + UInt128(
                carry
            )
            work_pointer.unsafe_store(word_count - 1, UInt64(edge))
            work_pointer.unsafe_store(
                word_count,
                UInt64(edge >> 64) + work_pointer.unsafe_load(word_count + 1),
            )
            work_pointer.unsafe_store(word_count + 1, 0)
        var reduce = work_pointer.unsafe_load(word_count) != 0
        if not reduce:
            comptime for offset in range(word_count):
                comptime i = word_count - 1 - offset
                var value = work_pointer.unsafe_load(i)
                var modulus_word = modulus_pointer.unsafe_load(i)
                if value > modulus_word:
                    reduce = True
                    break
                if value < modulus_word:
                    break
                if i == 0:
                    reduce = True
        if reduce:
            var borrow = UInt64(0)
            comptime for i in range(word_count):
                var left = UInt128(work_pointer.unsafe_load(i))
                var right = UInt128(modulus_pointer.unsafe_load(i)) + UInt128(
                    borrow
                )
                if left < right:
                    work_pointer.unsafe_store(
                        i, UInt64((UInt128(1) << 64) + left - right)
                    )
                    borrow = 1
                else:
                    work_pointer.unsafe_store(i, UInt64(left - right))
                    borrow = 0
        comptime for i in range(word_count):
            var word = work_pointer.unsafe_load(i)
            output_pointer.unsafe_store(2 * i, UInt32(word))
            output_pointer.unsafe_store(2 * i + 1, UInt32(word >> 32))

    def _montgomery_multiply_fixed[
        word_count: Int
    ](
        self,
        other: Self,
        modulus_words: List[UInt64],
        negated_inverse: UInt64,
        mut output: Self,
        mut work: List[UInt64],
        mut right_words: List[UInt64],
    ):
        """Fixed-width Montgomery product with compile-time-unrolled limbs."""
        var work_pointer = Span(work).unsafe_ptr()
        var left_pointer = Span(self.limbs).unsafe_ptr()
        var right_pointer = Span(other.limbs).unsafe_ptr()
        var modulus_pointer = Span(modulus_words).unsafe_ptr()
        var output_pointer = Span(output.limbs).unsafe_ptr()
        comptime for i in range(2 * word_count + 2):
            work_pointer.unsafe_store(i, 0)
        var left_count = min((len(self.limbs) + 1) // 2, word_count)
        var right_count = min((len(other.limbs) + 1) // 2, word_count)
        var right_words_pointer = Span(right_words).unsafe_ptr()
        comptime for j in range(word_count):
            var right_word = UInt64(0)
            if j < right_count:
                right_word = UInt64(right_pointer.unsafe_load(2 * j))
                if 2 * j + 1 < len(other.limbs):
                    right_word |= (
                        UInt64(right_pointer.unsafe_load(2 * j + 1)) << 32
                    )
            right_words_pointer.unsafe_store(j, right_word)
        comptime for i in range(word_count):
            if i < left_count:
                var left_word = UInt64(left_pointer.unsafe_load(2 * i))
                if 2 * i + 1 < len(self.limbs):
                    left_word |= (
                        UInt64(left_pointer.unsafe_load(2 * i + 1)) << 32
                    )
                var carry = UInt64(0)
                comptime for j in range(word_count):
                    var index = i + j
                    var total = (
                        UInt128(work_pointer.unsafe_load(index))
                        + UInt128(left_word)
                        * UInt128(right_words_pointer.unsafe_load(j))
                        + UInt128(carry)
                    )
                    work_pointer.unsafe_store(index, UInt64(total))
                    carry = UInt64(total >> 64)
                var index = i + word_count
                while carry != 0:
                    var total = UInt128(
                        work_pointer.unsafe_load(index)
                    ) + UInt128(carry)
                    work_pointer.unsafe_store(index, UInt64(total))
                    carry = UInt64(total >> 64)
                    index += 1
        comptime for i in range(word_count):
            var multiplier = work_pointer.unsafe_load(i) * negated_inverse
            var carry = UInt64(0)
            comptime for j in range(word_count):
                var index = i + j
                var total = (
                    UInt128(work_pointer.unsafe_load(index))
                    + UInt128(multiplier)
                    * UInt128(modulus_pointer.unsafe_load(j))
                    + UInt128(carry)
                )
                work_pointer.unsafe_store(index, UInt64(total))
                carry = UInt64(total >> 64)
            var index = i + word_count
            while carry != 0:
                var total = UInt128(work_pointer.unsafe_load(index)) + UInt128(
                    carry
                )
                work_pointer.unsafe_store(index, UInt64(total))
                carry = UInt64(total >> 64)
                index += 1
        var reduce = work_pointer.unsafe_load(2 * word_count) != 0
        if not reduce:
            comptime for offset in range(word_count):
                comptime i = word_count - 1 - offset
                var modulus_word = modulus_pointer.unsafe_load(i)
                var value = work_pointer.unsafe_load(word_count + i)
                if value > modulus_word:
                    reduce = True
                    break
                if value < modulus_word:
                    break
                if i == 0:
                    reduce = True
        if reduce:
            var borrow = UInt64(0)
            comptime for i in range(word_count):
                var index = word_count + i
                var left = UInt128(work_pointer.unsafe_load(index))
                var right = UInt128(modulus_pointer.unsafe_load(i)) + UInt128(
                    borrow
                )
                if left < right:
                    work_pointer.unsafe_store(
                        index, UInt64((UInt128(1) << 64) + left - right)
                    )
                    borrow = 1
                else:
                    work_pointer.unsafe_store(index, UInt64(left - right))
                    borrow = 0
        comptime for i in range(word_count):
            var word = work_pointer.unsafe_load(word_count + i)
            output_pointer.unsafe_store(2 * i, UInt32(word))
            output_pointer.unsafe_store(2 * i + 1, UInt32(word >> 32))

    @always_inline("nodebug")
    def _montgomery_multiply_into(
        self,
        other: Self,
        modulus: Self,
        modulus_words: List[UInt64],
        negated_inverse: UInt64,
        word_count: Int,
        mut output: Self,
        mut work: List[UInt64],
        mut right_words: List[UInt64],
    ):
        if word_count == 3:
            if len(self.limbs) >= 6 and len(other.limbs) >= 6:
                self._montgomery_multiply_cios_fixed[3](
                    other,
                    modulus_words,
                    negated_inverse,
                    output,
                    work,
                    right_words,
                )
            else:
                self._montgomery_multiply_fixed[3](
                    other,
                    modulus_words,
                    negated_inverse,
                    output,
                    work,
                    right_words,
                )
            return
        if word_count == 4:
            if len(self.limbs) >= 8 and len(other.limbs) >= 8:
                self._montgomery_multiply_cios_fixed[4](
                    other,
                    modulus_words,
                    negated_inverse,
                    output,
                    work,
                    right_words,
                )
            else:
                self._montgomery_multiply_fixed[4](
                    other,
                    modulus_words,
                    negated_inverse,
                    output,
                    work,
                    right_words,
                )
            return
        if word_count == 8 and len(self.limbs) >= 16 and len(other.limbs) >= 16:
            self._montgomery_multiply_cios_fixed[8](
                other,
                modulus_words,
                negated_inverse,
                output,
                work,
                right_words,
            )
            return
        if word_count == 8:
            self._montgomery_multiply_fixed[8](
                other,
                modulus_words,
                negated_inverse,
                output,
                work,
                right_words,
            )
            return
        if word_count == 16:
            self._montgomery_multiply_fixed[16](
                other,
                modulus_words,
                negated_inverse,
                output,
                work,
                right_words,
            )
            return
        if word_count == 32:
            self._montgomery_multiply_fixed[32](
                other,
                modulus_words,
                negated_inverse,
                output,
                work,
                right_words,
            )
            return
        var work_pointer = Span(work).unsafe_ptr()
        var left_pointer = Span(self.limbs).unsafe_ptr()
        var right_pointer = Span(other.limbs).unsafe_ptr()
        var modulus_pointer = Span(modulus_words).unsafe_ptr()
        var output_pointer = Span(output.limbs).unsafe_ptr()
        for i in range(len(work)):
            work_pointer.unsafe_store(i, 0)
        var left_count = min((len(self.limbs) + 1) // 2, word_count)
        var right_count = min((len(other.limbs) + 1) // 2, word_count)
        var right_words_pointer = Span(right_words).unsafe_ptr()
        for j in range(right_count):
            var right_word = UInt64(right_pointer.unsafe_load(2 * j))
            if 2 * j + 1 < len(other.limbs):
                right_word |= UInt64(right_pointer.unsafe_load(2 * j + 1)) << 32
            right_words_pointer.unsafe_store(j, right_word)
        for i in range(left_count):
            var left_word = UInt64(left_pointer.unsafe_load(2 * i))
            if 2 * i + 1 < len(self.limbs):
                left_word |= UInt64(left_pointer.unsafe_load(2 * i + 1)) << 32
            var carry = UInt64(0)
            for j in range(right_count):
                var right_word = right_words_pointer.unsafe_load(j)
                var index = i + j
                var total = (
                    UInt128(work_pointer.unsafe_load(index))
                    + UInt128(left_word) * UInt128(right_word)
                    + UInt128(carry)
                )
                work_pointer.unsafe_store(index, UInt64(total))
                carry = UInt64(total >> 64)
            var index = i + right_count
            while carry != 0:
                var total = UInt128(work_pointer.unsafe_load(index)) + UInt128(
                    carry
                )
                work_pointer.unsafe_store(index, UInt64(total))
                carry = UInt64(total >> 64)
                index += 1
        for i in range(word_count):
            var multiplier = work_pointer.unsafe_load(i) * negated_inverse
            var carry = UInt64(0)
            for j in range(word_count):
                var modulus_word = modulus_pointer.unsafe_load(j)
                var index = i + j
                var total = (
                    UInt128(work_pointer.unsafe_load(index))
                    + UInt128(multiplier) * UInt128(modulus_word)
                    + UInt128(carry)
                )
                work_pointer.unsafe_store(index, UInt64(total))
                carry = UInt64(total >> 64)
            var index = i + word_count
            while carry != 0:
                var total = UInt128(work_pointer.unsafe_load(index)) + UInt128(
                    carry
                )
                work_pointer.unsafe_store(index, UInt64(total))
                carry = UInt64(total >> 64)
                index += 1
        var reduce = work_pointer.unsafe_load(2 * word_count) != 0
        if not reduce:
            for i in range(word_count - 1, -1, -1):
                var modulus_word = modulus_pointer.unsafe_load(i)
                var value = work_pointer.unsafe_load(word_count + i)
                if value > modulus_word:
                    reduce = True
                    break
                if value < modulus_word:
                    break
                if i == 0:
                    reduce = True
        if reduce:
            var borrow = UInt64(0)
            for i in range(word_count):
                var modulus_word = modulus_pointer.unsafe_load(i)
                var index = word_count + i
                var left = UInt128(work_pointer.unsafe_load(index))
                var right = UInt128(modulus_word) + UInt128(borrow)
                if left < right:
                    work_pointer.unsafe_store(
                        index, UInt64((UInt128(1) << 64) + left - right)
                    )
                    borrow = 1
                else:
                    work_pointer.unsafe_store(index, UInt64(left - right))
                    borrow = 0
        for i in range(word_count):
            var word = work_pointer.unsafe_load(word_count + i)
            output_pointer.unsafe_store(2 * i, UInt32(word))
            output_pointer.unsafe_store(2 * i + 1, UInt32(word >> 32))

    @always_inline("nodebug")
    def _swap_storage(mut self, mut other: Self):
        var storage = self.limbs^
        self.limbs = other.limbs^
        other.limbs = storage^

    def _to_montgomery(self, modulus: Self, limb_count: Int) raises -> Self:
        var reduced = self.copy() if self.compare(modulus) < 0 else self.modulo(
            modulus
        )
        var source = reduced.copy()
        var complement = modulus.subtract(reduced)
        var negate = complement.compare(reduced) < 0
        if negate:
            source = complement^
        var shifted = List[UInt32](
            length=len(source.limbs) + limb_count, fill=0
        )
        for i in range(len(source.limbs)):
            shifted[i + limb_count] = source.limbs[i]
        var encoded = BigUInt.from_limbs(Span(shifted)).modulo(modulus)
        if negate and not encoded.is_zero():
            return modulus.subtract(encoded)
        return encoded^

    @always_inline("nodebug")
    def _reduced_subtract_into(
        self,
        other: Self,
        modulus: Self,
        mut output: Self,
        limb_count: Int,
    ):
        """Write `(self - other) mod modulus` without allocating storage."""
        var borrow = UInt64(0)
        var order = 0
        for i in range(limb_count - 1, -1, -1):
            var left = UInt32(0)
            var right = UInt32(0)
            if i < len(self.limbs):
                left = self.limbs[i]
            if i < len(other.limbs):
                right = other.limbs[i]
            if left != right and order == 0:
                order = 1 if left > right else -1
        if order >= 0:
            for i in range(limb_count):
                var left = UInt64(0)
                var right = borrow
                if i < len(self.limbs):
                    left = UInt64(self.limbs[i])
                if i < len(other.limbs):
                    right += UInt64(other.limbs[i])
                if left < right:
                    output.limbs[i] = UInt32((UInt64(1) << 32) + left - right)
                    borrow = 1
                else:
                    output.limbs[i] = UInt32(left - right)
                    borrow = 0
            return
        for i in range(limb_count):
            var left = UInt64(0)
            var right = borrow
            if i < len(other.limbs):
                left = UInt64(other.limbs[i])
            if i < len(self.limbs):
                right += UInt64(self.limbs[i])
            if left < right:
                output.limbs[i] = UInt32((UInt64(1) << 32) + left - right)
                borrow = 1
            else:
                output.limbs[i] = UInt32(left - right)
                borrow = 0
        borrow = 0
        for i in range(limb_count):
            var left = UInt64(0)
            if i < len(modulus.limbs):
                left = UInt64(modulus.limbs[i])
            var right = UInt64(output.limbs[i]) + borrow
            if left < right:
                output.limbs[i] = UInt32((UInt64(1) << 32) + left - right)
                borrow = 1
            else:
                output.limbs[i] = UInt32(left - right)
                borrow = 0

    @always_inline("nodebug")
    def _reduced_add_into(
        self,
        other: Self,
        modulus: Self,
        mut output: Self,
        limb_count: Int,
    ):
        """Write `(self + other) mod modulus` without allocating storage."""
        var carry = UInt64(0)
        for i in range(limb_count):
            var total = carry
            if i < len(self.limbs):
                total += UInt64(self.limbs[i])
            if i < len(other.limbs):
                total += UInt64(other.limbs[i])
            output.limbs[i] = UInt32(total)
            carry = total >> 32
        var reduce = carry != 0
        if not reduce:
            for i in range(limb_count - 1, -1, -1):
                var modulus_limb = modulus.limbs[i] if i < len(
                    modulus.limbs
                ) else UInt32(0)
                if output.limbs[i] > modulus_limb:
                    reduce = True
                    break
                if output.limbs[i] < modulus_limb:
                    break
                if i == 0:
                    reduce = True
        if reduce:
            var borrow = UInt64(0)
            for i in range(limb_count):
                var left = UInt64(output.limbs[i])
                var right = borrow
                if i < len(modulus.limbs):
                    right += UInt64(modulus.limbs[i])
                if left < right:
                    output.limbs[i] = UInt32((UInt64(1) << 32) + left - right)
                    borrow = 1
                else:
                    output.limbs[i] = UInt32(left - right)
                    borrow = 0

    def modular_lucas(self, exponent: Self, modulus: Self) raises -> Self:
        """Return the Lucas V value using one reusable Montgomery context."""
        if modulus.compare(BigUInt(2)) <= 0 or modulus.bit(0) == 0:
            raise Error(
                "Lucas Montgomery modulus must be odd and greater than two"
            )
        if exponent.is_zero():
            return BigUInt(2).modulo(modulus)
        var modulus_low = UInt64(modulus.limbs[0])
        if len(modulus.limbs) > 1:
            modulus_low |= UInt64(modulus.limbs[1]) << 32
        var inverse = UInt64(1)
        for _ in range(6):
            inverse *= UInt64(2) - modulus_low * inverse
        var negated_inverse = ~inverse + UInt64(1)
        var word_count = (len(modulus.limbs) + 1) // 2
        var modulus_words = List[UInt64](unsafe_uninit_length=word_count)
        for i in range(word_count):
            modulus_words[i] = UInt64(modulus.limbs[2 * i])
            if 2 * i + 1 < len(modulus.limbs):
                modulus_words[i] |= UInt64(modulus.limbs[2 * i + 1]) << 32
        var right_words = List[UInt64](unsafe_uninit_length=word_count)
        var storage_limb_count = 2 * word_count
        var parameter = self._to_montgomery(modulus, storage_limb_count)
        var one = BigUInt(1)
        var two = BigUInt(2)
        var two_montgomery = two._to_montgomery(modulus, storage_limb_count)
        var first = parameter.copy()
        while len(first.limbs) < storage_limb_count:
            first.limbs.append(0)
        var second = BigUInt()
        second.limbs = List[UInt32](unsafe_uninit_length=storage_limb_count)
        var first_product = BigUInt()
        first_product.limbs = List[UInt32](
            unsafe_uninit_length=storage_limb_count
        )
        var second_product = BigUInt()
        second_product.limbs = List[UInt32](
            unsafe_uninit_length=storage_limb_count
        )
        var work = List[UInt64](unsafe_uninit_length=2 * word_count + 2)
        parameter._montgomery_square_into(
            modulus,
            modulus_words,
            negated_inverse,
            word_count,
            first_product,
            work,
            right_words,
        )
        first_product._reduced_subtract_into(
            two_montgomery, modulus, second, storage_limb_count
        )
        for bit in range(exponent.bit_length() - 2, -1, -1):
            first._montgomery_multiply_into(
                second,
                modulus,
                modulus_words,
                negated_inverse,
                word_count,
                first_product,
                work,
                right_words,
            )
            if exponent.bit(bit) != 0:
                second._montgomery_square_into(
                    modulus,
                    modulus_words,
                    negated_inverse,
                    word_count,
                    second_product,
                    work,
                    right_words,
                )
            else:
                first._montgomery_square_into(
                    modulus,
                    modulus_words,
                    negated_inverse,
                    word_count,
                    second_product,
                    work,
                    right_words,
                )
            if exponent.bit(bit) != 0:
                first_product._reduced_subtract_into(
                    parameter, modulus, first, storage_limb_count
                )
                second_product._reduced_subtract_into(
                    two_montgomery, modulus, second, storage_limb_count
                )
            else:
                first_product._reduced_subtract_into(
                    parameter, modulus, second, storage_limb_count
                )
                second_product._reduced_subtract_into(
                    two_montgomery, modulus, first, storage_limb_count
                )
        var output = BigUInt()
        output.limbs = List[UInt32](unsafe_uninit_length=storage_limb_count)
        first._montgomery_multiply_into(
            one,
            modulus,
            modulus_words,
            negated_inverse,
            word_count,
            output,
            work,
            right_words,
        )
        output._normalize()
        return output^

    def modular_power(self, exponent: Self, modulus: Self) raises -> Self:
        if modulus.is_zero():
            raise Error("modulo by zero")
        if len(modulus.limbs) == 1 and modulus.limbs[0] == 1:
            return BigUInt()
        if modulus.bit(0) == 0:
            var result = BigUInt(1)
            var factor = self.modulo(modulus)
            for i in range(exponent.bit_length()):
                if exponent.bit(i) != 0:
                    result = result.modular_multiply(factor, modulus)
                factor = factor.modular_multiply(factor, modulus)
            return result^
        var modulus_low = UInt64(modulus.limbs[0])
        if len(modulus.limbs) > 1:
            modulus_low |= UInt64(modulus.limbs[1]) << 32
        var inverse = UInt64(1)
        for _ in range(6):
            inverse *= UInt64(2) - modulus_low * inverse
        var negated_inverse = ~inverse + UInt64(1)
        var word_count = (len(modulus.limbs) + 1) // 2
        var modulus_words = List[UInt64](unsafe_uninit_length=word_count)
        for i in range(word_count):
            modulus_words[i] = UInt64(modulus.limbs[2 * i])
            if 2 * i + 1 < len(modulus.limbs):
                modulus_words[i] |= UInt64(modulus.limbs[2 * i + 1]) << 32
        var right_words = List[UInt64](unsafe_uninit_length=word_count)
        var storage_limb_count = 2 * word_count
        var factor = self._to_montgomery(modulus, storage_limb_count)
        var one = BigUInt(1)
        var result = one._to_montgomery(modulus, storage_limb_count)
        while len(result.limbs) < storage_limb_count:
            result.limbs.append(0)
        var work = List[UInt64](unsafe_uninit_length=2 * word_count + 2)
        var scratch = BigUInt()
        scratch.limbs = List[UInt32](unsafe_uninit_length=storage_limb_count)
        var exponent_bits = exponent.bit_length()
        var set_bits = 0
        for bit in range(exponent_bits):
            set_bits += Int(exponent.bit(bit))
        var window_bits = 4 if exponent_bits <= 384 else (
            5 if exponent_bits <= 1536 else 6
        )
        var table_entries = 1 << (window_bits - 1)
        var sliding_products = table_entries + (
            exponent_bits + window_bits
        ) // (window_bits + 1)
        if set_bits < sliding_products:
            for bit in range(exponent_bits - 1, -1, -1):
                result._montgomery_multiply_into(
                    result,
                    modulus,
                    modulus_words,
                    negated_inverse,
                    word_count,
                    scratch,
                    work,
                    right_words,
                )
                result._swap_storage(scratch)
                if exponent.bit(bit) != 0:
                    result._montgomery_multiply_into(
                        factor,
                        modulus,
                        modulus_words,
                        negated_inverse,
                        word_count,
                        scratch,
                        work,
                        right_words,
                    )
                    result._swap_storage(scratch)
            result._montgomery_multiply_into(
                one,
                modulus,
                modulus_words,
                negated_inverse,
                word_count,
                scratch,
                work,
                right_words,
            )
            scratch._normalize()
            return scratch^
        var factor_squared = BigUInt()
        factor_squared.limbs = List[UInt32](
            unsafe_uninit_length=storage_limb_count
        )
        factor._montgomery_multiply_into(
            factor,
            modulus,
            modulus_words,
            negated_inverse,
            word_count,
            factor_squared,
            work,
            right_words,
        )
        var odd_powers = List[BigUInt](capacity=table_entries)
        odd_powers.append(factor.copy())
        for index in range(1, table_entries):
            var entry = BigUInt()
            entry.limbs = List[UInt32](unsafe_uninit_length=storage_limb_count)
            odd_powers[index - 1]._montgomery_multiply_into(
                factor_squared,
                modulus,
                modulus_words,
                negated_inverse,
                word_count,
                entry,
                work,
                right_words,
            )
            odd_powers.append(entry^)
        var top_bit = exponent_bits - 1
        while top_bit >= 0:
            if exponent.bit(top_bit) == 0:
                result._montgomery_multiply_into(
                    result,
                    modulus,
                    modulus_words,
                    negated_inverse,
                    word_count,
                    scratch,
                    work,
                    right_words,
                )
                result._swap_storage(scratch)
                top_bit -= 1
                continue
            var low_bit = max(0, top_bit - window_bits + 1)
            while exponent.bit(low_bit) == 0:
                low_bit += 1
            var digit = 0
            for bit in range(low_bit, top_bit + 1):
                digit |= Int(exponent.bit(bit)) << (bit - low_bit)
            for _ in range(top_bit - low_bit + 1):
                result._montgomery_multiply_into(
                    result,
                    modulus,
                    modulus_words,
                    negated_inverse,
                    word_count,
                    scratch,
                    work,
                    right_words,
                )
                result._swap_storage(scratch)
            result._montgomery_multiply_into(
                odd_powers[digit // 2],
                modulus,
                modulus_words,
                negated_inverse,
                word_count,
                scratch,
                work,
                right_words,
            )
            result._swap_storage(scratch)
            top_bit = low_bit - 1
        result._montgomery_multiply_into(
            one,
            modulus,
            modulus_words,
            negated_inverse,
            word_count,
            scratch,
            work,
            right_words,
        )
        scratch._normalize()
        return scratch^

    def modular_add(self, other: Self, modulus: Self) raises -> Self:
        return self.modulo(modulus).add(other.modulo(modulus)).modulo(modulus)

    def modular_subtract(self, other: Self, modulus: Self) raises -> Self:
        var left = self.modulo(modulus)
        var right = other.modulo(modulus)
        if left.compare(right) >= 0:
            return left.subtract(right)
        return modulus.subtract(right.subtract(left))

    def jacobi_symbol(self, odd_modulus: Self) raises -> Int:
        """Return the Jacobi symbol `(self / odd_modulus)`."""
        if odd_modulus.is_zero() or odd_modulus.bit(0) == 0:
            raise Error("Jacobi modulus must be positive and odd")
        var a = self.modulo(odd_modulus)
        var n = odd_modulus.copy()
        var sign = 1
        while not a.is_zero():
            while a.bit(0) == 0:
                a.shift_right_one()
                var n8 = n.limbs[0] & UInt32(7)
                if n8 == 3 or n8 == 5:
                    sign = -sign
            var swap = a^
            a = n^
            n = swap^
            if (a.limbs[0] & UInt32(3)) == 3 and (n.limbs[0] & UInt32(3)) == 3:
                sign = -sign
            a = a.modulo(n)
        return sign if n.compare(BigUInt(1)) == 0 else 0

    def modular_inverse(self, modulus: Self) raises -> Self:
        """Inverse modulo an odd modulus using binary extended GCD."""
        var one = BigUInt(1)
        if modulus.compare(one) <= 0 or modulus.bit(0) == 0:
            raise Error("inverse requires an odd modulus greater than one")
        var u = self.modulo(modulus)
        if u.is_zero():
            raise Error("zero has no multiplicative inverse")
        var v = modulus.copy()
        var x1 = one.copy()
        var x2 = BigUInt()
        while u.compare(one) != 0 and v.compare(one) != 0:
            if u.is_zero() or v.is_zero():
                raise Error("integer has no multiplicative inverse")
            while u.bit(0) == 0:
                u.shift_right_one()
                if x1.bit(0) == 0:
                    x1.shift_right_one()
                else:
                    x1 = x1.add(modulus)
                    x1.shift_right_one()
            while v.bit(0) == 0:
                v.shift_right_one()
                if x2.bit(0) == 0:
                    x2.shift_right_one()
                else:
                    x2 = x2.add(modulus)
                    x2.shift_right_one()
            if u.compare(v) >= 0:
                u = u.subtract(v)
                if x1.compare(x2) >= 0:
                    x1 = x1.subtract(x2)
                else:
                    x1 = modulus.subtract(x2.subtract(x1))
            else:
                v = v.subtract(u)
                if x2.compare(x1) >= 0:
                    x2 = x2.subtract(x1)
                else:
                    x2 = modulus.subtract(x1.subtract(x2))
        if u.compare(one) == 0:
            return x1^
        if v.compare(one) == 0:
            return x2^
        raise Error("integer has no multiplicative inverse")

    def to_hex(self) -> String:
        var result = String()
        for i in range(len(self.limbs) - 1, -1, -1):
            for shift in range(28, -1, -4):
                var digit = UInt8((self.limbs[i] >> UInt32(shift)) & 0xF)
                if result.byte_length() != 0 or digit != 0:
                    var code = Int(digit) + (48 if digit < 10 else 87)
                    result += String(chr(code))
        if result.byte_length() == 0:
            return "0"
        return result^


struct _MontgomeryContext(Movable):
    """Reusable odd-modulus Montgomery arithmetic with shared scratch storage.
    """

    var modulus: BigUInt
    var modulus_words: List[UInt64]
    var negated_inverse: UInt64
    var word_count: Int
    var limb_count: Int
    var work: List[UInt64]
    var r2: BigUInt
    var right_words: List[UInt64]

    def __init__(out self, modulus: BigUInt) raises:
        if modulus.compare(BigUInt(2)) <= 0 or modulus.bit(0) == 0:
            raise Error("Montgomery modulus must be odd and greater than two")
        self.modulus = modulus.copy()
        self.word_count = (len(modulus.limbs) + 1) // 2
        self.limb_count = 2 * self.word_count
        self.modulus_words = List[UInt64](unsafe_uninit_length=self.word_count)
        for i in range(self.word_count):
            self.modulus_words[i] = UInt64(modulus.limbs[2 * i])
            if 2 * i + 1 < len(modulus.limbs):
                self.modulus_words[i] |= UInt64(modulus.limbs[2 * i + 1]) << 32
        var inverse = UInt64(1)
        for _ in range(6):
            inverse *= UInt64(2) - self.modulus_words[0] * inverse
        self.negated_inverse = ~inverse + UInt64(1)
        self.work = List[UInt64](unsafe_uninit_length=2 * self.word_count + 2)
        self.right_words = List[UInt64](unsafe_uninit_length=self.word_count)
        self.r2 = BigUInt(1)._to_montgomery(self.modulus, 2 * self.limb_count)
        while len(self.r2.limbs) < self.limb_count:
            self.r2.limbs.append(0)

    def __init__(out self, *, fork: Self):
        self.modulus = fork.modulus.copy()
        self.modulus_words = fork.modulus_words.copy()
        self.negated_inverse = fork.negated_inverse
        self.word_count = fork.word_count
        self.limb_count = fork.limb_count
        self.work = List[UInt64](unsafe_uninit_length=2 * self.word_count + 2)
        self.right_words = List[UInt64](unsafe_uninit_length=self.word_count)
        self.r2 = fork.r2.copy()

    def __init__(out self, *, deinit move: Self):
        self.modulus = move.modulus^
        self.modulus_words = move.modulus_words^
        self.negated_inverse = move.negated_inverse
        self.word_count = move.word_count
        self.limb_count = move.limb_count
        self.work = move.work^
        self.right_words = move.right_words^
        self.r2 = move.r2^

    def encode(mut self, value: BigUInt) raises -> BigUInt:
        var reduced = value.copy() if value.compare(
            self.modulus
        ) < 0 else value.modulo(self.modulus)
        while len(reduced.limbs) < self.limb_count:
            reduced.limbs.append(0)
        var output = BigUInt()
        output.limbs = List[UInt32](unsafe_uninit_length=self.limb_count)
        var r2 = self.r2.copy()
        self.multiply_into(reduced, r2, output)
        return output^

    @always_inline("nodebug")
    def multiply_into(
        mut self, left: BigUInt, right: BigUInt, mut output: BigUInt
    ):
        """Write one Montgomery product into fixed-width caller storage."""
        left._montgomery_multiply_into(
            right,
            self.modulus,
            self.modulus_words,
            self.negated_inverse,
            self.word_count,
            output,
            self.work,
            self.right_words,
        )

    @always_inline("nodebug")
    def square_into(mut self, value: BigUInt, mut output: BigUInt):
        value._montgomery_square_into(
            self.modulus,
            self.modulus_words,
            self.negated_inverse,
            self.word_count,
            output,
            self.work,
            self.right_words,
        )

    def multiply(mut self, left: BigUInt, right: BigUInt) -> BigUInt:
        var output = BigUInt()
        output.limbs = List[UInt32](unsafe_uninit_length=self.limb_count)
        left._montgomery_multiply_into(
            right,
            self.modulus,
            self.modulus_words,
            self.negated_inverse,
            self.word_count,
            output,
            self.work,
            self.right_words,
        )
        output._normalize()
        return output^

    def decode(mut self, value: BigUInt) -> BigUInt:
        var output = self.multiply(value, BigUInt(1))
        return output^


struct FixedBaseModularPower(Movable):
    """Radix-32 table for repeated exponentiation of one modular base."""

    var context: _MontgomeryContext
    var table: List[BigUInt]
    var window_count: Int

    def __init__(
        out self,
        base: BigUInt,
        modulus: BigUInt,
        exponent_bits: Int,
    ) raises:
        if exponent_bits <= 0:
            raise Error("fixed-base exponent width must be positive")
        self.context = _MontgomeryContext(modulus)
        self.window_count = (exponent_bits + 4) // 5
        self.table = List[BigUInt](capacity=self.window_count * 32)
        var one = self.context.encode(BigUInt(1))
        var base_power = self.context.encode(base)
        while len(one.limbs) < self.context.limb_count:
            one.limbs.append(0)
        while len(base_power.limbs) < self.context.limb_count:
            base_power.limbs.append(0)
        for _ in range(self.window_count):
            self.table.append(one.copy())
            self.table.append(base_power.copy())
            var multiple = base_power.copy()
            for _ in range(2, 32):
                multiple = self.context.multiply(multiple, base_power)
                while len(multiple.limbs) < self.context.limb_count:
                    multiple.limbs.append(0)
                self.table.append(multiple.copy())
            for _ in range(5):
                base_power = self.context.multiply(base_power, base_power)
                while len(base_power.limbs) < self.context.limb_count:
                    base_power.limbs.append(0)

    def __init__(out self, *, deinit move: Self):
        self.context = move.context^
        self.table = move.table^
        self.window_count = move.window_count

    def power(self, exponent: BigUInt) raises -> BigUInt:
        if exponent.bit_length() > self.window_count * 5:
            raise Error("exponent exceeds fixed-base table width")
        var context = _MontgomeryContext(fork=self.context)
        var result = self.table[0].copy()
        var scratch = BigUInt()
        scratch.limbs = List[UInt32](unsafe_uninit_length=context.limb_count)
        for window in range(self.window_count):
            var digit = 0
            for bit in range(5):
                digit |= Int(exponent.bit(window * 5 + bit)) << bit
            if digit != 0:
                context.multiply_into(
                    result,
                    self.table[window * 32 + digit],
                    scratch,
                )
                result._swap_storage(scratch)
        return context.decode(result)


struct FixedExponentLucasPower(Movable):
    """Reusable variable-base Lucas power with allocation-free scratch."""

    var context: _MontgomeryContext
    var exponent_bits: List[UInt8]
    var two: BigUInt
    var first: BigUInt
    var second: BigUInt
    var first_product: BigUInt
    var second_product: BigUInt

    def __init__(out self, exponent: BigUInt, modulus: BigUInt) raises:
        if exponent.is_zero():
            raise Error("fixed Lucas exponent must be positive")
        self.context = _MontgomeryContext(modulus)
        self.exponent_bits = List[UInt8](
            capacity=max(0, exponent.bit_length() - 1)
        )
        for bit in range(exponent.bit_length() - 2, -1, -1):
            self.exponent_bits.append(
                UInt8(1) if exponent.bit(bit) != 0 else UInt8(0)
            )
        self.two = self.context.encode(BigUInt(2))
        self.first = _montgomery_scratch(self.context.limb_count)
        self.second = _montgomery_scratch(self.context.limb_count)
        self.first_product = _montgomery_scratch(self.context.limb_count)
        self.second_product = _montgomery_scratch(self.context.limb_count)

    def __init__(out self, *, deinit move: Self):
        self.context = move.context^
        self.exponent_bits = move.exponent_bits^
        self.two = move.two^
        self.first = move.first^
        self.second = move.second^
        self.first_product = move.first_product^
        self.second_product = move.second_product^

    def power(mut self, value: BigUInt) raises -> BigUInt:
        var parameter = self.context.encode(value)
        for i in range(self.context.limb_count):
            self.first.limbs[i] = parameter.limbs[i]
        self.context.square_into(parameter, self.first_product)
        self.first_product._reduced_subtract_into(
            self.two,
            self.context.modulus,
            self.second,
            self.context.limb_count,
        )
        for bit in self.exponent_bits:
            var exponent_bit = bit != 0
            self.context.multiply_into(
                self.first, self.second, self.first_product
            )
            if exponent_bit:
                self.context.square_into(self.second, self.second_product)
            else:
                self.context.square_into(self.first, self.second_product)
            if exponent_bit:
                self.first_product._reduced_subtract_into(
                    parameter,
                    self.context.modulus,
                    self.first,
                    self.context.limb_count,
                )
                self.second_product._reduced_subtract_into(
                    self.two,
                    self.context.modulus,
                    self.second,
                    self.context.limb_count,
                )
            else:
                self.first_product._reduced_subtract_into(
                    parameter,
                    self.context.modulus,
                    self.second,
                    self.context.limb_count,
                )
                self.second_product._reduced_subtract_into(
                    self.two,
                    self.context.modulus,
                    self.first,
                    self.context.limb_count,
                )
        return self.context.decode(self.first)


def _pad_montgomery(mut value: BigUInt, limb_count: Int):
    while len(value.limbs) < limb_count:
        value.limbs.append(0)


def _montgomery_scratch(limb_count: Int) -> BigUInt:
    var value = BigUInt()
    value.limbs = List[UInt32](unsafe_uninit_length=limb_count)
    return value^


def _compose_lucas_power_pair(
    mut context: _MontgomeryContext,
    coefficient: BigUInt,
    left_a: BigUInt,
    left_b: BigUInt,
    right_a: BigUInt,
    right_b: BigUInt,
) raises -> Tuple[BigUInt, BigUInt]:
    var p0 = context.multiply(left_a, right_a)
    var p1 = context.multiply(left_b, right_b)
    var left_sum = left_a.modular_add(left_b, context.modulus)
    var right_sum = right_a.modular_add(right_b, context.modulus)
    var p2 = context.multiply(left_sum, right_sum)
    var output_a = p0.modular_subtract(p1, context.modulus)
    var weighted = context.multiply(coefficient, p1)
    var output_b = p2.modular_subtract(p0, context.modulus).modular_add(
        weighted, context.modulus
    )
    _pad_montgomery(output_a, context.limb_count)
    _pad_montgomery(output_b, context.limb_count)
    return (output_a^, output_b^)


struct FixedBaseLucasPower(Movable):
    """Radix-32 table for repeated V_n(P,1) Lucas exponentiation."""

    var context: _MontgomeryContext
    var coefficient: BigUInt
    var parameter: BigUInt
    var table_a: List[BigUInt]
    var table_b: List[BigUInt]
    var window_count: Int
    var runtime_a: BigUInt
    var runtime_b: BigUInt
    var runtime_p0: BigUInt
    var runtime_p1: BigUInt
    var runtime_left_sum: BigUInt
    var runtime_right_sum: BigUInt
    var runtime_p2: BigUInt
    var runtime_new_a: BigUInt
    var runtime_weighted: BigUInt
    var runtime_temporary: BigUInt
    var runtime_new_b: BigUInt
    var runtime_trace: BigUInt

    def __init__(
        out self,
        parameter: BigUInt,
        modulus: BigUInt,
        exponent_bits: Int,
    ) raises:
        if exponent_bits <= 0:
            raise Error("fixed-base Lucas exponent width must be positive")
        self.context = _MontgomeryContext(modulus)
        self.window_count = (exponent_bits + 4) // 5
        self.table_a = List[BigUInt](capacity=self.window_count * 32)
        self.table_b = List[BigUInt](capacity=self.window_count * 32)
        self.parameter = self.context.encode(parameter)
        self.coefficient = self.context.encode(
            parameter.modular_subtract(BigUInt(1), modulus)
        )
        var one = self.context.encode(BigUInt(1))
        var zero = BigUInt()
        zero.limbs = List[UInt32](length=self.context.limb_count, fill=0)
        _pad_montgomery(self.parameter, self.context.limb_count)
        _pad_montgomery(self.coefficient, self.context.limb_count)
        _pad_montgomery(one, self.context.limb_count)
        var base_a = zero.copy()
        var base_b = one.copy()
        for _ in range(self.window_count):
            self.table_a.append(one.copy())
            self.table_b.append(zero.copy())
            self.table_a.append(base_a.copy())
            self.table_b.append(base_b.copy())
            var multiple_a = base_a.copy()
            var multiple_b = base_b.copy()
            for _ in range(2, 32):
                var multiple = _compose_lucas_power_pair(
                    self.context,
                    self.coefficient,
                    multiple_a,
                    multiple_b,
                    base_a,
                    base_b,
                )
                multiple_a = multiple[0].copy()
                multiple_b = multiple[1].copy()
                self.table_a.append(multiple_a.copy())
                self.table_b.append(multiple_b.copy())
            for _ in range(5):
                var squared = _compose_lucas_power_pair(
                    self.context,
                    self.coefficient,
                    base_a,
                    base_b,
                    base_a,
                    base_b,
                )
                base_a = squared[0].copy()
                base_b = squared[1].copy()
        self.runtime_a = _montgomery_scratch(self.context.limb_count)
        self.runtime_b = _montgomery_scratch(self.context.limb_count)
        self.runtime_p0 = _montgomery_scratch(self.context.limb_count)
        self.runtime_p1 = _montgomery_scratch(self.context.limb_count)
        self.runtime_left_sum = _montgomery_scratch(self.context.limb_count)
        self.runtime_right_sum = _montgomery_scratch(self.context.limb_count)
        self.runtime_p2 = _montgomery_scratch(self.context.limb_count)
        self.runtime_new_a = _montgomery_scratch(self.context.limb_count)
        self.runtime_weighted = _montgomery_scratch(self.context.limb_count)
        self.runtime_temporary = _montgomery_scratch(self.context.limb_count)
        self.runtime_new_b = _montgomery_scratch(self.context.limb_count)
        self.runtime_trace = _montgomery_scratch(self.context.limb_count)

    def __init__(out self, *, deinit move: Self):
        self.context = move.context^
        self.coefficient = move.coefficient^
        self.parameter = move.parameter^
        self.table_a = move.table_a^
        self.table_b = move.table_b^
        self.window_count = move.window_count
        self.runtime_a = move.runtime_a^
        self.runtime_b = move.runtime_b^
        self.runtime_p0 = move.runtime_p0^
        self.runtime_p1 = move.runtime_p1^
        self.runtime_left_sum = move.runtime_left_sum^
        self.runtime_right_sum = move.runtime_right_sum^
        self.runtime_p2 = move.runtime_p2^
        self.runtime_new_a = move.runtime_new_a^
        self.runtime_weighted = move.runtime_weighted^
        self.runtime_temporary = move.runtime_temporary^
        self.runtime_new_b = move.runtime_new_b^
        self.runtime_trace = move.runtime_trace^

    def power(self, exponent: BigUInt) raises -> BigUInt:
        if exponent.bit_length() > self.window_count * 5:
            raise Error("exponent exceeds fixed-base Lucas table width")
        var context = _MontgomeryContext(fork=self.context)
        var a = self.table_a[0].copy()
        var b = self.table_b[0].copy()
        var p0 = _montgomery_scratch(context.limb_count)
        var p1 = _montgomery_scratch(context.limb_count)
        var left_sum = _montgomery_scratch(context.limb_count)
        var right_sum = _montgomery_scratch(context.limb_count)
        var p2 = _montgomery_scratch(context.limb_count)
        var new_a = _montgomery_scratch(context.limb_count)
        var weighted = _montgomery_scratch(context.limb_count)
        var temporary = _montgomery_scratch(context.limb_count)
        var new_b = _montgomery_scratch(context.limb_count)
        var trace = _montgomery_scratch(context.limb_count)
        for window in range(self.window_count):
            var digit = 0
            for bit in range(5):
                digit |= Int(exponent.bit(window * 5 + bit)) << bit
            if digit == 0:
                continue
            var index = window * 32 + digit
            context.multiply_into(a, self.table_a[index], p0)
            context.multiply_into(b, self.table_b[index], p1)
            a._reduced_add_into(
                b, context.modulus, left_sum, context.limb_count
            )
            self.table_a[index]._reduced_add_into(
                self.table_b[index],
                context.modulus,
                right_sum,
                context.limb_count,
            )
            context.multiply_into(left_sum, right_sum, p2)
            p0._reduced_subtract_into(
                p1, context.modulus, new_a, context.limb_count
            )
            context.multiply_into(self.coefficient, p1, weighted)
            p2._reduced_subtract_into(
                p0, context.modulus, temporary, context.limb_count
            )
            temporary._reduced_add_into(
                weighted, context.modulus, new_b, context.limb_count
            )
            a._swap_storage(new_a)
            b._swap_storage(new_b)
        context.multiply_into(self.parameter, b, p0)
        a._reduced_add_into(a, context.modulus, p1, context.limb_count)
        p1._reduced_add_into(p0, context.modulus, trace, context.limb_count)
        return context.decode(trace)

    def power_reusing(mut self, exponent: BigUInt) raises -> BigUInt:
        if exponent.bit_length() > self.window_count * 5:
            raise Error("exponent exceeds fixed-base Lucas table width")
        for i in range(self.context.limb_count):
            self.runtime_a.limbs[i] = self.table_a[0].limbs[i]
            self.runtime_b.limbs[i] = self.table_b[0].limbs[i]
        for window in range(self.window_count):
            var digit = 0
            for bit in range(5):
                digit |= Int(exponent.bit(window * 5 + bit)) << bit
            if digit == 0:
                continue
            var index = window * 32 + digit
            self.context.multiply_into(
                self.runtime_a, self.table_a[index], self.runtime_p0
            )
            self.context.multiply_into(
                self.runtime_b, self.table_b[index], self.runtime_p1
            )
            self.runtime_a._reduced_add_into(
                self.runtime_b,
                self.context.modulus,
                self.runtime_left_sum,
                self.context.limb_count,
            )
            self.table_a[index]._reduced_add_into(
                self.table_b[index],
                self.context.modulus,
                self.runtime_right_sum,
                self.context.limb_count,
            )
            self.context.multiply_into(
                self.runtime_left_sum,
                self.runtime_right_sum,
                self.runtime_p2,
            )
            self.runtime_p0._reduced_subtract_into(
                self.runtime_p1,
                self.context.modulus,
                self.runtime_new_a,
                self.context.limb_count,
            )
            self.context.multiply_into(
                self.coefficient,
                self.runtime_p1,
                self.runtime_weighted,
            )
            self.runtime_p2._reduced_subtract_into(
                self.runtime_p0,
                self.context.modulus,
                self.runtime_temporary,
                self.context.limb_count,
            )
            self.runtime_temporary._reduced_add_into(
                self.runtime_weighted,
                self.context.modulus,
                self.runtime_new_b,
                self.context.limb_count,
            )
            self.runtime_a._swap_storage(self.runtime_new_a)
            self.runtime_b._swap_storage(self.runtime_new_b)
        self.context.multiply_into(
            self.parameter, self.runtime_b, self.runtime_p0
        )
        self.runtime_a._reduced_add_into(
            self.runtime_a,
            self.context.modulus,
            self.runtime_p1,
            self.context.limb_count,
        )
        self.runtime_p1._reduced_add_into(
            self.runtime_p0,
            self.context.modulus,
            self.runtime_trace,
            self.context.limb_count,
        )
        return self.context.decode(self.runtime_trace)
