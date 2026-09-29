"""Owned byte storage that is overwritten with volatile stores before release."""


@no_inline
def secure_zero[origin: MutOrigin](data: Span[mut=True, UInt8, origin]):
    """Overwrite a mutable span using stores that cannot be optimized away."""
    var pointer = data.unsafe_ptr()
    for i in range(len(data)):
        pointer.unsafe_store[volatile=True](i, UInt8(0))


struct SecretBytes(Movable, Sized):
    var _bytes: List[UInt8]

    def __init__(out self, length: Int) raises:
        if length < 0:
            raise Error("secret length cannot be negative")
        self._bytes = List[UInt8](length=length, fill=0)

    def __init__[origin: Origin](out self, data: Span[UInt8, origin]):
        self._bytes = List[UInt8](capacity=len(data))
        for byte in data:
            self._bytes.append(byte)

    def __init__(out self, *, deinit move: Self):
        self._bytes = move._bytes^

    def __deinit__(deinit self):
        secure_zero(Span(self._bytes))

    def __len__(self) -> Int:
        return len(self._bytes)

    def span(ref self) -> Span[UInt8, origin_of(self._bytes)]:
        return Span(self._bytes)

    def mut_span(mut self) -> Span[mut=True, UInt8, origin_of(self._bytes)]:
        return Span(self._bytes)

    def clear(mut self):
        """Observably overwrite the allocation while retaining it for reuse."""
        secure_zero(Span(self._bytes))

    def expose_copy(self) -> List[UInt8]:
        return self._bytes.copy()
