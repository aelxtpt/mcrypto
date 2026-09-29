"""Secure-memory primitives with observable wiping and page locking.

`secure_zero` uses volatile stores so the overwrite cannot be removed.
`LockedSecretBytes` locks its owned allocation, wipes before unlocking, and
reports lock failures rather than silently degrading.
"""
from std.ffi import external_call
from std.sys import CompilationTarget

from .internal.secret import SecretBytes, secure_zero
from .traits import constant_time_equal




def page_locking_available() -> Bool:
    return True




@fieldwise_init
struct _LockRegion(ImplicitlyCopyable):
    var address: Int
    var length: UInt


def _lock_region[
    origin: MutOrigin
](data: Span[mut=True, UInt8, origin]) raises -> _LockRegion:
    var address = Int(data.unsafe_ptr())
    comptime if CompilationTarget.is_linux():
        return _LockRegion(address, UInt(len(data)))
    elif CompilationTarget.is_macos():
        var page_size = Int(external_call["getpagesize", Int32]())
        if page_size <= 0:
            raise Error("getpagesize failed")
        var aligned = address - address % page_size
        var prefix = UInt(address - aligned)
        var length = prefix + UInt(len(data))
        if length < prefix:
            raise Error("page-lock length overflow")
        return _LockRegion(aligned, length)
    else:
        CompilationTarget.unsupported_target_error[operation="page locking"]()


def _lock(region: _LockRegion) raises:
    var pointer = Pointer[mut=True, UInt8, MutUnsafeAnyOrigin](
        unsafe_from_address=region.address
    )
    if external_call["mlock", Int32](pointer, region.length) != 0:
        raise Error("mlock failed; check RLIMIT_MEMLOCK")


def _unlock(region: _LockRegion) raises:
    var pointer = Pointer[mut=True, UInt8, MutUnsafeAnyOrigin](
        unsafe_from_address=region.address
    )
    if external_call["munlock", Int32](pointer, region.length) != 0:
        raise Error("munlock failed")


def lock_memory[origin: MutOrigin](data: Span[mut=True, UInt8, origin]) raises:
    if len(data) == 0:
        return
    _lock(_lock_region(data))


def unlock_memory[
    origin: MutOrigin
](data: Span[mut=True, UInt8, origin]) raises:
    secure_zero(data)
    if len(data) == 0:
        return
    _unlock(_lock_region(data))


struct LockedSecretBytes(Movable, Sized):
    """Owned bytes whose allocation remains page-locked for its lifetime."""

    var _bytes: List[UInt8]
    var _locked: Bool
    var _lock_address: Int
    var _lock_length: UInt

    def __init__(out self, length: Int) raises:
        if length < 0:
            raise Error("secret length cannot be negative")
        self._bytes = List[UInt8](length=length, fill=0)
        self._locked = False
        self._lock_address = 0
        self._lock_length = 0
        if length != 0:
            var region = _lock_region(Span(self._bytes))
            _lock(region)
            self._lock_address = region.address
            self._lock_length = region.length
            self._locked = True

    def __init__[origin: Origin](out self, data: Span[UInt8, origin]) raises:
        self._bytes = List[UInt8](capacity=len(data))
        self._locked = False
        self._lock_address = 0
        self._lock_length = 0
        for byte in data:
            self._bytes.append(byte)
        if len(data) != 0:
            var region = _lock_region(Span(self._bytes))
            _lock(region)
            self._lock_address = region.address
            self._lock_length = region.length
            self._locked = True

    def __init__(out self, *, deinit move: Self):
        self._bytes = move._bytes^
        self._locked = move._locked
        self._lock_address = move._lock_address
        self._lock_length = move._lock_length

    def __deinit__(deinit self):
        secure_zero(Span(self._bytes))
        if self._locked and self._lock_length != 0:
            var pointer = Pointer[mut=True, UInt8, MutUnsafeAnyOrigin](
                unsafe_from_address=self._lock_address
            )
            _ = external_call["munlock", Int32](pointer, self._lock_length)

    def __len__(self) -> Int:
        return len(self._bytes)

    def span(ref self) -> Span[UInt8, origin_of(self._bytes)]:
        return Span(self._bytes)

    def mut_span(
        mut self,
    ) -> Span[mut=True, UInt8, origin_of(self._bytes)]:
        return Span(self._bytes)

    def clear(mut self):
        secure_zero(Span(self._bytes))

    def expose_copy(self) -> List[UInt8]:
        """Explicitly copy the secret into ordinary, pageable memory."""
        return self._bytes.copy()
