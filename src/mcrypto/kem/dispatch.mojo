"""Pure-Mojo ML-KEM-512/768 and X-Wing KEM interface."""

from .algorithm import KemAlgorithm
from . import mlkem512, mlkem768, xwing


def _sizes(algorithm: KemAlgorithm) raises -> Tuple[Int, Int, Int, Int]:
    if algorithm == KemAlgorithm.ML_KEM_512:
        return (
            mlkem512.PUBLIC_KEY_BYTES,
            mlkem512.SECRET_KEY_BYTES,
            mlkem512.CIPHERTEXT_BYTES,
            mlkem512.SHARED_SECRET_BYTES,
        )
    if algorithm == KemAlgorithm.ML_KEM_768:
        return (
            mlkem768.PUBLIC_KEY_BYTES,
            mlkem768.SECRET_KEY_BYTES,
            mlkem768.CIPHERTEXT_BYTES,
            mlkem768.SHARED_SECRET_BYTES,
        )
    if algorithm == KemAlgorithm.X_WING:
        return (
            xwing.PUBLIC_KEY_BYTES,
            xwing.SECRET_KEY_BYTES,
            xwing.CIPHERTEXT_BYTES,
            xwing.SHARED_SECRET_BYTES,
        )
    raise Error("invalid KEM selector")


def keypair(
    algorithm: KemAlgorithm,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    _ = _sizes(algorithm)
    if algorithm == KemAlgorithm.ML_KEM_768:
        return mlkem768.keypair()
    if algorithm == KemAlgorithm.ML_KEM_512:
        return mlkem512.keypair()
    return xwing.keypair()


def encapsulate[
    origin: Origin
](algorithm: KemAlgorithm, public_key: Span[UInt8, origin]) raises -> Tuple[
    List[UInt8], List[UInt8]
]:
    _ = _sizes(algorithm)
    if algorithm == KemAlgorithm.ML_KEM_768:
        return mlkem768.encapsulate(public_key)
    if algorithm == KemAlgorithm.ML_KEM_512:
        return mlkem512.encapsulate(public_key)
    return xwing.encapsulate(public_key)


def decapsulate[
    cipher_origin: Origin, key_origin: Origin
](
    algorithm: KemAlgorithm,
    ciphertext: Span[UInt8, cipher_origin],
    secret_key: Span[UInt8, key_origin],
) raises -> List[UInt8]:
    _ = _sizes(algorithm)
    if algorithm == KemAlgorithm.ML_KEM_768:
        return mlkem768.decapsulate(ciphertext, secret_key)
    if algorithm == KemAlgorithm.ML_KEM_512:
        return mlkem512.decapsulate(ciphertext, secret_key)
    return xwing.decapsulate(ciphertext, secret_key)
