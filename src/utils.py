from hashlib import sha256

__all__ = [
    "randbytes",
    "set_seed",
    "sha256",
    "hexdigest",
    "hexdigest_in_bytes",
    "bytes_xor"
]

try:
    from random import randbytes  # Python 3.9 and later
    from random import seed as set_seed
except ImportError:
    from random import Random

    class _Random(Random):

        def randbytes(self, n: int) -> bytes:
            return self.getrandbits(n * 8).to_bytes(n, "little")

    _inst = _Random()
    randbytes = _inst.randbytes
    set_seed = _inst.seed


def hexdigest(bytes_: bytes) -> str:
    return sha256(bytes_).hexdigest()


def hexdigest_in_bytes(bytes_: bytes) -> bytes:
    return sha256(bytes_).hexdigest().encode("utf-8")


def bytes_xor(x: bytes, y: bytes, length: int) -> bytes:
    """
    len(x) and len(y) should always be equal to 'length'.

    For performance concern, this function assumes that
    all arguments are valid.

    Please pass arguments carefully.
    """
    int_ = int.from_bytes(x, "big") ^ int.from_bytes(y, "big")
    return int_.to_bytes(length, "big")
