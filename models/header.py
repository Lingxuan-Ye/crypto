from base64 import b64decode, b64encode
from pathlib import Path
from typing import Any, NamedTuple, Optional

from ..utils import hexdigest_in_bytes


class HeaderInfo(NamedTuple):

    is_valid: bool
    format: Optional[str] = None
    version: Optional[int] = None
    does_match: Optional[bool] = None
    path_in_bytes: Optional[bytes] = None


class Header:
    r"""
    Header Example
    --------------
    | format | version |  password_hash  | base64_path | newline |
    ├--------|---------|-----------------|-------------|---------┤
    | b'CRY' |  b'0'   |  b'ABC012...'   |   b'Zm9v'   |  b'\n'  |


    Components
    ----------
    format:
        Specify the format of encrypted file.

    version:
        Version of format.

    password_hash:
        Save utf-8 encoded HEXADECIMAL (in order not to break the header line)
        digest of the password for verification.

    base64_path:
        Save base64 encoded file path (in plaintext or ciphertext) for
        directory reconstruction.

    Note that each component is seperated by b'\t'.
    """
    def __setattr__(self, __name: str, __value: Any) -> None:
        has_error = True
        if __name == "format":
            if isinstance(__value, bytes):
                __value = __value.decode("utf-8")
            if isinstance(__value, str):
                if __value.isascii() and __value.isalpha():
                    has_error = False
        elif __name == "version":
            if not isinstance(__value, int):
                try:
                    __value = int(__value)
                except:
                    pass
            if isinstance(__value, int):
                has_error = False
        elif __name == "password":
            if isinstance(__value, bytes):
                __value = __value.decode("utf-8")
            if isinstance(__value, str):
                has_error = False
        elif __name == "path_in_bytes":
            if isinstance(__value, str):
                __value = __value.encode("utf-8")
            elif isinstance(__value, Path):
                __value = bytes(__value)
            if isinstance(__value, bytes):
                has_error = False
        if has_error:
            raise AttributeError("invalid value to assign")
        return super().__setattr__(__name, __value)

    def __init__(
        self,
        format: str,
        version: int,
        password: str,
        path_in_bytes: bytes
    ) -> None:
        """
        'pathlib.Path' instance and str are acceptable for argument
        'path_in_bytes'.
        """
        self.format = format
        self.version = version
        self.password = password
        self.path_in_bytes = path_in_bytes

    @property
    def password_hash(self) -> bytes:
        return hexdigest_in_bytes(self.password.encode("utf-8"))

    def base64_path_encode(self) -> bytes:
        return b64encode(self.path_in_bytes)

    @staticmethod
    def base64_path_decode(base64_path: bytes) -> bytes:
        return b64decode(base64_path)

    @classmethod
    def read(cls, headerline: bytes, password: str) -> HeaderInfo:
        if not headerline.endswith(b"\n"):
            return HeaderInfo(False)
        metadata = headerline.strip().split(b"\t")
        try:
            format = metadata[0].decode("utf-8")
            version = int(metadata[1])
            if hexdigest_in_bytes(password.encode("utf-8")) == metadata[2]:
                dees_match = True
            else:
                dees_match = False
            path_in_bytes = cls.base64_path_decode(metadata[3])
        except:
            return HeaderInfo(False)
        else:
            return HeaderInfo(True, format, version, dees_match, path_in_bytes)

    def to_bytes(self) -> bytes:
        metadata = (
            self.format.encode("utf-8"),
            str(self.version).encode("utf-8"),
            self.password_hash,
            self.base64_path_encode()
        )
        return b"\t".join(metadata) + b"\n"
