from pathlib import Path
from typing import Any, NamedTuple, Optional, Tuple

from ..docs import Status, StatusList
from ..utils import bytes_xor, hexdigest, randbytes, set_seed, sha256
from .header import Header, HeaderInfo


class PathString(NamedTuple):

    encrypt: str = "__encrypted__"
    decrypt: str = "__decrypted__"
    root: str = "__root__"
    parent: str = "__parent__"
    escape: str = "_ESC"


class Formatter:

    FORMAT: str
    VERSIONS: Tuple[int, ...]
    PATH_STRING = PathString()
    DEFAULT_CHUNK = 0x10000000  # 256 MB

    @property
    def EXTENSION(self) -> str:
        return self.FORMAT.lower()

    @property
    def SUFFIX(self) -> str:
        return "." + self.EXTENSION

    def __setattr__(self, __name: str, __value: Any) -> None:
        has_error = True
        if __name == "password":
            if isinstance(__value, bytes):
                __value = __value.decode("utf-8")
            if isinstance(__value, str):
                has_error = False
        elif __name in ("file_path", "save_to"):
            if isinstance(__value, bytes):
                __value = Path(__value.decode("utf-8"))
            elif isinstance(__value, str):
                __value = Path(__value)
            if isinstance(__value, Path):
                has_error = False
            elif __name == "save_to" and __value is None:
                has_error = False
        if __name == "chunk":
            if not isinstance(__value, int):
                try:
                    __value = int(__value)
                except:
                    pass
            if isinstance(__value, int):
                has_error = False
        if has_error:
            raise AttributeError("invalid value to assign")
        return super().__setattr__(__name, __value)

    def __init__(
        self,
        password: str,
        file_path: Path,
        save_to: Optional[Path] = None,
        chunk: Optional[int] = None
    ) -> None:
        self.password = password
        file_path = file_path
        self.file_path = file_path
        self.save_to = save_to
        self.chunk = chunk if chunk is not None else self.DEFAULT_CHUNK

    @property
    def encrypt_to(self) -> Path:
        if self.save_to is None:
            return Path(self.PATH_STRING.encrypt)
        return self.save_to

    @property
    def decrypt_to(self) -> Path:
        if self.save_to is None:
            return Path(self.PATH_STRING.decrypt)
        return self.save_to

    def encrypt(self, version: int) -> StatusList:
        pass

    def decrypt(self, header_info: HeaderInfo) -> StatusList:
        pass


class Cry(Formatter):
    """
    Version
    -------
    - 0     Save original file path as base64 encoded plaintext.

    - 1     Encrypt original file path with specified seed and
            encode it to base64. Then encrypt the raw data with the
            same seed. For safety concern, encrypted file will NOT
            keep its original file name.

    - 2     Encrypt original file path with specified seed and
            encode it to base64. Then encrypt the raw data with a
            new seed. The seed will be different with different
            file name. For safety concern, encrypted file will NOT
            keep its original file name.
    """

    FORMAT = "CRY"
    VERSIONS = (0, 1, 2)

    @property
    def file_path_in_bytes(self) -> bytes:
        return bytes(self.file_path)

    def encrypt(self, version: int) -> StatusList:
        set_seed(self.password, version=2)
        file_path_in_bytes = self.file_path_in_bytes

        if version not in self.VERSIONS:
            return [Status.EN_VERSION_ERROR]
        elif version == 0:
            file_name = self.file_path.name + self.SUFFIX
            headerline = Header(
                self.FORMAT,
                version,
                self.password,
                file_path_in_bytes
            ).to_bytes()
        else:
            file_name = hexdigest(file_path_in_bytes) + self.SUFFIX
            raw = file_path_in_bytes
            length = len(raw)
            key = randbytes(length)
            encrypted_path = bytes_xor(raw, key, length)
        if version == 1:
            headerline = Header(
                self.FORMAT,
                version,
                self.password,
                encrypted_path
            ).to_bytes()
            set_seed(self.password, version=2)
        if version == 2:
            headerline = Header(
                self.FORMAT,
                version,
                self.password,
                encrypted_path
            ).to_bytes()
            seed = self.password + hexdigest(file_path_in_bytes)
            set_seed(seed, version=2)

        saving_path = self.encrypt_to / file_name
        saving_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.file_path, "rb") as f:
            file_hash = sha256(self.password.encode("utf-8"))
            data_size = self.file_path.stat().st_size
            _quotient, _remainder = divmod(data_size, self.chunk)
            with open(saving_path, "wb") as g:
                g.write(headerline)
                for _ in range(_quotient):
                    raw = f.read(self.chunk)
                    key = randbytes(self.chunk)
                    g.write(bytes_xor(raw, key, self.chunk))
                    file_hash.update(raw)
                else:
                    raw = f.read(_remainder)
                    key = randbytes(_remainder)
                    g.write(bytes_xor(raw, key, _remainder))
                    file_hash.update(raw)
                    g.write(b"\n")
                    g.write(file_hash.hexdigest().encode("utf-8"))
                    g.write(b"\n")

        return [Status.EN_SUCCESS]

    def decrypt(self, header_info: HeaderInfo) -> StatusList:
        status_list: StatusList = []
        set_seed(self.password, version=2)

        # these two lines are just for mypy
        assert header_info.format is not None
        assert header_info.path_in_bytes is not None

        if header_info.version not in self.VERSIONS:
            return [Status.DE_VERSION_ERROR]
        if header_info.version == 0:
            path_in_str = header_info.path_in_bytes.decode("utf-8")
        else:
            raw = header_info.path_in_bytes
            length = len(raw)
            key = randbytes(length)
            decrypted_path_in_bytes = bytes_xor(raw, key, length)
            path_in_str = decrypted_path_in_bytes.decode("utf-8")
        if header_info.version == 1:
            set_seed(self.password, version=2)
        if header_info.version == 2:
            seed = self.password + hexdigest(decrypted_path_in_bytes)
            set_seed(seed, version=2)

        # code below endeavors to solve malicious behavior which causes
        # writing file beyond specified top-level directory.
        path = Path(path_in_str).resolve()
        path_parts: list = list(path.parts)
        cwd_parts: tuple = Path.cwd().parts
        cwd_parts_len = len(cwd_parts)
        # 'Path.resolve' returns absolute path basing on cwd, therefore
        # it compares 'path' with cwd instead of specified directory.
        for _index, _part in enumerate(cwd_parts):
            # 'Path.resolve(...).drive' (if any) is in uppercase while
            # 'Path.cwd().drive' (if any) is in lowercase, which results in
            # an absurd bug without if-statement below.
            if _index == 0:
                if _part.lower() == path_parts[0].lower():
                    continue
                else:
                    pos = 0
                    break
            if _part != path_parts[_index]:
                pos = _index
                break
        else:
            pos = cwd_parts_len - 1
        path_parts = [
            self.PATH_STRING.parent for _ in range(cwd_parts_len - pos - 1)
        ] + path_parts[pos + 1:]

        for _index, _part in enumerate(path_parts[cwd_parts_len - pos - 1:]):
            if _part in self.PATH_STRING:  # '_part' can not be '"."'
                path_parts[_index] = self.PATH_STRING.escape + _part
        saving_path = self.decrypt_to / "/".join(path_parts)
        saving_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.file_path, "rb") as f:
            headerline = f.readline(0x1000)
            file_hash = sha256(self.password.encode("utf-8"))
            data_size = self.file_path.stat().st_size - len(headerline) - 66
            _quotient, _remainder = divmod(data_size, self.chunk)
            with open(saving_path, "wb") as g:
                for _ in range(_quotient):
                    raw = f.read(self.chunk)
                    key = randbytes(self.chunk)
                    decrypted_data = bytes_xor(raw, key, self.chunk)
                    g.write(decrypted_data)
                    file_hash.update(decrypted_data)
                else:
                    raw = f.read(_remainder)
                    key = randbytes(_remainder)
                    decrypted_data = bytes_xor(raw, key, _remainder)
                    g.write(decrypted_data)
                    file_hash.update(decrypted_data)
            digest = f.read().strip().decode("utf-8")
            if file_hash.hexdigest() != digest:
                status_list.append(Status.DE_TAMPER_WARNING)
        status_list.append(Status.DE_SUCCESS)
        return status_list
