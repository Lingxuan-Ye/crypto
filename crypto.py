import argparse
import random
from argparse import Namespace
from base64 import b64decode, b64encode
from enum import Enum
from hashlib import sha256
from multiprocessing import Pool
from pathlib import Path, PosixPath, WindowsPath
from typing import Any, NamedTuple, Optional, Union

__author__ = "Lingxuan Ye"
__version__ = "3.2.4"
__all__ = ["Namespace", "bytes_xor", "encrypt", "decrypt", "task", "run"]

NoneType = type(None)

DEFAULT_CHUNK = 0x100000

try:
    random.randbytes
except AttributeError:

    class _Random(random.Random):

        def randbytes(self, n: int) -> bytes:
            return self.getrandbits(n * 8).to_bytes(n, "little")

    _inst = _Random()
    randbytes = _inst.randbytes
    set_seed = _inst.seed
else:
    randbytes = random.randbytes
    set_seed = random.seed


class Help(Enum):
    """
    'argparse.ArgumentParser' will remove leading and trailing whitespace,
    including newline. Therefore docstrings are recommended to assign members.

    Note that help info will NOT display in the terminal as what it looks like
    in the docstring.
    """

    DESCRIPTION = """
        Encrypt and decrypt sacrosanct legacies of little Ye.
    """

    EPILOG = """
        Do encrypt if the option from mutually exclusive
        group [ -e | -d | -V ] is not specified.
    """

    FILE = """
        file to be processed. if a directory is given, it will recursively
        process all the files in the directory. this option is allowed
        to be specified multiple times and will be set to current working
        directory if omitted
    """

    SAVE_TO = """
        path of the saving directory
    """

    PASSWORD = """
        password for encryption and decryption (required)
    """
    ENCRYPT = """
        encrypt file(s) with .cry format, version 2
    """

    DECRYPT = """
        decrypt file(s)
    """

    VERSION = """
        encrypt file(s) with specified version of .cry format (please read
        source code for further information)
    """

    QUIET = """
        print quietly
    """

    VERBOSE = """
        print verbosely
    """


class Status(Enum):
    EXIT = "finished."
    PATH_ERROR = "error: cannot find files in '{file_path}'."
    ENCRYPT_SUCCESS = "success: '{file_path}' has been encrypted."
    ENCRYPT_VERSION_ERROR = "error: argument 'version' must be 0, 1 or 2."
    DECRYPT_SUCCESS = "success: '{file_path}' has been decrypted."
    DECRYPT_WARNING = "warning: can not reconstruct the directory structure."
    DECRYPT_FILE_ERROR = "error: '{file_path}' is not an encrypted file."
    DECRYPT_VERSION_ERROR = "error: unknown version for '{file_path}'."
    DECRYPT_PASSWORD_ERROR = "error: incorrect password for '{file_path}'."
    UNKNOWN_WARNING = "warning: unknown warning."
    UNKNOWN_ERROR = "warning: unknown error."


class HeaderTuple(NamedTuple):
    """
    Header Example
    --------------
    | format | version |  password_hash  |  path   |
    ├--------|---------|-----------------|---------┤
    | b"CRY" |  b"2"   | b"ABCabc123..." | b'Zm9v' |

    Note that components of a header is seperated by b"\t", and that at the end
    of a header, there will be a newline b"\n" following.

    Components
    ----------
    format:
        Specify the format of encrypted file.
        - b'CRY'    The only available format for now.

    version:
        Version of .cry format.
        - b"0"      Original file path is saved as plaintext.
        - b"1"      Original file path is saved as ciphertext. To be more
                    specific, the path will be encrypted by function
                    'bytes_xor' with specified seed, then be encoded to Base64
                    in order not to break the header line. Reset seed, then
                    encrypt.
        - b"2"      Original file path is saved as ciphertext. To be more
                    specific, the path will be encrypted by function
                    'bytes_xor' with specified seed, then be encoded to Base64
                    in order not to break the header line. Change seed as
                    follow:
                        seed = seed + sha256(file_path_bytes).hexdigest()
                    where 'file_path_bytes' are bytes form of original file
                    path. After that, encrypt file.
        In some old versions of .cry format, this component of header may not
        exist. Files in those versions will be considered as b"0".

    password_hash:
        Use 'hashlib.sha256' and some other methods to get bytes of HEXADECIMAL
        (in order not to break the header line) digest of the password to
        further verify whether the password for decryption is correct. In some
        old versions of .cry format, this component of header may not exist.
        Files in those versions will be continue decrypting with incorrect
        password by mistake.

    path:
        As aforementioned, how the original file path is saved depends on the
        version of .cry format. The principle is that path must be processed
        properly in order not to break the header line.
    """

    format: bytes
    version: bytes
    password_hash: Optional[bytes]
    path: bytes

    def b64encode(self):
        return self._replace(path=b64encode(self.path))

    def b64decode(self):
        return self._replace(path=b64decode(self.path))

    @classmethod
    def from_bytes(cls, header: bytes):
        has_error: bool = True
        metadata: list = header.strip().split(b"\t")
        if len(metadata) == 2:
            # header == b"{format}\t{path}\n"
            if metadata[0].isalpha():
                metadata.insert(1, b"0")
                metadata.insert(2, None)
                has_error = False
                return cls._make(metadata)
        elif len(metadata) == 3:
            # header == b"{format}\t{version}\t{path}\n"
            if all((
                metadata[0].isalpha(),
                metadata[1].isdigit()
            )):
                metadata.insert(2, None)
                has_error = False
                return cls._make(metadata)
        elif len(metadata) == 4:
            # header == b"{format}\t{version}\t{password_hash}\t{path}\n"
            if all((
                metadata[0].isalpha(),
                metadata[1].isdigit(),
                metadata[2].isalnum()
            )):
                has_error = False
                return cls._make(metadata)
        if has_error:
            raise ValueError("invalid header")

    def to_bytes(self):
        metadata: list = list(self)
        if self.password_hash is None:
            metadata.pop(2)
        return b"\t".join(metadata) + b"\n"

    @classmethod
    def custom_init(
        cls,
        path: Union[bytes, str, Path],
        *,
        format: Union[bytes, str] = b"CRY",
        version: Union[bytes, str, int] = b"2",
        password: Union[bytes, str, NoneType] = None
    ):
        if isinstance(path, bytes):
            pass
        elif isinstance(path, str):
            path = path.encode("utf-8")
        elif isinstance(path, Path):
            path = bytes(path)
        else:
            raise ValueError(
                "argument 'path' must be 'byte', 'str' or "
                "'pathlib.Path' instance."
            )
        if isinstance(format, bytes) and format.isalpha():
            pass
        elif isinstance(format, str) and format.isalpha():
            format = format.encode("utf-8")
        else:
            raise ValueError(
                "argument 'format' must be 'byte' or 'str'."
            )
        if isinstance(version, bytes) and version.isdigit():
            pass
        elif isinstance(version, str) and version.isdigit():
            version = version.encode("utf-8")
        elif isinstance(version, int):
            version = str(version).encode("utf-8")
        else:
            raise ValueError(
                "argument 'version' must be 'byte', 'str' or 'int'."
            )
        if password is None:
            password_hash = None
        elif isinstance(password, bytes):
            password_hash = sha256(password).hexdigest().encode("utf-8")
        elif isinstance(password, str):
            password = password.encode("utf-8")
            password_hash = sha256(password).hexdigest().encode("utf-8")
        else:
            raise ValueError(
                "argument 'password' must be 'byte', 'str' or 'NoneType'."
            )
        return cls(format, version, password_hash, path)


class Printer:
    """
    Singleton class.
    """
    __instance = None

    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

    def __init__(self, quiet: bool = False):
        self.__quiet: bool = quiet
        self.__state: str = "quiet" if quiet else "verbose"

    @property
    def state(self):
        return self.__state

    def set_state(self, quiet: bool):
        self.__quiet = quiet
        self.__state = "quiet" if quiet else "verbose"

    def __call__(self, *args, force_print: bool = False, **kwargs):
        if not self.__quiet or force_print:
            print(*args, **kwargs)


def bytes_xor(x: bytes, y: bytes, length: int) -> bytes:
    """
    len(x), len(y) and argument 'length' should always be equal. Due to
    performance concern, this function will NOT exam whether
    len(y) == len(x) == length. Please pass arguments carefully.
    """
    result_int = int.from_bytes(x, "big") ^ int.from_bytes(y, "big")
    return result_int.to_bytes(length, "big")


def _encrypt(file_path: Path, seed: str, save_to: Path, chunk: int,
             version: int) -> Status:

    status = Status.ENCRYPT_SUCCESS
    set_seed(seed, version=2)
    file_path_bytes = bytes(file_path)

    if version not in {0, 1, 2}:
        return Status.ENCRYPT_VERSION_ERROR
    if version == 0:
        file_name = file_path.stem + ".cry"
        header = HeaderTuple.custom_init(
            version=b"0",
            password=seed,
            path=file_path_bytes
        ).to_bytes()
    else:
        file_name = sha256(file_path_bytes).hexdigest() + ".cry"
        raw = file_path_bytes
        length = len(raw)
        key = randbytes(length)
        encrypted_path = bytes_xor(raw, key, length)
    if version == 1:
        header = HeaderTuple.custom_init(
            version=b"1",
            password=seed,
            path=encrypted_path
        ).b64encode().to_bytes()
        set_seed(seed, version=2)
    if version == 2:
        header = HeaderTuple.custom_init(
            version=b"2",
            password=seed,
            path=encrypted_path
        ).b64encode().to_bytes()
        seed = seed + sha256(file_path_bytes).hexdigest()
        set_seed(seed, version=2)

    with open(file_path, "rb") as f:
        save_to = save_to / file_name
        save_to.parent.mkdir(parents=True, exist_ok=True)
        body_size = file_path.stat().st_size
        _quotient, _remainder = divmod(body_size, chunk)
        with open(save_to, "wb") as g:
            g.write(header)
            for _ in range(_quotient):
                raw = f.read(chunk)
                key = randbytes(chunk)
                g.write(bytes_xor(raw, key, chunk))
            else:
                raw = f.read(_remainder)
                key = randbytes(_remainder)
                g.write(bytes_xor(raw, key, _remainder))

    return status


def encrypt(file_path: Union[Path, str, NoneType] = None,
            *,
            seed: Any,
            save_to: Union[Path, str, NoneType] = None,
            chunk: int = DEFAULT_CHUNK,
            version: int = 2):
    """
    A .cry format file is formed by header and body. The header specifies
    the version of .cry format and the relative path of the original file,
    which helps to reconstruct the directory structure.

    Parameters
    ----------
    file_path: Path | str | NoneType
        Specify the file to be encrypted.

    seed: str
        Seed for the instance of random.Random or __main__._Random.

    save_to: Path | str | NoneType
        Specify the directory to save encrypted file.

    chunk: int
        Determine the buffer size in I/O. It is set to 0x100000 by default,
        which means the buffer size is 1 MB.

    version: int
        Determine the version of .cry format.
        - 0         Save the original file path as plaintext in the header.
        - 1         Save the original file path as ciphertext in the header.
                    Reset seed, then encrypt. The body of encrypted file
                    will be just the same as version 0 if the seed remains
                    unchanged.
        - 2         Save the original file path as ciphertext in the header.
                    Change seed in particular way, then encrypt. The body
                    of encrypted file will be different if the original file
                    is renamed. RECOMMENDED.
    """
    if isinstance(file_path, Path):
        pass
    elif isinstance(file_path, str):
        file_path = Path(file_path)
    elif file_path is None:
        file_path = Path()
    else:
        raise TypeError(
            "argument 'file_path' must be 'str', 'NoneType' or "
            "'pathlib.Path' instance."
        )

    if not isinstance(seed, str):
        seed = str(seed)

    if isinstance(save_to, Path):
        pass
    elif isinstance(save_to, str):
        save_to = Path(save_to)
    elif save_to is None:
        save_to = Path("__encrypted__")
    else:
        raise TypeError(
            "argument 'file_path' must be 'str', 'NoneType' or "
            "'pathlib.Path' instance."
        )

    if not isinstance(chunk, int):
        raise TypeError("argument 'chunk' must be 'int'.")

    if not isinstance(version, int):
        raise TypeError("argument 'version' must be 'int'.")
    elif version not in {0, 1, 2}:
        raise ValueError("argument 'version' must be 0, 1 or 2.")

    _encrypt(file_path, seed, save_to, chunk, version)


def _decrypt(file_path: Path, seed: str, save_to: Path, chunk: int) -> Status:

    status = Status.DECRYPT_SUCCESS
    set_seed(seed, version=2)

    with open(file_path, "rb") as f:
        header = f.readline(0x1000)
        if not header.endswith(b"\n"):
            return Status.DECRYPT_FILE_ERROR
        try:
            header_tuple = HeaderTuple.from_bytes(header)
        except ValueError:
            return Status.DECRYPT_FILE_ERROR
        if header_tuple.format.upper() != b"CRY":
            return Status.DECRYPT_FILE_ERROR
        if header_tuple.version not in {b"0", b"1", b"2"}:
            return Status.DECRYPT_VERSION_ERROR
        if header_tuple.password_hash not in {
            None,
            sha256(seed.encode("utf-8")).hexdigest().encode("utf-8")
        }:
            return Status.DECRYPT_PASSWORD_ERROR

        if header_tuple.version == b"0":
            original_path_str = header_tuple.path.decode("utf-8")
        else:
            raw = header_tuple.b64decode().path
            length = len(raw)
            key = randbytes(length)
            original_path_bytes = bytes_xor(raw, key, length)
            original_path_str = original_path_bytes.decode("utf-8")
        if header_tuple.version == b"1":
            set_seed(seed, version=2)
        if header_tuple.version == b"2":
            seed = seed + sha256(original_path_bytes).hexdigest()
            set_seed(seed, version=2)

        original_path = Path(original_path_str)
        raw_filesystem_path = str(original_path)

        if original_path.is_absolute():
            save_to = save_to / original_path.name
            status = Status.DECRYPT_WARNING
        else:
            if isinstance(original_path, PosixPath):
                node_list = raw_filesystem_path.split("/")
            elif isinstance(original_path, WindowsPath):
                node_list = raw_filesystem_path.split("\\")
            else:
                return Status.UNKNOWN_ERROR
            for index, node in enumerate(node_list):
                if node == "..":
                    node_list[index] = "__parent_directory__"
                elif node == "__parent_directory__" or node.startswith("_ESC"):
                    node_list[index] = "_ESC" + node
            save_to = save_to / "/".join(node_list)
            save_to.parent.mkdir(parents=True, exist_ok=True)

        body_size = file_path.stat().st_size - len(header)
        _quotient, _remainder = divmod(body_size, chunk)

        with open(save_to, "wb") as g:
            for _ in range(_quotient):
                raw = f.read(chunk)
                key = randbytes(chunk)
                g.write(bytes_xor(raw, key, chunk))
            else:
                raw = f.read(_remainder)
                key = randbytes(_remainder)
                g.write(bytes_xor(raw, key, _remainder))

        return status


def decrypt(file_path: Union[Path, str, NoneType] = None,
            *,
            seed: Any,
            save_to: Union[Path, str, NoneType] = None,
            chunk: int = DEFAULT_CHUNK):
    """
    Parameters
    ----------
    file_path: Path | str | NoneType
        Specify the file to be decrypted.

    seed: str
        Seed for the instance of random.Random or __main__._Random.

    save_to: Path | str | NoneType
        Specify the directory to save decrypted file.

    chunk: int
        Determine the buffer size in I/O. It is set to 0x100000 by default,
        which means the buffer size is 1 MB.
    """
    if isinstance(file_path, Path):
        pass
    elif isinstance(file_path, str):
        file_path = Path(file_path)
    elif file_path is None:
        file_path = Path()
    else:
        raise TypeError(
            "argument 'file_path' must be 'str', 'NoneType' or "
            "'pathlib.Path' instance."
        )

    if not isinstance(seed, str):
        seed = str(seed)

    if isinstance(save_to, Path):
        pass
    elif isinstance(save_to, str):
        save_to = Path(save_to)
    elif save_to is None:
        save_to = Path("__decrypted__")
    else:
        raise TypeError(
            "argument 'save_to' must be 'str', 'NoneType' or "
            "'pathlib.Path' instance."
        )

    if not isinstance(chunk, int):
        raise TypeError("argument 'chunk' must be 'int'.")

    _decrypt(file_path, seed, save_to, chunk)


def task(*, mode: int, file_path: Path, printer: Printer, **kwargs):
    """
    Parameters
    ----------
    mode: int
        Determine whether to encrypt or decrypt.
        - 0         encrypt.
        - 1         decrypt.

    file_path: Path
        Specify the file be processed.

    seed: str
        Seed for the instance of random.Random or __main__._Random.

    save_to: Path
        Specify the directory to save encrypted file.

    chunk: int
        Determine the buffer size in I/O. It is set to 0x100000 by default,
        which means the buffer size is 1 MB.

    version: int
        Determine the version of .cry format.
        - 0         Save the original file path as plaintext in the header.
        - 1         Save the original file path as ciphertext in the header.
                    Reset seed, then encrypt. The body of encrypted file
                    will be just the same as version 0 if the seed remains
                    unchanged.
        - 2         Save the original file path as ciphertext in the header.
                    Change seed in particular way, then encrypt. The body
                    of encrypted file will be different if the original file
                    is renamed. RECOMMENDED.

    printer: Printer
        Singleton instance of Printer determining whether to print quietly
        or verbosely in the terminal.
    """
    if mode == 0:
        status = _encrypt(file_path, **kwargs)
    elif mode == 1:
        kwargs.pop("version")
        status = _decrypt(file_path, **kwargs)
    else:
        raise ValueError("value of argument 'mode' must be 0 or 1.")
    printer(status.value.format(file_path=file_path))


def main(args: Namespace):
    """
    Entry.
    """
    printer = Printer(args.quiet)

    file_list = []
    if args.file is None:
        path_list = [Path()]
    else:
        path_list = [Path(i) for i in args.file]
    while path_list:
        path = path_list.pop()
        if path.is_file():
            if path.name != "crypto.py":
                file_list.append(path)
        elif path.is_dir():
            path_list.extend(path.iterdir())
        else:
            printer(Status.PATH_ERROR.value.format(file_path=str(path)))

    if args.save_to is None:
        if not args.decrypt:
            save_to = Path("__encrypted__")
        else:
            save_to = Path("__decrypted__")
    else:
        save_to = Path(args.save_to)

    process_pool = Pool()
    for file_path in file_list:
        kwargs = {
            "mode": 1 if args.decrypt else 0,
            "file_path": file_path,
            "seed": args.password,
            "save_to": save_to,
            "chunk": DEFAULT_CHUNK,
            "version": args.version,
            "printer": printer
        }
        process_pool.apply_async(task, kwds=kwargs)
    process_pool.close()
    process_pool.join()
    printer(Status.EXIT.value, force_print=True)


run = main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=Help.DESCRIPTION.value,
        epilog=Help.EPILOG.value
    )

    parser.add_argument(
        "-f", "--file",
        action="append",
        help=Help.FILE.value,
        metavar=""
    )
    parser.add_argument(
        "-s", "--save_to",
        help=Help.SAVE_TO.value,
        metavar=""
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help=Help.PASSWORD.value,
        metavar=""
    )

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help=Help.ENCRYPT.value
    )
    action_group.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help=Help.DECRYPT.value
    )
    action_group.add_argument(
        "-V", "--version",
        default=2,
        choices=(0, 1, 2),
        type=int,
        help=Help.VERSION.value,
        metavar=""
    )

    print_control = parser.add_mutually_exclusive_group()
    print_control.add_argument(
        "-q", "--quiet",
        action="store_true",
        help=Help.QUIET.value
    )
    print_control.add_argument(
        "-v", "--verbose",
        action="store_true",
        help=Help.VERBOSE.value
    )

    main(parser.parse_args())
