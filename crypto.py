import argparse
import random
from hashlib import sha256
from multiprocessing import Process
from pathlib import Path, PosixPath

__author__ = "Lingxuan Ye"
__version__ = "3.0.0"

DEFAULT_CHUNK = 0x100000
HLEP_DOC = {
    "DESCRIPTION":
    """
    Encrypt and decrypt sacrosanct legacies of little Ye.
    """,

    "EPILOG":
    """
    This program will encrypt file(s) if the option from mutually exclusive
    group [ -e | -d | -V ] is not specified.
    """,

    "-f":
    """
    file to be processed. if a directory path is given, it will recursively
    encrypt/decrypt all the files in the directory. this option is allowed
    to be specified multiple times and will be set to current working directory
    if omitted.
    """,

    "-p":
    """
    password for encryption and decryption. required.
    """,

    "-s":
    """
    path of the saving directory. this option will be set to "./result"
    if omitted.
    """,

    "-e":
    """
    encrypt file(s) with .cry format, version 2.
    """,

    "-d":
    """
    decrypt file(s).
    """,

    "-V":
    """
    encrypt file(s) with specified version of .cry format. please read source
    code for further information.
    """,

    "-q":
    """
    print quietly.
    """,

    "-v":
    """
    print verbosely.
    """
}


try:
    random.randbytes
except AttributeError:
    class _Random(random.Random):
        def randbytes(self, n: int) -> bytes:
            return self.getrandbits(n * 8).to_bytes(n, 'little')
    _inst = _Random()
    randbytes = _inst.randbytes
    set_seed = _inst.seed
else:
    randbytes = random.randbytes
    set_seed = random.seed


def bytes_xor(x: bytes, y: bytes, length: int) -> bytes:
    """
    len(y) should be equal to len(x).
    due to performance concern, this function will NOT exam if len(y) == len(x).
    """
    result_int = int.from_bytes(x, "big") ^ int.from_bytes(y, "big")
    return result_int.to_bytes(length, "big")


def encrypt(
    file_path: Path, *,
    seed: str,
    save_to: Path = Path(),
    chunk: int = DEFAULT_CHUNK,
    version: int = 2
):
    """
    A .cry format file is formed by header and body. The header specifies
    the version of .cry format and the relative path of the original file,
    which helps to reconstruct the directory structure.

    Parameters
    ----------
    file_path : Path
        An instance of pathlib.Path indicating the file to be encrypted.

    seed : str
        Seed for the instance of random.Random or __main__._Random.

    save_to : Path
        An instance of pathlib.Path indicating the saving directory.

    chunk : int
        Determines the buffer size in I/O. It is set to 0x100000 by default,
        which means that the buffer size is 1 MB.

    version : int
        Determine the version of .cry format.
        - 0         Save the original file name as plaintext in the header.
        - 1         Save the original file name as ciphertext in the header.
                    Reset seed, then encrypt. The body of encrypted file
                    will be just the same as version 0 if the seed remains
                    unchanged.
        - 2         Save the original file name as ciphertext in the header.
                    Change seed in particular way, then encrypt. The body
                    of encrypted file will be different with differnent
                    original file name. RECOMMENDED.
        - elsewhere Follow the same behavior as version == 2 for now.
                    NOT RECOMMENDED.
    """
    set_seed(seed, version=2)
    file_path_bytes = bytes(file_path)

    # for Python 3.10 or later #
    # match version:
    #     case 0:
    #         file_name = file_path.stem + ".cry"
    #         header = b"CRY\t" + b"0\t" + file_path_bytes + b"\n"
    #     case 1:
    #         file_name = sha256(file_path_bytes).hexdigest() + ".cry"
    #         raw = file_path_bytes
    #         length = len(raw)
    #         key = randbytes(length)
    #         header = b"CRY\t" + b"1\t" + bytes_xor(raw, key, length) + b"\n"
    #         set_seed(seed, version=2)
    #     case 2 | _:
    #         file_name = sha256(file_path_bytes).hexdigest() + ".cry"
    #         raw = file_path_bytes
    #         length = len(raw)
    #         key = randbytes(length)
    #         header = b"CRY\t" + b"2\t" + bytes_xor(raw, key, length) + b"\n"
    #         seed = seed + sha256(file_path_bytes).hexdigest()
    #         set_seed(seed, version=2)

    if version == 0:
        file_name = file_path.stem + ".cry"
        header = b"CRY\t" + b"0\t" + file_path_bytes + b"\n"
    elif version == 1:
        file_name = sha256(file_path_bytes).hexdigest() + ".cry"
        raw = file_path_bytes
        length = len(raw)
        key = randbytes(length)
        header = b"CRY\t" + b"1\t" + bytes_xor(raw, key, length) + b"\n"
        set_seed(seed, version=2)
    else:
        file_name = sha256(file_path_bytes).hexdigest() + ".cry"
        raw = file_path_bytes
        length = len(raw)
        key = randbytes(length)
        header = b"CRY\t" + b"2\t" + bytes_xor(raw, key, length) + b"\n"
        seed = seed + sha256(file_path_bytes).hexdigest()
        set_seed(seed, version=2)

    with open(file_path, "rb") as f:
        save_to = save_to / file_name
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


def decrypt(
    file_path: Path, *,
    seed: str,
    save_to: Path = Path(),
    chunk: int = DEFAULT_CHUNK
) -> int:
    """
    Parameters
    ----------
    file_path : Path
        An instance of pathlib.Path indicating the file to be decrypted.

    seed : str
        Seed for the instance of random.Random or __main__._Random.

    save_to : Path
        An instance of pathlib.Path indicating the saving directory.

    chunk : int
        Determines the buffer size in I/O. It is set to 0x100000 by default,
        which means that the buffer size is 1 MB.
    """
    set_seed(seed, version=2)
    exit_code = 0
    with open(file_path, "rb") as f:
        header = f.readline(0x400)
        if not header.endswith(b"\n"):
            exit_code = 1
            return exit_code
        metadata = header.strip().split(b"\t")
        if metadata[0].lower() != b"cry":
            exit_code = 1
            return exit_code

        # for Python 3.10 or later #
        # match metadata[1]:
        #     case b"0":
        #         _file_path_str = metadata[-1].decode("utf-8")
        #     case b"1":
        #         raw = metadata[-1]
        #         length = len(raw)
        #         key = randbytes(length)
        #         _file_path_str = bytes_xor(raw, key, length).decode("utf-8")
        #         set_seed(seed, version=2)
        #     case b"2":
        #         raw = metadata[-1]
        #         length = len(raw)
        #         key = randbytes(length)
        #         _file_path_bytes = bytes_xor(raw, key, length)
        #         _file_path_str = _file_path_bytes.decode("utf-8")
        #         seed = seed + sha256(_file_path_bytes).hexdigest()
        #         set_seed(seed, version=2)
        #     case _:
        #         _file_path_str = metadata[-1].decode("utf-8")

        if metadata[1] == b"0":
            _file_path_str = metadata[-1].decode("utf-8")
        elif metadata[1] == b"1":
            raw = metadata[-1]
            length = len(raw)
            key = randbytes(length)
            _file_path_str = bytes_xor(raw, key, length).decode("utf-8")
            set_seed(seed, version=2)
        elif metadata[1] == b"2":
            raw = metadata[-1]
            length = len(raw)
            key = randbytes(length)
            _file_path_bytes = bytes_xor(raw, key, length)
            _file_path_str = _file_path_bytes.decode("utf-8")
            seed = seed + sha256(_file_path_bytes).hexdigest()
            set_seed(seed, version=2)
        else:  # compatibility concern
            _file_path_str = metadata[-1].decode("utf-8")

        _file_path = Path(_file_path_str)
        _file_path_str = str(_file_path)  # return string representation of raw filesystem path
        if _file_path.is_absolute():
            save_to = save_to / _file_path.name
            exit_code = -1
        else:
            if isinstance(_file_path, PosixPath):
                node_list = _file_path_str.split("/")
            else:  # isinstance(_file_path, WindowsPath)
                node_list = _file_path_str.split("\\")
            for index, node in enumerate(node_list):
                if node == "..":
                    node_list[index] = "__parent_directory__"
                elif node == "__parent_directory__" or node.startswith("_ESC"):
                    node_list[index] = "_ESC" + node
            save_to = save_to / "/".join(node_list)
            if not save_to.parent.is_dir():
                save_to.parent.mkdir(parents=True)

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
        return exit_code


def main(*, mode: int, file_path: Path, quiet: bool = False, **kwargs):
    """
    Parameters
    ----------
    mode : int
        Determine whether to encrypt or decrypt.
        - 0         encrypt.
        - elsewhere decrypt.

    file_path : Path
        An instance of pathlib.Path indicating the file to be processed.

    seed : str
        Seed for the instance of random.Random or __main__._Random.

    save_to : Path
        An instance of pathlib.Path indicating the saving directory.

    chunk : int
        Determines the buffer size in I/O. It is set to 0x100000 by default,
        which means that the buffer size is 1 MB.

    version : int
        Determine the version of .cry format. omitted if mode != 0.
        - 0         Save the original file name as plaintext in the header.
        - 1         Save the original file name as ciphertext in the header.
                    Reset seed, then encrypt. The body of encrypted file
                    will be just the same as version 0 if the seed remains
                    unchanged.
        -  2        Save the original file name as ciphertext in the header.
                    Change seed in particular way, then encrypt. The body
                    of encrypted file will be different with differnent
                    original file name. RECOMMENDED.
        - elsewhere Follow the same behavior as version == 2 for now.
                    NOT RECOMMENDED.

    quiet : bool
        - True      Print quietly.
        - False     Print verbosely.
    """
    if mode == 0:
        encrypt(file_path, **kwargs)
        message = f'success: "{file_path}" has been encrypted.'
    else:
        kwargs.pop("version")
        exit_code = decrypt(file_path, **kwargs)
        if exit_code < 0:
            if exit_code == -1:
                warning_info = "can not reconstruct the directory structure."
            else:
                warning_info = "unknown warning."
            message = f"warning: {warning_info}"
        elif exit_code > 0:
            if exit_code == 1:
                error_info = f'format of "{file_path}" is unsupported.'
            else:
                error_info = "unknown error."
            message = f"error: {error_info}"
        else:
            message = f'success: "{file_path}" has been decrypted.'

    if not quiet:
        print(message)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=HLEP_DOC["DESCRIPTION"], epilog=HLEP_DOC["EPILOG"])
    parser.add_argument("-f", "--file_path", action="append", help=HLEP_DOC["-f"], metavar="")
    parser.add_argument("-p", "--password", required=True, help=HLEP_DOC["-p"], metavar="")
    parser.add_argument("-s", "--save_to", default="./result", help=HLEP_DOC["-s"], metavar="")
    mutex_group_0 = parser.add_mutually_exclusive_group()
    mutex_group_0.add_argument("-e", "--encrypt", action="store_true", help=HLEP_DOC["-e"])
    mutex_group_0.add_argument("-d", "--decrypt", action="store_true", help=HLEP_DOC["-d"])
    mutex_group_0.add_argument("-V", "--version", default=2, choices=(0,1,2), type=int, help=HLEP_DOC["-V"], metavar="")
    mutex_group_1 = parser.add_mutually_exclusive_group()
    mutex_group_1.add_argument("-q", "--quiet", action="store_true", help=HLEP_DOC["-q"])
    mutex_group_1.add_argument("-v", "--verbose", action="store_true", help=HLEP_DOC["-v"])
    args = parser.parse_args()

    save_to = Path(args.save_to)
    if not save_to.is_dir():
        save_to.mkdir(parents=True)

    if args.file_path is None:
        args.file_path = ["."]

    path_list = [Path(i) for i in args.file_path]
    file_path_list = []

    while path_list:
        path = path_list.pop()
        if path.is_file():
            if path.name != "crypto.py":
                file_path_list.append(path)
        elif path.is_dir():
            path_list.extend(path.iterdir())
        elif not args.quiet:
            print(f'error: can not find files in "{str(path)}".')

    for file_path in file_path_list:
        kwargs = {
            "mode": 1 if args.decrypt else 0,
            "file_path": file_path,
            "seed": args.password,
            "save_to": save_to,
            "chunk": DEFAULT_CHUNK,
            "version": args.version,
            "quiet": args.quiet
        }
        Process(target=main, kwargs=kwargs).start()
