import argparse
import random
from multiprocessing import Process
from pathlib import Path
from typing import Union

__author__ = "Lingxuan Ye"
__version__ = "2.0.0"

NoneType = type(None)

DEFAULT_CHUNK = 0x100000
HLEP_DOC = {
    "DESCRIPTION":
    """
    Encrypt and decrypt sacrosanct legacies of little Ye.
    """,

    "-e":
    """
    encrypt file(s).
    """,

    "-d":
    """
    decrypt file(s).
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
    seed: Union[NoneType, int, float, str, bytes, bytearray],
    save_to: Path = Path.cwd(),
    chunk: int = DEFAULT_CHUNK
):
    set_seed(seed, version=2)
    with open(file_path, "rb") as f:
        save_to = save_to / (file_path.stem + ".cry")
        body_size = file_path.stat().st_size
        _quotient, _remainder = divmod(body_size, chunk)
        with open(save_to, "wb") as g:
            header = b"CRY\t" + file_path.name.encode("utf-8") + b"\n"
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
    seed: Union[NoneType, int, float, str, bytes, bytearray],
    save_to: Path = Path.cwd(),
    chunk: int = DEFAULT_CHUNK
):
    set_seed(seed, version=2)
    with open(file_path, "rb") as f:
        header = f.readline(chunk)
        meta_list = header.strip().split(b"\t", 1)
        if meta_list[0].lower() != b"cry":
            return
        file_name = meta_list[1].decode("utf-8")
        save_to = save_to / file_name
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

def main(mode: int, file_path: Path, **kwargs):
    """
    Parameters
    ----------
    mode : int
        Determine whether to encrypt or decrypt.

        - mode == 0, encrypt.
        - mode != 0, decrypt.

    file_path : Path
        An instance of pathlib.Path indicating the file to be processed.

    seed : NoneType | int | float | str | bytes | bytearray
        Seed for the instance of random.Random or __main__._Random.

    save_to : Path
        An instance of pathlib.Path indicating the saving directory.

    chunk : int
        Determines the buffer size in I/O. It is set to 0x100000 by default,
        which means the buffer size is 1 MB.
    """
    if mode == 0:
        encrypt(file_path, **kwargs)
        print(f'success: "{file_path}" has been encrypted.')
    else:
        decrypt(file_path, **kwargs)
        print(f'success: "{file_path}" has been decrypted.')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=HLEP_DOC["DESCRIPTION"])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help=HLEP_DOC["-e"])
    group.add_argument("-d", "--decrypt", action="store_true", help=HLEP_DOC["-d"])
    parser.add_argument("-f", "--file_path", action="append", help=HLEP_DOC["-f"], metavar="")
    parser.add_argument("-p", "--password", required=True, help=HLEP_DOC["-p"], metavar="")
    parser.add_argument("-s", "--save_to", default="./result", help=HLEP_DOC["-s"], metavar="")
    args = parser.parse_args()

    save_to: Path = Path(args.save_to)

    if not save_to.is_dir():
        save_to.mkdir(parents=True)

    if args.file_path is None:
        args.file_path = ["."]

    path_list: list = [Path(i) for i in args.file_path]
    file_path_list: list = []

    while path_list:
        path = path_list.pop()
        if path.is_file():
            if path.name != "crypto.py":
                file_path_list.append(path)
        elif path.is_dir():
            path_list.extend(path.iterdir())
        else:
            print(f'error: can not find files in "{str(path)}".')

    for file_path in file_path_list:
        kwargs = {
            "mode": 0 if args.encrypt else 1,
            "file_path": file_path,
            "seed": args.password,
            "save_to": save_to,
            "chunk": DEFAULT_CHUNK,
        }
        Process(target=main, kwargs=kwargs).start()
