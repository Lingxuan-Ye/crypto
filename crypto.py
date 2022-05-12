import argparse
import random
from multiprocessing import Process
from pathlib import Path

__author__ = "Lingxuan Ye"
__version__ = "1.1.0"

DEFAULT_CHUNK = 1048576
HLEP_DOC = {
    "DESCRIPTION":
    """
    Encrypt and decrypt sacrosanct legacies of little Ye.
    """,

    "-f":
    """
    file(s) to be processed. seperate paths with SPACE for multiple files.
    if a directory path is given, it will recursively encrypt/decrypt
    all the files in the directory. current working directory by default.
    """,

    "-p":
    """
    password for encryption and decryption. required.
    """,

    "-s":
    """
    path of the saving directory. "./result" by default.
    """,

    "-e":
    """
    encrypt file(s).
    """,

    "-d":
    """
    decrypt file(s).
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

def main(file_path: Path, *,
         seed,
         save_to: Path,
         chunk: int = DEFAULT_CHUNK,
         decrypt: bool = False):
    """
    buffer size in reading and writing file is determined by argument `chunk`,
    and is set to 1 MB by default.
    """
    set_seed(seed, version=2)
    if not decrypt:
        # encrypt
        save_to = save_to / (file_path.name + ".cry")
    else:
        # decrypt
        save_to = save_to / file_path.stem
    quotient, remainder = divmod(file_path.stat().st_size, chunk)
    with open(file_path, "rb") as f:
        with open(save_to, "wb") as g:
            for _ in range(quotient):
                raw = f.read(chunk)
                key = randbytes(chunk)
                g.write(bytes_xor(raw, key, chunk))
            else:
                raw = f.read(remainder)
                key = randbytes(remainder)
                g.write(bytes_xor(raw, key, remainder))
    print(f'success: "{file_path}" has been {"decrypted" if decrypt else "encrypted"}.')


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
            "file_path": file_path,
            "seed": args.password,
            "save_to": save_to,
            "chunk": DEFAULT_CHUNK,
            "decrypt": args.decrypt
        }
        Process(target=main, kwargs=kwargs).start()
