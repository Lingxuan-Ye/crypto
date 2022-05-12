import argparse
import random
from multiprocessing import Process
from pathlib import Path

__author__ = "Lingxuan Ye"
__version__ = "1.0.1"

DEFAULT_CHUNK = 1048576
HLEP_DOC = {
    "DESCRIPTION":
    """
    Encrypt and decrypt sacrosanct legacies of little Ye.
    """,

    "-f":
    """
    File(s) to be processed. Seperate paths with SPACE for multiple files.
    If a directory path is given, it will recursively encrypt/decrypt
    all the files in the directory.
    """,

    "-p":
    """
    Password for encryption and decryption.
    """,

    "-s":
    """
    Path of the saving directory ("./result" by default).
    """,

    "-e":
    """
    Encrypt file(s).
    """,

    "-d":
    """
    Decrypt file(s).
    """
}


def bytes_xor(x: bytes, y: bytes, length: int) -> bytes:
    """
    len(y) should be equal to len(x)
    due to performance concern, this function will NOT exam if len(y) == len(x)
    """
    result_int = int.from_bytes(x, "big") ^ int.from_bytes(y, "big")
    return result_int.to_bytes(length, "big")

def main(file_path: Path, *,
         seed,
         saving_directory: Path,
         chunk: int = DEFAULT_CHUNK,
         decrypt: bool = False):
    """
    buffer size in reading and writing file is determined by argument `chunk`,
    and is set to 1 MB by default.
    """
    random.seed(seed, version=2)
    if not decrypt:
        # encrypt
        save_to = saving_directory / (file_path.name + ".cry")
    else:
        # decrypt
        save_to = saving_directory / file_path.stem
    quotient, remainder = divmod(file_path.stat().st_size, chunk)
    with open(file_path, "rb") as f:
        with open(save_to, "wb") as g:
            for _ in range(quotient):
                raw = f.read(chunk)
                key = random.randbytes(chunk)
                g.write(bytes_xor(raw, key, chunk))
            else:
                raw = f.read(remainder)
                key = random.randbytes(remainder)
                g.write(bytes_xor(raw, key, remainder))
    print(f'success: "{file_path}" has been {"decrypted" if decrypt else "encrypted"}.')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=HLEP_DOC["DESCRIPTION"])
    parser.add_argument("-f", "--file_path", action="append", help=HLEP_DOC["-f"], metavar="")
    parser.add_argument("-p", "--password", required=True, help=HLEP_DOC["-p"], metavar="")
    parser.add_argument("-s", default="./result", help=HLEP_DOC["-s"], metavar="")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help=HLEP_DOC["-e"])
    group.add_argument("-d", "--decrypt", action="store_true", help=HLEP_DOC["-d"])
    args = parser.parse_args()

    saving_directory: Path = Path(args.s)

    if not saving_directory.is_dir():
        saving_directory.mkdir(parents=True)

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
            "saving_directory": saving_directory,
            "chunk": DEFAULT_CHUNK,
            "decrypt": args.decrypt
        }
        Process(target=main, kwargs=kwargs).start()
