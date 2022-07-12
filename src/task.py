from inspect import isclass
from pathlib import Path
from typing import Optional

from .docs import Status, StatusList
from .models import Header, Printer, formatter

FORMATTERS = {
    i.FORMAT.upper(): i for i in vars(formatter).values()
    if isclass(i)
    and issubclass(i, formatter.Formatter)
    and i is not formatter.Formatter  # for class A, issubclass(A, A) is True
}


def encrypt(
    password: str,
    file_path: Path,
    save_to: Optional[Path] = None,
    chunk: Optional[int] = None,
    *,
    format: str,
    version: int
) -> StatusList:
    formatter = FORMATTERS.get(format.upper())
    if formatter is not None:
        inst = formatter(password, file_path, save_to, chunk)
        return inst.encrypt(version)
    else:
        return [Status.EN_VERSION_ERROR]


def decrypt(
    password: str,
    file_path: Path,
    save_to: Optional[Path] = None,
    chunk: Optional[int] = None,
) -> StatusList:
    with open(file_path, "rb") as f:
        headerline = f.readline(0x1000)
    header_info = Header.read(headerline, password)
    if not header_info.is_valid:
        return [Status.DE_FILE_ERROR]
    if not header_info.does_match:
        return [Status.DE_PASSWORD_ERROR]
    assert header_info.format is not None  # for mypy
    formatter = FORMATTERS.get(header_info.format.upper())
    if formatter is not None:
        inst = formatter(password, file_path, save_to, chunk)
        return inst.decrypt(header_info)
    else:
        return [Status.DE_FILE_ERROR]


def task(
    *,
    mode: int,
    file_path: Path,
    printer: Printer,
    **kwargs
) -> None:
    """
    Parameters
    ----------
    mode: int
        Determine whether to encrypt or decrypt.
        - 0     encrypt.
        - 1     decrypt.

    file_path: Path
        Determine file to be processed.

    password: str
        Password for encryption / decryption.

    save_to: Path
        Specify saving directory.

    chunk: int
        Determine the buffer size in I/O. It is set to 0x1000000 by default,
        which means the buffer size is 16 MB.

    format: str
        Specify encryption format. Valid when 'mode' is set to 0.

    version: int
        Specify format version. Valid when 'mode' is set to 0.

    printer: Printer
        Control printing behavior.
    """
    if mode == 0:
        status_list = encrypt(file_path=file_path, **kwargs)
    elif mode == 1:
        kwargs.pop("format")
        kwargs.pop("version")
        status_list = decrypt(file_path=file_path, **kwargs)
    else:
        raise ValueError("'mode' must be 0 or 1.")
    for i in status_list:
        message = i.value.format(file_path=file_path)
        printer(message)
