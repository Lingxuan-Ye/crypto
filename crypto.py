from inspect import isclass
from pathlib import Path
from typing import Optional

from .docs import Status, StatusList
from .models import Header, Printer, format

FORMATS = {
    i[0].upper(): i[1] for i in format.__dict__.items()
    if isclass(i[1]) and issubclass(i[1], format.FormatType)
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
    format_type = FORMATS.get(format.upper())
    if format_type is not None:
        inst = format_type(password, file_path, save_to, chunk)
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

    # these two lines are just for mypy
    if header_info.format is None:
        return [Status.UN_ERROR]

    format_type = FORMATS.get(header_info.format.upper())
    if format_type is not None:
        inst = format_type(password, file_path, save_to, chunk)
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
        Determine the buffer size in I/O. It is set to 0x10000000 by default,
        which means the buffer size is 256 MB.

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
