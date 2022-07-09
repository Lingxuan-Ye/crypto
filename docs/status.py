from enum import Enum
from typing import List


class Status(Enum):
    EXIT = "finished."
    PATH_ERROR = "error: '{file_path}' is not a file or directory."
    EN_SUCCESS = "success: '{file_path}' has been encrypted."
    EN_FORMAT_ERROR = "error: unknown format."
    EN_VERSION_ERROR = "error: unknown version code."
    DE_SUCCESS = "success: '{file_path}' has been decrypted."
    DE_TAMPER_WARNING = "warning: '{file_path}' may be tampered."
    DE_FILE_ERROR = "error: '{file_path}' is not an encrypted file."
    DE_FORMAT_ERROR = "error: '{file_path}' was encrypted with unknown format."
    DE_VERSION_ERROR = "error: '{file_path}' has an unknown version code."
    DE_PASSWORD_ERROR = "error: incorrect password for '{file_path}'."
    UN_WARNING = "warning: unknown warning."
    UN_ERROR = "warning: unknown error."

StatusList = List[Status]
