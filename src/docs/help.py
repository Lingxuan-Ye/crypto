"""
Norm
----
- Text for description and epilog of a command should be capitalized with a
  trailling period.

- Text for help info of an option should be lower case with no trailling
  period.
"""


class Help:

    DESCRIPTION = "Encrypt and decrypt sacrosanct legacies of Little Ye."
    EPILOG = "Go to https://github.com/Lingxuan-Ye/crypto for more info."

    f = "specify file(s) to be processed. if a directory is given, " \
        "recursively process all files under the directory. " \
        "if omitted, this will be set to current working directory"
    s = "specify saving directory"
    p = "password for encryption and decryption"
    e = "encrypt"
    d = "decrypt"
    V = "specify the version of encryption (read source code for details)"
    q = "print quietly"
    v = "print verbosely"
