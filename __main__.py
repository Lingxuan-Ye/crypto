import argparse
from multiprocessing import Pool
from pathlib import Path

from src.crypto import task
from src.docs import Help, Status
from src.models import Printer


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="crypto",
        description=Help.DESCRIPTION,
        epilog=Help.EPILOG
    )
    parser.add_argument(
        "-f",
        "--file",
        action="extend",
        nargs="*",
        help=Help.f,
        metavar=""
    )
    parser.add_argument("-s", "--save_to", help=Help.s, metavar="")
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        help=Help.p,
        metavar=""
    )
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help=Help.e
    )
    action_group.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help=Help.d
    )
    action_group.add_argument(
        "-V",
        "--version",
        default=2,
        choices=(0, 1, 2),
        type=int,
        help=Help.V,
        metavar=""
    )
    print_control = parser.add_mutually_exclusive_group()
    print_control.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=Help.q
        )
    print_control.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help=Help.v
    )

    args = parser.parse_args()

    printer = Printer(args.quiet)  # print verbosely by default

    file_list = []
    if args.file is None or not args.file:
        path_list = [Path()]
    else:
        path_list = [Path(i) for i in args.file]
    while path_list:
        path = path_list.pop()
        if path.is_file():
            file_list.append(path)
        elif path.is_dir():
            if path.name != "crypto":
                path_list.extend(path.iterdir())
        else:
            printer(Status.PATH_ERROR.value.format(file_path=str(path)))

    process_pool = Pool()
    kwargs = {
            "mode": 1 if args.decrypt else 0,
            "password": args.password,
            "save_to": args.save_to,
            "chunk": None,
            "format": "CRY",
            "version": args.version,
            "printer": printer
        }
    for file_path in file_list:
        kwargs["file_path"] = file_path
        process_pool.apply_async(func=task, kwds=kwargs)
    process_pool.close()
    process_pool.join()
    printer(Status.EXIT.value, force_print=True)


if __name__ == "__main__":
    main()
