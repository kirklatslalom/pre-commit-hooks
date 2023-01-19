from __future__ import annotations

import argparse
import re
from typing import Sequence

BLACKLIST = [
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN DSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN PRIVATE KEY",
    b"PuTTY-User-Key-File-2",
    b"BEGIN SSH2 ENCRYPTED PRIVATE KEY",
    b"BEGIN PGP PRIVATE KEY BLOCK",
    b"BEGIN ENCRYPTED PRIVATE KEY",
    b"BEGIN OpenVPN Static key V1",
]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    parser.add_argument(
        "--ignore",
        type=str,
        help="Comma-separated list of regular expressions to ignore",
    )
    args = parser.parse_args(argv)

    private_key_files = set()

    ignore_re_list = (
        [re.compile(ignore) for ignore in args.ignore.split(",")] if args.ignore else []
    )

    for filename in args.filenames:
        if any(ignore_re.search(filename) for ignore_re in ignore_re_list):
            continue
        with open(filename, "rb") as f:
            content = f.read()
            if any(line in content for line in BLACKLIST):
                private_key_files.add(filename)

    if private_key_files:
        for private_key_file in private_key_files:
            print(f"Private key found: {private_key_file}")
        return 1
    else:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
