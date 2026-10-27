#!/usr/bin/env python3
"""Generate a controlled open/close burst for electric-eye load testing.

This is intentionally simple: it exercises the open path and therefore the
ring -> userspace -> SQLite pipeline. It does not try to be a filesystem or
network benchmark.

Examples:
    python3 tests/load/ring-burst.py --count 20000
    python3 tests/load/ring-burst.py --count 30000 --path /dev/null

The default target is a temporary file under /tmp, removed after the run.
Use an isolated LXC container for disruptive tests.
"""

import argparse
import os
import sys
import tempfile
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count",
        type=int,
        default=20_000,
        help="number of open/close operations (default: 20000)",
    )
    parser.add_argument(
        "--path",
        help="file to open repeatedly; defaults to a temporary file under /tmp",
    )
    args = parser.parse_args()
    if args.count <= 0:
        parser.error("--count must be positive")

    cleanup = False
    path = args.path
    if path is None:
        fd, path = tempfile.mkstemp(prefix="electric-eye-load-", dir="/tmp")
        os.close(fd)
        cleanup = True

    flags = os.O_WRONLY | os.O_APPEND
    start = time.monotonic()
    try:
        for _ in range(args.count):
            os.close(os.open(path, flags))
    finally:
        elapsed = time.monotonic() - start
        if cleanup:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    rate = args.count / elapsed if elapsed > 0 else float("inf")
    print(
        f"opened {args.count} times in {elapsed:.3f}s "
        f"({rate:,.0f} opens/s) target={path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
