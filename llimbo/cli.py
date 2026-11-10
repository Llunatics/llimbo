"""Command-line interface for llimbo."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .carver import SIGNATURES, carve

EXIT_OK = 0          # scan complete, at least one file recovered
EXIT_NOTHING = 10    # scan complete, nothing recovered
EXIT_ERROR = 2       # usage or I/O error

_TYPE_NAMES = ", ".join(t.name for t in SIGNATURES)


def parse_size(text: str) -> int:
    """Parse a byte size like ``512``, ``64K``, ``10M`` or ``2G``."""
    text = text.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3}
    if text and text[-1] in multipliers:
        number, mult = text[:-1], multipliers[text[-1]]
    else:
        number, mult = text, 1
    try:
        value = int(number)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid size: {text!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"size must not be negative: {text!r}")
    return value * mult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llimbo",
        description=(
            "Recover deleted files from a disk image or raw file by "
            "carving on magic bytes. Standard library only."
        ),
    )
    parser.add_argument("--version", action="version", version=f"llimbo {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="scan an image and recover the files it still contains",
        description=(
            "Scan IMAGE for embedded files (JPEG, PNG, GIF, PDF, ZIP) and "
            "write each recovered file into OUT_DIR."
        ),
    )
    scan.add_argument("image", help="disk image or raw file to scan")
    scan.add_argument("-o", "--out-dir", required=True,
                      help="directory for recovered files (created if needed)")
    scan.add_argument("--types", default=None,
                      help=f"comma-separated subset of: {_TYPE_NAMES} (default: all)")
    scan.add_argument("--min-size", type=parse_size, default=0, metavar="SIZE",
                      help="ignore carved blobs smaller than SIZE (e.g. 512, 64K)")
    scan.add_argument("--max-size", type=parse_size, default=0, metavar="SIZE",
                      help="cap a single carved file at SIZE; files cut here "
                           "are marked truncated (default: no cap)")
    scan.add_argument("--prefix", default="recovered",
                      help="output filename prefix (default: %(default)s)")
    scan.add_argument("--json", default=None, metavar="FILE",
                      help="write the recovery report as JSON to FILE")
    scan.add_argument("--quiet", action="store_true",
                      help="print only the summary line")
    return parser


def _report(result, written: list[str], image: str) -> dict:
    return {
        "image": image,
        "bytes_scanned": result.bytes_scanned,
        "recovered": len(result.files),
        "skipped_too_small": result.skipped_too_small,
        "files": [
            {
                "name": path.split("/")[-1],
                "type": f.file_type,
                "offset": f.offset,
                "size": f.size,
                "status": f.status,
                "sha256": f.sha256,
            }
            for f, path in zip(result.files, written)
        ],
    }


def cmd_scan(args: argparse.Namespace) -> int:
    types = None
    if args.types is not None:
        types = tuple(t.strip().lower() for t in args.types.split(",") if t.strip())
        if not types:
            print("llimbo: --types must name at least one type",
                  file=sys.stderr)
            print(f"llimbo: known types: {_TYPE_NAMES}", file=sys.stderr)
            return EXIT_ERROR
        unknown = sorted(set(types) - {t.name for t in SIGNATURES})
        if unknown:
            print(f"llimbo: unknown file type(s): {', '.join(unknown)}",
                  file=sys.stderr)
            print(f"llimbo: known types: {_TYPE_NAMES}", file=sys.stderr)
            return EXIT_ERROR
    try:
        os.makedirs(args.out_dir, exist_ok=True)
    except OSError as exc:
        print(f"llimbo: cannot create {args.out_dir}: "
              f"{exc.strerror or exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        result, written = carve(
            args.image,
            args.out_dir,
            types=types,
            min_size=args.min_size,
            max_size=args.max_size,
            prefix=args.prefix,
        )
    except ValueError as exc:
        print(f"llimbo: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError:
        print(f"llimbo: no such file: {args.image}", file=sys.stderr)
        return EXIT_ERROR
    except IsADirectoryError:
        print(f"llimbo: not a file: {args.image}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"llimbo: cannot read {args.image}: {exc.strerror or exc}",
              file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        for found, path in zip(result.files, written):
            flag = "" if found.status == "complete" else " (truncated)"
            print(f"{path}: {found.file_type} at offset {found.offset}, "
                  f"{found.size} bytes{flag}")
    complete = sum(1 for f in result.files if f.status == "complete")
    truncated = len(result.files) - complete
    print(f"scanned {result.bytes_scanned} bytes: {len(result.files)} file(s) "
          f"recovered ({complete} complete, {truncated} truncated), "
          f"{result.skipped_too_small} skipped as too small")

    if args.json:
        report = _report(result, written, args.image)
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
                fh.write("\n")
        except OSError as exc:
            print(f"llimbo: cannot write {args.json}: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_ERROR
    return EXIT_OK if result.files else EXIT_NOTHING


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
