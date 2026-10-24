from __future__ import annotations

import argparse
import json

from . import __version__
from .core import audit, to_dot


def positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected positive integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("Expected positive integer")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inventory local requirements includes without pip install"
    )
    parser.add_argument("entries", nargs="+", help="Entry filenames relative to current directory")
    parser.add_argument("--root", required=True, help="Declared bundle root directory")
    parser.add_argument("--version", action="version", version=f"reqfile-graph {__version__}")
    parser.add_argument("--format", choices=["text", "json", "dot"], default="text")
    parser.add_argument("--warnings-as-errors", action="store_true")
    parser.add_argument("--max-files", type=positive, default=512)
    parser.add_argument("--max-depth", type=positive, default=64)
    parser.add_argument("--max-file-bytes", type=positive, default=1_048_576)
    parser.add_argument("--max-total-bytes", type=positive, default=16_777_216)
    parser.add_argument("--max-findings", type=positive, default=1000)
    args = parser.parse_args(argv)
    if args.max_depth > 128:
        parser.error("--max-depth must not exceed 128")
    result = audit(
        args.entries,
        root=args.root,
        max_files=args.max_files,
        max_depth=args.max_depth,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_findings=args.max_findings,
        warnings_as_errors=args.warnings_as_errors,
    )
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=True, indent=2))
    elif args.format == "dot":
        print(to_dot(result))
    else:
        print(
            f"{'OK' if result['ok'] else 'FAIL'}: {len(result['files'])} files, "
            f"{len(result['edges'])} includes, {result['error_count']} errors, "
            f"{result['warning_count']} warnings"
        )
        for file in result["files"]:
            print(f"file {json.dumps(file['path'])} contexts={','.join(file['contexts'])}")
        for finding in result["findings"]:
            print(json.dumps(finding, ensure_ascii=True))
        if result["findings_truncated"]:
            print("Additional findings omitted; all counted findings affect the result")
    return 0 if result["ok"] else 1
