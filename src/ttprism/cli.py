"""Command-line interface: ``ttprism extract`` and ``ttprism validate-rules``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from ttprism._version import __version__
from ttprism._yaml import ConfigError
from ttprism.allowlist import Allowlist
from ttprism.analyze import AnalysisOptions, analyze_file
from ttprism.attack import AttackCatalog, RuleSet, default_rules_path
from ttprism.export import to_csv, to_json
from ttprism.inputs import DEFAULT_MAX_BYTES, InputError
from ttprism.stix import to_stix_bundle

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2


def _size(value: str) -> int:
    units = {"k": 1024, "m": 1024**2, "g": 1024**3}
    value = value.strip().lower().removesuffix("b")
    multiplier = units.get(value[-1:], 1)
    number = value[:-1] if value[-1:] in units else value
    try:
        size = int(number) * multiplier
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a size: {value!r} (examples: 500k, 64m)") from None
    if size <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ttprism",
        description="Extract IOCs from threat reports and sandbox output and map behaviour to MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ex = sub.add_parser("extract", help="extract IOCs and ATT&CK techniques from a file")
    ex.add_argument("input", help="report text/Markdown, CAPE report.json, or - for stdin")
    ex.add_argument(
        "-f",
        "--format",
        choices=("json", "csv", "stix"),
        default="json",
        help="output format (default: json)",
    )
    ex.add_argument("-o", "--output", help="write to this file instead of standard output")
    ex.add_argument(
        "--input-format",
        choices=("auto", "text", "cape"),
        default="auto",
        help="how to read the input (default: auto)",
    )
    ex.add_argument("--encoding", help="input text encoding (default: UTF-8, e.g. big5, gb18030)")
    ex.add_argument("--defang", action="store_true", help="defang IOC values in JSON/CSV output (hxxp, [.])")
    ex.add_argument(
        "--include-reserved",
        action="store_true",
        help="keep private/documentation IPs and example/test domains",
    )
    ex.add_argument(
        "--allowlist",
        action="append",
        default=[],
        metavar="FILE",
        help="additional allowlist YAML (repeatable)",
    )
    ex.add_argument("--no-default-allowlist", action="store_true", help="do not apply the built-in allowlist")
    ex.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="additional ATT&CK rule file or directory (repeatable)",
    )
    ex.add_argument(
        "--no-default-rules", action="store_true", help="do not load the built-in ATT&CK mapping rules"
    )
    ex.add_argument(
        "--max-size",
        type=_size,
        default=DEFAULT_MAX_BYTES,
        metavar="SIZE",
        help=f"refuse inputs larger than this (default: {DEFAULT_MAX_BYTES // 1024**2}m)",
    )
    ex.add_argument("-q", "--quiet", action="store_true", help="do not print warnings")

    val = sub.add_parser("validate-rules", help="check ATT&CK mapping rule files")
    val.add_argument("paths", nargs="*", help="rule files or directories (default: built-in rules)")
    return parser


def _warn(message: str) -> None:
    print(f"ttprism: warning: {message}", file=sys.stderr)


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _cmd_extract(args: argparse.Namespace) -> int:
    if args.output and args.input != "-" and _same_file(args.input, args.output):
        print("ttprism: error: output file is the input file", file=sys.stderr)
        return EXIT_USAGE

    allowlist = Allowlist.empty() if args.no_default_allowlist else Allowlist.default()
    for path in args.allowlist:
        allowlist.update(Allowlist.from_file(path))
    catalog = AttackCatalog.default()
    rules = RuleSet.empty() if args.no_default_rules else RuleSet.default()
    if args.rules:
        rules.extend(RuleSet.load(args.rules, catalog))
    options = AnalysisOptions(
        allowlist=allowlist, rules=rules, catalog=catalog, include_reserved=args.include_reserved
    )

    result = analyze_file(
        args.input,
        options,
        input_format=args.input_format,
        encoding=args.encoding,
        max_bytes=args.max_size,
    )
    if args.format == "json":
        output = to_json(result, defanged=args.defang)
    elif args.format == "csv":
        output = to_csv(result, defanged=args.defang)
    else:
        if args.defang:
            _warn("--defang is ignored for STIX output; patterns need the real values")
        output = json.dumps(to_stix_bundle(result), ensure_ascii=False, indent=2) + "\n"

    if not args.quiet:
        for warning in result.warnings:
            _warn(warning)

    if args.output:
        # The output path comes only from the user, never from input content.
        with Path(args.output).open("w", encoding="utf-8", newline="") as handle:
            handle.write(output)
    else:
        _write_stdout(output)
    return EXIT_OK


def _write_stdout(text: str) -> None:
    """Write UTF-8 regardless of the console code page (e.g. cp1252 on Windows redirects)."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)
        return
    sys.stdout.flush()
    buffer.write(text.encode("utf-8"))
    buffer.flush()


def _cmd_validate_rules(args: argparse.Namespace) -> int:
    paths = args.paths or [default_rules_path()]
    ruleset = RuleSet.load(paths)
    for warning in ruleset.warnings:
        print(f"WARNING {warning}")
    status = "with warnings" if ruleset.warnings else "OK"
    print(f"{len(ruleset.rules)} rules checked against ATT&CK {AttackCatalog.default().version}: {status}")
    return EXIT_ERROR if ruleset.warnings else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "extract":
            return _cmd_extract(args)
        return _cmd_validate_rules(args)
    except (InputError, ConfigError) as exc:
        print(f"ttprism: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"ttprism: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
