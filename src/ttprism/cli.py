"""Command-line interface: ``ttprism extract`` and ``ttprism validate-rules``."""

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO, NoReturn

from ttprism._version import __version__
from ttprism._yaml import ConfigError
from ttprism.allowlist import Allowlist
from ttprism.analyze import AnalysisOptions, analyze_file
from ttprism.attack import AttackCatalog, RuleSet, default_rules_path
from ttprism.export import to_csv, to_json
from ttprism.inputs import DEFAULT_MAX_BYTES, TERMINAL_UNSAFE_RE, InputError, without_surrogates
from ttprism.stix import to_stix_bundle

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2
MAX_SIZE = 16 * 1024**3


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
    if size > MAX_SIZE:
        # Larger limits make no sense for text reports and would only allow exhausting memory.
        raise argparse.ArgumentTypeError(f"size too large: {value!r} (at most {MAX_SIZE // 1024**3}g)")
    return size


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # "unrecognized arguments" quotes command-line words, such as file names from a glob.
        super().error(_terminal_safe(message))


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
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


def _terminal_safe(message: str) -> str:
    """Replace characters that a terminal would act on with U+FFFD.

    Messages can quote rule files, allowlists and inputs. Newlines are kept
    (PyYAML errors span several lines) but indented, so that a line cannot
    pass itself off as a separate ttprism message.
    """
    return TERMINAL_UNSAFE_RE.sub("\ufffd", message).replace("\n", "\n  ")


def _print_stderr(message: str) -> None:
    # With stderr closed, print(file=None) would write to stdout and corrupt the output.
    if sys.stderr is not None:
        print(_terminal_safe(message), file=sys.stderr)


def _warn(message: str) -> None:
    _print_stderr(f"ttprism: warning: {message}")


def _error(message: str) -> None:
    _print_stderr(f"ttprism: error: {message}")


def _same_file(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _cmd_extract(args: argparse.Namespace) -> int:
    if args.output and args.input != "-" and _same_file(args.input, args.output):
        _error("output file is the input file")
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
            result.warnings.append("--defang is ignored for STIX output; patterns need the real values")
        output = json.dumps(to_stix_bundle(result), ensure_ascii=False, indent=2) + "\n"

    if not args.quiet:
        for warning in result.warnings:
            _warn(warning)

    data = _encode(output)
    if args.output:
        # The output path comes only from the user, never from input content.
        _write_file(Path(args.output), data)
    else:
        _write_stdout(data)
    return EXIT_OK


def _encode(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates, e.g. from "\ud800" escapes in a JSON report
        return without_surrogates(text).encode("utf-8")


def _write_all(stream: BinaryIO, data: bytes) -> None:
    """Write every byte: a pipe or a full disk can accept part of a write without an error."""
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if not written:
            raise OSError("output was cut short: a write accepted no bytes")
        view = view[written:]


def _write_stdout(data: bytes) -> None:
    """Write UTF-8 regardless of the console code page (e.g. cp1252 on Windows redirects)."""
    stdout = sys.stdout
    if stdout is None:  # fd 1 was closed when Python started
        raise OSError("standard output is not available")
    buffer = getattr(stdout, "buffer", None)
    if buffer is None:
        stdout.write(data.decode("utf-8"))
        stdout.flush()
        return
    stdout.flush()
    _write_all(buffer, data)
    buffer.flush()


def _write_file(path: Path, data: bytes) -> None:
    try:
        _replace_file(path, data)
    except OSError as exc:
        raise OSError(f"cannot write {path}: {exc.strerror or exc}") from None


def _replace_file(path: Path, data: bytes) -> None:
    """Write ``data`` to a temporary file and move it over ``path``.

    A failed run then never leaves a truncated or half-written output file. Where a new file
    cannot stand in for the old one, the old one is overwritten in place, as open() would.
    """
    try:
        info: os.stat_result | None = path.stat()
    except FileNotFoundError:
        info = None
    if info is not None and not stat.S_ISREG(info.st_mode):
        # A device or pipe such as /dev/null: it must not be replaced and cannot be truncated.
        _write_in_place(path, data)
        return
    if info is not None and not os.access(path, os.W_OK):
        # Replacing needs only a writable directory; keep refusing read-only files as open() did.
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))
    target = Path(os.path.realpath(path))  # through a symlink, replace the file it points to
    if info is not None and (info.st_nlink > 1 or os.path.ismount(target) or _has_xattrs(target)):
        # Other hard links would keep the old content, a bind-mounted file (a container volume)
        # cannot be renamed over, and a new file would not have the old one's ACL or attributes.
        _write_in_place(target, data)
        return
    mode = stat.S_IMODE(info.st_mode) if info is not None else 0o666 & ~_umask()
    try:
        # A short name: the target's own name may already be close to NAME_MAX.
        fd, temp = tempfile.mkstemp(prefix=f".{target.name[:48]}.", suffix=".tmp", dir=target.parent)
    except PermissionError:
        if info is None:
            raise
        _write_in_place(target, data)  # a writable file in a directory that is not writable
        return
    try:
        with os.fdopen(fd, "wb") as handle:
            _write_all(handle, data)
        os.chmod(temp, mode)  # mkstemp creates the file as 0600
        if info is not None and not _same_owner(temp, info):
            # A file shared through its group or owner would change hands.
            os.unlink(temp)
            _write_in_place(target, data)
            return
        try:
            os.replace(temp, target)
        except OSError as exc:
            if info is None or exc.errno not in (errno.EBUSY, errno.EXDEV):
                raise
            # A mount point that ismount() cannot see, such as a bind mount within one file system.
            os.unlink(temp)
            _write_in_place(target, data)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp)
        raise


def _has_xattrs(path: Path) -> bool:
    """True if ``path`` has extended attributes, such as a POSIX ACL (Linux only)."""
    try:
        return bool(os.listxattr(path))
    except (AttributeError, OSError):
        return False


def _write_in_place(path: Path, data: bytes) -> None:
    with path.open("wb") as handle:
        _write_all(handle, data)


def _same_owner(temp: str, info: os.stat_result) -> bool:
    """Give ``temp`` the owner and group in ``info`` where allowed; True if it then has both."""
    if sys.platform == "win32":
        return True
    with contextlib.suppress(OSError):
        os.chown(temp, info.st_uid if os.geteuid() == 0 else -1, info.st_gid)
    new = os.stat(temp)
    return (new.st_uid, new.st_gid) == (info.st_uid, info.st_gid)


def _umask() -> int:
    mask = os.umask(0)
    os.umask(mask)
    return mask


def _cmd_validate_rules(args: argparse.Namespace) -> int:
    paths = args.paths or [default_rules_path()]
    ruleset = RuleSet.load(paths)
    lines = [f"WARNING {_terminal_safe(warning)}" for warning in ruleset.warnings]
    status = "with warnings" if ruleset.warnings else "OK"
    lines.append(
        f"{len(ruleset.rules)} rules checked against ATT&CK {AttackCatalog.default().version}: {status}"
    )
    # Same UTF-8 writer as extract: print() fails on a non-ASCII rule path under a cp1252 console.
    _write_stdout(_encode("".join(f"{line}\n" for line in lines)))
    return EXIT_ERROR if ruleset.warnings else EXIT_OK


def _silence_stdout() -> None:
    """Point stdout at devnull so the flush at interpreter exit cannot fail again."""
    with contextlib.suppress(AttributeError, OSError, ValueError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "extract":
            return _cmd_extract(args)
        return _cmd_validate_rules(args)
    except (InputError, ConfigError) as exc:
        _error(str(exc))
        return EXIT_ERROR
    except BrokenPipeError:
        # The reader went away (e.g. `| head`): stop quietly, but do not report success.
        _silence_stdout()
        return EXIT_ERROR
    except OSError as exc:
        _error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
