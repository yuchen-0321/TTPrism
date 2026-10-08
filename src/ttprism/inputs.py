"""Reading untrusted input files with size, encoding and nesting limits."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, BinaryIO

DEFAULT_MAX_BYTES = 64 * 1024 * 1024


class InputError(ValueError):
    """The input is too large, unreadable or malformed."""


def read_bytes(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Read at most ``max_bytes`` from ``path`` ("-" means standard input)."""
    try:
        if str(path) == "-":
            return _read_limited(sys.stdin.buffer, max_bytes, "standard input")
        with Path(path).open("rb") as handle:
            return _read_limited(handle, max_bytes, str(path))
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc.strerror or exc}") from None


def _read_limited(handle: BinaryIO, max_bytes: int, name: str) -> bytes:
    data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InputError(
            f"{name}: larger than the {max_bytes}-byte limit; raise it with --max-size if expected"
        )
    return data


def decode_text(data: bytes, encoding: str | None = None) -> tuple[str, list[str]]:
    """Decode ``data``; returns (text, warnings)."""
    if encoding:
        try:
            return data.decode(encoding, errors="replace"), []
        except LookupError:
            raise InputError(f"unknown encoding: {encoding}") from None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace"), []
    try:
        return data.decode("utf-8-sig"), []
    except UnicodeDecodeError:
        warning = (
            "input is not valid UTF-8; undecodable bytes were replaced "
            "(pass --encoding, e.g. big5 or gb18030, for legacy Chinese text)"
        )
        return data.decode("utf-8", errors="replace"), [warning]


def load_json(text: str) -> Any:
    """Parse JSON. Nesting depth is bounded by the json module's recursion guard.

    CPython's decoder raises RecursionError once nesting reaches the
    interpreter recursion limit (about 1000 levels), before it can exhaust
    the C stack. A separate pre-scan would add a second full pass over large
    sandbox reports for no extra protection.
    """
    try:
        return json.loads(text)
    except RecursionError:
        raise InputError("JSON nesting too deep") from None
    except ValueError as exc:
        raise InputError(f"invalid JSON: {exc}") from None
