"""Reading untrusted input files with size, encoding and nesting limits."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, BinaryIO

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 1024 * 1024
_UTF32_BOMS = (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")  # checked first: they start like UTF-16 BOMs
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
# Characters a terminal may act on: C0 controls except tab and newline, DEL and C1 controls, lone
# surrogates, and the bidi marks, embeddings, overrides and isolates ("Trojan Source").
_UNSAFE = r"\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"
TERMINAL_UNSAFE_RE = re.compile(f"[{_UNSAFE}]")
_UNSAFE_OR_NEWLINE_RE = re.compile(rf"[\n{_UNSAFE}]")


class InputError(ValueError):
    """The input is too large, unreadable or malformed."""


def read_bytes(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Read at most ``max_bytes`` from ``path`` ("-" means standard input)."""
    try:
        if str(path) == "-":
            return _read_stdin(max_bytes)
        with Path(path).open("rb") as handle:
            return _read_limited(handle, max_bytes, str(path))
    except OSError as exc:
        raise InputError(f"{path}: cannot read: {exc.strerror or exc}") from None


def _read_stdin(max_bytes: int) -> bytes:
    stdin = sys.stdin
    if stdin is None:  # fd 0 was closed when Python started
        raise InputError("standard input is not available")
    buffer = getattr(stdin, "buffer", None)
    if buffer is not None:
        return _read_limited(buffer, max_bytes, "standard input")
    # Text-only streams (IDLE, some embedding hosts): every character is at least one byte.
    data = stdin.read(max_bytes + 1).encode("utf-8", errors="replace")
    if len(data) > max_bytes:
        raise _too_large("standard input", max_bytes)
    return data


def _read_limited(handle: BinaryIO, max_bytes: int, name: str) -> bytes:
    # Read in chunks: read(max_bytes + 1) would allocate the whole limit up front.
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        chunk = handle.read(min(_CHUNK_BYTES, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > max_bytes:
        raise _too_large(name, max_bytes)
    return b"".join(chunks)


def _too_large(name: str, max_bytes: int) -> InputError:
    return InputError(f"{name}: larger than the {max_bytes}-byte limit; raise it with --max-size if expected")


def decode_text(data: bytes, encoding: str | None = None) -> tuple[str, list[str]]:
    """Decode ``data``; returns (text, warnings). Without ``encoding``, input that is not UTF-8 (or
    UTF-16/32 with a byte-order mark) raises InputError."""
    warnings: list[str] = []
    if encoding:
        try:
            text = data.decode(encoding, errors="replace")
        except LookupError:
            raise InputError(f"unknown encoding: {encoding}") from None
        except ValueError as exc:  # UnicodeError, or a codec that rejects errors="replace" (idna)
            raise InputError(f"cannot decode input as {encoding}: {exc}") from None
    elif data.startswith(_UTF32_BOMS) and (utf32 := _strict_utf32(data)) is not None:
        text = utf32
    elif data.startswith(_UTF16_BOMS):
        text = data.decode("utf-16", errors="replace")
    else:
        try:
            # Two byte-order marks are removed, one here and one below: a tool that adds one to a
            # file that already has one leaves two.
            text = data.decode("utf-8").removeprefix("\ufeff")
        except UnicodeDecodeError as exc:
            # Replacing the bad bytes would report wrong values: Big5 "網域：c2.example" gives gc2.example.
            bad = f"input is not valid UTF-8 (byte 0x{data[exc.start]:02x} at offset {exc.start})"
            if data.count(0) * 100 > len(data):
                raise InputError(
                    f"{bad}; it is probably UTF-16 or UTF-32 without a byte-order mark: pass "
                    "--encoding utf-16-le (or utf-16-be, utf-32)"
                ) from None
            raise InputError(
                f"{bad}; pass its encoding, e.g. --encoding big5, cp950 or gb18030 for Chinese text"
            ) from None
    text = text.removeprefix("\ufeff")
    if text.count("\x00") * 100 > len(text):
        warnings.append(
            "input has many NUL characters, so it is probably UTF-16 or UTF-32 without a "
            "byte-order mark; pass --encoding utf-16-le (or utf-16-be, utf-32)"
        )
    return text, warnings


def _strict_utf32(data: bytes) -> str | None:
    """``data`` as UTF-32, or None if it is not: FF FE 00 00 also starts UTF-16 text whose first
    character is U+0000. A few bad code units or a stray last byte do not make it UTF-16; read as
    UTF-32, UTF-16 text is nearly all invalid code units."""
    text = data.decode("utf-32", errors="replace")
    bad = text.count("\ufffd")
    return text if bad <= 2 or bad * 100 <= len(text) else None


def printable(text: str) -> str:
    """Replace newlines and every character in :data:`TERMINAL_UNSAFE_RE` with U+FFFD.

    For attacker-controlled text shown on one line: evidence, input file names.
    """
    return _UNSAFE_OR_NEWLINE_RE.sub("\ufffd", text)


def without_surrogates(text: str) -> str:
    """Replace lone surrogates, which cannot be encoded, with U+FFFD.

    They come from JSON escapes such as "\\ud800" and from file names that are
    not valid UTF-8 (Python maps their bytes to surrogates).
    """
    return _SURROGATE_RE.sub("\ufffd", text)


def load_json(text: str) -> Any:
    """Parse JSON. Nesting depth is bounded by the interpreter's recursion guard.

    CPython's decoder raises RecursionError before it can exhaust the C stack:
    at about 1,000 levels on Python 3.11, about 10,000 on 3.12-3.13 (C recursion
    limit), and when stack space runs low (about 40,000 levels with an 8 MiB
    stack) on 3.14+. Deeper
    documents are rejected; shallower ones are harmless because TTPrism never
    walks parsed data recursively. An explicit depth check would cost a second
    pass over large sandbox reports for no extra protection.
    """
    try:
        return json.loads(text)
    except RecursionError:
        raise InputError("JSON nesting too deep") from None
    except ValueError as exc:
        raise InputError(f"invalid JSON: {exc}") from None
