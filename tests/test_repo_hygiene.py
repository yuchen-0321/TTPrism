"""Repository checks that protect reviewers and users."""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".yaml", ".yml", ".md", ".json", ".toml", ".txt", ".cfg"}
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "build",
    "dist",
    "__pycache__",
    ".hypothesis",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}


def tracked_text_files() -> list[Path]:
    return [
        p
        for p in ROOT.rglob("*")
        if p.is_file() and p.suffix in TEXT_SUFFIXES and not SKIP_DIRS.intersection(p.relative_to(ROOT).parts)
    ]


@pytest.mark.parametrize("path", tracked_text_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_invisible_or_bidi_characters(path: Path) -> None:
    """Invisible and bidirectional-control characters can hide code from review
    ("Trojan Source", CVE-2021-42574). Test data must spell them as escapes."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for char in line:
            if char != "\t" and unicodedata.category(char) in ("Cc", "Cf"):
                pytest.fail(f"line {number}: U+{ord(char):04X} {unicodedata.name(char, '')}")
