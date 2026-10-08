#!/usr/bin/env python3
"""Regenerate src/ttprism/data/tlds.txt from IANA's list of top-level domains.

Usage:
    python scripts/update_tlds.py                         # download from IANA
    python scripts/update_tlds.py --input tlds-alpha-by-domain.txt
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "ttprism" / "data" / "tlds.txt"


def render(raw: str, source: str) -> str:
    header = [line for line in raw.splitlines() if line.startswith("#")]
    tlds = sorted({line.strip().lower() for line in raw.splitlines() if line and not line.startswith("#")})
    lines = [*header, f"# Source: {source}", *tlds]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, help="local copy of tlds-alpha-by-domain.txt")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    if args.input:
        raw, source = args.input.read_text(encoding="utf-8"), str(args.input.name)
    else:
        with urllib.request.urlopen(IANA_URL, timeout=60) as response:
            raw, source = response.read().decode("ascii"), IANA_URL

    text = render(raw, source)
    args.output.write_text(text, encoding="utf-8")
    count = sum(1 for line in text.splitlines() if not line.startswith("#"))
    print(f"{count} TLDs -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
