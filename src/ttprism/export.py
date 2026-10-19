"""JSON and CSV output."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from ttprism._version import __version__
from ttprism.extract import (
    _LABEL,
    _TLD,
    DOMAIN_RE,
    EMAIL_RE,
    IPV4_RE,
    IPV6_RE,
    normalize_domain,
    normalize_ip,
)
from ttprism.inputs import printable
from ttprism.models import AnalysisResult, IOCType
from ttprism.refang import defang

# A cell starting with one of these is evaluated as a formula by Excel,
# LibreOffice and Google Sheets (OWASP "CSV injection").
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


# A URL's scheme, "://" and what comes before its path, at a token start, any scheme. The host ends
# where the next URL starts, so each URL of "'http://a.example','http://b.example'" is found.
_URL_START_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://"
    r"(?:(?![A-Za-z][A-Za-z0-9+-]{0,31}://)[^/?#\s]){0,1024}"
)
# A name anywhere but inside a longer name: also after "\", "@", "_" or "/", which DOMAIN_RE
# excludes ("...\ZoneMap\Domains\evil.example", "dig @ns1.evil.example", "_dmarc.evil.example").
_NAME_RE = re.compile(rf"(?<![A-Za-z0-9.-])(?:{_LABEL}\.){{1,126}}{_TLD}(?![A-Za-z0-9-]|\.[A-Za-z0-9])")


def defang_text(text: str) -> str:
    """``text``, such as a command line in technique evidence, with the URLs, domains, IP addresses
    and e-mail addresses in it defanged as :func:`~ttprism.refang.defang` defangs IOC values. Any
    scheme followed by ``://`` counts as a URL; a dot elsewhere is defanged only in a name with a
    known TLD or in an IP address, so ``T1059.001`` and ``cmd.exe`` stay as they are."""
    covered = bytearray(len(text))
    parts: list[tuple[int, int, str]] = []

    def take(start: int, end: int, ioc_type: IOCType) -> None:
        if covered.find(1, start, end) == -1:
            covered[start:end] = b"\x01" * (end - start)
            parts.append((start, end, defang(text[start:end], ioc_type)))

    for match in _URL_START_RE.finditer(text):
        take(*match.span(), IOCType.URL)
    for match in EMAIL_RE.finditer(text):
        if normalize_domain(match.group().rpartition("@")[2]) is not None:
            take(*match.span(), IOCType.EMAIL)
    for name_re in (DOMAIN_RE, _NAME_RE):
        for match in name_re.finditer(text):
            if normalize_domain(match.group()) is not None:
                take(*match.span(), IOCType.DOMAIN)
    for match in IPV6_RE.finditer(text):
        if normalize_ip(match.group()) is not None:
            take(*match.span(), IOCType.IPV6)
    for match in IPV4_RE.finditer(text):
        take(*match.span(), IOCType.IPV4)
    out, pos = [], 0
    for start, end, defanged in sorted(parts):
        out += [text[pos:start], defanged]
        pos = end
    out.append(text[pos:])
    return "".join(out)


def to_dict(result: AnalysisResult, *, defanged: bool = False) -> dict[str, Any]:
    iocs = []
    for ioc in result.iocs:
        entry = ioc.to_dict()
        if defanged:
            entry["value"] = defang(ioc.value, ioc.type)
        iocs.append(entry)
    name = result.input_name
    return {
        "tool": "ttprism",
        "version": __version__,
        # Library callers may set any name: no surrogates (unencodable) or terminal controls.
        "input": {"name": printable(name) if name else name, "format": result.input_format},
        "attack_version": result.attack_version,
        "defanged": defanged,
        "iocs": iocs,
        "techniques": [_technique(t.to_dict(), defanged) for t in result.techniques],
        "suppressed": result.suppressed,
        "warnings": [printable(w) for w in result.warnings],  # may quote rule file names
    }


def _technique(entry: dict[str, Any], defanged: bool) -> dict[str, Any]:
    if defanged:
        entry["evidence"] = [defang_text(e) for e in entry["evidence"]]
    return entry


def to_json(result: AnalysisResult, *, defanged: bool = False) -> str:
    return json.dumps(to_dict(result, defanged=defanged), ensure_ascii=False, indent=2) + "\n"


def escape_csv_cell(value: str) -> str:
    """Neutralise spreadsheet formulas by prefixing a single quote."""
    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def to_csv(result: AnalysisResult, *, defanged: bool = False) -> str:
    rows = [["type", "value", "sources", "detail"]]
    for ioc in result.iocs:
        value = defang(ioc.value, ioc.type) if defanged else ioc.value
        rows.append([str(ioc.type), value, ";".join(ioc.sources), ""])
    for technique in result.techniques:
        sources = (["reported"] if technique.reported else []) + [f"rule:{r}" for r in technique.rules]
        detail = technique.name
        if technique.original_ids:
            detail += f" (reported as {', '.join(technique.original_ids)})"
        rows.append(["attack-technique", technique.technique_id, ";".join(sources), detail])

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows([escape_csv_cell(cell) for cell in row] for row in rows)
    return buffer.getvalue()
