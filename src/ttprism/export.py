"""JSON and CSV output."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from ttprism._version import __version__
from ttprism.inputs import without_surrogates
from ttprism.models import AnalysisResult
from ttprism.refang import defang

# A cell starting with one of these is evaluated as a formula by Excel,
# LibreOffice and Google Sheets (OWASP "CSV injection").
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


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
        # A name taken from a non-UTF-8 file name carries surrogates, which cannot be encoded.
        "input": {"name": without_surrogates(name) if name else name, "format": result.input_format},
        "attack_version": result.attack_version,
        "defanged": defanged,
        "iocs": iocs,
        "techniques": [t.to_dict() for t in result.techniques],
        "suppressed": result.suppressed,
        "warnings": result.warnings,
    }


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
