from __future__ import annotations

import csv
import io
import json
from typing import Any

import pytest

from ttprism import IOC, AnalysisOptions, AnalysisResult, IOCType, TechniqueMatch, analyze_cape, analyze_text
from ttprism.export import escape_csv_cell, to_csv, to_dict, to_json


def sample_result() -> AnalysisResult:
    return AnalysisResult(
        input_format="text",
        iocs=[
            IOC(IOCType.URL, "https://evil.com/a", ("text",)),
            IOC(IOCType.DOMAIN, "evil.com", ("text",)),
            IOC(IOCType.EMAIL, "+cmd@evil.com", ("text",)),
        ],
        techniques=[
            TechniqueMatch(
                technique_id="T1059.001",
                name="PowerShell",
                tactics=("execution",),
                status="active",
                reported=True,
                rules=("cmd.powershell",),
                confidence="high",
                evidence=("command: powershell -enc AAAA",),
                original_ids=("T1086",),
            )
        ],
        attack_version="19.2",
        suppressed={"reserved": 1},
        warnings=["something"],
        input_name="report.md",
    )


def test_json_structure() -> None:
    data = json.loads(to_json(sample_result()))
    assert data["tool"] == "ttprism"
    assert data["attack_version"] == "19.2"
    assert data["input"] == {"name": "report.md", "format": "text"}
    assert data["iocs"][0] == {"type": "url", "value": "https://evil.com/a", "sources": ["text"]}
    technique = data["techniques"][0]
    assert technique["id"] == "T1059.001"
    assert technique["original_ids"] == ["T1086"]
    assert technique["url"] == "https://attack.mitre.org/techniques/T1059/001/"
    assert data["suppressed"] == {"reserved": 1}


def test_defanged_json() -> None:
    data = to_dict(sample_result(), defanged=True)
    assert data["defanged"] is True
    assert [i["value"] for i in data["iocs"]] == ["hxxps[://]evil[.]com/a", "evil[.]com", "+cmd[@]evil[.]com"]


def test_csv_rows_and_formula_escaping() -> None:
    rows = list(csv.reader(io.StringIO(to_csv(sample_result()))))
    assert rows[0] == ["type", "value", "sources", "detail"]
    assert rows[1] == ["url", "https://evil.com/a", "text", ""]
    assert rows[3][1] == "'+cmd@evil.com"  # would otherwise be a formula
    assert rows[4] == [
        "attack-technique",
        "T1059.001",
        "reported;rule:cmd.powershell",
        "PowerShell (reported as T1086)",
    ]


@pytest.mark.parametrize("cell", ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1"])
def test_escape_csv_cell(cell: str) -> None:
    assert escape_csv_cell(cell) == "'" + cell


def test_escape_csv_cell_leaves_normal_values() -> None:
    assert escape_csv_cell("evil.com") == "evil.com"
    assert escape_csv_cell("") == ""


def test_output_never_contains_raw_control_characters(cape_report: dict[str, Any]) -> None:
    cape_report["behavior"]["summary"]["executed_commands"].append("powershell \x1b]0;pwned\x07 -c x")
    result = analyze_cape(cape_report)
    for text in (to_json(result), to_csv(result)):
        assert "\x1b" not in text
        assert "\x07" not in text


def test_round_trip_through_text() -> None:
    result = analyze_text("hxxp://evil[.]com/x 203.0.113[.]9", AnalysisOptions(include_reserved=True))
    data = to_dict(result)
    assert [i["value"] for i in data["iocs"]] == ["http://evil.com/x", "evil.com", "203.0.113.9"]
