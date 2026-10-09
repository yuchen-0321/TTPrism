from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ttprism import __version__
from ttprism.cli import main


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_extract_json(capsys: pytest.CaptureFixture[str], data_dir: Path) -> None:
    code, out, err = run(capsys, "extract", str(data_dir / "report_zh.md"), "--include-reserved")
    assert code == 0, err
    data = json.loads(out)
    values = {(i["type"], i["value"]) for i in data["iocs"]}
    assert ("domain", "update-check.example") in values
    assert ("domain", "sync.example.net") in values
    assert ("url", "https://cdn.update-check.example/payload/stage2.bin") in values
    assert ("ipv4", "198.51.100.23") in values
    assert ("email", "attacker@mail-update.example") in values
    assert ("cve", "CVE-2023-23397") in values
    assert ("cve", "CVE-2021-40444") in values
    assert ("domain", "payload.zip") not in values
    techniques = {t["id"]: t for t in data["techniques"]}
    assert techniques["T1059.001"]["original_ids"] == ["T1086"]
    assert techniques["T1685"]["original_ids"] == ["T1562.001"]


def test_extract_defaults_hide_reserved_values(capsys: pytest.CaptureFixture[str], data_dir: Path) -> None:
    code, out, _ = run(capsys, "extract", str(data_dir / "report_zh.md"))
    assert code == 0
    data = json.loads(out)
    assert {i["type"] for i in data["iocs"]} == {"md5", "sha256", "cve"}
    assert data["suppressed"]["reserved"] > 5


def test_extract_cape_to_csv_file(capsys: pytest.CaptureFixture[str], data_dir: Path, tmp_path: Path) -> None:
    output = tmp_path / "out.csv"
    report = str(data_dir / "cape_report.json")
    code, out, err = run(capsys, "extract", report, "-f", "csv", "-o", str(output))
    assert code == 0, err
    assert out == ""
    rows = list(csv.reader(io.StringIO(output.read_text(encoding="utf-8"))))
    assert ["attack-technique", "T1490", "rule:cmd.inhibit-recovery", "Inhibit System Recovery"] in rows


def test_extract_stix(capsys: pytest.CaptureFixture[str], data_dir: Path) -> None:
    code, out, err = run(capsys, "extract", str(data_dir / "cape_report.json"), "-f", "stix", "--defang")
    assert code == 0
    assert json.loads(out)["type"] == "bundle"
    assert "--defang is ignored" in err


def test_extract_defang(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "r.txt"
    report.write_text("https://evil.com/x", encoding="utf-8")
    code, out, _ = run(capsys, "extract", str(report), "--defang", "-f", "csv")
    assert code == 0
    assert "hxxps[://]evil[.]com/x" in out


def test_stdin(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO("evil【.】com".encode())))
    code, out, _ = run(capsys, "extract", "-")
    assert code == 0
    assert json.loads(out)["iocs"][0]["value"] == "evil.com"


def test_encoding_option(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "big5.txt"
    report.write_bytes("惡意網域 evil．com".encode("big5", errors="ignore") + b" evil2.com")
    code, out, err = run(capsys, "extract", str(report))
    assert code == 0
    assert "not valid UTF-8" in err
    code, out, err = run(capsys, "extract", str(report), "--encoding", "big5")
    assert code == 0
    assert err == ""
    assert {i["value"] for i in json.loads(out)["iocs"]} == {"evil.com", "evil2.com"}


def test_max_size(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "big.txt"
    report.write_text("x" * 2048, encoding="utf-8")
    code, _, err = run(capsys, "extract", str(report), "--max-size", "1k")
    assert code == 1
    assert "larger than the 1024-byte limit" in err


def test_refuses_to_overwrite_input(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "r.txt"
    report.write_text("evil.com", encoding="utf-8")
    code, _, err = run(capsys, "extract", str(report), "-o", str(report))
    assert code == 2
    assert "output file is the input file" in err
    assert report.read_text(encoding="utf-8") == "evil.com"


def test_bad_inputs(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "extract", str(tmp_path / "missing.txt"))
    assert code == 1
    assert "cannot read" in err

    # Valid JSON nested deeper than the interpreter allows on every supported
    # version: the recursion limit on 3.11-3.13, stack-space checks on 3.14+.
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 1_000_000 + "]" * 1_000_000, encoding="utf-8")
    code, _, err = run(capsys, "extract", str(deep), "--input-format", "cape")
    assert code == 1
    assert "nesting too deep" in err

    not_cape = tmp_path / "x.json"
    not_cape.write_text('{"a": "evil.com"}', encoding="utf-8")
    code, out, err = run(capsys, "extract", str(not_cape))
    assert code == 0
    assert "not a CAPE report" in err
    assert json.loads(out)["iocs"][0]["value"] == "evil.com"


def test_custom_allowlist_and_rules(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "r.txt"
    report.write_text("evil.com good.com", encoding="utf-8")
    allow = tmp_path / "allow.yaml"
    allow.write_text("domains: [good.com]\n", encoding="utf-8")
    code, out, _ = run(capsys, "extract", str(report), "--allowlist", str(allow))
    assert [i["value"] for i in json.loads(out)["iocs"]] == ["evil.com"]

    allow.write_text("domains: [not valid]\n", encoding="utf-8")
    code, _, err = run(capsys, "extract", str(report), "--allowlist", str(allow))
    assert code == 1
    assert "not a valid domain" in err

    rules = tmp_path / "rules.yaml"
    rules.write_text(
        'attack_version: "19.2"\nrules: [{id: cmd.powershell, technique: T1059.001, '
        "match: {commands: [x]}}]\n",
        encoding="utf-8",
    )
    code, _, err = run(capsys, "extract", str(report), "--rules", str(rules))
    assert code == 1
    assert "duplicate rule id" in err
    code, _, err = run(capsys, "extract", str(report), "--rules", str(rules), "--no-default-rules")
    assert code == 0


def test_validate_rules(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run(capsys, "validate-rules")
    assert code == 0
    assert "against ATT&CK 19.2: OK" in out

    rules = tmp_path / "old.yaml"
    rules.write_text(
        'attack_version: "19.2"\nrules: [{id: x, technique: T1086, match: {commands: [x]}}]\n',
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "validate-rules", str(rules))
    assert code == 1
    assert "T1086 is revoked; use T1059.001" in out


def test_module_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "ttprism", "--version"], capture_output=True, text=True, check=True
    )
    assert proc.stdout.strip() == f"ttprism {__version__}"
