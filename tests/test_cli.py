from __future__ import annotations

import codecs
import csv
import functools
import io
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from ttprism import __version__, cli
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


def _report(tmp_path: Path, text: str = "evil.com") -> Path:
    report = tmp_path / "r.txt"
    report.write_text(text, encoding="utf-8")
    return report


def test_unencodable_output_is_replaced(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A lone surrogate (from a "\ud800" escape in a JSON report) used to crash the UTF-8 encoder.
    report = _report(tmp_path)
    monkeypatch.setattr(cli, "to_json", lambda result, defanged: "x\ud800\n")
    code, out, err = run(capsys, "extract", str(report))
    assert code == 0, err
    assert out == "x\ufffd\n"
    output = tmp_path / "out.json"
    code, _, err = run(capsys, "extract", str(report), "-o", str(output))
    assert code == 0, err
    assert output.read_bytes() == "x\ufffd\n".encode()


@pytest.mark.skipif(sys.platform != "linux", reason="needs a file system that accepts non-UTF-8 names")
def test_non_utf8_file_name(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / os.fsdecode(b"n\xffame.txt")  # the name reaches Python with a surrogate
    report.write_text("evil.com", encoding="utf-8")
    code, out, err = run(capsys, "extract", str(report))
    assert code == 0, err
    assert json.loads(out)["input"]["name"].endswith("n\ufffdame.txt")


def test_failed_write_keeps_the_existing_output_file(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _report(tmp_path)
    output = tmp_path / "out.json"
    output.write_text("previous", encoding="utf-8")

    def disk_full(stream: Any, data: bytes) -> None:
        stream.write(data[:10])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "_write_all", disk_full)
    code, _, err = run(capsys, "extract", str(report), "-o", str(output))
    assert code == 1
    assert f"cannot write {output}: No space left on device" in err
    assert output.read_text(encoding="utf-8") == "previous"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.json", "r.txt"]  # no temporary file left


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions and symlinks")
def test_output_file_keeps_its_mode_and_symlink(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = _report(tmp_path)
    output = tmp_path / "out.json"
    output.write_text("previous", encoding="utf-8")
    output.chmod(0o640)
    link = tmp_path / "link.json"
    link.symlink_to(output)
    code, _, err = run(capsys, "extract", str(report), "-o", str(link))
    assert code == 0, err
    assert link.is_symlink()
    assert stat.S_IMODE(output.stat().st_mode) == 0o640
    assert json.loads(output.read_text(encoding="utf-8"))["iocs"][0]["value"] == "evil.com"


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX permissions, not root")
def test_read_only_output_file_is_refused(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    # Moving a new file into place needs only a writable directory; keep honouring the file's mode.
    report = _report(tmp_path)
    output = tmp_path / "out.json"
    output.write_text("previous", encoding="utf-8")
    output.chmod(0o444)
    code, _, err = run(capsys, "extract", str(report), "-o", str(output))
    assert code == 1
    assert "Permission denied" in err
    assert output.read_text(encoding="utf-8") == "previous"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_output_to_a_named_pipe_is_written_through(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Special files such as /dev/null or a FIFO must be written to, never replaced.
    report = _report(tmp_path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    received: list[bytes] = []
    reader = threading.Thread(target=lambda: received.append(fifo.read_bytes()), daemon=True)
    reader.start()
    code, _, err = run(capsys, "extract", str(report), "-o", str(fifo))
    reader.join(10)
    assert code == 0, err
    assert stat.S_ISFIFO(fifo.stat().st_mode)
    assert json.loads(received[0])["iocs"][0]["value"] == "evil.com"


def test_rule_file_aliases_and_deep_nesting(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    # Lists of lists are valid in rule files, so aliases used to expand to N*M phrases.
    phrases, aliases = ", ".join(["p"] * 2000), ", ".join(["*a"] * 2000)
    rules = tmp_path / "alias.yaml"
    rules.write_text(
        'attack_version: "19.2"\nrules:\n  - id: x\n    technique: T1059\n    match:\n'
        f"      commands: [&a [{phrases}], {aliases}]\n",
        encoding="utf-8",
    )
    start = time.perf_counter()
    code, _, err = run(capsys, "validate-rules", str(rules))
    assert time.perf_counter() - start < 2
    assert code == 1
    assert "YAML aliases are not allowed" in err

    rules.write_text("rules: " + "[" * 2000 + "]" * 2000 + "\n", encoding="utf-8")
    code, _, err = run(capsys, "validate-rules", str(rules))
    assert code == 1
    assert "YAML nesting too deep" in err


def test_auto_mode_reports_unparsable_json(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    broken = tmp_path / "report.json"
    broken.write_text('{"info": {}, "network": {"hosts": ["evil.com"', encoding="utf-8")
    code, out, err = run(capsys, "extract", str(broken))
    assert code == 0, err
    assert "input looks like JSON but could not be parsed (invalid JSON: " in err
    data = json.loads(out)
    assert data["input"]["format"] == "text"
    assert data["iocs"][0]["value"] == "evil.com"

    broken.write_text('{"info": {}, "x": ' + "[" * 1_000_000 + "]" * 1_000_000 + "}", encoding="utf-8")
    code, out, err = run(capsys, "extract", str(broken))
    assert code == 0, err
    assert "could not be parsed (JSON nesting too deep)" in err


def test_bom_is_stripped_with_explicit_encoding(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "bom.json"
    report.write_bytes(
        codecs.BOM_UTF8
        + b'{"info": {}, "behavior": {"summary": {"executed_commands": ["vssadmin delete shadows /all"]}}}'
    )
    for extra in ([], ["--encoding", "utf-8"]):
        code, out, err = run(capsys, "extract", str(report), *extra)
        assert code == 0, err
        assert err == ""
        data = json.loads(out)
        assert data["input"]["format"] == "cape"
        assert "T1490" in {t["id"] for t in data["techniques"]}


def test_max_size_ceiling(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = _report(tmp_path)
    with pytest.raises(SystemExit) as exit_info:
        main(["extract", str(report), "--max-size", "17g"])
    assert exit_info.value.code == 2
    assert "size too large: '17g' (at most 16g)" in capsys.readouterr().err
    code, out, err = run(capsys, "extract", str(report), "--max-size", "16g")
    assert code == 0, err
    assert json.loads(out)["iocs"][0]["value"] == "evil.com"


def test_input_is_read_in_chunks(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # read(max_size + 1) used to allocate the whole limit up front (MemoryError for large --max-size).
    requested: list[int] = []

    class Recorder(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            requested.append(-1 if size is None else size)
            return super().read(size)

    payload = b"evil.com " * 300_000
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(Recorder(payload)))
    code, _, err = run(capsys, "extract", "-", "--max-size", "16g")
    assert code == 0, err
    assert 0 < max(requested) <= 1024 * 1024
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
    code, _, err = run(capsys, "extract", "-", "--max-size", str(len(payload) - 1))
    assert code == 1
    assert f"larger than the {len(payload) - 1}-byte limit" in err


@pytest.mark.parametrize("encoding", ["idna", "undefined", "punycode"])
def test_unusable_encodings_are_clean_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, encoding: str
) -> None:
    report = tmp_path / "r.txt"
    report.write_bytes(b"abc-\xff\xfe!!zz~~")
    code, _, err = run(capsys, "extract", str(report), "--encoding", encoding)
    # From Python 3.13 the punycode codec honours errors="replace" and decodes this input;
    # earlier versions, and the other codecs on every version, refuse it.
    if encoding == "punycode" and code == 0:
        assert "Traceback" not in err
    else:
        assert code == 1
        assert f"ttprism: error: cannot decode input as {encoding}: " in err
    code, _, err = run(capsys, "extract", str(report), "--encoding", "no-such-codec")
    assert code == 1
    assert "unknown encoding: no-such-codec" in err


def test_utf32_and_bomless_utf16(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = tmp_path / "r.txt"
    for bom, codec in ((codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be")):
        report.write_bytes(bom + "evil.com\n".encode(codec))
        code, out, err = run(capsys, "extract", str(report))
        assert code == 0, err
        assert err == ""
        assert [i["value"] for i in json.loads(out)["iocs"]] == ["evil.com"]

    report.write_bytes("evil.com\n".encode("utf-16-le"))
    code, out, err = run(capsys, "extract", str(report))
    assert code == 0
    assert "many NUL characters" in err
    assert "--encoding utf-16-le" in err
    code, out, err = run(capsys, "extract", str(report), "--encoding", "utf-16-le")
    assert err == ""
    assert [i["value"] for i in json.loads(out)["iocs"]] == ["evil.com"]


def test_missing_standard_streams(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "stdin", None)
    code, _, err = run(capsys, "extract", "-")
    assert code == 1
    assert "ttprism: error: standard input is not available" in err

    monkeypatch.setattr(sys, "stdin", io.StringIO("evil.com"))  # a text stream without .buffer
    code, out, err = run(capsys, "extract", "-")
    assert code == 0, err
    assert json.loads(out)["iocs"][0]["value"] == "evil.com"

    monkeypatch.setattr(sys, "stdout", None)
    code = main(["extract", str(_report(tmp_path))])
    assert code == 1
    assert "ttprism: error: standard output is not available" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="closes a standard descriptor in the child")
@pytest.mark.parametrize(("fd", "stream"), [(0, "input"), (1, "output")])
def test_closed_standard_descriptors(tmp_path: Path, fd: int, stream: str) -> None:
    target = "-" if fd == 0 else str(_report(tmp_path))
    proc = subprocess.run(
        [sys.executable, "-m", "ttprism", "extract", target],
        stderr=subprocess.PIPE,
        preexec_fn=functools.partial(os.close, fd),
        check=False,
    )
    assert proc.returncode == 1
    assert proc.stderr.decode() == f"ttprism: error: standard {stream} is not available\n"


class _TrickleBuffer(io.BytesIO):
    """Accepts a few bytes per write, as a pipe or a nearly full disk may."""

    def write(self, data: Any) -> int:
        return super().write(bytes(data[:7]))


class _StuckBuffer(io.BytesIO):
    def write(self, data: Any) -> int:
        return 0


def test_short_writes_are_completed_or_reported(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _report(tmp_path)
    sink = _TrickleBuffer()
    wrapper = io.TextIOWrapper(sink, encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", wrapper)
    assert main(["extract", str(report)]) == 0
    assert json.loads(sink.getvalue())["iocs"][0]["value"] == "evil.com"

    stuck = io.TextIOWrapper(_StuckBuffer(), encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", stuck)
    assert main(["extract", str(report)]) == 1
    assert "output was cut short" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="Windows reports a closed pipe as EINVAL")
def test_closed_pipe_fails_quietly(tmp_path: Path) -> None:
    # Like `ttprism extract big.txt | head -c 10`: no traceback or message, but a failure status.
    report = _report(tmp_path, "\n".join(f"host{i}.evil.com" for i in range(20_000)))
    proc = subprocess.Popen(
        [sys.executable, "-m", "ttprism", "extract", str(report)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    assert proc.stdout.read(10) == b'{\n  "tool"'
    proc.stdout.close()
    stderr = proc.stderr.read()
    proc.stderr.close()
    assert proc.wait(timeout=120) == 1
    assert stderr == b""


def test_messages_are_safe_for_terminals(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    report = _report(tmp_path)
    allow = tmp_path / "allow.yaml"
    # YAML escapes put raw ESC and BEL into a key name.
    allow.write_text('"\\e]0;PWNED\\a\\e[2J": []\n', encoding="utf-8")
    code, _, err = run(capsys, "extract", str(report), "--allowlist", str(allow))
    assert code == 1
    assert "unknown keys" in err
    assert "\x1b" not in err
    assert "\x07" not in err

    # PyYAML quotes the offending line, bidi override and all.
    allow.write_text("domains: [x\u202ey\n", encoding="utf-8")
    code, _, err = run(capsys, "extract", str(report), "--allowlist", str(allow))
    assert code == 1
    assert "invalid YAML" in err
    assert "\u202e" not in err
    assert "x\ufffdy" in err
    assert all(line.startswith(("ttprism: error: ", "  ")) for line in err.splitlines())


def test_terminal_safe() -> None:
    message = "a\x1b[2J\x07b\r\u202ec\u2066d\x85e\udcfff\tg\nh"
    assert cli._terminal_safe(message) == ("a\ufffd[2J\ufffdb\ufffd\ufffdc\ufffdd\ufffde\ufffdf\tg\n  h")


@pytest.mark.skipif(os.name != "posix", reason="needs a control character in a file name")
def test_validate_rules_output_is_terminal_safe(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rules = tmp_path / "a\x1b[2Jb.yaml"
    rules.write_text('attack_version: "18.0"\nrules: []\n', encoding="utf-8")
    code, out, _ = run(capsys, "validate-rules", str(rules))
    assert code == 1
    assert "WARNING" in out
    assert "\x1b" not in out


def test_validate_rules_on_a_narrow_console(tmp_path: Path) -> None:
    # print() raised UnicodeEncodeError for a non-ASCII rule path when stdout is cp1252 (Windows redirects).
    rules = tmp_path / "規則.yaml"
    rules.write_text('attack_version: "18.0"\nrules: []\n', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "ttprism", "validate-rules", str(rules)],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "cp1252"},
        check=False,
    )
    assert b"Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 1
    out = proc.stdout.decode("utf-8")
    assert "WARNING" in out
    assert "規則.yaml" in out
    assert "with warnings" in out
