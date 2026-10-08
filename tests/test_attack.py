from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ttprism import AttackCatalog, Behavior, RuleError, RuleSet
from ttprism.attack import TechniqueAccumulator, default_rules_path, normalize_command

CATALOG = AttackCatalog.default()


def write_rules(tmp_path: Path, body: str, version: str = '"19.2"') -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(
        f"attack_version: {version}\nrules:\n" + textwrap.indent(textwrap.dedent(body), "  "),
        encoding="utf-8",
    )
    return path


# --------------------------------------------------------------------------- catalog


def test_catalog_version_and_lookup() -> None:
    assert CATALOG.version == "19.2"
    technique = CATALOG.get("T1059.001")
    assert technique is not None
    assert technique.name == "PowerShell"
    assert technique.tactics == ("execution",)


@pytest.mark.parametrize(
    ("old", "current"),
    [
        ("T1086", "T1059.001"),  # PowerShell, revoked in 2020
        ("T1045", "T1027.002"),  # Software Packing
        ("T1562.001", "T1685"),  # Disable or Modify Tools, moved in v19
        ("T1070.001", "T1685.005"),  # Clear Windows Event Logs, moved in v19
        ("T1059.001", "T1059.001"),
    ],
)
def test_resolve_follows_revocations(old: str, current: str) -> None:
    resolved = CATALOG.resolve(old)
    assert resolved is not None
    assert resolved.id == current
    assert resolved.status == "active"


def test_deprecated_and_unknown() -> None:
    scripting = CATALOG.resolve("T1064")
    assert scripting is not None
    assert scripting.status == "deprecated"
    assert CATALOG.resolve("T9999") is None


def test_accumulator_merges_and_records_original_ids() -> None:
    acc = TechniqueAccumulator(CATALOG)
    acc.add_reported("T1086", "named in text: T1086")
    acc.add_reported("T1059.001", "named in text: T1059.001")
    acc.add_reported("T9999", "named in text: T9999")
    (match,) = acc.results()
    assert match.technique_id == "T1059.001"
    assert match.original_ids == ("T1086",)
    assert match.reported
    assert acc.unknown == {"T9999": 1}


# --------------------------------------------------------------------------- rule loading


def test_bundled_rules_are_clean() -> None:
    ruleset = RuleSet.load([default_rules_path()])
    assert ruleset.warnings == []
    assert len(ruleset.rules) >= 100
    for rule in ruleset.rules:
        technique = CATALOG.get(rule.technique)
        assert technique is not None, rule.id
        assert technique.status == "active", rule.id
        assert rule.references, f"{rule.id} needs a reference"
        assert rule.description, f"{rule.id} needs a description"


def test_rule_warnings_for_outdated_techniques(tmp_path: Path) -> None:
    path = write_rules(
        tmp_path,
        """\
        - id: old
          technique: T1086
          match: {commands: [powershell]}
        - id: gone
          technique: T1064
          match: {commands: [wscript]}
        - id: future
          technique: T1999
          match: {commands: [whatever]}
        """,
        version='"18.0"',
    )
    ruleset = RuleSet.load([path])
    text = "\n".join(ruleset.warnings)
    assert "written for ATT&CK 18.0" in text
    assert "T1086 is revoked; use T1059.001" in text
    assert "T1064 is deprecated" in text
    assert "T1999 is not in ATT&CK 19.2" in text


@pytest.mark.parametrize(
    ("body", "version", "message"),
    [
        ("- id: x\n  technique: T1059\n  match: {commands: [a]}\n", "19.2", "quoted string"),
        ("- id: x\n  technique: 1059\n  match: {commands: [a]}\n", '"19.2"', "technique"),
        ("- id: x\n  technique: T1059\n", '"19.2"', "'match'"),
        ("- id: x\n  technique: T1059\n  match: {cmd: [a]}\n", '"19.2"', "unknown matchers"),
        ("- id: x\n  technique: T1059\n  typo: 1\n  match: {commands: [a]}\n", '"19.2"', "unknown keys"),
        (
            "- id: x\n  technique: T1059\n  confidence: certain\n  match: {commands: [a]}\n",
            '"19.2"',
            "confidence",
        ),
        ("- id: 'bad id'\n  technique: T1059\n  match: {commands: [a]}\n", '"19.2"', "'id'"),
        ("- id: x\n  technique: T1059\n  match: {signatures: ['[a-z]*']}\n", '"19.2"', "signature patterns"),
        ("- id: x\n  technique: T1059\n  match: {apis: ['Nt Foo']}\n", '"19.2"', "not an API name"),
        ("- id: x\n  technique: T1059\n  match: {commands: []}\n", '"19.2"', "non-empty"),
        (
            "- id: x\n  technique: T1059\n  match: {commands: [a]}\n"
            "- id: x\n  technique: T1059\n  match: {commands: [b]}\n",
            '"19.2"',
            "duplicate rule id",
        ),
    ],
)
def test_invalid_rules(tmp_path: Path, body: str, version: str, message: str) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(f"attack_version: {version}\nrules:\n" + textwrap.indent(body, "  "), encoding="utf-8")
    with pytest.raises(RuleError, match=message):
        RuleSet.load([path])


def test_missing_rules_path(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="no such file"):
        RuleSet.load([tmp_path / "nope"])


# --------------------------------------------------------------------------- rule matching


def evaluate(tmp_path: Path, match: str, behavior: Behavior) -> list[str]:
    path = write_rules(tmp_path, f"- id: r\n  technique: T1059\n  match: {match}\n")
    hits = RuleSet.load([path]).evaluate(behavior)
    return hits[0][1] if hits else []


def test_command_phrases_respect_word_boundaries(tmp_path: Path) -> None:
    match = "{commands: [[sc, create, binpath]]}"
    assert evaluate(tmp_path, match, Behavior(commands=['"C:\\Windows\\sc.exe" create svc binPath= x']))
    assert not evaluate(tmp_path, match, Behavior(commands=["describe script create binpaths"]))


def test_command_normalisation_defeats_caret_and_quote_obfuscation(tmp_path: Path) -> None:
    assert normalize_command('s^c^h^t^a^s^k^s  /Create   "/TN" x') == "schtasks /create /tn x"
    evidence = evaluate(
        tmp_path, "{commands: [[schtasks, /create]]}", Behavior(commands=['s^c^h^t^a^s^k^s /Create /TN "x"'])
    )
    assert evidence == ['command: s^c^h^t^a^s^k^s /Create /TN "x"']


def test_signature_globs(tmp_path: Path) -> None:
    behavior = Behavior(signatures=["antivm_vbox_files", "packer_upx"])
    assert evaluate(tmp_path, "{signatures: ['antivm_*']}", behavior) == ["signature: antivm_vbox_files"]
    assert evaluate(tmp_path, "{signatures: ['ANTIVM_VBOX_FILES']}", behavior)
    assert not evaluate(tmp_path, "{signatures: [antivm]}", behavior)


def test_apis_and_apis_all(tmp_path: Path) -> None:
    behavior = Behavior(apis={"NtWriteVirtualMemory", "CreateRemoteThread"})
    assert evaluate(tmp_path, "{apis: ['WriteProcessMemory|NtWriteVirtualMemory']}", behavior)
    assert evaluate(
        tmp_path, "{apis_all: [[ 'NtWriteVirtualMemory|WriteProcessMemory', CreateRemoteThread ]]}", behavior
    ) == ["apis: createremotethread, ntwritevirtualmemory"]
    assert not evaluate(tmp_path, "{apis_all: [[NtWriteVirtualMemory, NtQueueApcThread]]}", behavior)


def test_registry_patterns(tmp_path: Path) -> None:
    key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\updater"
    behavior = Behavior(registry_writes=[key])
    assert evaluate(tmp_path, r"{registry: ['\currentversion\run\']}", behavior) == [f"registry: {key}"]
    assert evaluate(tmp_path, r"{registry: [['hkey_current_user', '\run\']]}", behavior)
    assert not evaluate(tmp_path, r"{registry: [['hkey_local_machine', '\run\']]}", behavior)


def test_evidence_is_sanitised(tmp_path: Path) -> None:
    evidence = evaluate(
        tmp_path,
        "{commands: [powershell]}",
        Behavior(commands=["powershell \x1b[31mred\x1b[0m " + "A" * 500]),
    )
    assert "\x1b" not in evidence[0]
    assert len(evidence[0]) <= 200
