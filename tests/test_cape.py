from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from timing import seconds_per_mb, size_mb
from ttprism import AnalysisOptions, AttackCatalog, IOCType, analyze_cape
from ttprism.cape import (
    MAX_API_CHARS,
    MAX_FIELD_CHARS,
    MAX_ITEMS,
    MAX_SIGNATURE_CHARS,
    looks_like_cape,
    parse_cape,
)


def test_looks_like_cape(cape_report: dict[str, Any]) -> None:
    assert looks_like_cape(cape_report)
    assert not looks_like_cape({"info": {}})
    assert not looks_like_cape([cape_report])


def test_network_and_file_iocs(cape_report: dict[str, Any], raw_options: AnalysisOptions) -> None:
    result = analyze_cape(cape_report, raw_options)
    assert result.iocs_of(IOCType.URL) == [
        "http://update-check.example/gate.php?id=1",
        "http://update-check.example/p.ps1",  # only on the PowerShell command line
        "https://cdn.update-check.example/stage2.bin",
    ]
    assert result.iocs_of(IOCType.DOMAIN) == [
        "cdn.update-check.example",
        "update-check.example",
        "www.msftconnecttest.com",
    ]
    assert result.iocs_of(IOCType.IPV4) == [
        "192.0.2.80",
        "198.51.100.23",
        "203.0.113.5",
        "203.0.113.7",
        "8.8.8.8",
    ]
    assert "5f89cef4c9ed3f109bc7c400d822e60e" in result.iocs_of(IOCType.MD5)  # target
    assert "1b2062450bd3d9b1f41aadadae4f44f1" in result.iocs_of(IOCType.MD5)  # dropped
    sources = {i.value: i.sources for i in result.iocs}
    assert sources["update-check.example"] == (
        "cape:commands",
        "cape:network.domains",
        "cape:network.http",
    )


def test_default_filters_hide_reserved_and_noise(cape_report: dict[str, Any]) -> None:
    result = analyze_cape(cape_report)
    assert result.iocs_of(IOCType.DOMAIN) == []
    assert result.iocs_of(IOCType.IPV4) == []
    assert len(result.iocs_of(IOCType.SHA256)) == 2
    assert result.suppressed["allowlisted"] == 2  # 8.8.8.8, www.msftconnecttest.com


def test_rules_and_reported_ttps(cape_report: dict[str, Any]) -> None:
    result = analyze_cape(cape_report)
    by_id = {t.technique_id: t for t in result.techniques}

    # Rules: command line, caret-obfuscated command, registry, API sequence, signatures.
    assert by_id["T1490"].rules == ("cmd.inhibit-recovery",)
    assert by_id["T1053.005"].rules == ("cmd.scheduled-task",)
    assert by_id["T1547.001"].rules == ("reg.run-keys",)
    assert set(by_id["T1055.012"].rules) == {"cape.injection-runpe", "api.process-hollowing"}
    assert by_id["T1055.012"].confidence == "high"
    assert set(by_id["T1105"].rules) == {"cmd.download", "api.download-to-file"}

    # CAPE's own TTPs, with revoked IDs mapped to the current technique.
    packing = by_id["T1027.002"]
    assert packing.reported
    assert packing.original_ids == ("T1045",)
    assert "cape.packer-known" in packing.rules
    assert by_id["T1055"].reported
    assert by_id["T1055"].rules == ()

    assert result.suppressed["non_technique_ttp"] == 1  # S0105 is software, not a technique
    assert result.attack_version == "19.2"


def test_legacy_ttp_layout(cape_report: dict[str, Any]) -> None:
    report = copy.deepcopy(cape_report)
    report["ttps"] = [{"signature": "powershell_download", "ttp": "T1086"}]
    result = analyze_cape(report)
    powershell = next(t for t in result.techniques if t.technique_id == "T1059.001")
    assert powershell.reported
    assert powershell.original_ids == ("T1086",)


def test_old_style_string_hosts() -> None:
    parsed = parse_cape({"info": {}, "network": {"hosts": ["198.51.100.1", {"ip": "198.51.100.2"}, 7]}})
    assert {v for _, v, _ in parsed.iocs} == {"198.51.100.1", "198.51.100.2"}


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.update(network="oops"),
        lambda r: r.update(network={"hosts": "1.2.3.4", "dns": [None, 1, "x"], "http": {"uri": 1}}),
        lambda r: r.update(behavior={"processes": [{"calls": "NtWriteVirtualMemory"}], "summary": []}),
        lambda r: r.update(behavior={"summary": {"executed_commands": [None, 5, {"a": 1}]}}),
        lambda r: r.update(signatures=[None, {"name": 5}, "injection_runpe"]),
        lambda r: r.update(ttps=[{"signature": None, "ttps": [None, 5, "T1055"]}, "junk"]),
        lambda r: r.update(target={"file": {"md5": "zz" * 16, "sha256": 7}}),
        lambda r: r.update(dropped={"md5": "x"}, CAPE=[]),
        # Unhashable DNS answer types used to raise TypeError in the set lookup.
        lambda r: r.update(
            network={"dns": [{"request": "a.com", "answers": [{"type": ["A"], "data": "1"}]}]}
        ),
        lambda r: r.update(network={"dns": [{"answers": [{"type": {"A": 1}, "data": "1.2.3.4"}]}]}),
    ],
)
def test_malformed_reports_do_not_crash(cape_report: dict[str, Any], mutation: Any) -> None:
    report = copy.deepcopy(cape_report)
    mutation(report)
    analyze_cape(report)


def test_huge_field_values_are_truncated() -> None:
    report = {"info": {}, "behavior": {"summary": {"executed_commands": ["powershell " + "A" * 100_000]}}}
    result = analyze_cape(report)
    technique = next(t for t in result.techniques if t.technique_id == "T1059.001")
    assert all(len(e) <= 200 for e in technique.evidence)


def test_oversized_behaviour_lists_are_capped_and_fast() -> None:
    count = 50_000
    report = {
        "info": {},
        "behavior": {
            "summary": {
                "executed_commands": [f"cmd /c echo {i}" for i in range(count)],
                "write_keys": [f"HKEY_CURRENT_USER\\Software\\k{i}" for i in range(count)],
            },
            "processes": [{"calls": [{"api": f"Api{i}"} for i in range(count)]}],
        },
        "signatures": [{"name": f"sig_{i}"} for i in range(count)],
        "ttps": [{"signature": "s", "ttps": [f"T{9000 + i % 1000}" for i in range(count)]}],
    }
    results = []
    assert seconds_per_mb(lambda: results.append(analyze_cape(report)), size_mb(json.dumps(report))) < 2
    result = results[0]
    assert result.suppressed["truncated_commands"] == count - MAX_ITEMS
    assert result.suppressed["truncated_registry_writes"] == count - MAX_ITEMS
    assert result.suppressed["truncated_signatures"] == count - MAX_ITEMS
    assert result.suppressed["truncated_apis"] == count - MAX_ITEMS
    (warning,) = [w for w in result.warnings if "not in ATT&CK" in w]
    assert warning.endswith("and 980 more")


def test_rule_matching_sees_a_bounded_amount_of_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ttprism.cape.MAX_RULE_COMMAND_CHARS", 1000)
    commands = [f"cmd /c echo {i:03d} " + "x" * 280 for i in range(5)]
    commands.append("vssadmin delete shadows /all http://late.example.net/a")
    report = {"info": {}, "behavior": {"summary": {"executed_commands": commands}}}
    parsed = parse_cape(report)
    assert parsed.behavior.commands == commands[:3]
    assert parsed.stats["truncated_rule_commands"] == 3
    # IOCs still come from every command; the rules do not see the last ones.
    assert (IOCType.URL, "http://late.example.net/a") in {(t, v) for t, v, _ in parsed.iocs}
    result = analyze_cape(report)
    assert result.suppressed["truncated_rule_commands"] == 3
    assert "truncated_ioc_commands" not in result.suppressed
    assert "T1490" not in {t.technique_id for t in result.techniques}
    (warning,) = [w for w in result.warnings if "command line" in w]
    assert warning == (
        "3 command line(s) after the first 1,000 characters of commands were not matched against "
        "the ATT&CK rules"
    )


def test_ioc_extraction_sees_a_bounded_amount_of_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ttprism.cape.MAX_IOC_COMMAND_CHARS", 1000)
    commands = [f"curl http://c{i}.example.net/a " + "x" * 270 for i in range(5)]
    report = {
        "info": {},
        "target": {"file": {"md5": "5f89cef4c9ed3f109bc7c400d822e60e"}},
        "network": {"hosts": [{"ip": "198.51.100.7"}], "domains": [{"domain": "late.example.org"}]},
        "behavior": {"summary": {"executed_commands": commands}},
    }
    result = analyze_cape(report, AnalysisOptions(include_reserved=True))
    urls = result.iocs_of(IOCType.URL)
    assert urls == [f"http://c{i}.example.net/a" for i in range(3)]
    assert result.suppressed["truncated_ioc_commands"] == 2
    assert "truncated_rule_commands" not in result.suppressed
    (warning,) = [w for w in result.warnings if "command line" in w]
    assert (
        warning == "2 command line(s) after the first 1,000 characters of commands were not searched for IOCs"
    )
    # Structured fields are not capped.
    assert result.iocs_of(IOCType.IPV4) == ["198.51.100.7"]
    assert "late.example.org" in result.iocs_of(IOCType.DOMAIN)
    assert result.iocs_of(IOCType.MD5) == ["5f89cef4c9ed3f109bc7c400d822e60e"]


def test_dropped_api_names_are_counted_once() -> None:
    calls = [{"api": f"Api{i}"} for i in range(MAX_ITEMS)]
    # Repeats of kept names, names that are too long, invalid names and repeats of dropped names are
    # not counted.
    calls += [{"api": "Api0"}, {"api": "x" * 101}, {"api": 5}, {"api": "Late1"}, {"api": "Late2"}]
    calls += [{"api": "Late1"}]
    parsed = parse_cape({"info": {}, "behavior": {"processes": [{"calls": calls}, {"calls": calls}]}})
    assert len(parsed.behavior.apis) == MAX_ITEMS
    assert parsed.stats["truncated_apis"] == 2


def test_long_api_names_are_counted_once() -> None:
    calls = [{"api": "a" * MAX_API_CHARS}, {"api": "b" * (MAX_API_CHARS + 1)}, {"api": "c" * 5000}]
    calls += [{"api": "b" * (MAX_API_CHARS + 1)}]
    parsed = parse_cape({"info": {}, "behavior": {"processes": [{"calls": calls}, {"calls": calls}]}})
    assert parsed.behavior.apis == {"a" * MAX_API_CHARS}
    assert parsed.stats["long_api_names"] == 2


def test_long_signature_names_are_counted() -> None:
    names = ["s" * MAX_SIGNATURE_CHARS, "t" * (MAX_SIGNATURE_CHARS + 1), "t" * (MAX_SIGNATURE_CHARS + 1)]
    names.append("u" * (MAX_FIELD_CHARS + 1))
    parsed = parse_cape({"info": {}, "signatures": [{"name": n} for n in names]})
    assert parsed.behavior.signatures == ["s" * MAX_SIGNATURE_CHARS]
    # Counted as listed, like truncated_signatures; a name over MAX_FIELD_CHARS counts only here.
    assert parsed.stats == {"long_signature_names": 3}


def test_ttp_pairs_merged_by_the_signature_cut_are_counted() -> None:
    prefix = "s" * MAX_SIGNATURE_CHARS
    ttps = [
        {"signature": prefix + "_one", "ttps": ["T1055", "T1112"]},
        {"signature": prefix + "_two", "ttps": ["T1055"]},  # same pair as the first once cut
        {"signature": prefix + "_one", "ttps": ["T1055"]},  # a repeat, not a merge
        {"signature": "short", "ttps": ["T1055"]},
    ]
    parsed = parse_cape({"info": {}, "ttps": ttps})
    assert parsed.reported_ttps == [("T1055", prefix), ("T1112", prefix), ("T1055", "short")]
    assert parsed.stats == {"merged_ttps": 1}


def test_command_line_over_the_field_limit_is_cut_between_values() -> None:
    # The limit falls inside 198.51.100.23, which used to be reported as 198.51.100.2.
    head = "curl http://first.example.net/a "
    command = head + "x" * (MAX_FIELD_CHARS - len(head) - 13) + " 198.51.100.23 http://late.example.net/b"
    assert command[:MAX_FIELD_CHARS].endswith(" 198.51.100.2")
    report = {"info": {}, "behavior": {"summary": {"executed_commands": [command]}}}
    result = analyze_cape(report, AnalysisOptions(include_reserved=True))
    assert [(i.type, i.value) for i in result.iocs] == [
        (IOCType.URL, "http://first.example.net/a"),
        (IOCType.DOMAIN, "first.example.net"),
    ]
    assert result.suppressed == {"truncated_fields": 1}


@pytest.mark.parametrize(
    "value",
    [
        "c2.example {.} net",
        "c2.example <.> net",
        "c2.example \u300c.\u300d net",
        "c2.example \uff3b.\uff3d net",
        "c2.example \ufe5b.\ufe5c net",
        "c2.example[ . ]net",
        "c2.example \u3016 . \u3017 net",
        "c2.example ( dot ) net",
        "http[ :// ]c2.example.net",
    ],
)
def test_command_line_is_not_cut_inside_a_spaced_defang(value: str) -> None:
    # refang joins these across their spaces, so a cut at any of them would report c2.example (or
    # nothing for the URL) for c2.example.net; the line is cut before the value instead.
    head = "curl http://first.example.net/a "
    last_blank = value.rindex(" ")
    command = head + "x" * (MAX_FIELD_CHARS - len(head) - last_blank - 3) + " " + value + " tail"
    assert command[:MAX_FIELD_CHARS].endswith(value[: last_blank + 2])
    report = {"info": {}, "behavior": {"summary": {"executed_commands": [command]}}}
    assert parse_cape(report).behavior.commands == [command[: command.index(" " + value)]]
    result = analyze_cape(report, AnalysisOptions(include_reserved=True))
    assert [(i.type, i.value) for i in result.iocs] == [
        (IOCType.URL, "http://first.example.net/a"),
        (IOCType.DOMAIN, "first.example.net"),
    ]
    assert result.suppressed == {"truncated_fields": 1}


def test_fields_of_exactly_the_field_limit_are_kept() -> None:
    uri = "http://h.example.com/" + "a" * (MAX_FIELD_CHARS - 21)
    key = "HKCU\\Software\\" + "k" * (MAX_FIELD_CHARS - 14)
    command = "vssadmin delete shadows /all " + "x" * (MAX_FIELD_CHARS - 29)
    assert {len(uri), len(key), len(command)} == {MAX_FIELD_CHARS}
    report = {
        "info": {},
        "network": {
            "http": [{"uri": uri}],
            "https_ex": [{"host": "cdn.example.com", "uri": "/" + "a" * (MAX_FIELD_CHARS - 1)}],
        },
        "behavior": {"summary": {"executed_commands": [command], "write_keys": [key]}},
    }
    parsed = parse_cape(report)
    assert parsed.behavior.commands == [command]
    assert parsed.behavior.registry_writes == [key]
    assert {v for t, v, _ in parsed.iocs if t is IOCType.DOMAIN} == {"h.example.com", "cdn.example.com"}
    assert len({v for t, v, _ in parsed.iocs if t is IOCType.URL}) == 2
    assert parsed.stats == {}


def test_repeated_long_command_lines_are_cut_once() -> None:
    command = "cmd /c echo " + "a " * MAX_FIELD_CHARS
    report = {"info": {}, "behavior": {"summary": {"executed_commands": [command] * 3}}}
    report["behavior"]["processes"] = [{"environ": {"CommandLine": command}}]
    parsed = parse_cape(report)
    assert parsed.behavior.commands == [command[: MAX_FIELD_CHARS - 1]]
    assert parsed.stats == {"truncated_fields": 1}


def test_command_line_over_the_field_limit_without_a_blank_is_left_out() -> None:
    command = "http://first.example.net/" + "a" * MAX_FIELD_CHARS
    environ = {"environ": {"CommandLine": "vssadmin delete shadows /all /quiet " + "x" * MAX_FIELD_CHARS}}
    report = {"info": {}, "behavior": {"summary": {"executed_commands": [command]}, "processes": [environ]}}
    parsed = parse_cape(report)
    assert parsed.behavior.commands == ["vssadmin delete shadows /all /quiet"]
    assert list(parsed.iocs) == []
    assert parsed.stats == {"truncated_fields": 2}
    assert "T1490" in {t.technique_id for t in analyze_cape(report).techniques}


def test_other_fields_over_the_field_limit_are_left_out() -> None:
    long = "a" * (MAX_FIELD_CHARS - 11) + ".example.com"
    assert len(long) == MAX_FIELD_CHARS + 1
    report = {
        "info": {},
        "target": {"file": {"md5": "5f89cef4c9ed3f109bc7c400d822e60e" * 300}},
        "network": {
            "hosts": [long, {"ip": long}],
            "domains": [{"domain": long, "ip": "198.51.100.7"}],
            "dns": [{"request": long, "answers": [{"type": "A", "data": long}]}],
            "http": [{"uri": f"http://h.example.com/{long}", "host": long}],
            # The host is kept, but no URL is made up from it with the path "/".
            "https_ex": [{"host": "cdn.example.com", "uri": "/" + long}],
        },
        "behavior": {"summary": {"write_keys": ["HKCU\\Software\\" + long, "HKCU\\Software\\x"]}},
        "ttps": [{"signature": "s", "ttps": ["T" + long, "T1055"]}, {"signature": "s", "ttp": "T" + long}],
    }
    parsed = parse_cape(report)
    assert sorted(v for _, v, _ in parsed.iocs) == ["198.51.100.7", "cdn.example.com"]
    assert parsed.behavior.registry_writes == ["HKCU\\Software\\x"]
    assert parsed.reported_ttps == [("T1055", "s")]
    assert parsed.stats == {"truncated_fields": 12}


def test_network_fields_keep_masked_names() -> None:
    report = {
        "info": {},
        "network": {
            "hosts": ["wiki.xxxx.example.com"],
            "domains": [{"domain": "mail.xxxx.example.com"}],
            "dns": [{"request": "dns.xxxx.example.com"}],
            "http": [{"uri": "http://cdn.xxxx.example.com/a", "host": "cdn.xxxx.example.com:8080"}],
            "http_ex": [{"host": "dl.xxxx.example.com", "uri": "/b?u=payload.zip"}],
        },
        "behavior": {"summary": {"executed_commands": ["curl http://cmd.xxxx.example.com/c"]}},
    }
    result = analyze_cape(report, AnalysisOptions(include_reserved=True))
    assert result.iocs_of(IOCType.DOMAIN) == [
        "cdn.xxxx.example.com",
        "dl.xxxx.example.com",
        "dns.xxxx.example.com",
        "mail.xxxx.example.com",
        "wiki.xxxx.example.com",
    ]
    assert result.iocs_of(IOCType.URL) == [
        "http://cdn.xxxx.example.com/a",
        "http://dl.xxxx.example.com/b?u=payload.zip",
    ]
    # A command line is text that may hide a value, as in a report; the drops in a network URL are
    # counted too.
    assert result.suppressed == {"filename_like_domain": 1, "masked_name": 1}


def test_dns_answer_types() -> None:
    answers = [{"type": "A", "data": "198.51.100.1"}, {"type": "CNAME", "data": "198.51.100.2"}]
    parsed = parse_cape({"info": {}, "network": {"dns": [{"answers": answers}]}})
    assert {v for _, v, _ in parsed.iocs} == {"198.51.100.1"}


def test_reported_ttps_are_capped() -> None:
    ids = [f"T{i}" for i in range(MAX_ITEMS + 5)]
    parsed = parse_cape({"info": {}, "ttps": [{"signature": "s" * 8000, "ttps": ids}, {"ttp": "T1"}]})
    assert len(parsed.reported_ttps) == MAX_ITEMS
    assert parsed.stats["truncated_ttps"] == 6
    assert {len(signature) for _, signature in parsed.reported_ttps} == {MAX_SIGNATURE_CHARS}


def test_long_ttp_signatures_do_not_amplify_work() -> None:
    # Every catalog ID paired with 8 KiB signatures used to sanitise each signature once per ID.
    ids = sorted(AttackCatalog.default().techniques)
    report = {"info": {}, "ttps": [{"signature": f"{i:06d}" + "A" * 8186, "ttps": ids} for i in range(40)]}
    results = []
    assert seconds_per_mb(lambda: results.append(analyze_cape(report)), size_mb(json.dumps(report))) < 2
    result = results[0]
    assert result.suppressed["truncated_ttps"] == 40 * len(ids) - MAX_ITEMS
    assert all(len(e) <= 200 for t in result.techniques for e in t.evidence)
