from __future__ import annotations

import time
from pathlib import Path

import pytest

from ttprism import Allowlist, AllowlistError, AnalysisOptions, IOCType, analyze_text


def test_default_allowlist_drops_bare_platform_domains_but_keeps_urls() -> None:
    result = analyze_text("google.com https://drive.google.com/uc?id=abc github.com/evil/repo")
    assert result.iocs_of(IOCType.DOMAIN) == ["drive.google.com"]
    assert result.iocs_of(IOCType.URL) == ["https://drive.google.com/uc?id=abc"]
    assert result.suppressed["allowlisted"] == 2


def test_default_allowlist_drops_reference_urls() -> None:
    result = analyze_text("See https://attack.mitre.org/techniques/T1055/ and https://nvd.nist.gov/x")
    assert result.iocs_of(IOCType.URL) == []
    assert result.iocs_of(IOCType.DOMAIN) == []


def test_default_allowlist_sandbox_noise_and_resolvers() -> None:
    allowlist = Allowlist.default()
    assert allowlist.matches(IOCType.DOMAIN, "www.msftconnecttest.com")
    assert allowlist.matches(IOCType.DOMAIN, "23.100.51.198.in-addr.arpa")
    assert allowlist.matches(IOCType.IPV4, "8.8.8.8")
    assert allowlist.matches(IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e")
    assert not allowlist.matches(IOCType.DOMAIN, "evil-bucket.s3.amazonaws.com")


def test_reserved_values_dropped_by_default() -> None:
    text = "update.example 198.51.100.7 10.0.0.1 2001:db8:1::1 http://localhost/x a@b.example evil.test"
    result = analyze_text(text)
    assert result.iocs == []
    assert result.suppressed["reserved"] == 7
    kept = analyze_text(text, AnalysisOptions(include_reserved=True))
    assert "198.51.100.7" in kept.iocs_of(IOCType.IPV4)


def test_custom_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "allow.yaml"
    path.write_text(
        "domains: ['*.corp-lab.com', partner.org]\n"
        "url_hosts: [intranet.corp-lab.com]\n"
        "ips: [203.0.113.0/24, '2001:db8::/32']\n"
        "hashes: [5F89CEF4C9ED3F109BC7C400D822E60E]\n"
        "emails: [SOC@corp-lab.com]\n",
        encoding="utf-8",
    )
    allowlist = Allowlist.from_file(path)
    assert allowlist.matches(IOCType.DOMAIN, "corp-lab.com")
    assert allowlist.matches(IOCType.DOMAIN, "a.b.corp-lab.com")
    assert not allowlist.matches(IOCType.DOMAIN, "notcorp-lab.com")
    assert allowlist.matches(IOCType.DOMAIN, "partner.org")
    assert not allowlist.matches(IOCType.DOMAIN, "www.partner.org")
    assert allowlist.matches(IOCType.URL, "https://intranet.corp-lab.com:8443/x")
    assert not allowlist.matches(IOCType.URL, "https://files.corp-lab.com/x")
    assert allowlist.matches(IOCType.IPV4, "203.0.113.200")
    assert allowlist.matches(IOCType.URL, "http://203.0.113.9/x")
    assert allowlist.matches(IOCType.IPV6, "2001:db8::5")
    assert allowlist.matches(IOCType.MD5, "5f89cef4c9ed3f109bc7c400d822e60e")
    assert allowlist.matches(IOCType.EMAIL, "soc@corp-lab.com")


def test_empty_file_is_empty_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "allow.yaml"
    path.write_text("# nothing yet\n", encoding="utf-8")
    assert not Allowlist.from_file(path).matches(IOCType.DOMAIN, "evil.com")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("domains: evil.com\n", "must be a list"),
        ("domains: [not a domain]\n", "not a valid domain"),
        ("domains: [123]\n", "must be strings"),
        ("ips: [999.1.1.1]\n", "not an IP"),
        ("hashes: [abc]\n", "hex digest"),
        ("emails: [nobody]\n", "not an email"),
        ("domain: [evil.com]\n", "unknown keys"),
        ("- evil.com\n", "mapping"),
        ("domains: [unclosed\n", "invalid YAML"),
        ("!!python/object/apply:os.system ['true']\n", "invalid YAML"),
    ],
)
def test_invalid_allowlists(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "allow.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AllowlistError, match=message):
        Allowlist.from_file(path)


def test_alias_expansion_is_rejected_quickly(tmp_path: Path) -> None:
    # A "billion laughs" document: nested aliases that would expand to 10^9 items.
    lines = ["a: &a [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 9):
        prev, cur = chr(ord("a") + i - 1), chr(ord("a") + i)
        lines.append(f"{cur}: &{cur} [{', '.join(['*' + prev] * 10)}]")
    lines.append("domains: *i")
    path = tmp_path / "bomb.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    start = time.perf_counter()
    with pytest.raises(AllowlistError):
        Allowlist.from_file(path)
    assert time.perf_counter() - start < 2


def test_oversized_allowlist_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.yaml"
    path.write_text("domains:\n" + "  - a.com\n" * 300_000, encoding="utf-8")
    with pytest.raises(AllowlistError, match="larger than"):
        Allowlist.from_file(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AllowlistError, match="cannot read"):
        Allowlist.from_file(tmp_path / "missing.yaml")
