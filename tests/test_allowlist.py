from __future__ import annotations

import ipaddress
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
        ("domains: &d [evil.com]\nurl_hosts: *d\n", "aliases are not allowed"),
    ],
)
def test_invalid_allowlists(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "allow.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AllowlistError, match=message):
        Allowlist.from_file(path)


@pytest.mark.parametrize(
    "content",
    ["- " * 1000 + "x\n", "domains: " + "[" * 5000 + "]" * 5000 + "\n"],
    ids=["block", "flow"],
)
def test_deep_nesting_is_a_clean_error(tmp_path: Path, content: str) -> None:
    # PyYAML composes recursively; a RecursionError used to escape as a traceback.
    path = tmp_path / "allow.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AllowlistError, match="YAML nesting too deep"):
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


def test_unknown_keys_are_escaped(tmp_path: Path) -> None:
    path = tmp_path / "allow.yaml"
    # YAML "\e" and "\a" escapes put raw terminal control characters into the key.
    path.write_text(
        '"\\e]0;PWNED\\a\\e[2Jdomains": []\n' + "".join(f"k{i}: []\n" for i in range(20)), encoding="utf-8"
    )
    with pytest.raises(AllowlistError) as info:
        Allowlist.from_file(path)
    message = str(info.value)
    assert "\x1b" not in message
    assert "\x07" not in message
    assert "'\\x1b]0;PWNED\\x07\\x1b[2Jdomains'" in message
    assert message.endswith("and 11 more")


def test_ip_lookups_use_an_index() -> None:
    # A large analyst allowlist (cloud ranges) used to be scanned once per IP IOC.
    networks = [f"{10 + i % 200}.{i * 7 % 256}.{i // 256}.0/24" for i in range(5000)]
    allowlist = Allowlist.from_mapping({"ips": networks})
    addresses = [str(ipaddress.IPv4Address(i * 2_654_435_761 % 2**32)) for i in range(5000)]
    addresses += [n.replace(".0/24", f".{i % 256}") for i, n in enumerate(networks)]
    start = time.perf_counter()
    hits = [a for a in addresses if allowlist.matches(IOCType.IPV4, a)]
    assert time.perf_counter() - start < 2  # 50 million network tests without the index
    assert hits[-len(networks) :] == addresses[-len(networks) :]
    parsed = [ipaddress.ip_network(n) for n in networks]
    sample, listed = addresses[::97], set(hits)
    assert [a for a in sample if a in listed] == [
        a for a in sample if any(ipaddress.ip_address(a) in net for net in parsed)
    ]


@pytest.mark.parametrize(
    ("ips", "value", "listed"),
    [
        (["0.0.0.0/0"], "203.0.113.9", True),
        (["0.0.0.0/0"], "2001:db8::1", False),
        (["::/0"], "2001:db8::1", True),
        (["::/0"], "203.0.113.9", False),
        (["203.0.113.9"], "203.0.113.9", True),
        (["203.0.113.9"], "203.0.113.10", False),
        (["203.0.113.9/31"], "203.0.113.8", True),  # host bits are ignored
        (["203.0.113.128/25", "198.51.100.0/24"], "203.0.113.127", False),
        (["203.0.113.128/25", "198.51.100.0/24"], "198.51.100.255", True),
        (["2001:db8::1"], "2001:db8::1", True),
        (["2001:db8::/127"], "2001:db8::1", True),
        (["2001:db8::/127"], "2001:db8::2", False),
        (["2001:db8::/32"], "2001:db9::", False),
        (["::ffff:0:0/96"], "203.0.113.9", False),  # versions never mix
        # ...but an IPv4-mapped address is the IPv4 address, as for the reserved check.
        (["203.0.113.0/24"], "::ffff:203.0.113.5", True),
        (["::ffff:0:0/96"], "::ffff:203.0.113.5", True),
        (["203.0.113.0/24"], "::cb00:7105", False),  # IPv4-compatible, deprecated
        (["203.0.113.0/24"], "64:ff9b::cb00:7105", True),  # NAT64, as for the reserved check
    ],
)
def test_ip_matching(ips: list[str], value: str, listed: bool) -> None:
    ioc_type = IOCType.IPV6 if ":" in value else IOCType.IPV4
    allowlist = Allowlist.from_mapping({"ips": ips})
    assert allowlist.matches(ioc_type, value) is listed
    url = f"http://[{value}]/x" if ":" in value else f"http://{value}/x"
    assert allowlist.matches(IOCType.URL, url) is listed


def test_ip_index_follows_updates() -> None:
    allowlist = Allowlist.from_mapping({"ips": ["198.51.100.0/24"]})
    assert not allowlist.matches(IOCType.IPV4, "203.0.113.9")
    allowlist.update(Allowlist.from_mapping({"ips": ["203.0.113.0/24"]}))
    assert allowlist.matches(IOCType.IPV4, "203.0.113.9")
    assert allowlist.matches(IOCType.IPV4, "198.51.100.1")
    # The networks are a tuple, so a change is a new value, even with the same length.
    allowlist.networks = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("203.0.113.0/24"))
    assert allowlist.matches(IOCType.IPV4, "192.0.2.7")
    assert not allowlist.matches(IOCType.IPV4, "198.51.100.1")
    assert isinstance(Allowlist.default().networks, tuple)


def test_url_hosts_with_underscores_can_be_listed() -> None:
    allowlist = Allowlist.from_mapping({"domains": ["my_bucket.example.com"], "url_hosts": ["*.example.com"]})
    assert allowlist.matches(IOCType.DOMAIN, "my_bucket.example.com")
    assert allowlist.matches(IOCType.URL, "https://my_bucket.example.com/x")
    with pytest.raises(AllowlistError, match="not a valid domain name"):
        Allowlist.from_mapping({"domains": ["evil.co_m"]})


def test_oversized_allowlist_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.yaml"
    path.write_text("domains:\n" + "  - a.com\n" * 300_000, encoding="utf-8")
    with pytest.raises(AllowlistError, match="larger than"):
        Allowlist.from_file(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(AllowlistError, match="cannot read"):
        Allowlist.from_file(tmp_path / "missing.yaml")


def test_networks_given_as_a_list_are_frozen() -> None:
    allowlist = Allowlist(networks=[ipaddress.ip_network("192.0.2.0/24")])  # type: ignore[arg-type]
    assert isinstance(allowlist.networks, tuple)
    assert allowlist.matches(IOCType.IPV4, "192.0.2.7")
    allowlist.networks = [ipaddress.ip_network("198.51.100.0/24")]  # type: ignore[assignment]
    assert allowlist.matches(IOCType.IPV4, "198.51.100.7")
    assert not allowlist.matches(IOCType.IPV4, "192.0.2.7")


@pytest.mark.parametrize(
    "content",
    [
        "domains: !!map [a, b]\n",
        "domains: !!map x\n",
        "<<: {domains: [a.com], domains: [b.com]}\n",
        "x: {<<: [{a: 1, a: 2}]}\n",
    ],
)
def test_malformed_mappings_are_clean_errors(tmp_path: Path, content: str) -> None:
    path = tmp_path / "allow.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AllowlistError):
        Allowlist.from_file(path)
