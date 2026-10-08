from __future__ import annotations

import pytest

from ttprism import IOCType, extract_iocs
from ttprism.extract import find_technique_ids


def values(text: str, ioc_type: IOCType) -> list[str]:
    return [i.value for i in extract_iocs(text) if i.type == ioc_type]


# --------------------------------------------------------------------------- URLs


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("see https://evil.com/a/b.php?x=1.", ["https://evil.com/a/b.php?x=1"]),
        ("(https://evil.com/path)", ["https://evil.com/path"]),
        ("[link](https://evil.com/x)", ["https://evil.com/x"]),
        ("https://en.wikipedia.org/wiki/Foo_(bar)", ["https://en.wikipedia.org/wiki/Foo_(bar)"]),
        ("下載網址：https://evil.com/a作為第二階段", ["https://evil.com/a"]),
        ("網址 https://evil.com/a，請封鎖", ["https://evil.com/a"]),
        ("'http://evil.com/p.ps1')", ["http://evil.com/p.ps1"]),
        ("HTTP://EVIL.COM/Path", ["http://evil.com/Path"]),
        ("http://user:pw@evil.com:8080/x", ["http://user:pw@evil.com:8080/x"]),
        ("http://198.51.100.7:8443/gate", ["http://198.51.100.7:8443/gate"]),
        ("Visit http://198.51.100.7.", ["http://198.51.100.7"]),
        ("Visit http://evil.com.", ["http://evil.com"]),
        ("http://[2001:db8::1]/x", ["http://[2001:db8::1]/x"]),
        ("hxxps://cdn-update【.】com/stage2.bin", ["https://cdn-update.com/stage2.bin"]),
    ],
)
def test_urls(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.URL) == expected


@pytest.mark.parametrize(
    "text",
    ["http://nodot/", "http://evil.notatld/x", "http://evil.com:99999/", "http://999.1.1.1/"],
)
def test_invalid_urls_rejected(text: str) -> None:
    assert values(text, IOCType.URL) == []


def test_url_host_becomes_domain_or_ip() -> None:
    iocs = extract_iocs("http://evil.com/a http://198.51.100.9/b")
    assert ("domain", "evil.com") in [(i.type, i.value) for i in iocs]
    assert ("ipv4", "198.51.100.9") in [(i.type, i.value) for i in iocs]


# --------------------------------------------------------------------------- domains


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C2 at evil.com, backup Evil-Backup.co.uk.", ["evil-backup.co.uk", "evil.com"]),
        ("攻擊者使用update-check.com作為C2", ["update-check.com"]),
        ("ｓｙｎｃ．ｅｘａｍｐｌｅ．ｎｅｔ", ["sync.example.net"]),
        ("evil.onion", ["evil.onion"]),
        ("xn--80ak6aa92e.xn--p1ai", ["xn--80ak6aa92e.xn--p1ai"]),
        # Not domains: unknown TLDs, file names, version strings.
        ("stage2.bin config.json invoice.pdf", []),
        ("libssl.so.3 version 1.2.3", []),
    ],
)
def test_domains(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.DOMAIN) == expected


def test_filename_like_domains_are_dropped_unless_url_host() -> None:
    assert values("payload.zip and setup.py and readme.md", IOCType.DOMAIN) == []
    assert values("https://payload.zip/x", IOCType.DOMAIN) == ["payload.zip"]
    # Three labels is not a file name.
    assert values("cdn.payload.zip", IOCType.DOMAIN) == ["cdn.payload.zip"]


def test_domain_not_taken_from_paths_or_emails() -> None:
    assert values(r"C:\Users\a\evil.com", IOCType.DOMAIN) == []
    assert values("first.name@evil.com", IOCType.DOMAIN) == []


# --------------------------------------------------------------------------- IPs


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("connects to 198.51.100.23:443", ["198.51.100.23"]),
        ("198.51.100[.]23", ["198.51.100.23"]),
        ("１９８．５１．１００．２３", ["198.51.100.23"]),
        ("IP:203.0.113.7。", ["203.0.113.7"]),
        ("256.1.1.1 1.2.3 1.2.3.4.5 v1.2.3.4 010.1.1.1", []),
        ("23.100.51.198.in-addr.arpa", []),
    ],
)
def test_ipv4(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.IPV4) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2001:DB8:85a3:0:0:8a2e:370:7334", ["2001:db8:85a3::8a2e:370:7334"]),
        ("[2001:db8::7]:443", ["2001:db8::7"]),
        ("2001:db8:1::5.", ["2001:db8:1::5"]),
        ("::ffff:198.51.100.1", ["::ffff:198.51.100.1"]),
        # Not IPv6: MAC addresses, times, C++ scopes, two-group fragments.
        ("00:1A:2B:3C:4D:5E 12:30:45 std::string dead::beef", []),
    ],
)
def test_ipv6(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.IPV6) == expected


# --------------------------------------------------------------------------- hashes, emails, CVEs


def test_hashes() -> None:
    md5 = "5F89CEF4C9ED3F109BC7C400D822E60E"
    sha1 = "a2eebf3d37a530f407d8907e869f880fa5346b29"
    sha256 = "8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05"
    text = f"MD5 {md5}\nSHA1:{sha1}\n雜湊值{sha256}。"
    assert values(text, IOCType.MD5) == [md5.lower()]
    assert values(text, IOCType.SHA1) == [sha1]
    assert values(text, IOCType.SHA256) == [sha256]


def test_hash_lookalikes_ignored() -> None:
    assert values("a" * 48, IOCType.MD5) == []  # wrong length
    assert values("1" * 32, IOCType.MD5) == []  # all digits
    assert values("0" * 64, IOCType.SHA256) == []  # one repeated character
    assert values("x" + "a1" * 16, IOCType.MD5) == []  # part of a longer token


def test_emails() -> None:
    text = "寄件者 Attacker［＠］Mail-Update．com and first.last+tag@evil.co.uk"
    assert values(text, IOCType.EMAIL) == ["attacker@mail-update.com", "first.last+tag@evil.co.uk"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CVE-2023-23397", ["CVE-2023-23397"]),
        ("cve-2021-44228", ["CVE-2021-44228"]),
        ("ＣＶＥ－２０２３－２３３９７", ["CVE-2023-23397"]),
        ("CVE–2021–40444", ["CVE-2021-40444"]),
        ("CVE-2024-1234567", ["CVE-2024-1234567"]),
        ("CVE-24-1234 CVE-2024-123 CVE-1899-1234", []),
    ],
)
def test_cves(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.CVE) == expected


# --------------------------------------------------------------------------- techniques


def test_technique_ids() -> None:
    text = (
        "T1059.001, T1566 and https://attack.mitre.org/techniques/T1055/012/ "
        "but not RT1234, T12345 or T1059.0011"
    )
    assert find_technique_ids(text) == ["T1059.001", "T1566", "T1055.012"]


def test_sources_and_dedup() -> None:
    iocs = extract_iocs("evil.com evil.com EVIL.COM", source="report")
    assert [(i.value, i.sources) for i in iocs] == [("evil.com", ("report",))]
