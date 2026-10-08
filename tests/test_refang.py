from __future__ import annotations

import pytest

from ttprism import IOCType, defang, refang


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("evil[.]com", "evil.com"),
        ("evil(.)com", "evil.com"),
        ("evil{.}com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("evil[DOT]com", "evil.com"),
        ("evil[ . ]com", "evil.com"),
        ("evil\\.com", "evil.com"),
        # CJK and full-width forms common in Chinese-language reports.
        ("evil【.】com", "evil.com"),
        ("evil【。】com", "evil.com"),
        ("evil[。]com", "evil.com"),
        ("evil〔.〕com", "evil.com"),
        ("evil［．］com", "evil.com"),
        ("evil（.）com", "evil.com"),
        ("evil．com", "evil.com"),
        ("evil[點]com", "evil.com"),
        ("ｅｖｉｌ．ｃｏｍ", "evil.com"),
        # Invisible characters inserted by PDF converters.
        ("evil\u200b.com", "evil.com"),
        ("ev\u00adil.com", "evil.com"),
    ],
)
def test_refang_dots(defanged: str, expected: str) -> None:
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxp://evil.com", "http://evil.com"),
        ("hXXps://evil.com", "https://evil.com"),
        ("h**p://evil.com", "http://evil.com"),
        ("h[xx]ps://evil.com", "https://evil.com"),
        ("hxxp[:]//evil.com", "http://evil.com"),
        ("hxxps[://]evil.com", "https://evil.com"),
        ("http【:】//evil.com", "http://evil.com"),
        ("ｈｘｘｐｓ：／／evil.com", "https://evil.com"),
        ("fxp://files.evil.com", "ftp://files.evil.com"),
    ],
)
def test_refang_schemes(defanged: str, expected: str) -> None:
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    "defanged",
    ["user[@]evil.com", "user[at]evil.com", "user(at)evil.com", "user［＠］evil.com", "user【@】evil.com"],
)
def test_refang_at(defanged: str) -> None:
    assert refang(defanged) == "user@evil.com"


def test_refang_ipv6_brackets() -> None:
    assert refang("2001[:]db8[:][:]1") == "2001:db8::1"
    # A bracketed IPv6 address is not a defang marker.
    assert refang("[2001:db8::1]:443") == "[2001:db8::1]:443"


def test_bare_ideographic_full_stop_is_left_alone() -> None:
    # "。" ends Chinese sentences; only the bracketed form is treated as a dot.
    assert refang("使用PowerShell。Windows") == "使用PowerShell。Windows"


@pytest.mark.parametrize(
    ("value", "ioc_type", "expected"),
    [
        ("evil.com", IOCType.DOMAIN, "evil[.]com"),
        ("198.51.100.1", IOCType.IPV4, "198[.]51[.]100[.]1"),
        ("2001:db8::1", IOCType.IPV6, "2001[:]db8[:][:]1"),
        ("a.b@evil.com", IOCType.EMAIL, "a.b[@]evil[.]com"),
        ("https://evil.com/a.php?x=1.2", IOCType.URL, "hxxps[://]evil[.]com/a.php?x=1.2"),
        ("ftp://user@files.evil.com:21/x", IOCType.URL, "fxp[://]user@files[.]evil[.]com:21/x"),
        ("http://[2001:db8::1]/x", IOCType.URL, "hxxp[://][2001:db8::1]/x"),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
    ],
)
def test_defang(value: str, ioc_type: IOCType, expected: str) -> None:
    assert defang(value, ioc_type) == expected
    assert refang(expected) == value
