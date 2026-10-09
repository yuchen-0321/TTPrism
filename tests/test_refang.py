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


# --------------------------------------------------------------------------- compatibility folding


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("\uff45\uff56\uff49\uff4c\uff0e\uff43\uff4f\uff4d", "evil.com"),  # <wide>
        ("evil[\uff61]com", "evil.com"),  # <narrow> ideographic full stop, then the bracket marker
        ("evil\ufe52com user\ufe6bevil.com", "evil.com user@evil.com"),  # <small>
        ("evil\u2024com", "evil.com"),  # one dot leader
        ("\ufb01le \ufb00 \ufb03 \ufb05", "file ff ffi st"),  # Latin ligatures
        ("login\u2010x login\u2011x CVE\u22122021", "login-x login-x CVE-2021"),  # hyphens, minus sign
    ],
)
def test_refang_folds_width_forms_ligatures_and_hyphens(text: str, expected: str) -> None:
    assert refang(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "45.77.123.9\u00b2",  # superscript footnote marker
        "CVE-2021-40444\u00b9",
        "H\u2082O",  # subscript
        "\u2460evil.com \u2461evil.net",  # circled list numbers
        "\u2474 \u2488",  # parenthesised digit, digit full stop
        "\u00bd \u2153",  # fractions
        "\u3002",  # a bare ideographic full stop ends a sentence
        "\u00a0",  # no-break space is not a width variant
    ],
)
def test_refang_keeps_other_compatibility_characters(text: str) -> None:
    assert refang(text) == text


def test_refang_does_not_expand_text() -> None:
    # Under NFKC, U+FDFA expands to 18 characters.
    assert refang("\ufdfa" * 1000) == "\ufdfa" * 1000
    # Three-letter ligatures are the largest fold.
    assert len(refang("\ufb03" * 1000)) == 3000


@pytest.mark.parametrize(
    "mark",
    [
        "\u00ad",  # soft hyphen
        "\u061c",  # Arabic letter mark
        "\u180e",  # Mongolian vowel separator
        *"\u200b\u200c\u200d\u200e\u200f",  # zero-width characters, LRM, RLM
        *"\u202a\u202b\u202c\u202d\u202e",  # bidi embeddings and overrides
        *"\u2060\u2061\u2062\u2063\u2064",  # word joiner, invisible operators
        *"\u2066\u2067\u2068\u2069",  # bidi isolates
        "\ufeff",  # BOM
        "\U000110bd",
        "\U000110cd",
        "\U00013430",
        "\U0001343f",
        "\U0001bca0",
        "\U0001d173",
        "\U000e0001",  # language tag
        "\U000e0041",  # tag letter
        "\U000e007f",
    ],
)
def test_refang_removes_format_characters(mark: str) -> None:
    assert refang(f"ev{mark}il{mark}.c{mark}om") == "evil.com"


# --------------------------------------------------------------------------- more defang forms


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxp://evil-cdn[.]net[/]gate.php", "http://evil-cdn.net/gate.php"),
        ("https:[//]evil.com/x", "https://evil.com/x"),
        ("hxxp[s]://evil.com", "https://evil.com"),
        ("hXXp[S]://evil.com", "https://evil.com"),
        ("h[tt]p[s]://evil.com", "https://evil.com"),
        ("http[s]://evil.com", "https://evil.com"),
        ("h[tt]p://evil.com", "http://evil.com"),
        ("hxxp[s][:]//evil.com", "https://evil.com"),
        ("evil [.] com", "evil.com"),
        ("evil [DOT] com", "evil.com"),
        ("evil (.) com", "evil.com"),
        ("john [at] evil [dot] co [.] uk", "john@evil.co.uk"),
    ],
)
def test_refang_more_forms(defanged: str, expected: str) -> None:
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Without a label character on both sides only the marker itself is refanged.
        ("item: [.] next", "item: . next"),
        ("a, [at] b", "a, @ b"),
        ("a [.]  b", "a .  b"),
        # A plain scheme is not rewritten, so its case is kept.
        ("HTTP://EVIL.COM/x", "HTTP://EVIL.COM/x"),
    ],
)
def test_refang_leaves_lookalikes(text: str, expected: str) -> None:
    assert refang(text) == expected


def test_defang_round_trips_scheme_and_host_of_other_schemes() -> None:
    for value in ("ldap://evil.com:1389/a", "tcp://c2.evil.net:4444", "http://my_bucket.s3.evil.com/x"):
        assert refang(defang(value, IOCType.URL)) == value
