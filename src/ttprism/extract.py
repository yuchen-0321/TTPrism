"""Regex-based IOC extraction from untrusted text.

Input is attacker-controlled, so every pattern is written to run in linear
time on Python's backtracking engine:

* each pattern starts with a negative lookbehind (or fixed-width lookbehinds),
  so a match can only begin at a token boundary and the engine never rescans
  the inside of a long token;
* every repetition is bounded (labels <= 63, domains <= 126 labels, URL
  paths <= 2048 characters), and adjacent quantifiers never overlap in a way
  that allows exponential backtracking.

``tests/test_redos.py`` keeps these properties honest with pathological inputs.
"""

from __future__ import annotations

import bisect
import functools
import ipaddress
import re
import unicodedata
from collections import Counter
from collections.abc import Iterator
from importlib import resources
from urllib.parse import unquote

from ttprism.models import IOC, IOCCollector, IOCType, sort_iocs
from ttprism.refang import refang

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
_DOMAIN_END = r"(?![A-Za-z0-9_@-]|\.[A-Za-z0-9])"
# A name right after one of these characters is part of a path, an address or a
# longer name.
_NAME_CHARS = r"A-Za-z0-9._/\\@:%-"
_DOMAIN_START = (
    r"(?:(?<![A-Za-z0-9._/\\@-])"
    # A leading dot or wildcard at a token start: ".evil.com", "*.evil.com".
    rf"|(?<=\.)(?<![{_NAME_CHARS}]\.)"
    # UNC paths and protocol-relative URLs: "\\host\share", "//host/path".
    rf"|(?<=\\\\)(?<![{_NAME_CHARS}]\\\\)"
    rf"|(?<=//)(?<![{_NAME_CHARS}]//))"
)

DOMAIN_RE = re.compile(rf"{_DOMAIN_START}(?:{_LABEL}\.){{1,126}}{_TLD}{_DOMAIN_END}")
EMAIL_RE = re.compile(
    rf"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{{1,64}}@(?:{_LABEL}\.){{1,8}}{_TLD}{_DOMAIN_END}"
)

_URL_SCHEMES = r"https?|ftps?|sftp|wss?|ldaps?|rmi|iiop|dns|tcp|udp|smb|file|ssh|telnet|irc|rtsp"
_URL_PATH_CHARS = r"A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%"
# A path ends before a separator that starts the next URL ("/a,http://b/") and
# at a shell "&&". '"', '|', '<' and '>' are not path characters at all.
_URL_PATH_STOP = rf"[,;'()\[\]](?:{_URL_SCHEMES})://|&&"
URL_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<scheme>{_URL_SCHEMES})://"
    r"(?P<userinfo>[A-Za-z0-9\-._~!$&'()*+,;=%:]{1,256}@)?"
    # "_" is accepted in URL host labels (S3 buckets, internal names), but not as
    # the last character, so "_http://evil.com_" keeps its host.
    r"(?P<host>\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9._-]{0,252}[A-Za-z0-9.-])"
    # Wider than a port so that ":443123" is rejected instead of truncated.
    r"(?::(?P<port>[0-9]{1,10}))?"
    rf"(?P<rest>[/?#](?:(?!{_URL_PATH_STOP})[{_URL_PATH_CHARS}]){{0,2048}})?",
    re.IGNORECASE,
)

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(
    rf"(?:(?<![A-Za-z0-9.])|(?<=%[0-9A-Fa-f]{{2}}))(?:{_OCTET}\.){{3}}{_OCTET}(?![0-9]|\.[A-Za-z0-9])"
)
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:.])(?=[0-9A-Fa-f]{0,4}:)[0-9A-Fa-f:.]{2,45}(?![0-9A-Za-z:])")
HASH_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Za-z])")
_DASH = "-\u2010\u2011\u2012\u2013\u2014\u2015\u2212"
CVE_RE = re.compile(
    rf"(?<![A-Za-z0-9])CVE[{_DASH}]([0-9]{{4}})[{_DASH}]([0-9]{{4,7}})(?![0-9])", re.IGNORECASE
)
# "T1566/001" is how attack.mitre.org URLs spell sub-techniques.
TECHNIQUE_RE = re.compile(r"(?<![A-Za-z0-9])T[0-9]{4}(?:[./][0-9]{3})?(?![0-9A-Za-z]|\.[0-9])")

_LABEL_RE = re.compile(_LABEL)
_HOST_LABEL_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")
_HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_URL_TRAILING = ".,;:!?'\"([{*"
_BRACKET_PAIRS = {")": "(", "]": "["}
_FOOTNOTE_TAIL_RE = re.compile(r"\[[0-9]{1,3}\]\Z")
_ENTITY_TAIL_RE = re.compile(r"&(?:gt|lt|quot|amp|#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6})\Z")

# Letters of scripts written without spaces between words may touch an IOC
# ("攻擊者使用evil.com作為C2"). Any other non-ASCII letter next to a match is part
# of the same name: "micros\u043eft.com" (Cyrillic o) must not yield "ft.com".
_SPACELESS_SCRIPT_RE = re.compile(
    "[\u0e00-\u0eff"  # Thai, Lao
    "\u1000-\u109f"  # Myanmar
    "\u1100-\u11ff"  # Hangul Jamo
    "\u1780-\u17ff"  # Khmer
    "\u2e80-\u9fff"  # CJK radicals and punctuation, Kana, Bopomofo, Hangul compatibility, CJK ideographs
    "\ua960-\ua97f\uac00-\ud7ff"  # Hangul
    "\uf900-\ufaff\ufe30-\ufe4f"  # CJK compatibility
    "\uff00-\uffef"  # full-width and half-width forms
    "\U0001b000-\U0001b16f"  # Kana supplements
    "\U00020000-\U0003ffff]"  # CJK extensions
)

# Special-use names (RFC 2606, RFC 6761, RFC 6762, ICANN .internal): accepted as
# syntactically valid but reported as reserved. ".onion" is special-use too but
# is a real IOC, so it is valid and not reserved.
RESERVED_TLDS = frozenset({"example", "invalid", "localhost", "test", "local", "internal"})
_EXTRA_VALID_TLDS = RESERVED_TLDS | {"onion"}
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")

# Real TLDs that are far more often file extensions in reports ("payload.zip",
# "setup.py"). A bare two-label name with one of these TLDs is dropped, and so
# is a three-label one whose middle label is a file extension too
# ("invoice.pdf.zip"). The same names as URL hosts or in sandbox network data
# are kept.
FILE_EXTENSION_TLDS = frozenset(
    {"app", "cab", "dot", "java", "md", "mm", "mov", "one", "pm", "ps", "py", "rs", "run", "sh", "so", "zip"}
)
_INNER_FILE_EXTENSIONS = frozenset(
    {
        "doc",
        "docx",
        "exe",
        "gif",
        "hta",
        "htm",
        "html",
        "img",
        "iso",
        "jpeg",
        "jpg",
        "js",
        "lnk",
        "pdf",
        "png",
        "ppt",
        "pptx",
        "rtf",
        "scr",
        "txt",
        "vbs",
        "xls",
        "xlsx",
    }
)
# COM ProgIDs and .NET names that end in a real TLD. As bare names they are code
# ("CreateObject(\"WScript.Shell\")"); as URL hosts they are kept.
CODE_IDENTIFIERS = frozenset(
    {
        "ado.net",
        "adodb.stream",
        "asp.net",
        "microsoft.office",
        "system.data",
        "system.io",
        "system.management",
        "system.net",
        "system.security",
        "system.web",
        "system.web.services",
        "system.windows",
        "vb.net",
        "wscript.network",
        "wscript.shell",
    }
)


def _cidr_table(*cidrs: str) -> tuple[tuple[int, int], ...]:
    networks = [ipaddress.ip_network(cidr) for cidr in cidrs]
    return tuple((int(network.network_address), int(network.netmask)) for network in networks)


# IANA special-purpose, private, documentation and multicast ranges, checked
# explicitly so the result does not depend on the Python version's tables.
_RESERVED_IPV4 = _cidr_table(
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
)
_RESERVED_IPV6 = _cidr_table(
    "::/128",
    "::1/128",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)


@functools.cache
def known_tlds() -> frozenset[str]:
    data = resources.files("ttprism").joinpath("data/tlds.txt").read_text(encoding="utf-8")
    tlds = {line.strip() for line in data.splitlines() if line.strip() and not line.startswith("#")}
    return frozenset(tlds) | _EXTRA_VALID_TLDS


def normalize_domain(value: str, *, allow_underscore: bool = False) -> str | None:
    """Return the lower-cased domain if it is syntactically valid, else None.

    ``allow_underscore`` accepts "_" in labels other than the TLD, as URL hosts
    may have them.
    """
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    label_re = _HOST_LABEL_RE if allow_underscore else _LABEL_RE
    if not all(label_re.fullmatch(label) for label in labels):
        return None
    tld = labels[-1]
    if tld.startswith("xn--"):
        return domain if tld in known_tlds() else None
    if not tld.isalpha() or tld not in known_tlds():
        return None
    return domain


def _ipv6_text(address: ipaddress.IPv6Address) -> str:
    if address.ipv4_mapped is not None:
        # Spelled out here because Python patch releases format these differently.
        return f"::ffff:{address.ipv4_mapped}"
    return address.compressed


def normalize_ip(value: str) -> tuple[IOCType, str] | None:
    candidate = value.strip().strip("[]").rstrip(".")
    if "%" in candidate:
        # A scoped address ("fe80::1%eth0"): the zone ID is arbitrary text.
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv4Address):
        # ipaddress accepts "1.2.3.4" only; reject anything our regex would not.
        return (IOCType.IPV4, str(address)) if IPV4_RE.fullmatch(candidate) else None
    groups = [g for g in candidate.split(":") if g]
    if len(groups) < 3 and "." not in candidate:
        return None
    return IOCType.IPV6, _ipv6_text(address)


def is_reserved_domain(domain: str) -> bool:
    if domain.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return any(domain == d or domain.endswith("." + d) for d in RESERVED_DOMAINS)


def is_reserved_ip(value: str) -> bool:
    """True for special-purpose, private, documentation and multicast addresses."""
    address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    table = _RESERVED_IPV4 if address.version == 4 else _RESERVED_IPV6
    number = int(address)
    return any(number & mask == network for network, mask in table) or not address.is_global


def _strip_url_tail(url: str, *, strikethrough: bool = False) -> str:
    """Drop sentence punctuation, markup and unbalanced closing brackets after a URL.

    A trailing "~~" is dropped only with ``strikethrough``, when the text before
    the URL opened a Markdown strikethrough.
    """
    opens = {"(": url.count("("), "[": url.count("[")}
    closes = {")": url.count(")"), "]": url.count("]")}
    end = len(url)
    while end:
        last = url[end - 1]
        if last == "]" and (footnote := _FOOTNOTE_TAIL_RE.search(url, max(0, end - 5), end)):
            # A footnote marker: "https://evil.com/x[1]".
            opens["["] -= 1
            closes["]"] -= 1
            end = footnote.start()
            continue
        if last in closes:
            if opens[_BRACKET_PAIRS[last]] >= closes[last]:
                break
            closes[last] -= 1
        elif last in _URL_TRAILING:
            if last in opens:
                opens[last] -= 1
        elif strikethrough and last == "~" and url[end - 2 : end] == "~~":
            strikethrough = False
            end -= 2
            continue
        elif entity := _ENTITY_TAIL_RE.search(url, max(0, end - 10), end):
            # An HTML entity whose ";" was stripped above: "https://evil.com/a&gt;".
            end = entity.start()
            continue
        else:
            break
        end -= 1
    return url[:end]


def _url_matches(text: str) -> Iterator[re.Match[str]]:
    """URL_RE matches in ``text``; a URL right after a quote ends at the next same quote."""
    pos = 0
    while (match := URL_RE.search(text, pos)) is not None:
        start, pos = match.span()
        quote = text[start - 1 : start]
        if quote in ("'", '"') and (close := text.find(quote, start, pos)) != -1:
            # Scanning resumes at the quote, so a URL glued after it is still found.
            pos = close
            match = URL_RE.match(text, start, close)
            if match is None:
                continue
        yield match


def _parse_url(
    match: re.Match[str], *, strikethrough: bool = False
) -> tuple[str, str, tuple[IOCType, str] | None, str] | None:
    """Return (url, host, host IOC, tail) for a URL_RE match, or None if it is invalid.

    The host IOC is None for "localhost"; the tail is the part of the URL after
    the host.
    """
    host = match.group("host")
    host_ioc: tuple[IOCType, str] | None
    if host.startswith("["):
        # The "at least 3 groups" rule for bare text does not apply inside brackets.
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None
        host_ioc = (IOCType.IPV6, _ipv6_text(address))
        clean_host = f"[{host_ioc[1]}]"
    elif IPV4_RE.fullmatch(host.rstrip(".")):
        clean_host = host.rstrip(".")
        host_ioc = (IOCType.IPV4, clean_host)
    elif (domain := normalize_domain(host, allow_underscore=True)) is not None:
        clean_host = domain
        host_ioc = (IOCType.DOMAIN, domain)
    elif host.lower() == "localhost":
        clean_host = "localhost"
        host_ioc = None
    else:
        return None
    port = match.group("port")
    if port is not None and not 0 < int(port) < 65536:
        return None
    # Userinfo is kept verbatim.
    authority = f"{match.group('scheme').lower()}://{match.group('userinfo') or ''}{clean_host}"
    url = authority + (f":{port}" if port is not None else "") + (match.group("rest") or "")
    url = _strip_url_tail(url, strikethrough=strikethrough)
    return url, clean_host, host_ioc, url[len(authority) :]


def normalize_url_match(match: re.Match[str]) -> tuple[str, str] | None:
    """Return (url, host) for a URL_RE match, or None if the host is invalid."""
    parsed = _parse_url(match)
    return None if parsed is None else (parsed[0], parsed[1])


def _glued(text: str, index: int) -> bool:
    """True if ``text[index]`` is a letter or mark that continues the adjacent word."""
    if not 0 <= index < len(text):
        return False
    char = text[index]
    return (
        char > "\x7f" and unicodedata.category(char)[0] in "LM" and _SPACELESS_SCRIPT_RE.match(char) is None
    )


def _glued_before(text: str, start: int) -> bool:
    """Like :func:`_glued` for the character before a domain and its prefix."""
    if text[max(0, start - 2) : start] in ("//", "\\\\"):
        return _glued(text, start - 3)
    if text[start - 1 : start] == ".":
        return _glued(text, start - 2)
    return _glued(text, start - 1)


def _after_percent_escape(text: str, start: int, value: str) -> str:
    """Drop the hex digits of a "%2F" (or double-encoded "%252F") escape that the match starts with."""
    if text[start - 1 : start] != "%":
        return value
    skip = 0
    while value[skip : skip + 2] == "25" and _is_hex_pair(value[skip + 2 : skip + 4]):
        skip += 2
    if len(value) > skip + 2 and _is_hex_pair(value[skip : skip + 2]):
        return value[skip + 2 :]
    return value


def _is_hex_pair(chars: str) -> bool:
    return len(chars) == 2 and chars[0] in _HEX_DIGITS and chars[1] in _HEX_DIGITS


def _valid_local_part(local: str) -> bool:
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return any(c.isalnum() for c in local)


def _bare_name_noise(domain: str) -> str | None:
    """The stats key under which a bare (non-URL) name is dropped, or None to keep it."""
    labels = domain.split(".")
    if labels[-1] in FILE_EXTENSION_TLDS and (
        len(labels) == 2 or (len(labels) == 3 and labels[1] in _INNER_FILE_EXTENSIONS)
    ):
        return "filename_like_domain"
    if domain in CODE_IDENTIFIERS:
        return "code_identifier"
    return None


def extract_into(collector: IOCCollector, text: str, source: str, stats: Counter[str] | None = None) -> None:
    """Add every IOC in already-refanged ``text`` to ``collector``."""
    _extract(collector, text, source, stats if stats is not None else Counter(), nested=False)


def _extract(collector: IOCCollector, text: str, source: str, stats: Counter[str], *, nested: bool) -> None:
    userinfo_starts: list[int] = []
    userinfo_ends: list[int] = []
    decoded_tails: list[str] = []

    for match in _url_matches(text):
        if match.group("userinfo"):
            userinfo_starts.append(match.start("userinfo"))
            userinfo_ends.append(match.end("userinfo"))
        if _glued(text, match.end("host")):
            continue
        start = match.start()
        parsed = _parse_url(match, strikethrough="~~" in text[max(0, start - 256) : start])
        if parsed is None:
            continue
        url, _, host_ioc, tail = parsed
        collector.add(IOCType.URL, url, source)
        if host_ioc is not None:
            collector.add(host_ioc[0], host_ioc[1], source)
        if not nested and ("%" in tail or "://" in tail):
            # Open redirects and wrapped links: "?url=https%3A%2F%2Fevil.com".
            decoded_tails.append(unquote(tail))

    for match in EMAIL_RE.finditer(text):
        start, end = match.span()
        if _glued(text, start - 1) or _glued(text, end):
            continue
        # "ftp://user:pw@host" is userinfo, not an e-mail address.
        index = bisect.bisect_right(userinfo_ends, start)
        if index < len(userinfo_starts) and userinfo_starts[index] < end:
            continue
        local, _, domain_part = match.group(0).rpartition("@")
        domain = normalize_domain(domain_part)
        if domain is not None and _valid_local_part(local):
            collector.add(IOCType.EMAIL, f"{local.lower()}@{domain}", source)

    for match in DOMAIN_RE.finditer(text):
        start, end = match.span()
        if _glued_before(text, start) or _glued(text, end):
            continue
        domain = normalize_domain(_after_percent_escape(text, start, match.group(0)))
        if domain is None:
            continue
        noise = _bare_name_noise(domain)
        if noise is not None:
            stats[noise] += 1
            continue
        collector.add(IOCType.DOMAIN, domain, source)

    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        stripped = _after_percent_escape(text, match.start(), value)
        if stripped != value and IPV4_RE.fullmatch(stripped) is None:
            continue
        collector.add(IOCType.IPV4, stripped, source)

    for match in IPV6_RE.finditer(text):
        candidate = match.group(0)
        if candidate.startswith(":") and not candidate.startswith("::"):
            # A label colon before the address: "位址：2a03:2880::1" once "：" is folded.
            candidate = candidate[1:]
        ip = normalize_ip(candidate)
        if ip is None and candidate.endswith((":", ".")):
            # A label colon or full stop after it: "2001:db8::1: was used".
            ip = normalize_ip(candidate[:-1])
        if ip is not None and ip[0] == IOCType.IPV6:
            collector.add(IOCType.IPV6, ip[1], source)

    for match in HASH_RE.finditer(text):
        value = match.group(0).lower()
        if value.isdigit() or len(set(value)) == 1:
            continue
        collector.add(_HASH_TYPES[len(value)], value, source)

    for match in CVE_RE.finditer(text):
        year, number = match.group(1), match.group(2)
        if 1999 <= int(year) <= 2100:
            collector.add(IOCType.CVE, f"CVE-{year}-{number}", source)

    # One level only: URLs found in decoded tails are not decoded again. Their
    # stats are not counted, as the raw tail was already scanned above.
    for tail in decoded_tails:
        _extract(collector, tail, source, Counter(), nested=True)


def find_technique_ids(text: str) -> list[str]:
    """Return ATT&CK technique IDs (T1234, T1234.001) written in ``text``, in order."""
    return list(dict.fromkeys(m.group(0).replace("/", ".") for m in TECHNIQUE_RE.finditer(text)))


def extract_iocs(text: str, *, source: str = "text") -> list[IOC]:
    """Refang ``text`` and return the IOCs in it, without any filtering.

    Reserved values (documentation IPs, ``example.com``) and allowlisted values
    are *not* removed here; use :func:`ttprism.analyze_text` for that.
    """
    collector = IOCCollector()
    extract_into(collector, refang(text), source)
    return sort_iocs([IOC(t, v, tuple(sorted(s))) for t, v, s in collector])
