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
from urllib.parse import unquote, unquote_plus

from ttprism.models import IOC, IOCCollector, IOCType, sort_iocs
from ttprism.refang import refang

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
_DOMAIN_END = r"(?![A-Za-z0-9_@-]|\.[A-Za-z0-9])"
# A WebDAV host in a UNC path: "\\host@SSL\DavWWWRoot", "\\host@SSL@443\x", "\\host@80\x".
_WEBDAV_END = r"(?=@(?:[Ss][Ss][Ll](?:@[0-9]{1,5})?|[0-9]{1,5})[\\/])"
# A name right after one of these characters is part of a path, an address or a
# longer name. ")", "]" and "}" before a dot end a call or an index: "(...).Domain.Name".
_NAME_CHARS = r"A-Za-z0-9._/\\@:%-"
_PATH_CHARS = r"A-Za-z0-9._/\\@%-"  # the same without ":", which may be a label colon
_DOMAIN_START = (
    r"(?:(?<![A-Za-z0-9._/\\@-])"
    # A leading dot or wildcard at a token start: ".evil.com", "*.evil.com".
    rf"|(?<=\.)(?<![)\]}}{_NAME_CHARS}]\.)"
    # UNC paths, also after a label colon ("路徑：\\host") but not a drive ("C:\\dir"), and
    # JSON-escaped ones ("\\\\host\\share").
    rf"|(?<=\\\\)(?<![{_PATH_CHARS}]\\\\)(?<!(?<![A-Za-z0-9])[A-Za-z]:\\\\)"
    rf"|(?<=\\\\\\\\)(?<![{_PATH_CHARS}]\\\\\\\\)(?<!(?<![A-Za-z0-9])[A-Za-z]:\\\\\\\\)"
    # Protocol-relative URLs, also after a CJK label colon ("來源：//host"), not after "scheme:".
    rf"|(?<=//)(?<![{_PATH_CHARS}]//)(?<![A-Za-z0-9]://))"
)

DOMAIN_RE = re.compile(rf"{_DOMAIN_START}(?:{_LABEL}\.){{1,126}}{_TLD}(?:{_DOMAIN_END}|{_WEBDAV_END})")
EMAIL_RE = re.compile(
    rf"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{{1,64}}@(?:{_LABEL}\.){{1,8}}{_TLD}{_DOMAIN_END}"
)

_URL_SCHEMES = (
    r"https?|ftps?|sftp|wss?|ldaps?|rmi|iiop|dns|tcp|udp|ssl|tls|smb|file|ssh|telnet|irc|rtsp"
    r"|smtps?|imaps?|pop3s?|socks[45]?[ah]?|rediss?|mongodb|mysql|mssql|postgres(?:ql)?|amqps?|mqtts?"
    r"|rsync|git|svn|vnc|rdp"
)
# Compound schemes keep their prefix: "stratum+tcp://", "git+https://", "mongodb+srv://".
_URL_SCHEME = rf"(?:mongodb\+srv|(?:[A-Za-z][A-Za-z0-9]{{0,15}}\+)?(?:{_URL_SCHEMES}))"
_URL_PATH_CHARS = r"A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%"
# A path ends before a separator that starts the next URL ("/a,http://b/") and
# at a shell "&&". '"', '|', '<' and '>' are not path characters at all.
_URL_PATH_STOP = rf"[,;'()\[\]][*_~]{{0,2}}{_URL_SCHEME}://|&&"
_URL_AFTER_USERINFO = (
    # "_" is accepted in URL host labels (S3 buckets, internal names), but not as
    # the last character, so "_http://evil.com_." keeps its host.
    r"(?P<host>\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9._-]{0,251}[A-Za-z0-9-]\.?)"
    # Wider than a port so that ":443123" is rejected instead of truncated.
    r"(?::(?P<port>[0-9]{1,10}))?"
    rf"(?P<rest>[/?#](?:(?!{_URL_PATH_STOP})[{_URL_PATH_CHARS}]){{0,2048}})?"
)
# Not right after a letter or digit, nor after a word and a dot ("foo.tcp://"); "1.http://" and
# "e.g.https://" are fine.
_URL_START = rf"(?<![A-Za-z0-9+])(?<![A-Za-z]{{2}}\.)(?P<scheme>{_URL_SCHEME})://"
# Userinfo first without ",", ";" and "&", which also join lists ("http://192.0.2.1,ops@x.org");
# _url_matches retries with them when the text is not such a list ("ftp://u:Pa;ss@host").
URL_RE = re.compile(
    _URL_START + r"(?P<userinfo>[A-Za-z0-9\-._~!$'()*+=%:]{1,256}@)?" + _URL_AFTER_USERINFO, re.IGNORECASE
)
_URL_WIDE_USERINFO_RE = re.compile(
    _URL_START + r"(?P<userinfo>[A-Za-z0-9\-._~!$&'()*+,;=%:]{1,256}@)" + _URL_AFTER_USERINFO, re.IGNORECASE
)
_LIST_SEPARATOR_RE = re.compile(r"[,;&]")

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(
    # Also right after a percent escape, single or double encoded: "%2F198.51.100.7", "%252F...".
    rf"(?:(?<![A-Za-z0-9.])|(?<=%[0-9A-Fa-f]{{2}})|(?<=%25[0-9A-Fa-f]{{2}}))"
    rf"(?:{_OCTET}\.){{3}}{_OCTET}(?![0-9]|\.[A-Za-z0-9])"
)
IPV6_RE = re.compile(
    # Also after a label colon, when the label has a letter that is not a hex digit at most four
    # characters before the colon, so the label cannot be read as a group: "IP:2001:db8::1",
    # "IPv6:...", "src:...", "Interface:...". All-hex labels ("C2:") go to _drop_label_group.
    r"(?:(?<![0-9A-Za-z:.])|(?<=[G-Zg-z]:)|(?<=[G-Zg-z][0-9A-Fa-f]:)|(?<=[G-Zg-z][0-9A-Fa-f]{2}:)"
    r"|(?<=[G-Zg-z][0-9A-Fa-f]{3}:)|(?<=[G-Zg-z][0-9A-Fa-f]{4}:))"
    r"(?=[0-9A-Fa-f]{0,4}:)[0-9A-Fa-f:.]{2,45}(?![0-9A-Za-z:])"
)
HASH_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Za-z])")
# A certificate serial number can have the length of a hash: "SerialNumber: 00B7C6B7...". A bare
# "序號" also heads the row-number column of a table, so it counts only with a colon; "證書序號" and
# "憑證序號" (certificate serial number) need none.
_SERIAL_LABEL_RE = re.compile(
    r"(?:(?:serial[ _-]?(?:number|no\.?)?|序列号|序列號|證書序號|憑證序號)[ \t]{0,2}[:：=]?"
    r"|序號[ \t]{0,2}[:：])[ \t]{0,2}[\"']?\Z",
    re.IGNORECASE,
)
# PDF line breaks inside a name or a URL. Next to a dot a hyphen cannot belong to the name, so
# "evil.-\ncom" and "evil-\n.com" are joined without it. A URL that breaks after one of its own
# hyphens ("/a-\nb.exe"), over as many lines as it takes, is joined keeping them. Any other
# hyphen at the end of a line may or may not belong to the name ("dynamic-\ndns.net"), so the rest
# of the name on the next line is dropped as a fragment instead. The pattern starts with the
# hyphen, so the engine skips ahead to hyphens; _rejoin_wrapped_lines looks at the characters
# around it.
_HYPHEN_WRAP_RE = re.compile(r"-[ \t]{0,8}\r?\n[ \t]{0,8}")
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
_ENTITY_TAIL_RE = re.compile(r"&(?:gt|lt|quot|amp|apos|nbsp|#[0-9]{1,7}|#x[0-9A-F]{1,6})\Z", re.IGNORECASE)

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
        "7z",
        "apk",
        "bat",
        "chm",
        "cmd",
        "cpl",
        "csv",
        "dll",
        "doc",
        "docm",
        "docx",
        "exe",
        "gif",
        "hta",
        "htm",
        "html",
        "img",
        "iso",
        "jar",
        "jpeg",
        "jpg",
        "js",
        "jse",
        "lnk",
        "msi",
        "msix",
        "one",
        "pdf",
        "png",
        "ppt",
        "pptm",
        "pptx",
        "ps1",
        "psm1",
        "py",
        "rar",
        "rtf",
        "scr",
        "sh",
        "svg",
        "txt",
        "vbe",
        "vbs",
        "vhd",
        "vhdx",
        "wsf",
        "xls",
        "xlsm",
        "xll",
        "xlsx",
        "zip",
    }
)
# COM ProgIDs and .NET names that end in a real TLD. As bare names they are code
# ("CreateObject(\"WScript.Shell\")"), and so are names under them ("System.Net.Security"); as URL
# hosts they are kept.
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
# .NET namespaces written as in code, every label capitalised: "Microsoft.Data", "Windows.Media".
_NAMESPACE_ROOTS = frozenset({"System", "Microsoft", "Windows"})
# Second-level labels under which ccTLD registries sell names: "co.uk" and
# "com.tw" are public suffixes, not anybody's domain. A bare two-label name made
# of one of these and a two-letter TLD is dropped; "evil.co.uk" is kept. A short
# list instead of the Public Suffix List, which would need regular updates.
SUFFIX_SECOND_LEVEL_LABELS = frozenset(
    {"ac", "co", "com", "edu", "go", "gov", "mil", "ne", "net", "or", "org"}
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
# Every IPv6 address outside 2000::/3 (global unicast) is reserved too: loopback, ULA, link-
# and site-local, multicast, IPv4-compatible, and unassigned space.
_RESERVED_IPV6 = _cidr_table(
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
)
_NAT64_PREFIX = int(ipaddress.IPv6Address("64:ff9b::")) >> 32  # 64:ff9b::/96 embeds an IPv4 address


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
    """Compressed form; with the IPv4 address in dotted form where it is embedded (RFC 5952)."""
    if address.ipv4_mapped is not None:
        # Spelled out here because Python patch releases format these differently.
        return f"::ffff:{address.ipv4_mapped}"
    number = int(address)
    if 1 << 24 <= number < 1 << 32:  # IPv4-compatible ::198.51.100.7, so that it reads back
        return f"::{ipaddress.IPv4Address(number)}"
    if number >> 32 == _NAT64_PREFIX:
        return f"64:ff9b::{ipaddress.IPv4Address(number & 0xFFFFFFFF)}"
    return address.compressed


# Addresses in these ranges are addresses in their own right, not a label glued
# to one: "fd12:3456:789a::1" (ULA) must keep "fd12".
_NOT_LABELLED_IPV6 = _cidr_table("fc00::/7", "fe80::/10", "ff00::/8")


def _drop_label_group(candidate: str) -> str:
    """Drop a hex-looking label glued to an IPv6 address: "C2:2001:db8::1" -> "2001:db8::1".

    The first group goes only if it is outside 2000::/3, the rest is an address
    in 2000::/3, and the whole is not a ULA, link-local or multicast address.
    """
    first, _, rest = candidate.partition(":")
    head = rest.partition(":")[0]
    # String checks first, so that junk such as "1: 1: 1:" costs no address parsing. A group in
    # 2000::/3 is 2000 to 3fff: four digits, the first one 2 or 3.
    if len(head) != 4 or head[0] not in "23" or not _HEX_DIGITS.issuperset(head):
        return candidate
    if not 0 < len(first) <= 4 or not _HEX_DIGITS.issuperset(first) or 0x2000 <= int(first, 16) < 0x4000:
        return candidate
    unlabelled = normalize_ip(rest)
    if unlabelled is None or unlabelled[0] != IOCType.IPV6:
        return candidate
    whole = normalize_ip(candidate)
    if whole is not None and whole[0] == IOCType.IPV6:
        number = int(ipaddress.IPv6Address(whole[1]))
        if any(number & mask == network for network, mask in _NOT_LABELLED_IPV6):
            return candidate
    return rest


def normalize_ip(value: str) -> tuple[IOCType, str] | None:
    candidate = value.strip().strip("[]").rstrip(".")
    if "%" in candidate:
        # A scoped address ("fe80::1%eth0"): the zone ID is arbitrary text.
        return None
    # Cheap checks before parsing, which is slow on inputs made of many short colon tokens.
    if ":" not in candidate:
        if candidate.count(".") != 3:
            return None
    elif "." not in candidate and sum(1 for g in candidate.split(":") if g) < 3:
        # Too short to tell from times and C++ scopes ("12:30", "dead::beef").
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv4Address):
        # ipaddress accepts "1.2.3.4" only; reject anything our regex would not.
        return (IOCType.IPV4, str(address)) if IPV4_RE.fullmatch(candidate) else None
    return IOCType.IPV6, _ipv6_text(address)


def is_reserved_domain(domain: str) -> bool:
    if domain.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return any(domain == d or domain.endswith("." + d) for d in RESERVED_DOMAINS)


def embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv4-mapped (::ffff:0:0/96) or NAT64 (64:ff9b::/96) address carries."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    number = int(address)
    return ipaddress.IPv4Address(number & 0xFFFFFFFF) if number >> 32 == _NAT64_PREFIX else None


def is_reserved_ip(value: str) -> bool:
    """True for special-purpose, private, documentation and multicast addresses.

    Decided by the tables here only, so the result does not depend on the Python version.
    """
    address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        inner = embedded_ipv4(address)  # judged by the IPv4 address it carries
        if inner is not None:
            address = inner
        elif int(address) >> 125 != 1:
            return True
    table = _RESERVED_IPV4 if address.version == 4 else _RESERVED_IPV6
    number = int(address)
    return any(number & mask == network for network, mask in table)


def _strip_url_tail(url: str, *, strikethrough: bool = False, underscores: bool = False) -> str:
    """Drop sentence punctuation, markup and unbalanced closing brackets after a URL.

    A trailing "~~" is dropped only with ``strikethrough``, when the text before
    the URL opened a Markdown strikethrough, and a trailing "__" only with
    ``underscores``, when "__" comes right before the URL ("__bold__").
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
        elif underscores and last == "_" and url[end - 2 : end] == "__":
            underscores = False
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
        end = len(text)
        quote = text[start - 1 : start]
        if quote in ("'", '"') and (close := text.find(quote, start, pos)) != -1:
            # Scanning resumes at the quote, so a URL glued after it is still found.
            pos = end = close
            match = URL_RE.match(text, start, close)
            if match is None:
                continue
        if match.group("userinfo") is None and text[match.end("host") : match.end("host") + 1] in tuple(
            ":,;&"
        ):
            wide = _URL_WIDE_USERINFO_RE.match(text, start, end)
            if wide is not None and not _joins_list(wide.group("userinfo")):
                match = wide
                pos = max(pos, wide.end())
        yield match


def _joins_list(userinfo: str) -> bool:
    """True if a userinfo with ",", ";" or "&" is really a host and a list separator.

    "198.51.100.5,ops@" in "http://198.51.100.5,ops@example.org" is; "backup:Pa;ss@" is not.
    """
    head = _LIST_SEPARATOR_RE.split(userinfo, 1)[0]
    return ":" not in head and (normalize_ip(head) is not None or normalize_domain(head) is not None)


def _parse_url(
    match: re.Match[str], *, strikethrough: bool = False, underscores: bool = False
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
    elif (webdav := _webdav_host(match)) is not None:
        # "file://host@SSL/DavWWWRoot/x" in .url and .lnk files: the host is before the "@".
        clean_host = host.lower()
        host_ioc = webdav
    elif (legacy := _legacy_ipv4(host)) is not None:
        # "http://3221225985/" or "http://0xC0000201/": kept as written, the address reported.
        clean_host = host.lower()
        host_ioc = (IOCType.IPV4, legacy)
    else:
        return None
    port = match.group("port")
    if port is not None and not 0 < int(port) < 65536:
        return None
    # Userinfo is kept verbatim.
    authority = f"{match.group('scheme').lower()}://{match.group('userinfo') or ''}{clean_host}"
    url = authority + (f":{port}" if port is not None else "") + (match.group("rest") or "")
    url = _strip_url_tail(url, strikethrough=strikethrough, underscores=underscores)
    return url, clean_host, host_ioc, url[len(authority) :]


def _webdav_host(match: re.Match[str]) -> tuple[IOCType, str] | None:
    """The real host of a WebDAV URL written "file://host@SSL/..." or "file://host@80/..."."""
    userinfo, host = match.group("userinfo"), match.group("host").lower()
    if not userinfo or not (host == "ssl" or (host.isdigit() and len(host) <= 5)):
        return None
    name = userinfo[:-1]
    address = normalize_ip(name)
    if address is not None:
        return address
    domain = normalize_domain(name, allow_underscore=True)
    return (IOCType.DOMAIN, domain) if domain is not None else None


def host_address(host: str) -> str | None:
    """The IP address a URL host names ("[2001:db8::1]", "192.0.2.1", "3221225985"), or None."""
    if host.startswith("["):
        try:
            return str(ipaddress.IPv6Address(host[1:-1]))
        except ValueError:
            return None
    if IPV4_RE.fullmatch(host):
        return host
    return _legacy_ipv4(host)


def _legacy_ipv4(host: str) -> str | None:
    """The address of a host written as an integer, hex or octal IPv4 address, as browsers read it.

    "3221225985", "0xC0000201", "0300.0000.0002.0001" and "0xc0.0.2.1" are all 192.0.2.1.
    """
    parts = host.removesuffix(".").split(".")
    if len(parts) > 4 or not any(p[:1] == "0" or len(parts) == 1 for p in parts):
        return None  # a dotted quad without leading zeros is matched as a plain IPv4 address
    values: list[int] = []
    for part in parts:
        if part[:2].lower() == "0x":
            digits, base = part[2:], 16
            valid = len(digits) <= 8 and _HEX_DIGITS.issuperset(digits)
        elif len(part) > 1 and part[0] == "0":
            digits, base = part[1:], 8
            valid = len(digits) <= 11 and set(digits) <= set("01234567")
        else:
            digits, base = part, 10
            valid = 0 < len(digits) <= 10 and digits.isascii() and digits.isdigit()
        if not valid:
            return None
        values.append(int(digits, base) if digits else 0)
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(values)):
        return None
    number = last
    for index, value in enumerate(head):
        number |= value << (8 * (3 - index))
    return str(ipaddress.IPv4Address(number))


def normalize_url_match(match: re.Match[str]) -> tuple[str, str] | None:
    """Return (url, host) for a URL_RE match, or None if the host is invalid."""
    parsed = _parse_url(match)
    return None if parsed is None else (parsed[0], parsed[1])


def _glued(text: str, index: int) -> bool:
    """True if ``text[index]`` is a letter or mark that continues the adjacent word."""
    if not 0 <= index < len(text):
        return False
    char = text[index]
    if char <= "\x7f":
        return False
    category = unicodedata.category(char)
    if category[0] == "M":
        # Emoji presentation selectors and enclosing keycaps ("\u26a0\ufe0f", "1\ufe0f\u20e3") belong to
        # a symbol; any other mark continues a word only if it sits on a letter.
        if category == "Me" or "\ufe00" <= char <= "\ufe0f" or "\U000e0100" <= char <= "\U000e01ef":
            return False
        base = index - 1
        while base >= max(0, index - 32) and unicodedata.category(text[base])[0] == "M":
            base -= 1
        if base < 0:
            return False
        index = base
        char = text[base]
        if char <= "\x7f":
            return char.isalpha()
        category = unicodedata.category(char)
    return category[0] == "L" and _joins_latin(text, index)


def _joins_latin(text: str, index: int) -> bool:
    """True if the non-ASCII letter ``text[index]`` next to a name can be part of it.

    Letters of scripts written without spaces touch IOCs in running text. A right-to-left letter
    is a prefix or suffix of the word ("\u0648evil.com"), unless it sits inside a Latin word,
    as a homograph does ("secure-l\u05e1gin.example.com").
    """
    letter = text[index]
    if _SPACELESS_SCRIPT_RE.match(letter) is not None:
        return False
    if unicodedata.bidirectional(letter) not in ("R", "AL"):
        return True
    before, after = text[index - 1 : index], text[index + 1 : index + 2]
    return before.isascii() and before.isalnum() and after.isascii() and after.isalnum()


def _glued_before(text: str, start: int) -> bool:
    """Like :func:`_glued` for the character before a domain and its prefix."""
    if text[max(0, start - 2) : start] in ("//", "\\\\"):
        return _glued(text, start - 3)
    if text[start - 1 : start] == ".":
        return _glued(text, start - 2)
    return _glued(text, start - 1)


# Percent escapes of characters that end a name: every ASCII character except letters, digits and
# controls (tab and line breaks do end one). Escapes of bytes from 80 up are UTF-8 text, which
# ends a name too, but only in a run of escapes: "%cafe-cdn.example.com" after a SQL LIKE wildcard
# is a name.
_SEPARATOR_ESCAPES = frozenset(
    f"{byte:02X}"
    for byte in range(0x80)
    if not chr(byte).isalnum() and (byte >= 0x20 or byte in (0x09, 0x0A, 0x0D)) and byte != 0x7F
)
_HIGH_ESCAPES = frozenset(f"{byte:02X}" for byte in range(0x80, 0x100))


def _ends_name(text: str, percent: int, pair: str, width: int = 3) -> bool:
    """True if the escape of ``pair`` at ``text[percent : percent + width]`` ("%2F", or "%252F" with
    ``width`` 5) is a separator before a name."""
    pair = pair.upper()
    if pair in _SEPARATOR_ESCAPES:
        return True
    before = text[max(0, percent - width) : percent]
    return pair in _HIGH_ESCAPES and before[:1] == "%" and len(before) == width and _is_hex_pair(before[-2:])


def _after_percent_escape(text: str, start: int, value: str) -> str:
    """Drop the hex digits of a "%2F" (or double-encoded "%252F") escape that the match starts with.

    Only escapes of separators count: "%198.51.100.7%" is a SQL LIKE wildcard around an address,
    not "%19" followed by "8.51.100.7".
    """
    if text[start - 1 : start] != "%":
        return value
    skip = 0
    while value[skip : skip + 2] == "25" and _is_hex_pair(value[skip + 2 : skip + 4]):
        skip += 2
    pair = value[skip : skip + 2]
    if len(value) <= skip + 2 or not _is_hex_pair(pair):
        return value
    end = start + len(value)
    if (
        not skip
        and pair.upper() not in _SEPARATOR_ESCAPES
        and text[end : end + 1] == "%"
        and not _is_hex_pair(text[end + 1 : end + 3])
    ):
        return value  # "%cafe.example.com%": literal wildcards around a name
    if _ends_name(text, start - 1, pair, 3 + skip):
        return value[skip + 2 :]
    if skip:
        return value[2:]  # "%25" is an escaped "%", which ends a name too: "%25cafe.example.com"
    return value


def _escape_before(text: str, start: int) -> tuple[str, bool] | None:
    """The hex pair of a "%2F" or "%252F" escape that ends right before ``start``, if any, and
    whether it is a separator."""
    if text[start - 3 : start - 2] == "%" and _is_hex_pair(text[start - 2 : start]):
        pair = text[start - 2 : start].upper()
        return pair, _ends_name(text, start - 3, pair)
    if text[start - 5 : start - 2] == "%25" and _is_hex_pair(text[start - 2 : start]):
        pair = text[start - 2 : start].upper()
        return pair, _ends_name(text, start - 5, pair, 5)
    return None


_QUERY_SEPARATOR_RE = re.compile(r"[&;#]")
_VERSION_LIKE_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.0\.0")


def _product_version(text: str, start: int, value: str) -> bool:
    """True for "Chrome/120.0.0.0" or "Chrome%2F131.0.0.0": a User-Agent version, not an address."""
    if _VERSION_LIKE_RE.fullmatch(value) is None:
        return False
    if text[start - 1 : start] == "/":
        before = start - 2 - (text[start - 2 : start - 1] == "\\")  # also JSON's "Chrome\\/120.0.0.0"
    elif (escape := _escape_before(text, start)) is not None and escape[0] == "2F":
        before = text.rindex("%", 0, start) - 1
    else:
        return False
    return before >= 0 and text[before].isascii() and text[before].isalpha()


# Escapes of characters that cannot appear unquoted in an e-mail local part, or end one in a URL
# ("%3Cops@example.org%3E", "?to%3Dops@..."), single or double encoded.
_LOCAL_PART_DELIMITER_RE = re.compile(
    r"%(?:25){0,4}(?:[01][0-9A-Fa-f]|2[026-9CcFf]|3[A-Fa-f]|40|5[BCDbcd]|7[Ff]|[89A-Fa-f][0-9A-Fa-f])"
)


def _is_hex_pair(chars: str) -> bool:
    return len(chars) == 2 and chars[0] in _HEX_DIGITS and chars[1] in _HEX_DIGITS


def _valid_local_part(local: str) -> bool:
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return any(c.isalnum() for c in local)


def _bare_name_noise(domain: str, written: str) -> str | None:
    """The stats key under which a bare (non-URL) name is dropped, or None to keep it.

    ``written`` is the name as it appears in the text, before lower-casing.
    """
    labels = domain.split(".")
    if labels[-1] in FILE_EXTENSION_TLDS and (
        len(labels) == 2 or (len(labels) == 3 and labels[1] in _INNER_FILE_EXTENSIONS)
    ):
        return "filename_like_domain"
    if domain in CODE_IDENTIFIERS:
        return "code_identifier"
    original = written.split(".")
    in_code_style = not original[0].islower()  # "System.Net.Security"; "asp.net.example.org" is a name
    if in_code_style and any(".".join(labels[:size]) in CODE_IDENTIFIERS for size in range(2, len(labels))):
        return "code_identifier"
    if original[0] in _NAMESPACE_ROOTS and all(label[:1].isupper() for label in original):
        return "code_identifier"
    if len(labels) == 2 and len(labels[1]) == 2 and labels[0] in SUFFIX_SECOND_LEVEL_LABELS:
        return "public_suffix"
    if len(labels) >= 3 and labels[0] in _DETECTION_TYPES and labels[1] in _DETECTION_PLATFORMS:
        return "detection_name"
    return None


# Antivirus detection names whose family is also a TLD: "Backdoor.Win32.Ht", "Trojan.MSIL.Bot".
_DETECTION_TYPES = frozenset(
    {
        "adware", "backdoor", "dropper", "downloader", "exploit", "hacktool", "packed", "ransom",
        "riskware", "rootkit", "spyware", "trojan", "trojan-downloader", "trojan-dropper", "trojan-spy",
        "trojandownloader", "trojandropper", "trojanspy", "virtool", "virus", "worm",
    }
)  # fmt: skip
_DETECTION_PLATFORMS = frozenset(
    {
        "androidos", "linux", "macos", "msil", "msoffice", "o97m", "osx", "w32", "w64", "w97m", "win32",
        "win64", "x97m",
    }
)  # fmt: skip


def _masked_name(name: str) -> bool:
    """True for a name that a report masked: "wiki.xxxx.com", "mail.xxx.example.net"."""
    return any(len(label) >= 3 and not label.strip("x") for label in name.split(".")[:-1])


def _starts_wrapped_line(text: str, start: int) -> bool:
    """True if ``start`` begins a line and the line before ends in a hyphen after a letter or digit."""
    index = start
    while index > max(0, start - 8) and text[index - 1] in " \t":
        index -= 1
    if text[index - 1 : index] != "\n":
        return False
    index -= 1 + (text[index - 2 : index - 1] == "\r")
    end = index
    while index > max(0, end - 8) and text[index - 1] in " \t":
        index -= 1
    return index >= 2 and text[index - 1] == "-" and _is_alnum(text[index - 2])


def _rejoin_wrapped_lines(text: str) -> str:
    """Join names and URLs that a PDF line break split; see _HYPHEN_WRAP_RE."""
    if "\n" not in text:
        return text
    pieces = []
    last = 0
    url_line = url_rest = -1  # a line that continues a URL joined to it, and where the rest starts
    url_state: _UrlState | None = None
    for match in _HYPHEN_WRAP_RE.finditer(text):
        hyphen, after = match.start(), match.end()
        before, next_char = text[hyphen - 1 : hyphen], text[after : after + 1]
        dot_before = before == "." and _is_alnum(text[hyphen - 2 : hyphen - 1]) and _is_alnum(next_char)
        dot_after = _is_alnum(before) and next_char == "." and _is_alnum(text[after + 1 : after + 2])
        if not (dot_before or dot_after or (_is_alnum(before) and _is_alnum(next_char))):
            continue
        # The URL that runs up to the hyphen, if any: the one this line continues, else one on it.
        continuing = url_state is not None and text.rfind("\n", 0, hyphen) + 1 == url_line
        state = (_continues_url(text, url_rest, url_state, hyphen) if continuing else None) or _url_reaches(
            text, hyphen
        )
        if dot_before or dot_after:
            cut = hyphen  # "evil.-\ncom", "evil-\n.com": the hyphen cannot belong to the name
        elif state is not None:
            cut = hyphen + 1  # "http://evil.com/a-\nb.exe", also when the URL wraps again
        else:
            continue
        url_state = state
        url_line, url_rest = (text.rfind("\n", hyphen, after) + 1, after) if state else (-1, -1)
        pieces.append(text[last:cut])
        last = after
    pieces.append(text[last:])
    return "".join(pieces)


def _is_alnum(char: str) -> bool:
    return char.isascii() and char.isalnum()


# Where a URL that runs up to a line-end hyphen stands: still in its host (no path or port yet), and
# the quote before it, if any, at which _url_matches ends it.
_UrlState = tuple[bool, str]
_HOST_PART_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")


def _url_state(match: re.Match[str], quote: str) -> _UrlState:
    return match.start("rest") == -1 and match.group("port") is None, quote if quote in ("'", '"') else ""


def _url_reaches(text: str, hyphen: int) -> _UrlState | None:
    """The state of a URL on the hyphen's line that runs up to the hyphen, which is then its last
    character, or None.

    A URL earlier on the line that has ended does not count: in Chinese text without spaces,
    "...http://a.example/x.exe，时间为2019-" ends in a date, not in the URL. The URLs are those the
    extractor reads (_url_matches), so a URL that ended at its closing quote does not count either.
    """
    line_start = text.rfind("\n", 0, hyphen) + 1
    if text.rfind("://", line_start, hyphen) == -1:
        return None
    line = text[line_start : hyphen + 1]
    last = None
    for last in _url_matches(line):  # noqa: B007 (the last match is used)
        pass
    if last is None or last.end() != len(line):
        return None
    return _url_state(last, line[last.start() - 1 : last.start()])


def _continues_url(text: str, url_rest: int, state: _UrlState | None, hyphen: int) -> _UrlState | None:
    """The new state if the URL joined to the hyphen's line runs on from ``url_rest`` to the hyphen.

    In its host, only letters, digits, dots and hyphens carry the URL on, or a host followed by a
    port and a path; anything else there (a user name, a password, "(") may make the extractor read
    the joined text differently, so the URL is not carried on. After the host, the line must be URL
    path characters. A URL that began after a quote stops at that quote.
    """
    if state is None:
        return None
    in_host, quote = state
    rest = text[url_rest : hyphen + 1]
    if quote and quote in rest:
        return None
    if in_host:
        if _HOST_PART_RE.fullmatch(rest):
            return state
        url = "http://" + rest
        match = URL_RE.match(url)
        if match is None or match.end() != len(url) or match.group("userinfo") or match.start("rest") == -1:
            return None
        return False, quote
    url = "http://a/" + rest
    match = URL_RE.match(url)
    return (False, quote) if match is not None and match.end() == len(url) else None


def extract_into(collector: IOCCollector, text: str, source: str, stats: Counter[str] | None = None) -> None:
    """Add every IOC in already-refanged ``text`` to ``collector``."""
    _extract(
        collector,
        _rejoin_wrapped_lines(text),
        source,
        stats if stats is not None else Counter(),
        nested=False,
    )


def _extract(collector: IOCCollector, text: str, source: str, stats: Counter[str], *, nested: bool) -> None:
    userinfo_starts: list[int] = []
    userinfo_ends: list[int] = []
    decoded_tails: list[str] = []

    for match in _url_matches(text):
        if match.group("userinfo"):
            userinfo_starts.append(match.start("userinfo"))
            userinfo_ends.append(match.end("userinfo"))
        rest_start = match.start("rest")
        if rest_start != -1 and "://" in text[rest_start : match.end()]:
            # A URL inside this one, not encoded ("/web/2020/ftp://user:pw@host/"): its userinfo is
            # not an e-mail address either.
            for inner in URL_RE.finditer(text, rest_start, match.end()):
                if inner.group("userinfo"):
                    userinfo_starts.append(inner.start("userinfo"))
                    userinfo_ends.append(inner.end("userinfo"))
        if _glued(text, match.end("host")):
            continue
        start = match.start()
        parsed = _parse_url(
            match,
            strikethrough="~~" in text[max(0, start - 256) : start],
            underscores=text[max(0, start - 2) : start] == "__",
        )
        if parsed is None:
            continue
        url, _, host_ioc, tail = parsed
        if host_ioc is not None and host_ioc[0] == IOCType.DOMAIN and _masked_name(host_ioc[1]):
            stats["masked_name"] += 1
            continue
        collector.add(IOCType.URL, url, source)
        if host_ioc is not None:
            collector.add(host_ioc[0], host_ioc[1], source)
        if not nested and ("%" in tail or "://" in tail):
            decoded_tails.append(_decoded_tail(tail))

    for match in EMAIL_RE.finditer(text):
        start, end = match.span()
        if _glued(text, start - 1) or _glued(text, end):
            continue
        if _starts_wrapped_line(text, start):
            stats["line_wrap_fragment"] += 1
            continue
        # "ftp://user:pw@host" is userinfo, not an e-mail address.
        index = bisect.bisect_right(userinfo_ends, start)
        if index < len(userinfo_starts) and userinfo_starts[index] < end:
            continue
        local, _, domain_part = match.group(0).rpartition("@")
        delimiters = list(_LOCAL_PART_DELIMITER_RE.finditer(local))  # at most 64 characters
        if delimiters:
            # An encoded quote, bracket or separator ends what comes before: "%3Cops@example.org".
            local = local[delimiters[-1].end() :]
        domain = normalize_domain(domain_part)
        if domain is not None and _masked_name(domain):
            stats["masked_name"] += 1
        elif domain is not None and _valid_local_part(local):
            collector.add(IOCType.EMAIL, f"{local.lower()}@{domain}", source)

    for match in DOMAIN_RE.finditer(text):
        start, end = match.span()
        if _glued_before(text, start) or _glued(text, end):
            continue
        if _starts_wrapped_line(text, start):
            stats["line_wrap_fragment"] += 1
            continue
        written = _after_percent_escape(text, start, match.group(0))
        domain = normalize_domain(written)
        if domain is None:
            continue
        if _masked_name(domain):
            stats["masked_name"] += 1
            continue
        noise = _bare_name_noise(domain, written)
        if noise is not None:
            stats[noise] += 1
            continue
        collector.add(IOCType.DOMAIN, domain, source)

    for match in IPV4_RE.finditer(text):
        start, value = match.start(), match.group(0)
        escape = _escape_before(text, start)
        if escape is not None and not escape[1]:
            continue  # "%41198.51.100.7" decodes to "A198.51.100.7"
        stripped = _after_percent_escape(text, start, value)
        if stripped != value and IPV4_RE.fullmatch(stripped) is None:
            stripped = value
        if stripped == value and _product_version(text, start, value):
            stats["version_like"] += 1
            continue
        collector.add(IOCType.IPV4, stripped, source)

    for match in IPV6_RE.finditer(text):
        candidate = match.group(0)
        if candidate.startswith(":") and not candidate.startswith("::"):
            # A label colon before the address: "位址：2a03:2880::1" once "：" is folded.
            candidate = candidate[1:]
        ip = normalize_ip(_drop_label_group(candidate))
        if ip is None and candidate.endswith((":", ".")):
            # A label colon or full stop after it: "2001:db8::1: was used".
            ip = normalize_ip(_drop_label_group(candidate[:-1]))
        if ip is not None and ip[0] == IOCType.IPV6:
            collector.add(IOCType.IPV6, ip[1], source)

    for match in HASH_RE.finditer(text):
        value = match.group(0).lower()
        if value.isdigit() or len(set(value)) == 1:
            continue
        if _SERIAL_LABEL_RE.search(text, max(0, match.start() - 24), match.start()):
            stats["certificate_serial"] += 1
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


def _decoded_tail(tail: str) -> str:
    """The URL tail with its query parameters decoded one by one, for a second scan.

    Open redirects and wrapped links ("?url=https%3A%2F%2Fevil.com&data=05") carry the target in
    one parameter, so the wrapper's "&data=05" stays out of it, and "+" in a value is a space. A
    URL in the path ("/web/2020/http://evil.com/a?x=1&y=2") keeps its own query.
    """
    path, mark, query = tail.partition("?")
    if "://" in path or not mark:
        return unquote(tail)
    pieces = [unquote_plus(p) for p in _QUERY_SEPARATOR_RE.split(query) if "%" in p or "://" in p]
    return " ".join([unquote(path), *pieces])


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
