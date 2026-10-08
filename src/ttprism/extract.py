"""Regex-based IOC extraction from untrusted text.

Input is attacker-controlled, so every pattern is written to run in linear
time on Python's backtracking engine:

* each pattern starts with a negative lookbehind, so a match can only begin at
  a token boundary and the engine never rescans the inside of a long token;
* every repetition is bounded (labels <= 63, domains <= 126 labels, URL
  paths <= 2048 characters), and adjacent quantifiers never overlap in a way
  that allows exponential backtracking.

``tests/test_redos.py`` keeps these properties honest with pathological inputs.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from collections import Counter
from importlib import resources

from ttprism.models import IOC, IOCCollector, IOCType, sort_iocs
from ttprism.refang import refang

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_TLD = r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
_DOMAIN_END = r"(?![A-Za-z0-9_@-]|\.[A-Za-z0-9])"

DOMAIN_RE = re.compile(rf"(?<![A-Za-z0-9._/\\@-])(?:{_LABEL}\.){{1,126}}{_TLD}{_DOMAIN_END}")
EMAIL_RE = re.compile(
    rf"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{{1,64}}@(?:{_LABEL}\.){{1,8}}{_TLD}{_DOMAIN_END}"
)

_URL_PATH_CHARS = r"A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%"
URL_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<scheme>https?|ftps?|sftp|wss?)://"
    r"(?:[A-Za-z0-9\-._~!$&'()*+,;=%:]{1,256}@)?"
    r"(?P<host>\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.\-]{1,253})"
    r"(?::(?P<port>[0-9]{1,5}))?"
    rf"(?P<rest>[/?#][{_URL_PATH_CHARS}]{{0,2048}})?",
    re.IGNORECASE,
)

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(rf"(?<![A-Za-z0-9.])(?:{_OCTET}\.){{3}}{_OCTET}(?![0-9]|\.[A-Za-z0-9])")
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:.])(?=[0-9A-Fa-f]{0,4}:)[0-9A-Fa-f:.]{2,45}(?![0-9A-Za-z:])")
HASH_RE = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Za-z])")
_DASH = "-‐‑‒–—―"
CVE_RE = re.compile(
    rf"(?<![A-Za-z0-9])CVE[{_DASH}]([0-9]{{4}})[{_DASH}]([0-9]{{4,7}})(?![0-9])", re.IGNORECASE
)
# "T1566/001" is how attack.mitre.org URLs spell sub-techniques.
TECHNIQUE_RE = re.compile(r"(?<![A-Za-z0-9])T[0-9]{4}(?:[./][0-9]{3})?(?![0-9A-Za-z]|\.[0-9])")

_LABEL_RE = re.compile(_LABEL)
_HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
_URL_TRAILING = ".,;:!?'\"([{"
_BRACKET_PAIRS = {")": "(", "]": "["}

# Special-use names (RFC 2606, RFC 6761, RFC 6762, ICANN .internal): accepted as
# syntactically valid but reported as reserved. ".onion" is special-use too but
# is a real IOC, so it is valid and not reserved.
RESERVED_TLDS = frozenset({"example", "invalid", "localhost", "test", "local", "internal"})
_EXTRA_VALID_TLDS = RESERVED_TLDS | {"onion"}
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")

# Real TLDs that are far more often file extensions in reports ("payload.zip",
# "setup.py"). A bare two-label name with one of these TLDs is dropped; the same
# name as a URL host or in sandbox network data is kept.
FILE_EXTENSION_TLDS = frozenset(
    {"app", "cab", "dot", "java", "md", "mm", "mov", "one", "pm", "ps", "py", "rs", "run", "sh", "so", "zip"}
)


@functools.cache
def known_tlds() -> frozenset[str]:
    data = resources.files("ttprism").joinpath("data/tlds.txt").read_text(encoding="utf-8")
    tlds = {line.strip() for line in data.splitlines() if line.strip() and not line.startswith("#")}
    return frozenset(tlds) | _EXTRA_VALID_TLDS


def normalize_domain(value: str) -> str | None:
    """Return the lower-cased domain if it is syntactically valid, else None."""
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > 253:
        return None
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        return None
    tld = labels[-1]
    if tld.startswith("xn--"):
        return domain if tld in known_tlds() else None
    if not tld.isalpha() or tld not in known_tlds():
        return None
    return domain


def normalize_ip(value: str) -> tuple[IOCType, str] | None:
    candidate = value.strip().strip("[]").rstrip(".")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if address.version == 4:
        # ipaddress accepts "1.2.3.4" only; reject anything our regex would not.
        return (IOCType.IPV4, str(address)) if IPV4_RE.fullmatch(candidate) else None
    groups = [g for g in candidate.split(":") if g]
    if len(groups) < 3 and "." not in candidate:
        return None
    if address.ipv4_mapped is not None:
        # Spelled out here because Python patch releases format these differently.
        return IOCType.IPV6, f"::ffff:{address.ipv4_mapped}"
    return IOCType.IPV6, address.compressed


def is_reserved_domain(domain: str) -> bool:
    if domain.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return any(domain == d or domain.endswith("." + d) for d in RESERVED_DOMAINS)


def is_reserved_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not address.is_global or address.is_multicast


def _strip_url_tail(url: str) -> str:
    """Drop sentence punctuation and unbalanced closing brackets after a URL."""
    opens = {"(": url.count("("), "[": url.count("[")}
    closes = {")": url.count(")"), "]": url.count("]")}
    end = len(url)
    while end:
        last = url[end - 1]
        if last in closes:
            if opens[_BRACKET_PAIRS[last]] >= closes[last]:
                break
            closes[last] -= 1
        elif last in _URL_TRAILING:
            if last in opens:
                opens[last] -= 1
        else:
            break
        end -= 1
    return url[:end]


def normalize_url_match(match: re.Match[str]) -> tuple[str, str] | None:
    """Return (url, host) for a URL_RE match, or None if the host is invalid."""
    host = match.group("host")
    if host.startswith("["):
        ip = normalize_ip(host)
        if ip is None or ip[0] != IOCType.IPV6:
            return None
        clean_host = host
    elif IPV4_RE.fullmatch(host.rstrip(".")):
        clean_host = host.rstrip(".")
    else:
        domain = normalize_domain(host)
        if domain is None and host.lower() != "localhost":
            return None
        clean_host = domain or "localhost"
    port = match.group("port")
    if port is not None and not 0 < int(port) < 65536:
        return None
    url = f"{match.group('scheme').lower()}://"
    # Re-assemble from the original span so userinfo is preserved verbatim.
    start = match.start("host") - match.start()
    prefix = match.group(0)[len(url) : start]
    url += prefix + clean_host
    if port is not None:
        url += ":" + port
    url += match.group("rest") or ""
    url = _strip_url_tail(url)
    return url, clean_host


def extract_into(collector: IOCCollector, text: str, source: str, stats: Counter[str] | None = None) -> None:
    """Add every IOC in already-refanged ``text`` to ``collector``."""
    stats = stats if stats is not None else Counter()

    for match in URL_RE.finditer(text):
        normalized = normalize_url_match(match)
        if normalized is None:
            continue
        url, host = normalized
        collector.add(IOCType.URL, url, source)
        ip = normalize_ip(host) if not host[0].isalpha() else None
        if ip is not None:
            collector.add(ip[0], ip[1], source)
        elif host != "localhost":
            collector.add(IOCType.DOMAIN, host, source)

    for match in EMAIL_RE.finditer(text):
        local, _, domain_part = match.group(0).rpartition("@")
        domain = normalize_domain(domain_part)
        if domain is not None:
            collector.add(IOCType.EMAIL, f"{local.lower()}@{domain}", source)

    for match in DOMAIN_RE.finditer(text):
        domain = normalize_domain(match.group(0))
        if domain is None:
            continue
        labels = domain.split(".")
        if len(labels) == 2 and labels[1] in FILE_EXTENSION_TLDS:
            stats["filename_like_domain"] += 1
            continue
        collector.add(IOCType.DOMAIN, domain, source)

    for match in IPV4_RE.finditer(text):
        collector.add(IOCType.IPV4, match.group(0), source)

    for match in IPV6_RE.finditer(text):
        ip = normalize_ip(match.group(0))
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
