"""Pathological inputs must be processed in (roughly) linear time.

Each case is about 1 MB. A regex with catastrophic or quadratic backtracking
takes minutes or hours on these; the linear patterns take well under a second.
The time limit is generous so slow CI machines do not cause false failures.
"""

from __future__ import annotations

import time

import pytest

from ttprism import AnalysisOptions, analyze_text
from ttprism.inputs import InputError, load_json

SIZE = 1_000_000
LIMIT_SECONDS = 10.0

PATHOLOGICAL = {
    "dotted labels, invalid tld": "a1." * (SIZE // 3),
    "long label": "a" * SIZE,
    "hyphens": "a-" * (SIZE // 2),
    "digits and dots": "1." * (SIZE // 2),
    "ip-like run": "1.1.1.1." * (SIZE // 8),
    "colons": "1:" * (SIZE // 2),
    "hex colons": "ab:" * (SIZE // 3),
    "hex run": "ab" * (SIZE // 2),
    "at signs": "a@" * (SIZE // 2),
    "email-ish": "a.b@c" * (SIZE // 5),
    "url host": "http://" + "a" * SIZE,
    "url path": "http://a.com/" + "(" * SIZE,
    "url trailing punctuation": ("http://a.com/" + ")" * 2048 + " ") * (SIZE // 2062),
    "url schemes": "http://" * (SIZE // 7),
    "userinfo": "http://" + "a:" * (SIZE // 2),
    "defang markers": "[.]" * (SIZE // 3),
    "cjk brackets": "【.】" * (SIZE // 3),
    "hxxp": "hxxp" * (SIZE // 4),
    "cve prefixes": "CVE-" * (SIZE // 4),
    "technique prefixes": "T1" * (SIZE // 2),
    "full-width": "１．" * (SIZE // 2),
    "zero-width": "a\u200b." * (SIZE // 3),
    # URL boundaries: separators and quotes before schemes, "&&", other schemes.
    "separators before schemes": ",http://a.com/" * (SIZE // 14),
    "separator then partial scheme": "http://a.com/" + ",http:/" * (SIZE // 7),
    "quoted urls": "'http://a.co/'" * (SIZE // 14),
    "quote cut then glued urls": "'http://a.co/" + "'=http://a.co/" * (SIZE // 14),
    "shell and": "http://a.com/" + "&" * SIZE,
    "other schemes": "jndi:ldap://a." * (SIZE // 14),
    "underscore host": "http://" + "_" * SIZE,
    "long port": "http://a.com:" + "1" * SIZE,
    # Hosts after UNC, protocol-relative, wildcard and leading-dot prefixes.
    "unc prefixes": "\\\\a." * (SIZE // 4),
    "backslashes": "\\" * SIZE,
    "protocol-relative prefixes": "//a." * (SIZE // 4),
    "slashes": "/" * SIZE,
    "wildcard prefixes": "*.a" * (SIZE // 3),
    "leading dots": " .a" * (SIZE // 3),
    # Percent-encoding: escapes before names and IPs, decoded URL tails.
    "percent escapes": "%2F" * (SIZE // 3),
    "percent before names": "%2Fa.com" * (SIZE // 8),
    "double-encoded escapes": ("%25" * 20 + "2Fa.com ") * (SIZE // 68),
    "percent before ips": "%201.2.3.4" * (SIZE // 10),
    "percent in url tails": ("http://a.com/?" + "%2" * 1000 + " ") * (SIZE // 2015),
    "encoded redirects": "http://a.com/?u=" + "http%3A%2F%2Fa.com%2F%3Fu%3D" * (SIZE // 29),
    "nested redirects": "http://a.com/?u=" * (SIZE // 16),
    # URL tails: markup and entities.
    "url footnotes": ("http://a.com/" + "[1]" * 680 + " ") * (SIZE // 2054),
    "url entities": ("http://a.com/" + "&gt;" * 510 + " ") * (SIZE // 2054),
    "url stars and tildes": ("~~http://a.com/" + "*~" * 1020 + " ") * (SIZE // 2056),
    "userinfo and emails": "http://a:b@c.com/ b@c.com " * (SIZE // 26),
    # Refang: space-flanked and slash markers, scheme variants, folding.
    "spaced defang markers": "a [.] a [at] a (.) " * (SIZE // 19),
    "slash markers": "[/][//]" * (SIZE // 7),
    "scheme variants": "hxxp[s]h[tt]p[s]:" * (SIZE // 17),
    "format characters": "a\u200e" * (SIZE // 2),
    "nfkc expanders": "\ufdfa" * SIZE,
    "ligatures": "\ufb03" * SIZE,
    # Boundary checks against neighbouring letters and label colons.
    "glued letters": "\u00fca.com" * (SIZE // 6),
    "combining marks": "a\u0301" * (SIZE // 2),
    "label colons before ipv6": "\u5740:1:2:3::" * (SIZE // 9),
    "hex labels before ipv6": "c2:2001:db8::1 beef:2001:db8::" * (SIZE // 30),
    "hex label chains": "c2:" * (SIZE // 3),
    "short colon tokens": "1: " * (SIZE // 3),
    # Second review: label colons and hex labels before IPv6, wildcards, UA versions, legacy hosts.
    "letter labels before ipv6": "g:1:" * (SIZE // 4),
    "version labels before ipv6": "v6:1:2:" * (SIZE // 7),
    "percent wildcards": "'%1.2.3.4%'" * (SIZE // 11),
    "non-separator escapes": "%411.2.3.4 " * (SIZE // 11),
    "product versions": "Chrome/1.0.0.0 " * (SIZE // 15),
    "legacy url hosts": "http://0300.0000.0002.0001/ " * (SIZE // 28),
    "hex url hosts": "http://0x" + "1" * SIZE,
    "compound schemes": "stratum+tcp://a+tcp://" * (SIZE // 22),
    "redirect parameters": "http://a.com/?" + "u=http%3A%2F%2Fa.com&" * (SIZE // 21),
    "email delimiters": ("%3C" * 20 + "a@b.com ") * (SIZE // 68),
    "dots after calls": ").a.b" * (SIZE // 5),
    "unc after label colons": ":\\\\a." * (SIZE // 5),
    "json-escaped unc": "\\\\\\\\a." * (SIZE // 6),
    "webdav suffixes": "\\\\ab.co@SSL@443\\" * (SIZE // 17),
    "marks before a name": "\u0301" * SIZE + "evil.com",
    "emoji selectors": "\u26a0\ufe0fa.com " * (SIZE // 8),
    "bidi isolates": "\u2066a.com\u2069" * (SIZE // 7),
    "spaced brackets": "a (at) b {dot} c \u3010.\u3011 " * (SIZE // 24),
    "no-break spaces": "a[\u00a0.\u00a0]" * (SIZE // 5),
    "punycode dashes": "xn\u2013" * (SIZE // 3),
    "http or https": "hxxp(s)http(s):" * (SIZE // 15),
    "full-width punctuation": "http://a.com/\uff08\uff0c" * (SIZE // 15),
    "underscore markup": "__http://a.com/_" * (SIZE // 16),
    # Public-suffix names, bare and with leading dots.
    "public suffixes": "co.uk .com.tw " * (SIZE // 14),
    "public suffix chains": "co.uk." * (SIZE // 6),
}


@pytest.mark.parametrize("text", PATHOLOGICAL.values(), ids=PATHOLOGICAL.keys())
def test_extraction_is_linear(text: str) -> None:
    options = AnalysisOptions(include_reserved=True)
    start = time.perf_counter()
    analyze_text(text, options)
    elapsed = time.perf_counter() - start
    assert elapsed < LIMIT_SECONDS, f"{elapsed:.1f}s"


@pytest.mark.parametrize(
    "text",
    ["[" * SIZE, "{" * SIZE, '{"a":' * (SIZE // 5), '"' + "\\" * SIZE, '"\\' * (SIZE // 2)],
    ids=["arrays", "objects", "nested keys", "unterminated string", "escaped quotes"],
)
def test_malformed_json_fails_fast(text: str) -> None:
    start = time.perf_counter()
    with pytest.raises(InputError):
        load_json(text)
    assert time.perf_counter() - start < LIMIT_SECONDS
