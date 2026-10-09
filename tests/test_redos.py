"""Pathological inputs must be processed in linear time, at a bounded cost per MB.

Each case is about 1 MB. A regex with catastrophic or quadratic backtracking takes minutes or hours
on these; the linear patterns take well under a second. The limits are generous, so slow CI
machines do not cause false failures; the everyday command corpora have a much tighter one.
"""

from __future__ import annotations

import pytest

import command_corpus
import reference_matcher
from timing import seconds_per_mb, size_mb
from ttprism import AnalysisOptions, analyze_text
from ttprism.attack import Behavior, RuleSet
from ttprism.inputs import InputError, load_json

SIZE = 1_000_000
TEXT_SECONDS_PER_MB = 10.0
COMMAND_SECONDS_PER_MB = 5.0
JSON_SECONDS_PER_MB = 10.0
# Everyday command lines: about 0.03 to 0.1 s/MB in the development container, and 19 to 28 times
# faster than the matcher that tried every phrase list on every command (tests/reference_matcher.py).
EVERYDAY_COMMAND_SECONDS_PER_MB = 0.25
EVERYDAY_SPEEDUP = 10

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
    # Review of the fixes: compound schemes, list-like userinfo, label groups, escapes, bidi.
    "scheme prefix runs": "a+" * (SIZE // 2),
    "long scheme prefixes": "abcdefghijklmnop+" * (SIZE // 17) + "http://a.com",
    "dotted schemes": "ab.http://a.com " * (SIZE // 16),
    "comma userinfo": "http://a," * (SIZE // 9),
    "list userinfo": "http://a,b;c&d:" * (SIZE // 15),
    "long list userinfo": ("http://" + "a," * 200 + " ") * (SIZE // 408),
    "list hosts": "http://a.com,b.com;c.com&" * (SIZE // 25),
    "path stop marks": ("http://a.com/" + ",*_" * 680 + " ") * (SIZE // 2054),
    "letter hex labels before ipv6": "gabcd:1:" * (SIZE // 8),
    "high-byte escapes": "%C3%A9a.com " * (SIZE // 12),
    "json-escaped versions": "Chrome\\/1.0.0.0 " * (SIZE // 16),
    "query separators": ("http://a.com/?" + "a=%2F;" * 340 + " ") * (SIZE // 2055),
    "bidi beside cjk": "\u3002\u200ea" * (SIZE // 3),
    "soft hyphen and bidi": "a\u00ad\u200e" * (SIZE // 3),
    "rtl letters": "a\u05d0b.com " * (SIZE // 9),
}

# Command lines reach the ATT&CK rules from CAPE reports: quotes, carets and chaining, glued
# switches, switch phrases and "<arg>" phrases. One 1 MB command, although CAPE cuts commands to
# 8 KiB, so the patterns themselves are tested.
PATHOLOGICAL_COMMANDS = {
    "quotes": '"' * SIZE,
    "cmd quotes": 'cmd /c "' * (SIZE // 8),
    "escaped chains": "^&" * (SIZE // 2),
    "chains": "net view&" * (SIZE // 9),
    "glued switches": "/a" * (SIZE // 2),
    "long glued words": (" " + "a" * 32 + ("/" + "a" * 31) * 17 + "x") * (SIZE // 580),
    "glued words after backslashes": ("\\" + "a" * 32 + ("/" + "a" * 31) * 16 + "\\") * (SIZE // 580),
    "switch quotes": '/c"' * (SIZE // 3),
    "glued switch quotes": 'cmd/c"' * (SIZE // 6),
    "bare arguments": "net start " * (SIZE // 10),
    "long arguments": ("net share " + "a" * 259 + " ") * (SIZE // 270),
    "switch colons": "/c:" * (SIZE // 3),
    "dashes": "\u2013e " * (SIZE // 3),
    # The indexed matcher: slash hints, separators, quote runs, chaining, word runs.
    "slashes before long switches": ("a/" + "b" * 40 + " ") * (SIZE // 43),
    "switches after separators": "a&/c" * (SIZE // 4),
    "quote runs between words": ("a" + "\"'" * 40 + "b ") * (SIZE // 83),
    "quotes after words": 'a"' * (SIZE // 2),
    "single quotes after words": "a'" * (SIZE // 2),
    "pipes": "|" * SIZE,
    "escaped pipes": "^|" * (SIZE // 2),
    "non-ascii words": "\u00e9" * SIZE,
    "non-ascii quoted words": '\u00e9"' * (SIZE // 2),
}


@pytest.mark.parametrize("text", PATHOLOGICAL.values(), ids=PATHOLOGICAL.keys())
def test_extraction_is_linear(text: str) -> None:
    options = AnalysisOptions(include_reserved=True)
    cost = seconds_per_mb(lambda: analyze_text(text, options), size_mb(text))
    assert cost < TEXT_SECONDS_PER_MB, f"{cost:.2f} s/MB"


@pytest.mark.parametrize("command", PATHOLOGICAL_COMMANDS.values(), ids=PATHOLOGICAL_COMMANDS.keys())
def test_command_matching_is_linear(command: str) -> None:
    rules = RuleSet.default()
    cost = seconds_per_mb(lambda: rules.evaluate(Behavior(commands=[command])), size_mb(command))
    assert cost < COMMAND_SECONDS_PER_MB, f"{cost:.2f} s/MB"


@pytest.mark.parametrize(
    "lines",
    [command_corpus.normal(60), command_corpus.varied(60), command_corpus.short(3000)],
    ids=["normal", "varied", "short"],
)
def test_everyday_command_matching_cost(lines: list[str]) -> None:
    rules = RuleSet.default()
    behavior = Behavior(commands=lines)
    mb = size_mb(lines)
    cost = seconds_per_mb(lambda: rules.evaluate(behavior), mb, repeat=3)
    reference = seconds_per_mb(lambda: reference_matcher.reference_evaluate(rules, behavior), mb)
    assert cost < EVERYDAY_COMMAND_SECONDS_PER_MB, f"{cost:.3f} s/MB"
    assert reference / cost > EVERYDAY_SPEEDUP, f"{reference / cost:.1f} times faster"


@pytest.mark.parametrize(
    "text",
    ["[" * SIZE, "{" * SIZE, '{"a":' * (SIZE // 5), '"' + "\\" * SIZE, '"\\' * (SIZE // 2)],
    ids=["arrays", "objects", "nested keys", "unterminated string", "escaped quotes"],
)
def test_malformed_json_fails_fast(text: str) -> None:
    def parse() -> None:
        with pytest.raises(InputError):
            load_json(text)

    cost = seconds_per_mb(parse, size_mb(text))
    assert cost < JSON_SECONDS_PER_MB, f"{cost:.2f} s/MB"
