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
