"""Property-based fuzzing of the parsers with Hypothesis.

These run in CI on every pull request. For longer campaigns raise the example
count, e.g. ``HYPOTHESIS_PROFILE=fuzz pytest tests/test_fuzz.py``.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from ttprism import AnalysisOptions, IOCType, analyze_cape, analyze_text, defang, refang, to_csv, to_json
from ttprism.cape import parse_cape
from ttprism.export import escape_csv_cell
from ttprism.extract import FILE_EXTENSION_TLDS, extract_iocs, known_tlds
from ttprism.inputs import InputError, load_json

OPTIONS = AnalysisOptions(include_reserved=True)

# Text biased towards characters that matter to the extractor.
interesting = st.sampled_from(
    list(".:/@[](){}【】〔〕．。：＠-_%?#=&\\'\" \n\t\u200bhxtpsHXTP0123456789abcdef")
)
noisy_text = st.lists(st.one_of(interesting, st.characters()), max_size=400).map("".join)

# Three or more x's is how reports mask a label ("wiki.xxxx.com"); such names are dropped on purpose.
label = st.from_regex(r"[a-z0-9](?:[a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True).filter(
    lambda s: len(s) < 3 or s.strip("x")
)
tld = st.sampled_from(sorted(t for t in known_tlds() if t.isalpha() and t not in FILE_EXTENSION_TLDS))
domain = st.builds(lambda labels, t: ".".join([*labels, t]), st.lists(label, min_size=1, max_size=3), tld)
ipv4 = st.tuples(*[st.integers(0, 255)] * 4).map(lambda t: ".".join(map(str, t)))
# Paths do not end in "." or similar: a trailing period is read as sentence punctuation.
path = st.from_regex(r"(/[A-Za-z0-9_~-]{1,8}(\.[A-Za-z0-9]{1,4})?){0,3}/?", fullmatch=True)
url = st.builds(lambda s, d, p: f"{s}://{d}{p}", st.sampled_from(["http", "https", "ftp"]), domain, path)
separator = st.sampled_from([" ", "\n", "，", "、", "（", "：", "\t", " (", "<", "|"])


@given(noisy_text)
def test_analyze_text_never_crashes(text: str) -> None:
    result = analyze_text(text, OPTIONS)
    json.loads(to_json(result))
    to_csv(result)


@given(noisy_text)
def test_refang_never_crashes(text: str) -> None:
    refang(text)


@given(domain, separator, separator)
def test_domains_in_context_are_found(name: str, before: str, after: str) -> None:
    iocs = extract_iocs(f"前文{before}{name}{after}後文")
    assert (IOCType.DOMAIN, name) in [(i.type, i.value) for i in iocs]


@given(
    st.one_of(
        domain.map(lambda d: (d, IOCType.DOMAIN)),
        ipv4.map(lambda i: (i, IOCType.IPV4)),
        url.map(lambda u: (u, IOCType.URL)),
    )
)
def test_defang_round_trip(value_and_type: tuple[str, IOCType]) -> None:
    value, ioc_type = value_and_type
    defanged = defang(value, ioc_type)
    assert refang(defanged) == value
    assert (ioc_type, value) in [(i.type, i.value) for i in extract_iocs(f"IOC: {defanged} ")]


@given(st.text(max_size=50))
def test_csv_cells_never_start_a_formula(cell: str) -> None:
    escaped = escape_csv_cell(cell)
    assert not escaped.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))
    buffer = io.StringIO()
    csv.writer(buffer).writerow([escaped])
    assert next(csv.reader(io.StringIO(buffer.getvalue()))) == [escaped]


@given(st.text(max_size=300))
def test_load_json_only_raises_input_error(text: str) -> None:
    with contextlib.suppress(InputError):
        load_json(text)


json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), noisy_text),
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(st.text(max_size=10), children, max_size=4)
    ),
    max_leaves=30,
)
cape_keys = st.sampled_from(
    [
        "target",
        "dropped",
        "CAPE",
        "network",
        "behavior",
        "signatures",
        "ttps",
        "hosts",
        "domains",
        "dns",
        "http",
        "http_ex",
        "https_ex",
        "answers",
        "summary",
        "processes",
        "calls",
        "executed_commands",
        "write_keys",
        "environ",
        "CommandLine",
        "file",
        "md5",
        "sha256",
        "ip",
        "domain",
        "request",
        "uri",
        "host",
        "name",
        "api",
        "ttp",
        "type",
        "data",
    ]
)
cape_like = st.recursive(
    st.one_of(json_values, st.sampled_from(["A", "T1055", "198.51.100.1", "evil.com", "http://evil.com/x"])),
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(cape_keys, children, max_size=6)
    ),
    max_leaves=60,
)


@given(st.dictionaries(cape_keys, cape_like, max_size=8))
def test_parse_cape_never_crashes(report: dict[str, Any]) -> None:
    report["info"] = {}
    parse_cape(report)
    analyze_cape(report, OPTIONS)
