"""Evaluate TTPrism, iocextract and ioc-finder on public Chinese-language threat reports.

Run from the repository root in a virtual environment with the pinned tools and TTPrism:

    uv venv -p 3.11.17 /tmp/eval    # a Python with the 2025 html.parser security fixes
    uv pip install -p /tmp/eval/bin/python -r docs/research/2026-10-real-reports/requirements.txt -e .
    E=docs/research/2026-10-real-reports/evaluate.py
    /tmp/eval/bin/python -I $E text zh-tw            # PDF or HTML -> text, one method per format
    /tmp/eval/bin/python -I $E defang zh-tw          # how often each defang style occurs
    /tmp/eval/bin/python -I $E truth zh-tw           # ground-truth draft, review page and template
    /tmp/eval/bin/python -I $E review zh-tw          # check the filled-in reviews, write the manifest
    git add docs/research/2026-10-real-reports/manifest.json \
        docs/research/2026-10-real-reports/defang-zh-tw.json
    git commit -m "Reviewed zh-TW ground truth"      # before any tool runs
    /tmp/eval/bin/python -I $E run zh-tw heldout     # run the tools on the same text
    /tmp/eval/bin/python -I $E judge zh-tw heldout   # blinded sheet of the values outside the truth
    /tmp/eval/bin/python -I $E judge zh-tw heldout --import
    /tmp/eval/bin/python -I $E score zh-tw heldout   # recall and precision

Source files go in eval-data/<set>/<format>/<id>.<format> (format "pdf" unless the manifest says
"html"), attachments in eval-data/<set>/attachments/; eval-data/ is git-ignored, and so are the
extracted text, the ground-truth drafts, the review pages and the judging sheets. The script, the
manifest (with each report's reviewed ground truth), the judgements and the results are committed.
The manifest is checked first: an unknown or missing field, or a value of the wrong shape, stops
every command, and `text` stops while the set has no selection rule or its rule is not committed as
it stands.

Text: PDFs are read with pypdf (page.extract_text() per page, headers and footers included; a PDF
with only an owner password is decrypted with the empty user password; a glyph pypdf cannot map,
which it gives as a lone surrogate, becomes U+FFFD and is counted by page). Web pages are decoded
strictly and laid out by HtmlText below (Python's html.parser, no CSS); see decode_html and HtmlText
for the rules. html.parser changed in Python's 2025 security releases, and older releases lose page
content silently, so `text` first converts a few canary pages and stops on any other Python. When a
report's indicators are only in an attachment, its text follows the page text, and the conversion
records where each part and each PDF page starts. Line breaks are LF throughout.

Ground truth: a draft and a review. `truth` finds the values in each report's IOC appendix with the
line rules below (none of the evaluated tools is used for it, and neither is TTPrism's list of
top-level domains) and writes, for each report, the draft, a review page that shows every line of
the appendix with the values read from it and its warnings beside images of the rendered pages
(pdftoppm for a PDF, headless Chromium for a web page), and a review template. A reviewer checks
every line against the images, resolves every warning (confirmed, or corrected by adding, removing
or marking values ambiguous), and records for every value of the final truth its normalised form,
its original writing, its writing class (plain, ASCII defang, full-width or CJK-bracket defang) and
where it stands. `review` checks the filled-in templates against the drafts and writes them into the
manifest; `run` stops unless every report's review is complete, committed and made against the
current draft, so the truth is fixed before any tool has run. `review` stops once the set has
results, and `run` stops if earlier results of the set were made with another review.

Bindings: each step records the SHA-256 of what it was made from, and the next one stops if that
changed: `truth`, `defang` and `run` if the text, its source, an attachment, the manifest's format,
source, charsets or attachments, or this script changed since `text`; `run` and `score` if the
draft (the text, the appendix markers, the list of top-level domains or the rules' result) changed
since the review, or the review changed since it was committed; `score` if this script or the
review changed since `run`.

Matching: one function (normalise) gives the standard form of a value, for the ground truth and for
every tool's output alike: defang styles read as their ASCII characters, a URL's scheme and host
lower-cased (hxxp as http), names lower-cased without a trailing dot, e-mail addresses and hashes
lower-cased. A URL that cannot be parsed is kept as it is and listed. URLs are scored both as whole
URLs and by host; before domain recall, each tool's domain output gets the hosts of its URL output.
TTPrism runs with its defaults and raw (no reserved-value or allowlist filtering); the comparison
with the other tools uses raw. A tool that fails on a report is recorded as an error for that
report, with no output, and the run goes on.

Precision: an extracted value is right when it is in the ground truth; every other value has a
judgement in judgements.json (a: an indicator named in the body, b: a correct value that is not an
indicator, c: a wrong value), made on a blinded sheet (`judge`) that hides which tool found it.
Strict precision counts a as right, lenient counts a and b. While any value is unjudged, the totals
are marked provisional. Recall is also given by the writing class of the ground-truth values, and
totals for all reports and for each source format.
"""

from __future__ import annotations

import _markupbase
import bisect
import codecs
import hashlib
import html
import html.entities
import html.parser
import importlib.metadata
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DATA = ROOT / "eval-data"
MANIFEST = HERE / "manifest.json"
JUDGEMENTS = HERE / "judgements.json"
TLDS_FILE = HERE / "iana-tlds.txt"
SCRIPT = Path(__file__).resolve()
TYPES = ("url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256")
# Writing classes of a value in the appendix, from the plainest.
CLASSES = ("plain", "ascii-defang", "fullwidth-cjk-defang")
SETTINGS = {"ttprism-default": [], "ttprism-raw": ["--include-reserved", "--no-default-allowlist"]}
TOOLS = (*SETTINGS, "iocextract", "ioc-finder")
# What the results depend on besides the eval-data files: a run records whether any of these had
# uncommitted changes.
PIPELINE_FILES = (
    ROOT / "src",
    ROOT / "pyproject.toml",
    SCRIPT,
    MANIFEST,
    TLDS_FILE,
    HERE / "requirements.txt",
)


def dump_json(data: Any, indent: int = 1) -> str:
    """JSON for a committed or reviewed file: readable non-ASCII text, but every invisible character
    (control, format, private-use, surrogate, and white space other than the space) as an escape, so
    that no such character reaches a file a person reads or reviews."""
    text = json.dumps(data, ensure_ascii=False, indent=indent)
    return "".join(
        char
        if char in "\n " or unicodedata.category(char) not in ("Cc", "Cf", "Co", "Cs", "Zs", "Zl", "Zp")
        else json.dumps(char)[1:-1]
        if ord(char) < 0x10000
        else json.dumps(char, ensure_ascii=True)[1:-1]
        for char in text
    )


def visible(text: str) -> str:
    """``text`` with every invisible character shown as <U+XXXX>, for printing and review pages."""
    return "".join(
        f"<U+{ord(char):04X}>"
        if char not in " \t" and unicodedata.category(char) in ("Cc", "Cf", "Co", "Cs", "Zs", "Zl", "Zp")
        else char
        for char in text
    )


# --------------------------------------------------------------------------- reading defanged text

# ascii_reading turns the defang styles that reports use into the ASCII characters they stand for and
# remembers where each character came from. Dot, at sign, colon and slash in ASCII, full-width or
# CJK brackets ("[.]", "(dot)", "{.}", "[at]", "[:]", "[://]", "[/]", "【.】", "〔.〕", "［.］", "[。]",
# "（.）", "［＠］", "【:】", "【/】"), with up to two spaces inside and around the brackets (pypdf puts
# a space next to CJK brackets and full-width punctuation, and two where the source had one); a
# URL's colon and slashes with spaces around them after a scheme ("hxxps ： //", "https ：／／"); the
# full-width dot and at sign, with up to two spaces around them only between ASCII letters or digits
# (so that "１． 198.51.100.23" numbering stays apart from the value after it); the full-width colon,
# slash and hyphen, and full-width letters and digits; the hyphens U+2010, U+2011, U+2212 and U+FE63;
# and the ligatures U+FB00 to U+FB06 as their letters. A bare ideographic full stop is not a dot,
# and other full-width punctuation (，；（）) stays as it is, so that it ends a value. Whether a form
# is ASCII or full-width and CJK is decided without the spaces around it.
_SP = "[ \\u3000]{0,2}"
_BRACKETS = (
    ("\\[", "\\]"),
    ("\\(", "\\)"),
    ("\\{", "\\}"),
    ("【", "】"),
    ("〔", "〕"),
    ("［", "］"),
    ("（", "）"),
)
_INSIDE = {
    ".": "(?:[.\\uff0e\\u3002]|[Dd][Oo][Tt])",
    "@": "(?:[@\\uff20]|[Aa][Tt])",
    "://": "(?:[:\\uff1a]//|[:\\uff1a][/\\uff0f][/\\uff0f])",
    ":": "[:\\uff1a]",
    "//": "(?://|[/\\uff0f][/\\uff0f])",
    "/": "[/\\uff0f]",
}
_ALNUM_BEFORE, _ALNUM_AFTER = "(?<=[A-Za-z0-9])", "(?=[A-Za-z0-9])"
_FORMS = re.compile(
    "|".join(
        f"(?P<{name}{index}>{_SP}{opening}{_SP}{inside}{_SP}{closing}{_SP})"
        for name, inside in (
            ("scheme", _INSIDE["://"]),
            ("slashes", _INSIDE["//"]),
            ("dot", _INSIDE["."]),
            ("at", _INSIDE["@"]),
            ("colon", _INSIDE[":"]),
            ("slash", _INSIDE["/"]),
        )
        for index, (opening, closing) in enumerate(_BRACKETS)
    )
    # A scheme's colon and slashes with a space or a full-width character among them, or "://" with
    # spaces after it before a host.
    + "|(?P<fwscheme>(?<=[A-Za-z])(?:(?!://)"
    + f"{_SP}[:\\uff1a]{_SP}[/\\uff0f]{_SP}[/\\uff0f]"
    + "(?:[ \\u3000]{1,2}(?=[A-Za-z0-9\\[]))?|://[ \\u3000]{1,2}(?=[A-Za-z0-9\\[])))"
    + "".join(
        f"|(?P<{name}>{_ALNUM_BEFORE}(?:[ \\u3000]{{1,2}}{char}{_SP}|{char}[ \\u3000]{{1,2}}){_ALNUM_AFTER})"
        for name, char in (("fwdot", "\\uff0e"), ("fwat", "\\uff20"))
    )
)
_FORM_VALUES = {
    "scheme": "://",
    "slashes": "//",
    "dot": ".",
    "at": "@",
    "colon": ":",
    "slash": "/",
    "fwdot": ".",
    "fwat": "@",
    "fwscheme": "://",
}
_SINGLE = {
    "．": ".",
    "＠": "@",
    "：": ":",
    "／": "/",
    "－": "-",
    **{chr(code): chr(code - 0xFEE0) for code in range(0xFF10, 0xFF1A)},  # full-width digits
    **{chr(code): chr(code - 0xFEE0) for code in range(0xFF21, 0xFF3B)},  # full-width capitals
    **{chr(code): chr(code - 0xFEE0) for code in range(0xFF41, 0xFF5B)},  # full-width small letters
}
_HYPHENS = {"‐": "-", "‑": "-", "−": "-", "﹣": "-"}
_LIGATURES = {"\ufb00": "ff", "\ufb01": "fi", "\ufb02": "fl", "\ufb03": "ffi", "\ufb04": "ffl"}
_LIGATURES |= {"\ufb05": "st", "\ufb06": "st"}
# A URL whose scheme is written hxxp, hxxps or fxp is ASCII-defanged even when nothing else is: the
# scheme before a colon or a bracket form, with up to two spaces between (as for the defang statistic).
_SCHEME_FOLLOWS = "(?=[ \\u3000]{0,2}[:\uff1a\\[(\\{【〔［（])"
_DEFANGED_SCHEME = re.compile("\\s*(?:[Hh][Xx][Xx][Pp][Ss]?|[Ff][Xx][Pp])" + _SCHEME_FOLLOWS)
# The full-width dot and at sign are read as a dot and an at sign only after an ASCII letter, digit,
# hyphen or underscore (as read), or after a mask character ("ser***＠example.org" reads as its ASCII
# form does): after Chinese text or at the start of a line they are punctuation
# ("網域．bad.example.net"), and they end a value there.
_NAME_BEFORE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_*\uff0a#\u25cb\u25cf\u3007"
)


class Reading:
    """Text read through ascii_reading: the ASCII text, and for each of its characters where it came
    from in the original (start, end) and what it was read from ("" itself, "ascii" an ASCII defang,
    "cjk" a full-width or CJK form, "hyphen" a Unicode hyphen, "ligature" a ligature)."""

    __slots__ = ("kinds", "origins", "raw", "text")

    def __init__(self, raw: str, text: str, origins: list[tuple[int, int]], kinds: list[str]) -> None:
        self.raw, self.text, self.origins, self.kinds = raw, text, origins, kinds

    def span(self, start: int, end: int) -> tuple[int, int]:
        """The span of the original that the characters start..end of the text came from."""
        return self.origins[start][0], self.origins[end - 1][1]

    def writing_class(self, start: int, end: int, url: bool = False) -> str:
        """The writing class of the characters start..end: full-width or CJK if any of them was read
        from such a form, else ASCII defang if any was read from one (or, for a URL, its scheme is
        written hxxp or fxp), else plain."""
        kinds = set(self.kinds[start:end])
        if "cjk" in kinds:
            return "fullwidth-cjk-defang"
        raw_start, raw_end = self.span(start, end)
        if "ascii" in kinds or (url and _DEFANGED_SCHEME.match(self.raw, raw_start, raw_end)):
            return "ascii-defang"
        return "plain"


def ascii_reading(raw: str) -> Reading:
    chars: list[str] = []
    origins: list[tuple[int, int]] = []
    kinds: list[str] = []
    position = 0

    def single(index: int) -> None:
        char = raw[index]
        if char in "\uff0e\uff20" and not (chars and chars[-1] in _NAME_BEFORE):
            chars.append(char)
            kinds.append("")
        elif char in _SINGLE:
            chars.append(_SINGLE[char])
            kinds.append("cjk")
        elif char in _HYPHENS:
            chars.append(_HYPHENS[char])
            kinds.append("hyphen")
        elif char in _LIGATURES:
            letters = _LIGATURES[char]
            chars.extend(letters)
            kinds.extend(["ligature"] * len(letters))
            origins.extend([(index, index + 1)] * (len(letters) - 1))
        else:
            chars.append(char)
            kinds.append("")
        origins.append((index, index + 1))

    for match in _FORMS.finditer(raw):
        for index in range(position, match.start()):
            single(index)
        name = match.lastgroup or ""
        replacement = _FORM_VALUES[name.rstrip("0123456789")]
        form = match.group(0)
        kind = "ascii" if form.replace(" ", "").replace("\u3000", "").isascii() else "cjk"
        for char in replacement:
            chars.append(char)
            origins.append((match.start(), match.end()))
            kinds.append(kind)
        position = match.end()
    for index in range(position, len(raw)):
        single(index)
    return Reading(raw, "".join(chars), origins, kinds)


# --------------------------------------------------------------------------- normalisation

_URL_PARTS = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#\s]*)(.*)", re.DOTALL)


def normalise_url(value: str) -> tuple[str, bool]:
    """The standard form of a URL (defang styles read, scheme and host lower-cased, hxxp read as
    http and fxp as ftp) and whether it could be parsed (has a host that can be a name or an
    address); one that cannot is returned as it is, never with an exception."""
    value = ascii_reading(value.strip()).text
    value = re.sub(r"^[Ff][Xx][Pp]", "ftp", re.sub(r"^[Hh][Xx][Xx][Pp]", "http", value))
    match = _URL_PARTS.fullmatch(value)
    if match is None:
        return value, False
    scheme, netloc, rest = match.groups()
    url = f"{scheme.lower()}://{netloc.lower()}{rest}"
    return url, is_host(url_host(url))


def normalise(kind: str, value: str) -> str:
    """The standard form of a value of type ``kind``, for the ground truth and for tool output alike."""
    if kind == "url":
        return normalise_url(value)[0]
    text = ascii_reading(value.strip()).text
    if kind == "domain":
        return text.lower().rstrip(".")
    return text.lower()


def url_host(url: str) -> str:
    """The host of a URL in standard form, or "" if it has none; never an exception."""
    match = _URL_PARTS.fullmatch(url)
    if match is None:
        return ""
    host = match.group(2).rsplit("@", 1)[-1]
    if host.startswith("["):  # an IPv6 address
        return host[1 : host.find("]")].lower() if "]" in host else ""
    host = host.split(":", 1)[0]
    return host.lower().rstrip(".")


def host_class(writing: str) -> str:
    """The writing class of the host in a URL written so (as the review records the writing)."""
    reading = ascii_reading(writing)
    match = re.match(r"\s*[A-Za-z][A-Za-z0-9+.\-]*://([^/?#\s]*)", reading.text)
    if match is None or not match.group(1):
        return reading.writing_class(0, len(reading.text), url=True) if reading.text else CLASSES[0]
    start, end = match.span(1)
    start += match.group(1).rfind("@") + 1
    host = reading.text[start:end]
    if host.startswith("["):
        end = start + host.find("]") + 1 if "]" in host else end
    elif ":" in host:
        end = start + host.index(":")
    return reading.writing_class(start, end) if end > start else CLASSES[0]


def is_host(host: str) -> bool:
    """Whether a URL's host can be a name or an address: not empty, and no character that cannot be
    in either (two URLs joined by a comma give the host "a.example.com,hxxp")."""
    return bool(host) and (is_ip(host) or not re.search(r"[^\w.\-]", host))


def is_ip(host: str) -> bool:
    """Whether a URL's host is an address (digits and dots, or hex digits and colons), not a name."""
    return bool(re.fullmatch(r"[0-9.]+|[0-9a-f:]+", host)) and any(c in host for c in ".:")


# --------------------------------------------------------------------------- manifest

# Fields of the manifest, of a set's reports and of their parts: (required, optional).
_TOP_FIELDS = (
    {"description", "fields", "text_conversion", "selection_rule", "sets"},
    {"skipped", "skipped_fields"},
)
_SOURCE_FIELDS = ({"retrieved", "final_url", "saved"}, {"http_charset", "charset_override"})
_REPORT_FIELDS = (
    {"id", "title", "publisher", "published", "original_url", "url_source", "appendix"} | _SOURCE_FIELDS[0],
    {
        "format",
        "source",
        "collection_path",
        "collection_blob",
        "attachments",
        "truth_review",
        "legacy_truth_corrections",
    }
    | _SOURCE_FIELDS[1],
)
_ATTACHMENT_FIELDS = ({"file"} | _SOURCE_FIELDS[0], _SOURCE_FIELDS[1])
_APPENDIX_FIELDS = ({"start"}, {"end", "end_of_text", "start_occurrence", "start_occurrence_reason"})
_SAVED_FIELDS = ({"kind", "method", "tool"}, {"reason", "note"})
_CHARSET_OVERRIDE_FIELDS = ({"charset", "reason"}, set[str]())
_CORRECTION_FIELDS = (set[str](), {"add", "remove", "ambiguous", "notes"})
_SKIPPED_FIELDS = ({"title", "publisher", "url", "reason"}, {"id"})
_REVIEW_FIELDS = (
    {
        "draft_sha256",
        "reviewed_by",
        "reviewed_at",
        "pages_checked",
        "checked_every_line",
        "warnings",
        "add",
        "remove",
        "ambiguous",
        "values",
        "masked",
    },
    set[str](),
)
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z")
# The one lenient decoding there is, for a page or text whose UTF-8 is damaged: what is not UTF-8
# becomes U+FFFD (one for each invalid sequence), and the number of U+FFFD inserted is recorded.
# Nothing else (Big5 least of all) is decoded leniently.
UTF8_REPLACE = "utf-8:replace"


def _fields(where: str, entry: Any, fields: tuple[set[str], set[str]]) -> list[str]:
    """Problems with the fields of ``entry``: not an object, unknown or missing fields."""
    if not isinstance(entry, dict):
        return [f"{where}: not an object"]
    required, optional = fields
    problems = [f"{where}: unknown field {key!r}" for key in sorted(entry.keys() - required - optional)]
    problems += [f"{where}: missing field {key!r}" for key in sorted(required - entry.keys())]
    return problems


def _text(where: str, value: Any) -> list[str]:
    return [] if isinstance(value, str) and value.strip() else [f"{where}: not a non-empty string"]


def _source_problems(where: str, entry: dict[str, Any]) -> list[str]:
    """Problems with where and how a source file was obtained, and with its charsets."""
    problems = []
    if not _UTC_TIME.fullmatch(str(entry.get("retrieved", ""))):
        problems.append(f"{where}: retrieved must be a UTC time such as 2026-10-09T13:45:04Z")
    if not str(entry.get("final_url", "")).startswith(("https://", "http://")):
        problems.append(f"{where}: final_url must be an http(s) URL")
    saved = entry.get("saved")
    problems += _fields(f"{where}.saved", saved, _SAVED_FIELDS)
    if isinstance(saved, dict):
        if saved.get("kind") not in ("server", "rendered"):
            problems.append(f"{where}.saved: kind must be 'server' or 'rendered'")
        if saved.get("kind") == "rendered":
            problems += _text(f"{where}.saved.reason (why the server's was not enough)", saved.get("reason"))
        problems += _text(f"{where}.saved.method", saved.get("method"))
        problems += _text(f"{where}.saved.tool", saved.get("tool"))
    if "http_charset" in entry and _codec(str(entry["http_charset"])) is None:
        problems.append(f"{where}: unknown http_charset {entry['http_charset']!r}")
    if "charset_override" in entry:
        override = entry["charset_override"]
        problems += _fields(f"{where}.charset_override", override, _CHARSET_OVERRIDE_FIELDS)
        if isinstance(override, dict):
            problems += _text(f"{where}.charset_override.reason", override.get("reason"))
            label = str(override.get("charset", ""))
            if label.lower() != UTF8_REPLACE and _codec(label) is None:
                problems.append(
                    f"{where}.charset_override: unknown charset {label!r} (a codec label, or "
                    f"{UTF8_REPLACE!r} for damaged UTF-8; no other lenient decoding)"
                )
    return problems


def _report_problems(where: str, report: Any) -> list[str]:
    problems = _fields(where, report, _REPORT_FIELDS)
    if not isinstance(report, dict):
        return problems
    problems += _source_problems(where, report)
    if report.get("format", "pdf") not in ("pdf", "html"):
        problems.append(f"{where}: format must be 'pdf' or 'html'")
    if report.get("format", "pdf") == "pdf" and report.keys() & {"charset_override", "http_charset"}:
        problems.append(f"{where}: a PDF has no charset to declare or override")
    appendix = report.get("appendix")
    problems += _fields(f"{where}.appendix", appendix, _APPENDIX_FIELDS)
    if isinstance(appendix, dict):
        problems += _text(f"{where}.appendix.start", appendix.get("start"))
        if ("end" in appendix) == (appendix.get("end_of_text") is True):
            problems.append(f"{where}.appendix: give either an end marker or end_of_text: true")
        elif "end" in appendix:
            problems += _text(f"{where}.appendix.end", appendix.get("end"))
        if "end_of_text" in appendix and appendix["end_of_text"] is not True:
            problems.append(f"{where}.appendix: end_of_text can only be true")
        if "start_occurrence" in appendix:
            occurrence = appendix["start_occurrence"]
            if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence < 1:
                problems.append(f"{where}.appendix: start_occurrence must be a positive integer")
            reason = appendix.get("start_occurrence_reason")
            problems += _text(f"{where}.appendix.start_occurrence_reason", reason)
    for index, attachment in enumerate(report.get("attachments", [])):
        problems += _fields(f"{where}.attachments[{index}]", attachment, _ATTACHMENT_FIELDS)
        if isinstance(attachment, dict):
            problems += _source_problems(f"{where}.attachments[{index}]", attachment)
            is_pdf = str(attachment.get("file", "")).lower().endswith(".pdf")
            if is_pdf and attachment.keys() & {"charset_override", "http_charset"}:
                problems.append(f"{where}.attachments[{index}]: a PDF has no charset to declare or override")
    if "legacy_truth_corrections" in report:
        problems += _correction_problems(
            f"{where}.legacy_truth_corrections", report["legacy_truth_corrections"]
        )
    if "truth_review" in report:
        problems += _review_shape_problems(f"{where}.truth_review", report["truth_review"])
    return problems


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _correction_problems(where: str, corrections: Any) -> list[str]:
    """The legacy corrections of the zh-cn set: add and remove map a type to a list of values,
    ambiguous a type to a list of entries of two or more readings; notes is a list of reasons."""
    problems = _fields(where, corrections, _CORRECTION_FIELDS)
    if not isinstance(corrections, dict):
        return problems
    for change in ("add", "remove", "ambiguous"):
        values = corrections.get(change, {})
        if not isinstance(values, dict):
            problems.append(f"{where}.{change}: not an object keyed by type")
            continue
        for kind, entries in values.items():
            if kind not in TYPES:
                problems.append(f"{where}.{change}: unknown type {kind!r}")
            elif change != "ambiguous" and not _strings(entries):
                problems.append(f"{where}.{change}.{kind}: not a list of values")
            elif change == "ambiguous" and not (
                isinstance(entries, list) and all(_strings(entry) and len(entry) > 1 for entry in entries)
            ):
                problems.append(f"{where}.{change}.{kind}: not a list of entries of two or more readings")
    if "notes" in corrections and not _strings(corrections["notes"]):
        problems.append(f"{where}.notes: not a list of reasons")
    if corrections.keys() & {"add", "remove", "ambiguous"} and not corrections.get("notes"):
        problems.append(f"{where}: every correction needs a reason in notes")
    return problems


def manifest_problems(data: Any) -> list[str]:
    """Everything wrong with the manifest's structure; an unknown field is an error, not ignored."""
    problems = _fields("manifest", data, _TOP_FIELDS)
    if not isinstance(data, dict):
        return problems
    sets, rules = data.get("sets", {}), data.get("selection_rule", {})
    if not isinstance(sets, dict) or not isinstance(rules, dict):
        return [*problems, "manifest: sets and selection_rule must be objects keyed by set name"]
    for name in sorted(rules.keys() - sets.keys()):
        problems.append(f"selection_rule: unknown set {name!r}")
    skipped = data.get("skipped", {})
    if not isinstance(skipped, dict):
        return [*problems, "manifest: skipped must be an object keyed by set name"]
    for name in sorted(skipped.keys() - sets.keys()):
        problems.append(f"skipped: unknown set {name!r}")
    for name, entries in skipped.items():
        if not isinstance(entries, list):
            problems.append(f"skipped.{name}: not a list")
            continue
        for index, entry in enumerate(entries):
            problems += _fields(f"skipped.{name}[{index}]", entry, _SKIPPED_FIELDS)
    for name, reports in sets.items():
        if not isinstance(rules.get(name), str):
            problems.append(f"selection_rule: set {name!r} needs a selection rule (a string)")
        if not isinstance(reports, list):
            problems.append(f"sets.{name}: not a list")
            continue
        ids = [str(report.get("id")) for report in reports if isinstance(report, dict)]
        twice = sorted({i for i in ids if ids.count(i) > 1})
        problems += [f"sets.{name}: id {i!r} occurs twice" for i in twice]
        for index, report in enumerate(reports):
            label = report.get("id", index) if isinstance(report, dict) else index
            problems += _report_problems(f"sets.{name}[{label}]", report)
    return problems


def load_manifest() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems = manifest_problems(data)
    if problems:
        raise SystemExit("the manifest is not valid:\n    " + "\n    ".join(problems))
    return data


def manifest(name: str) -> list[dict[str, Any]]:
    sets = load_manifest()["sets"]
    if name not in sets:
        raise SystemExit(f"no set {name!r} in the manifest")
    reports: list[dict[str, Any]] = sets[name]
    return reports


def committed_json(path: Path) -> Any:
    """The JSON file ``path`` as committed at HEAD of the repository it is in, or None."""
    git = ["git", "-C", str(path.parent)]
    top = subprocess.run([*git, "rev-parse", "--show-toplevel"], capture_output=True, text=True)  # noqa: S603
    if top.returncode != 0:
        return None
    relative = path.resolve().relative_to(Path(top.stdout.strip()).resolve()).as_posix()
    show = [*git, "show", f"HEAD:{relative}"]
    shown = subprocess.run(show, capture_output=True, text=True, encoding="utf-8")  # noqa: S603
    if shown.returncode != 0:
        return None
    return json.loads(shown.stdout)


def committed_manifest() -> dict[str, Any] | None:
    """The manifest as committed at HEAD of the repository it is in, or None."""
    data: dict[str, Any] | None = committed_json(MANIFEST)
    return data


def selection_rule(name: str) -> str:
    """The set's selection rule; stop unless it is committed as it stands, since it has to be written
    before anyone looks at the files."""
    rule: str = load_manifest()["selection_rule"].get(name, "")
    committed = committed_manifest()
    if committed is None or committed.get("selection_rule", {}).get(name) != rule:
        raise SystemExit(f"the selection rule of set {name!r} is not committed as it stands; commit it first")
    return rule


def write_manifest(data: dict[str, Any]) -> None:
    MANIFEST.write_text(dump_json(data, indent=2) + "\n", "utf-8")


# --------------------------------------------------------------------------- inputs


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def object_sha256(data: Any) -> str:
    """The SHA-256 of a JSON value in a canonical form."""
    return hashlib.sha256(json.dumps(data, ensure_ascii=True, sort_keys=True).encode("ascii")).hexdigest()


def conversion_inputs_sha256(report: dict[str, Any]) -> str:
    """The SHA-256 of what `text` takes from the manifest: the format, the source file, the charsets
    and the attachments."""
    inputs = {key: report.get(key) for key in ("format", "source", "http_charset", "charset_override")}
    inputs["attachments"] = report.get("attachments", [])
    return object_sha256(inputs)


def source_format(report: dict[str, Any]) -> str:
    fmt: str = report.get("format", "pdf")
    if fmt not in ("pdf", "html"):
        raise SystemExit(f"{report['id']}: unknown format {fmt!r}")
    return fmt


def source_path(name: str, report: dict[str, Any]) -> Path:
    fmt = source_format(report)
    return DATA / name / fmt / str(report.get("source", f"{report['id']}.{fmt}"))


def text_path(name: str, report: dict[str, Any]) -> Path:
    return DATA / name / "text" / f"{report['id']}.txt"


def conversion_path(name: str, report: dict[str, Any]) -> Path:
    return DATA / name / "text" / f"{report['id']}.conversion.json"


_SURROGATE = re.compile("[\ud800-\udfff]")


def pdf_text(path: Path) -> tuple[str, dict[str, Any]]:
    """The text of a PDF, page by page, and where each page starts in it. A PDF with only an owner
    password (common in government reports) is decrypted with the empty user password. pypdf gives a
    lone surrogate for a glyph it cannot map (a Big5 user-defined character, 造字, or a CID with no
    ToUnicode entry); each is replaced with U+FFFD and counted, by page, so that the text can be
    written and the reviewer sees the character on the page."""
    import pypdf  # type: ignore[import-not-found]

    reader = pypdf.PdfReader(str(path))
    info: dict[str, Any] = {}
    if reader.is_encrypted:
        result = reader.decrypt("")
        if not result:
            raise SystemExit(f"{path.name}: encrypted with a user password, which cannot be read")
        info["encryption"] = f"decrypted with the empty user password ({result.name})"
    pages = [page.extract_text() or "" for page in reader.pages]
    surrogates = {}
    for number, page in enumerate(pages, start=1):
        count = len(_SURROGATE.findall(page))
        if count:
            surrogates[str(number)] = count
            pages[number - 1] = _SURROGATE.sub("\ufffd", page)
    if surrogates:
        info["lone_surrogates_replaced"] = surrogates
    text = "\n".join(pages)
    starts, offset = [], 0
    for page in pages:
        starts.append(offset)
        offset += len(page) + 1
    # Line breaks become LF, which shortens the text by one at each CR LF before a page start.
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    info["page_starts"] = [start - text.count("\r\n", 0, start) for start in starts]
    info["pages"] = len(pages)
    return normalised, info


def read_text(path: Path) -> str:
    """A text file exactly as written (no newline translation)."""
    return path.read_bytes().decode("utf-8")


def attachment_format(path: Path) -> str:
    suffix = path.suffix.lower()
    return "pdf" if suffix == ".pdf" else "html" if suffix in (".html", ".htm") else "text"


def charset_override(entry: dict[str, Any]) -> str | None:
    override = entry.get("charset_override")
    return None if override is None else str(override["charset"])


def decode_leniently(data: bytes) -> tuple[str, int]:
    """Damaged UTF-8 decoded with U+FFFD for each piece that is not UTF-8 (Python's "replace": one
    U+FFFD for each maximal invalid sequence, so a cut multi-byte character gives one), and how many
    U+FFFD that inserted."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    text = data.decode("utf-8", "replace")
    return text, text.count("\ufffd") - data.count(b"\xef\xbf\xbd")


def convert(
    path: Path, fmt: str, http_charset: str | None = None, override: str | None = None
) -> tuple[str, dict[str, Any]]:
    """The text of one source file (a PDF with pypdf, a web page with HtmlText, anything else as UTF-8
    text) and how it was made. Line breaks become LF, since pypdf can give CR and so can &#13; in a
    <pre>; the text that is hashed is then the text that every tool reads."""
    info: dict[str, Any] = {"format": fmt, "sha256": sha256(path)}
    if fmt == "pdf":
        text, pdf_info = pdf_text(path)
        info.update(pdf_info)
        info["method"] = PDF_METHOD.format(version=importlib.metadata.version("pypdf"))
    elif fmt == "html":
        page, info["decoding"] = decode_html(path.read_bytes(), http_charset, override)
        text, counts = html_to_text(page)
        info["method"] = HTML_METHOD
        info.update(counts)
    elif override is not None and override.lower() == UTF8_REPLACE:
        text, info["replacement_characters_inserted"] = decode_leniently(path.read_bytes())
        info["method"] = "text decoded as UTF-8, damaged bytes replaced (charset override in the manifest)"
    elif override is not None:
        codec = _codec(override)
        if codec is None:
            raise SystemExit(f"unknown charset override {override!r}")
        text = path.read_bytes().decode(codec)  # strict, as UTF-8 is
        info["method"] = f"text decoded as {codec} (charset override in the manifest)"
    else:
        text = read_text(path)
        info["method"] = "UTF-8 text"
    return text.replace("\r\n", "\n").replace("\r", "\n"), info


def command_text(name: str) -> None:
    reports = manifest(name)
    if not selection_rule(name).strip():
        raise SystemExit(
            f"set {name!r} has no selection rule; write it in the manifest and commit it before "
            "anyone looks at the files"
        )
    parser = check_html_parser()
    for report in reports:
        fmt = source_format(report)
        source = source_path(name, report)
        text, source_info = convert(source, fmt, report.get("http_charset"), charset_override(report))
        info: dict[str, Any] = {"format": fmt, "source_sha256": source_info.pop("sha256")}
        info["python"] = parser["python"]
        info["html_parser_sha256"] = parser["sha256"]
        info["evaluate_sha256"] = sha256(SCRIPT)
        info["conversion_inputs_sha256"] = conversion_inputs_sha256(report)
        info["commit"] = git_commit()
        if "charset_override" in report:
            info["charset_override"] = report["charset_override"]
        info.update(source_info)
        # Where each part of the text came from, so that each is read as what it is, and where each
        # PDF page starts, for the review.
        parts = [_part(fmt, source.relative_to(DATA / name).as_posix(), 0, text, source_info)]
        for attachment in report.get("attachments", []):
            path = DATA / name / "attachments" / attachment["file"]
            extra, attachment_info = convert(
                path, attachment_format(path), attachment.get("http_charset"), charset_override(attachment)
            )
            if "charset_override" in attachment:
                attachment_info["charset_override"] = attachment["charset_override"]
            text += "\n\n"
            relative = path.relative_to(DATA / name).as_posix()
            parts.append(_part(attachment_info["format"], relative, len(text), extra, attachment_info))
            text += extra
            info.setdefault("attachments", []).append({"file": attachment["file"], **attachment_info})
        info["parts"] = parts
        info["text_sha256"] = text_sha256(text)
        out = text_path(name, report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(text.encode("utf-8"))
        conversion_path(name, report).write_text(dump_json(info), "utf-8")
        print(f"{report['id']}: {fmt}, {len(text)} characters")
        print(f"    source sha256 {info['source_sha256']}")
        print(f"    text sha256   {info['text_sha256']}")
        if "encryption" in info:
            print(f"    {info['encryption']}")
        for part in [info, *info.get("attachments", [])]:
            if part.get("lone_surrogates_replaced"):
                print(
                    f"    UNMAPPED GLYPHS: lone surrogates replaced with U+FFFD, by page: "
                    f"{part['lone_surrogates_replaced']}"
                )
        if fmt == "html":
            print_html_conversion("    ", info)
        for attachment in info.get("attachments", []):
            print(
                f"    attachment {attachment['file']} ({attachment['format']}) sha256 {attachment['sha256']}"
            )
            if attachment["format"] == "html":
                print_html_conversion("        ", attachment)
            if "replacement_characters_inserted" in attachment:
                inserted = attachment["replacement_characters_inserted"]
                print(f"        DAMAGED UTF-8: {inserted} U+FFFD inserted for bytes that are not UTF-8")
        describe_appendix(text, report)


def _part(fmt: str, file: str, start: int, text: str, info: dict[str, Any]) -> dict[str, Any]:
    part: dict[str, Any] = {"format": fmt, "file": file, "start": start, "end": start + len(text)}
    if "page_starts" in info:
        part["page_starts"] = [start + offset for offset in info["page_starts"]]
    return part


def print_html_conversion(indent: str, info: dict[str, Any]) -> None:
    """Print how a web page was decoded and what its conversion counted (never an indicator count)."""
    decoding = info["decoding"]
    print(f"{indent}encoding {decoding['encoding']} ({decoding['chosen_by']})")
    print(f"{indent}declared {decoding['declared']}")
    if decoding["mismatch"]:
        print(f"{indent}DECLARED CHARSET DISAGREES: {'; '.join(decoding['mismatch'])}")
    if decoding.get("replacement_characters_inserted"):
        inserted = decoding["replacement_characters_inserted"]
        print(f"{indent}DAMAGED UTF-8: {inserted} U+FFFD inserted for bytes that are not UTF-8")
    print(
        f"{indent}U+FFFD: {info['replacement_characters']}, hidden characters kept: "
        f"{info['hidden_characters_kept']}, soft hyphens deleted: {info['soft_hyphens_deleted']}"
    )
    if info["unclosed_dropped_elements"]:
        unclosed = info["unclosed_dropped_elements"]
        print(f"{indent}UNCLOSED DROPPED ELEMENTS (the text after them is lost): {unclosed}")


def check_unchanged(name: str, report: dict[str, Any], conversion: dict[str, Any], text: str) -> None:
    """Stop if the text, its source, its attachments, what the manifest says about them or this
    script changed since `text`."""
    recorded = [(a["file"], a["sha256"]) for a in conversion.get("attachments", [])]
    current = []
    for attachment in report.get("attachments", []):
        path = DATA / name / "attachments" / attachment["file"]
        current.append((attachment["file"], sha256(path) if path.exists() else None))
    if (
        conversion["text_sha256"] != text_sha256(text)
        or conversion["source_sha256"] != sha256(source_path(name, report))
        or recorded != current
    ):
        raise SystemExit(
            f"{report['id']}: the text, its source or an attachment changed since `text`; run it again"
        )
    if conversion.get("conversion_inputs_sha256") != conversion_inputs_sha256(report):
        raise SystemExit(
            f"{report['id']}: the manifest's format, source, charsets or attachments changed since "
            "`text`; run it again"
        )
    if conversion.get("evaluate_sha256") != sha256(SCRIPT):
        raise SystemExit(f"{report['id']}: another version of evaluate.py made the text; run `text` again")


def load_text(name: str, report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """The report's text and its conversion record, checked to be current."""
    text = read_text(text_path(name, report))
    conversion: dict[str, Any] = json.loads(conversion_path(name, report).read_text(encoding="utf-8"))
    check_unchanged(name, report, conversion, text)
    return text, conversion


def describe_appendix(text: str, report: dict[str, Any]) -> None:
    """Print how often the appendix start marker occurs and the first and last line of the appendix."""
    count = len(list(_marker(report["appendix"]["start"]).finditer(text)))
    print(f"    appendix start marker found {count} time(s)")
    try:
        start, end = appendix_span(text, report)
    except SystemExit as exc:
        print(f"    APPENDIX NOT FOUND: {exc}")
        return
    lines = [line for line in text[start:end].splitlines() if line.strip()]
    print(f"    appendix first line: {visible(lines[0])!r}")
    print(f"    appendix last line:  {visible(lines[-1])!r}")


PDF_METHOD = (
    "pypdf {version}: page.extract_text() for each page, joined with line breaks; headers and footers kept"
)
HTML_METHOD = (
    "evaluate.py decode_html and HtmlText (Python standard library html.parser); rules in their docstrings"
)


# --------------------------------------------------------------------------- the HTML parser

# Pages that the html.parser of the releases with the 2025 security fixes (3.11.17, 3.12.3 as
# patched by Ubuntu, 3.13.16 and 3.14.6 were checked) converts as browsers do, and older releases do
# not: 3.11.4 raises AssertionError on the bogus comment and reads the rest of the page as script.
# The comment ending in "--!>" checks HtmlText.parse_comment.
_CANARIES = (
    ("<p>a</p><!-- x --!><p>b</p><!-- y --><p>c</p>", "a\n\nb\n\nc"),
    ("<p>a</p><![ if !IE ]><p>b</p><![endif]><p>c</p>", "a\n\nb\n\nc"),
    ("<script>x</script foo><p>b</p>", "b"),
    ("<p>a</p><!--><p>b</p><!-- y --><p>c</p>", "a\n\nb\n\nc"),
)


def html_parser_info() -> dict[str, Any]:
    """The Python version and the SHA-256 of the standard-library files that parse HTML."""
    files = {"html/parser.py": html.parser, "_markupbase.py": _markupbase, "html/entities.py": html.entities}
    return {
        "python": sys.version,
        "sha256": {label: sha256(Path(str(module.__file__))) for label, module in files.items()},
    }


def html_parser_problems() -> list[str]:
    """The canary pages that this Python's html.parser does not convert as expected."""
    problems = []
    for page, expected in _CANARIES:
        try:
            converted = html_to_text(page)[0]
        except Exception as exc:  # an older parser raises AssertionError
            converted = f"{type(exc).__name__}: {exc}"
        if converted != expected:
            problems.append(f"{page!r} gave {converted!r}, not {expected!r}")
    return problems


def check_html_parser() -> dict[str, Any]:
    """Stop unless this Python's html.parser has the 2025 security fixes; else describe it."""
    problems = html_parser_problems()
    if problems:
        raise SystemExit(
            f"the html.parser of Python {sys.version.split()[0]} loses or misreads page content; "
            "run `text` on a release with the 2025 security fixes (3.11.17, 3.13.16 and 3.14.6 were "
            "checked):\n    " + "\n    ".join(problems)
        )
    return html_parser_info()


# --------------------------------------------------------------------------- HTML to text

# Decoding is strict, in this order: a byte-order mark, valid UTF-8, the charset declared in the HTTP
# header (manifest "http_charset") or else in a <meta> tag, and Big5 (cp950). Nothing is decoded
# leniently: a page that fits none of them stops the run. A charset override in the manifest (with
# its reason) replaces all of them, for a page that this order would decode wrongly; the override
# "utf-8:replace", for a page whose UTF-8 is damaged, is the one lenient decoding, and the number of
# U+FFFD it inserted is recorded.
_BOMS = ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
_META_CHARSET = re.compile(
    rb"<meta\s[^>]{0,2048}?charset\s*=\s*[\"']?\s*([A-Za-z0-9._:-]{1,40})", re.IGNORECASE
)
# Labels as browsers read them (WHATWG Encoding Standard), for the encodings these reports may use;
# any other label goes to Python's codec registry. The standard decodes the GBK labels with its
# gb18030 decoder, which is wider than Python's gbk codec.
_CHARSET_LABELS = {
    **dict.fromkeys(("utf-8", "utf8", "unicode-1-1-utf-8"), "utf-8"),
    **dict.fromkeys(("big5", "big5-hkscs", "cn-big5", "csbig5", "x-x-big5"), "cp950"),
    **dict.fromkeys(("gb2312", "gbk", "x-gbk", "csgb2312", "chinese", "gb18030"), "gb18030"),
    **dict.fromkeys(("us-ascii", "ascii", "iso-8859-1", "latin1", "windows-1252"), "cp1252"),
}


def _codec(label: str) -> str | None:
    label = label.strip().lower()
    if label in _CHARSET_LABELS:
        return _CHARSET_LABELS[label]
    try:
        return codecs.lookup(label).name
    except LookupError:
        return None


def _without_comments(data: bytes) -> bytes:
    """``data`` without its comments, as browsers skip them when they look for <meta charset>: from
    "<!--" to the first "-->" after it, whose dashes may be those of the "<!--"."""
    pieces = []
    position = 0
    while (start := data.find(b"<!--", position)) != -1:
        pieces.append(data[position:start])
        end = data.find(b"-->", start + 2)
        if end == -1:
            return b" ".join(pieces)
        position = end + 3
    pieces.append(data[position:])
    return b" ".join(pieces)


def decode_html(
    data: bytes, http_charset: str | None = None, override: str | None = None
) -> tuple[str, dict[str, Any]]:
    """The page as text, and how it was decoded: the encoding, why it was chosen, the declared
    charsets, and those that disagree with it (only for pages with non-ASCII bytes, which ASCII-based
    encodings read alike). Line breaks are normalised to LF, as an HTML parser does."""
    head = _without_comments(data[:65536])
    end_of_head = head.lower().find(b"</head>")
    meta = _META_CHARSET.search(head if end_of_head == -1 else head[:end_of_head])
    declared = {"http": http_charset, "meta": meta.group(1).decode("ascii") if meta else None}
    candidates: list[tuple[str, str]] = []
    if override is not None and override.lower() == UTF8_REPLACE:
        text, replaced = decode_leniently(data)
        mismatch = [
            f"{where} declares {label}"
            for where, label in declared.items()
            if label and not data.isascii() and _codec(label) != "utf-8"
        ]
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        how = "charset override in the manifest: damaged UTF-8, bytes that are not UTF-8 replaced"
        info = {"encoding": "utf-8", "chosen_by": how, "declared": declared, "mismatch": mismatch}
        return text, {**info, "replacement_characters_inserted": replaced}
    if override is not None:
        codec = _codec(override)
        if codec is None:
            raise SystemExit(f"unknown charset override {override!r}")
        for bom, encoding in _BOMS:
            if data.startswith(bom) and encoding == codec:
                data = data[len(bom) :]
        candidates.append(("charset override in the manifest", codec))
    else:
        for bom, encoding in _BOMS:
            if data.startswith(bom):
                data = data[len(bom) :]
                candidates.append(("byte-order mark", encoding))
                break
        else:
            candidates.append(("valid UTF-8", "utf-8"))
            for where in ("http", "meta"):
                label = declared[where]
                codec = _codec(label) if label else None
                if codec is not None:
                    candidates.append((f"declared in {where}", codec))
            candidates.append(("Big5 fallback", "cp950"))
    errors = []
    for how, encoding in candidates:
        try:
            text = data.decode(encoding)  # strict: never "replace" or "ignore"
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding} ({how}): {exc.reason} at byte {exc.start}")
            continue
        mismatch = [
            f"{where} declares {label}"
            for where, label in declared.items()
            if label and not data.isascii() and _codec(label) != encoding
        ]
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return text, {"encoding": encoding, "chosen_by": how, "declared": declared, "mismatch": mismatch}
    raise SystemExit("cannot decode the page strictly: " + "; ".join(errors))


# Elements laid out as blocks (a line break before and after) and paragraphs (an empty line).
_BLOCK = frozenset(
    {
        "address", "article", "aside", "blockquote", "body", "caption", "center", "dd", "details",
        "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1",
        "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "html", "legend", "li", "listing", "main",
        "menu", "nav", "ol", "optgroup", "option", "p", "pre", "search", "section", "summary", "table",
        "tbody", "textarea", "tfoot", "thead", "tr", "ul", "xmp",
    }
)  # fmt: skip
_PARAGRAPH = frozenset({"p"})
# Breaks that end a table row; they also drop the TABs of empty cells at the end of the row.
_ROW_LEVEL = frozenset({"tr", "table", "thead", "tbody", "tfoot", "caption"})
# Kept as written, with their line breaks and runs of spaces.
_PREFORMATTED = frozenset({"pre", "listing", "xmp", "textarea"})
# Not shown on the page: <title> is part of <head>, browsers do not show <noembed>, <noframes>,
# <datalist> or <rp> (ruby's fallback parentheses), and SVG does not draw <desc> or <metadata>.
# Nothing inside them counts, not even their tags.
_SKIPPED = frozenset(
    {
        "head", "title", "script", "style", "noscript", "template", "iframe", "noembed", "noframes",
        "datalist", "rp", "desc", "metadata",
    }
)  # fmt: skip
_IN_HEAD = frozenset(
    {"base", "basefont", "bgsound", "link", "meta", "noscript", "script", "style", "template", "title"}
)
_VOID = frozenset(
    {
        "area", "base", "basefont", "bgsound", "br", "col", "embed", "hr", "img", "input", "keygen",
        "link", "meta", "param", "source", "track", "wbr",
    }
)  # fmt: skip
_CELLS = frozenset({"td", "th"})
_TABLE_PARTS = frozenset({"table", "caption", "thead", "tbody", "tfoot", "tr", "td", "th"})
# Where text in a table is fostered (moved before the table by a browser): directly in one of the
# first, not in one of the second.
_TABLE_SECTIONS = ("table", "thead", "tbody", "tfoot", "tr")
_TABLE_TEXT_PARTS = ("td", "th", "caption")
# A start tag that ends the innermost open element of the first kind, looking no further out than
# the second kind.
_CELL_SCOPE = frozenset({"td", "th", "caption", "table"})
_IMPLIED_END = {
    "li": ({"li"}, {"ul", "ol", "menu", *_CELL_SCOPE}),
    "dt": ({"dt", "dd"}, {"dl", *_CELL_SCOPE}),
    "dd": ({"dt", "dd"}, {"dl", *_CELL_SCOPE}),
    "tr": ({"tr"}, {"table"}),
    "td": ({"td", "th"}, {"tr", "table"}),
    "th": ({"td", "th"}, {"tr", "table"}),
    "option": ({"option"}, {"select", "datalist", "optgroup", *_CELL_SCOPE}),
}
# Start tags that end an open <rp>, whose end tag is optional.
_ENDS_RP = frozenset({"rp", "rt", "rtc"})
# html.parser reads these as raw text since the 2025 security releases, and textarea and title as
# escapable raw text; older releases parse their content as markup. HtmlText asks for raw text itself,
# so that the result does not depend on the Python release.
_RAW_TEXT = frozenset({"xmp", "iframe", "noembed", "noframes"})
_ESCAPABLE_RAW_TEXT_BUILT_IN = hasattr(html.parser.HTMLParser, "RCDATA_CONTENT_ELEMENTS")
_HTML_SPACE = re.compile(r"[ \t\n\f\r]+")
_HIDING_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)
_COMMENT_ABRUPT_END = re.compile(r"-?>")
_COMMENT_END = re.compile(r"--!?>")
# The states of script data in which "</script>" does not end the script (HTML's script data escaped
# and double escaped states), and what moves between them.
_SCRIPT_DATA, _SCRIPT_ESCAPED, _SCRIPT_DOUBLE_ESCAPED = range(3)
_SCRIPT_EVENTS = {
    _SCRIPT_DATA: re.compile(r"<!--"),
    _SCRIPT_ESCAPED: re.compile(r"-->|<script(?=[\t\n\f\r />])", re.IGNORECASE),
    _SCRIPT_DOUBLE_ESCAPED: re.compile(r"-->|</script(?=[\t\n\f\r />])", re.IGNORECASE),
}


class _Element:
    __slots__ = ("block", "closed_details", "hidden", "name", "preformatted", "skipped", "summary", "table")

    def __init__(
        self, name: str, attrs: list[tuple[str, str | None]], parent: _Element | None, *, block: bool
    ) -> None:
        names = {key for key, _ in attrs}
        style = " ".join(value or "" for key, value in attrs if key == "style")
        self.name = name
        self.block = block
        self.hidden = "hidden" in names or bool(_HIDING_STYLE.search(style))
        self.skipped = name in _SKIPPED
        self.preformatted = name in _PREFORMATTED
        self.closed_details = name == "details" and "open" not in names
        # The summary of a closed <details> is shown; the rest of it is not.
        self.summary = name == "summary" and parent is not None and parent.closed_details
        self.table = [0] if name == "table" else None  # the cells so far in the current row


class HtmlText(html.parser.HTMLParser):
    """The text of a page's body, hidden content included, laid out as a browser would, without
    computing CSS.

    Block elements start and end a line and <p> an empty line; <br> is a line break; so is the start
    and end of each SVG <text>. Inline elements (a, span, code, strong...) and <wbr> add nothing, so a
    name split by markup stays one name. The cells of a table row are separated by TABs, one per cell
    boundary (empty cells included, except at the end of a row), and its rows by line breaks; text in
    a table but outside its cells, which a browser moves to before the table, gets a line of its own.
    White space in the source, line breaks included, is folded to one space, so no line break of the
    source reaches the tools; <pre>, <listing>, <xmp> and <textarea> keep theirs (except a line break
    right after the start tag, which HTML ignores). Soft hyphens (&shy;) are deleted, since a browser
    shows none, and so are NUL characters (U+FFFD in <xmp> and <textarea>); other format characters
    and no-break spaces are kept. Attributes are never read: a link counts by its text, an image by
    nothing. <head>, <title>, <script>, <style>, <noscript>, <template>, <iframe>, <noembed>,
    <noframes>, <datalist>, <rp>, SVG <desc> and <metadata>, and comments are dropped with everything
    inside them; a "</script>" inside a comment in a script that opens another "<script>" does not end
    it, and "<!-->" is an empty comment, as in browsers. Text hidden by the hidden attribute, an inline
    display:none or visibility:hidden, or a closed <details> is kept, since appendices are often there
    and CSS is not computed, and its characters are counted. A self-closing "<x/>" ends x. Optional end
    tags are implied as in HTML (a new <li> ends the open one, a block ends an open <p>, <rt> ends an
    open <rp>); an end tag does not reach out of a table cell for an element opened outside it, and
    </body> and </html> end nothing. An unterminated tag or comment at the end of the page is dropped.

    Open elements are tracked by index (the open elements of each name, the open blocks, the closed
    <details> and their summaries, the dropped elements) and counted (hidden, preformatted), so that
    no event looks through all open elements: the time grows linearly with the page however deep its
    elements are nested.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.pieces: list[str] = []
        self.pending = ""  # the line break or empty line to write before the next text
        self.tabs = 0  # the TABs to write before the next text: cell boundaries passed in this row
        self.row_written = False  # text was written in the current table row
        self.cell_start = False  # nothing was written yet in the current table cell
        self.stack: list[_Element] = []
        self.positions: dict[str, list[int]] = {}  # the indices of the open elements of each name
        self.blocks: list[int] = []  # of the open blocks and table cells (an open <p> ends at a block)
        self.markers: list[int] = []  # of the open closed <details> and their summaries
        self.skipped_open: list[int] = []  # of the open dropped elements other than <head>
        self.hidden_open = 0
        self.preformatted_open = 0
        self.hidden_chars = 0
        self.soft_hyphens = 0
        self.unclosed_dropped: list[str] = []
        self.at_preformatted_start = False
        self.script_state = _SCRIPT_DATA
        self.foster_tabs: int | None = None  # in a line of fostered text: the TABs it put off

    # ----------------------------------------------------------------- open elements

    def _push(self, element: _Element) -> None:
        index = len(self.stack)
        self.stack.append(element)
        self.positions.setdefault(element.name, []).append(index)
        if element.name in _BLOCK or element.name in _CELLS:
            self.blocks.append(index)
        if element.closed_details or element.summary:
            self.markers.append(index)
        if element.skipped and element.name != "head":
            self.skipped_open.append(index)
        self.hidden_open += element.hidden
        self.preformatted_open += element.preformatted

    def _pop(self) -> _Element:
        element = self.stack.pop()
        index = len(self.stack)
        self.positions[element.name].pop()
        for indices in (self.blocks, self.markers, self.skipped_open):
            if indices and indices[-1] == index:
                indices.pop()
        self.hidden_open -= element.hidden
        self.preformatted_open -= element.preformatted
        return element

    def _open(self, name: str) -> int:
        """The index of the innermost open ``name`` element, or -1."""
        indices = self.positions.get(name)
        return indices[-1] if indices else -1

    def _innermost(self, names: frozenset[str] | set[str] | tuple[str, ...]) -> int:
        """The index of the innermost open element with one of ``names``, or -1."""
        return max((self._open(name) for name in names), default=-1)

    def _skipping(self) -> _Element | None:
        """The open element (other than <head>) whose content is dropped, or None."""
        return self.stack[self.skipped_open[0]] if self.skipped_open else None

    def _hidden(self) -> bool:
        return self.hidden_open > 0 or bool(self.markers and self.stack[self.markers[-1]].closed_details)

    def _fostered(self) -> bool:
        """Text here is in a table but outside its cells and caption."""
        return self._innermost(_TABLE_SECTIONS) > self._innermost(_TABLE_TEXT_PARTS)

    # ----------------------------------------------------------------- markup

    def _break(self, kind: str, *, row: bool = False) -> None:
        if row:
            self.tabs = 0
            self.cell_start = False
            self.foster_tabs = None
        elif self.cell_start:
            return  # a block at the start of a table cell starts right after the cell's TAB
        if len(kind) > len(self.pending):
            self.pending = kind

    def _start_foster(self) -> None:
        """Start a line of fostered text (text in a table outside its cells, which a browser moves to
        before the table), unless one is open: the TABs of the row wait until it ends."""
        if self.foster_tabs is None:
            self.foster_tabs = self.tabs
            self.tabs, self.cell_start = 0, False
            self._break("\n")

    def _end_foster(self) -> None:
        """End a line of fostered text; the row goes on after a line break."""
        if self.foster_tabs is not None:
            self.tabs, self.foster_tabs = self.foster_tabs, None
            self.row_written = False
            self.pending = self.pending or "\n"

    def parse_comment(self, i: int, report: bool = True) -> int:
        """A comment as browsers read it: "<!-->" and "<!--->" are empty comments, and "--!>" ends
        one too. html.parser reads on to the next "-->" in the first case, and before the 2025
        security releases in the second, which loses the page in between."""
        rawdata = self.rawdata
        match = _COMMENT_ABRUPT_END.match(rawdata, i + 4) or _COMMENT_END.search(rawdata, i + 4)
        if match is None:
            return -1
        if report:
            self.handle_comment(rawdata[i + 4 : match.start()])
        return match.end()

    def parse_endtag(self, i: int) -> int:
        """In a doubly escaped script, "</script" and the character after it only take the script
        back to the escaped state, as in browsers; what follows is script data again. html.parser
        would read the whole tag and end the script."""
        if self.cdata_elem == "script" and self.script_state == _SCRIPT_DOUBLE_ESCAPED:
            self.script_state = _SCRIPT_ESCAPED
            return i + len("</script") + 1
        end: int = super().parse_endtag(i)
        return end

    def _scan_script(self, data: str) -> None:
        """Follow the script data states through ``data``."""
        position = 0
        while match := _SCRIPT_EVENTS[self.script_state].search(data, position):
            event = match.group(0)
            if event == "<!--":
                self.script_state = _SCRIPT_ESCAPED
                position = match.start() + 2  # its dashes may end it: "<!-->"
                continue
            if event == "-->":
                self.script_state = _SCRIPT_DATA
            elif event.startswith("</"):
                self.script_state = _SCRIPT_ESCAPED
            else:
                self.script_state = _SCRIPT_DOUBLE_ESCAPED
            position = match.end()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, self_closing=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, self_closing=True)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], *, self_closing: bool) -> None:
        self.at_preformatted_start = False
        if tag == "script":
            self.script_state = _SCRIPT_DATA
        skipping = self._skipping()
        if skipping is not None and skipping.name == "rp" and tag in _ENDS_RP:
            self._close("rp")
            skipping = self._skipping()
        if skipping is not None:
            if tag == skipping.name:  # nested <template>s
                self._push(_Element(tag, attrs, self.stack[-1], block=False))
            return
        if tag in _TABLE_PARTS:
            self._end_foster()
        if not self_closing and (
            tag in _RAW_TEXT or (tag == "textarea" and not _ESCAPABLE_RAW_TEXT_BUILT_IN)
        ):
            self.set_cdata_mode(tag)
        if tag not in _IN_HEAD:
            self._close("head")  # the head ends where the body starts, with or without </head>
        if tag in _IMPLIED_END:
            ends, limits = _IMPLIED_END[tag]
            end = self._innermost(ends)
            if end > self._innermost(limits):
                self._close(self.stack[end].name)
        if tag in _BLOCK and self.blocks and self.stack[self.blocks[-1]].name == "p":
            self._close("p")
        if tag == "br":
            self._write("\n", raw=True)
            return
        if tag in _VOID:
            if tag == "hr":
                self._break("\n")
            return
        table_index = self._open("table")
        table = self.stack[table_index].table if table_index != -1 else None
        block = tag in _BLOCK or (tag == "text" and self._open("svg") != -1)
        if tag in _PARAGRAPH:
            self._break("\n\n")
        elif block:
            self._break("\n", row=tag in _ROW_LEVEL)
        if tag in ("tr", "table"):
            self.row_written = False
            if tag == "tr" and table is not None:
                table[0] = 0
        elif tag in _CELLS and table is not None:
            if table[0]:
                if self.row_written:
                    self.pending = ""  # a break from a block in the cell before gives way to the TAB
                self.tabs += 1
            table[0] += 1
            self.cell_start = True
        element = _Element(tag, attrs, self.stack[-1] if self.stack else None, block=block)
        self._push(element)
        self.at_preformatted_start = element.preformatted

    def handle_endtag(self, tag: str) -> None:
        self.at_preformatted_start = False
        skipping = self._skipping()
        if skipping is not None and skipping.name == "rp" and -1 < self._open(tag) < self.skipped_open[0]:
            self._close("rp")  # the end of an element it is in, such as </ruby>, ends an <rp>
            skipping = None
        if skipping is not None:
            if tag == skipping.name:
                self._close(tag)
            return
        if tag == "br":
            self._write("\n", raw=True)  # browsers read </br> as <br>
        elif tag == "p" and self._open("p") == -1:
            self._break("\n\n")  # and </p> without <p> as an empty paragraph
        elif tag not in ("body", "html"):
            self._close(tag)

    def _close(self, tag: str) -> None:
        """End the innermost open ``tag`` and everything inside it, unless that would reach out of a
        table cell or table for an element opened outside it."""
        index = self._open(tag)
        if index == -1:
            return  # an end tag without a start tag
        limits = frozenset() if tag == "table" else {"table"} if tag in _TABLE_PARTS else _CELL_SCOPE
        if self._innermost(limits) > index:
            return
        while len(self.stack) > index:
            element = self._pop()
            if element.name in _PARAGRAPH:
                self._break("\n\n")
            elif element.block:
                self._break("\n", row=element.name in _ROW_LEVEL)

    # ----------------------------------------------------------------- text

    def handle_data(self, data: str) -> None:
        if self.cdata_elem == "script":
            self._scan_script(data)
        if self.skipped_open:
            return
        if self._open("head") != -1:
            if not data.strip(" \t\n\f\r"):
                return
            self._close("head")  # text in the head starts the body
        if not _ESCAPABLE_RAW_TEXT_BUILT_IN and self._open("textarea") != -1:
            data = html.unescape(data)
        if "\0" in data:
            data = data.replace("\0", "\ufffd" if self.cdata_elem in ("textarea", "xmp") else "")
        if "\u00ad" in data:
            self.soft_hyphens += data.count("\u00ad")
            data = data.replace("\u00ad", "")
        if data.strip(" \t\n\f\r"):
            if self._fostered():
                self._start_foster()
            else:
                self._end_foster()
        if self.preformatted_open:
            if self.at_preformatted_start and data.startswith("\n"):
                data = data[1:]
            self._write(data, raw=True)
        else:
            self._write(_HTML_SPACE.sub(" ", data), raw=False)
        self.at_preformatted_start = False

    def _write(self, text: str, *, raw: bool) -> None:
        if not raw and (self.pending or self.tabs or not self.pieces or self.pieces[-1][-1] in " \n\t"):
            text = text.lstrip(" ")  # white space is folded across elements, and dropped at a break
        if not text:
            return
        if self.pending or self.tabs:
            while self.pieces and not self.pieces[-1].rstrip(" "):
                self.pieces.pop()
            if self.pieces:
                self.pieces[-1] = self.pieces[-1].rstrip(" ")
                self.pieces.append(self.pending + "\t" * self.tabs)
            self.pending, self.tabs = "", 0
        self.cell_start = False
        self.row_written = True
        if self._hidden():
            self.hidden_chars += len(text)
        self.pieces.append(text)

    def close(self) -> None:
        if self.rawdata.startswith("<"):
            self.rawdata = ""  # an unterminated tag or comment, which reaches to the end unshown
        super().close()
        self.unclosed_dropped = [element.name for element in self.stack if element.skipped]

    def text(self) -> str:
        return "".join(self.pieces).strip(" \t\n")


def html_to_text(page: str) -> tuple[str, dict[str, Any]]:
    """The text of a decoded page, and what the conversion counted."""
    parser = HtmlText()
    parser.feed(page)
    parser.close()
    text = parser.text()
    return text, {
        "hidden_characters_kept": parser.hidden_chars,
        "soft_hyphens_deleted": parser.soft_hyphens,
        "replacement_characters": text.count("\ufffd"),
        "unclosed_dropped_elements": parser.unclosed_dropped,
    }


# --------------------------------------------------------------------------- ground truth: the draft

# The line rules. Each line of the appendix is read first (read_line: format characters by the kind
# of its part, then the defang styles, see ascii_reading), and the rules find values in the ASCII
# text that results. A value is made of printable ASCII only (names of ASCII letters, digits and
# hyphens, hashes of hex digits), so a value right after Chinese text is found and one right before
# Chinese text or full-width punctuation ends there. A URL ends at white space, at a character that
# is not printable ASCII, at a quotation mark, a bracket, a parenthesis, "<", ">" or "&&", and loses
# trailing punctuation. A name's last label must be a top-level domain of the IANA list next to this
# script (iana-tlds.txt), which rules out file names such as setup.msi, invoice.iso or stage.scr;
# a name whose top-level domain is also a common file extension (payload.zip, run.sh) is left out with
# a warning. Masked entries (an asterisk inside a token, "evil.*.com", "ev*l.example.com",
# "*.example.net", or "xxx" standing alone, "wiki.xxxx.com"; not a lone asterisk before a name, nor a
# file glob such as "*.lnk") are left out with a warning, and so are tool outputs equal to them. The
# scheme of another kind of URL (ldap://, tcp://) is taken out, so that its host is found as a name
# or an address. Every rule is linear in the length of a line.
_MD5 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
_SHA1 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_SHA256 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
_URL_CHAR = r"[!#$%*+,\-./0-9:;=?@A-Z\\^_a-z{|}~]"
_URL = re.compile(
    rf"(?<![A-Za-z0-9_])(?:https?|hxxps?|ftp|fxp)://(?:{_URL_CHAR}|&(?!&))+", re.ASCII | re.IGNORECASE
)
_TLD = r"([A-Za-z]{2,63}|[Xx][Nn]--[A-Za-z0-9\-]{1,59})"
_EMAIL = re.compile(
    rf"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*@(?:[A-Za-z0-9\-]+\.)+{_TLD}"
    r"(?![A-Za-z0-9_\-])",
    re.ASCII,
)
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])", re.ASCII)
_DOMAIN = re.compile(rf"(?<![A-Za-z0-9_.\-@/])(?:[A-Za-z0-9\-]+\.)+{_TLD}(?![A-Za-z0-9_\-])", re.ASCII)
# Top-level domains that are also common file extensions: a name ending in one is more often a file
# ("payload.zip", "run.sh", "libc.so") than a host, so the draft leaves it out with a warning.
_FILE_EXTENSION_TLDS = frozenset(
    {"ai", "app", "cab", "dot", "inc", "java", "md", "mov", "one", "pl", "pm", "ps", "pub", "py", "rs", "run"}
    | {"sh", "so", "zip"}
)
# Masked values: an asterisk, or a run of three or more x standing alone ("wiki.xxxx.com", "?p=xxx&").
_MASKED = re.compile(r"\*|(?<![a-z0-9])x{3,}(?![a-z0-9])", re.IGNORECASE)
# A token of name characters and asterisks; one with an asterisk or "xxx" that ends in a dot and
# letters is a masked host.
_TOKEN = re.compile(r"(?<![\w*.\-])[\w*.\-]+", re.ASCII)
_MASKED_HOST = re.compile(r"\*|(?<![a-z0-9])x{3,}(?![a-z0-9])", re.IGNORECASE)
_ENDS_IN_LETTERS = re.compile(r"\.[A-Za-z]{2,24}\Z")
# What the warnings look for: hash labels, a dot or at sign that the reading did not read (an
# ideographic full stop or a middle dot between ASCII letters, or a dot in brackets it does not know).
_LABEL_GAP = "[ \\t\\u00a0\\u3000\\u2010-\\u2015-]?"
_HASH_LABEL = re.compile(
    f"(?<![A-Za-z0-9])(MD5|SHA{_LABEL_GAP}1|SHA2?{_LABEL_GAP}256)(?![A-Za-z0-9])", re.IGNORECASE
)
_LABEL_TYPES = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256", "SHA2256": "sha256"}
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_ODD_BRACKET = "[^\\x00-\\x3b=?-\\x7f]"  # not ASCII, or "<" or ">"
_UNREAD = re.compile(
    "[A-Za-z0-9][ \u3000]?(?:[。｡・‧･·•∙⋅﹒﹫]"
    f"|{_ODD_BRACKET}[ \u3000]?[.@。][ \u3000]?{_ODD_BRACKET})[ \u3000]?(?=[A-Za-z0-9])"
)
# Line ends and starts are found past any white space, the no-break spaces that pypdf gives included.
_HEX_TAIL = re.compile(r"(?<![0-9A-Za-z_])[0-9A-Fa-f]+\s*\Z")
_HEX_HEAD = re.compile(r"\s*([0-9A-Fa-f]+)(?![0-9A-Za-z_])")
_NAME_CUT_TAIL = re.compile(r"(?<![A-Za-z0-9.\-])[A-Za-z0-9][A-Za-z0-9.\-]*[.\-]\s*\Z")
_NAME_CUT_HEAD = re.compile(r"\s*[.\-][A-Za-z0-9]")
_SCHEME_START = re.compile(r"\s*(?:https?|hxxps?|ftp|fxp)://", re.IGNORECASE)
# Chinese text that goes on with a file extension or path ("年度計畫 .rar", pypdf's "年第 1 季報告 .pdf").
# The extension may start with a digit (".7z", ".001"); a "/" or "-" after a digit is a date or a port
# ("113/05/01", "2024-05-01", "443/tcp"), not a path.
_CJK_PATH_HEAD = re.compile(
    r"\s*[^\x00-\x7f\s](?:[^\x00-\x7f]|[0-9() ]){0,63}?"
    r"(?:\.(?:[A-Za-z]|[0-9][A-Za-z0-9]{0,4}[A-Za-z]|[0-9]{3}(?![0-9.]))|(?<![0-9])[/_?=&-][A-Za-z0-9])"
)
# A list number or a short cell before the next row's value: "2.", "2、", pypdf's "2 、", "(2)", "一、",
# "-", or a type cell from this list.
_TYPE_CELLS = (
    "urls?",
    "uris?",
    "ips?",
    "ipv4",
    "ipv6",
    "ip:port",
    "url/ip",
    "domains?",
    "hosts?",
    "hostnames?",
    "fqdn",
    "c2",
    "c&c",
    "cnc",
    "md5",
    "sha-?1",
    "sha-?256",
    "hash(?:es)?",
    "e-?mails?",
    "ports?",
)
_ROW_HEAD = re.compile(
    r"\s*(?:(?:\(?[0-9]{1,3}\s?[.)\u3001]|[\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341]{1,3}"
    r"\s?[\u3001.])[\t ]*|(?:[0-9]{1,3}|(?:" + "|".join(_TYPE_CELLS) + r"):?|[-*\u2022\u2027])[\t ]+)",
    re.IGNORECASE,
)
_OTHER_SCHEME = re.compile(
    r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,15}://(?:[^\s/@]{0,64}@)?", re.ASCII
)


@cache
def top_level_domains() -> frozenset[str]:
    """The top-level domains of iana-tlds.txt (a fixed copy of the IANA list, not TTPrism's)."""
    lines = TLDS_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))


def _marker(marker: str) -> re.Pattern[str]:
    """A heading as a regex in which any run of white space (pypdf gives NBSP, too) matches any other."""
    pattern = r"\s+".join(re.escape(part) for part in marker.split())
    return re.compile(pattern + (r"\s" if marker[-1].isspace() else ""))


def appendix_span(text: str, report: dict[str, Any]) -> tuple[int, int]:
    """The appendix region: from the start marker to the first end marker after it, or to the end of
    the text (end_of_text). The start marker must occur once, unless the manifest says which
    occurrence (1-based) to use; a page whose side bar or table of contents repeats the heading would
    otherwise be cut at the wrong place."""
    appendix = report["appendix"]
    starts = list(_marker(appendix["start"]).finditer(text))
    occurrence = appendix.get("start_occurrence")
    if not starts:
        raise SystemExit(f"{report['id']}: appendix start marker not found")
    if occurrence is None and len(starts) > 1:
        raise SystemExit(
            f"{report['id']}: appendix start marker found {len(starts)} times; "
            "set appendix.start_occurrence in the manifest"
        )
    if occurrence is not None and not 1 <= occurrence <= len(starts):
        raise SystemExit(
            f"{report['id']}: start_occurrence {occurrence}, but the marker occurs {len(starts)} times"
        )
    start = starts[(occurrence or 1) - 1].start()
    if appendix.get("end_of_text") is True:
        return start, len(text)
    end = _marker(appendix["end"]).search(text, start + 1)
    if end is None:
        raise SystemExit(f"{report['id']}: appendix end marker not found")
    return start, end.start()


def appendix(text: str, report: dict[str, Any]) -> str:
    start, end = appendix_span(text, report)
    return text[start:end]


# Format characters that separate two names (TTPrism reads them so): an invisible separator and the
# end of a bidi embedding or isolate.
_SEPARATING_FORMAT = frozenset("\u2063\u202c\u2069")


def read_line(raw: str, fmt: str) -> Reading:
    """A line of the appendix as the line rules read it, with where each character came from. A soft
    hyphen in text from a PDF or a text attachment is a drawn hyphen (pypdf gives U+00AD for one, as
    TTPrism reads it); a web page has none left (HtmlText deletes them as break hints). Other format
    characters (Cf) are invisible: they are deleted, except those that separate two names, which
    become spaces. Then ascii_reading reads the defang styles."""
    chars: list[str] = []
    where: list[int] = []
    for index, char in enumerate(raw):
        if char == "\u00ad" and fmt in ("pdf", "text"):
            chars.append("-")
        elif char in _SEPARATING_FORMAT:
            chars.append(" ")
        elif unicodedata.category(char) == "Cf":
            continue
        else:
            chars.append(char)
        where.append(index)
    reading = ascii_reading("".join(chars))
    origins = [(where[start], where[end - 1] + 1) for start, end in reading.origins]
    return Reading(raw, reading.text, origins, reading.kinds)


Values = dict[str, list[str]]


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    """``text`` with each span replaced by spaces of the same length."""
    chars = list(text)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def line_values(reading: Reading) -> dict[str, list[dict[str, Any]]]:
    """The values in one read line: "found" (type, value in standard form, start and end in the
    reading, and for a URL whether it parses), "masked", and "file names" (names under a top-level
    domain that is also a file extension). Hashes are looked for everywhere, then URLs; e-mail
    addresses outside URLs; addresses and names outside both, so that an address's domain is not
    listed as a name of its own."""
    text = reading.text
    tlds = top_level_domains()
    found: list[dict[str, Any]] = []
    masked: list[dict[str, Any]] = []
    file_names: list[dict[str, Any]] = []

    def add(kind: str, start: int, end: int, match_end: int | None = None) -> None:
        if (
            kind in ("domain", "email")
            and start > 1
            and text[start - 1] == "*"
            and _in_token(text[start - 2])
        ):
            # An asterisk inside a token masks part of a label: the masked value runs from the start of
            # its token (at most 256 characters back, so that the search stays linear). A lone
            # asterisk before a name (a footnote mark) leaves the name, with a warning.
            limit = max(0, start - 256)
            while start > limit and _in_token(text[start - 1]):
                start -= 1
        raw = text[start:end]
        if _MASKED.search(raw):
            masked.append({"type": kind, "value": raw.lower(), "start": start, "end": end})
            return
        entry: dict[str, Any] = {"type": kind, "start": start, "end": end}
        if kind == "url":
            entry["value"], entry["parses"] = normalise_url(raw)
            entry["match_end"] = match_end
        else:
            entry["value"] = normalise(kind, raw)
        found.append(entry)

    for regex, kind in ((_SHA256, "sha256"), (_SHA1, "sha1"), (_MD5, "md5")):
        for match in regex.finditer(text):
            add(kind, match.start(), match.end())
    taken: list[tuple[int, int]] = []
    for match in _URL.finditer(text):
        value = match.group(0).rstrip(".,;:!?")
        add("url", match.start(), match.start() + len(value), match.end())
        taken.append(match.span())
    # The scheme of another kind of URL (ldap://, tcp://, wss:// ...) and its user info are taken out,
    # so that its host is found as a name or an address; such URLs are not values of their own.
    rest = _blank(text, taken + [match.span() for match in _OTHER_SCHEME.finditer(text)])
    # A full-width slash outside a URL separates alternatives ("198.51.100.23／evil.example.com"), so a
    # name after it is not a path.
    rest = "".join(" " if char == "/" and reading.kinds[i] == "cjk" else char for i, char in enumerate(rest))
    taken = []
    for match in _EMAIL.finditer(rest):
        if match.group(1).lower() in tlds:
            add("email", *match.span())
            taken.append(match.span())
    rest = _blank(rest, taken)
    taken = []
    for match in _IPV4.finditer(rest):
        add("ipv4", *match.span())
        taken.append(match.span())
    rest = _blank(rest, taken)
    for match in _DOMAIN.finditer(rest):
        tld = match.group(1).lower()
        if tld not in tlds and tld != "onion":  # .onion is a special-use name, not on the IANA list
            continue
        if tld in _FILE_EXTENSION_TLDS and not _MASKED.search(match.group(0)):
            value = normalise("domain", match.group(0))
            file_names.append({"type": "domain", "value": value, "start": match.start(), "end": match.end()})
            continue
        add("domain", *match.span())
    covered = bytearray(len(text) + 1)  # where a masked value was already found
    for entry in masked:
        covered[entry["start"] : entry["end"]] = b"\x01" * (entry["end"] - entry["start"])
    for match in _TOKEN.finditer(text):
        token = match.group(0).rstrip(".")
        start, end = match.start(), match.start() + len(token)
        last = token.rsplit(".", 1)[-1].lower()
        # A lone asterisk before a name is a mark (a footnote or bullet), not a mask.
        inner = token[1:] if token[:1] == "*" and token[1:2].isalnum() else token
        if (
            _MASKED_HOST.search(inner)
            and _ENDS_IN_LETTERS.search(token)
            and 1 not in covered[start:end]
            and last in tlds
            and last not in _FILE_EXTENSION_TLDS
        ):
            masked.append({"type": "domain", "value": token.lower(), "start": start, "end": end})
    return {"found": found, "masked": masked, "file names": file_names}


def _in_token(char: str) -> bool:
    """Whether ``char`` can be part of a masked name or e-mail address."""
    return char.isascii() and (char.isalnum() or char in "*_.%+-")


def _ends_in_name_character(line: str) -> bool:
    last = line.rstrip()[-1:]
    return last.isascii() and last.isalnum()


def _starts_with_name_character(line: str) -> bool:
    first = line.lstrip()[:1]
    return first.isascii() and first.isalnum()


def _hex_tail(line: str) -> str:
    match = _HEX_TAIL.search(line)
    return match.group(0).rstrip() if match else ""


def _hex_head(line: str) -> str:
    match = _HEX_HEAD.match(line)
    return match.group(1) if match else ""


class _Warnings:
    """The warnings of a draft, numbered W1, W2 ... in the order of the lines."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.by_line: dict[int, list[str]] = {}

    def add(self, line: int, kind: str, message: str, values: list[str] | None = None) -> None:
        warning_id = f"W{len(self.items) + 1}"
        self.items.append(
            {"id": warning_id, "line": line, "kind": kind, "message": message, "values": values or []}
        )
        self.by_line.setdefault(line, []).append(warning_id)


# The kinds of warning, and what each asks the reviewer to check on the rendered page (shown on the
# review page for the kinds a draft has).
WARNING_KINDS = {
    "hex-cut": "hex digits at a line end and the next line's start that make a SHA-1 or SHA-256 together "
    "(unless both are whole MD5s under an MD5 label in effect, or both lines are rows of MD5s); a run of "
    "lines of 32 hex digits with no MD5 label in effect (none above, a label naming several types, or a "
    "line of other text since it ended its block); or a piece of 16 or more hex digits of the length of "
    "no hash: a hash may be cut",
    "hash-label": "a hash whose length differs from the hash type named in the label of its block (the "
    "label's line and the lines below it until a line with text but neither a label nor a hash; a line "
    "naming several types names none)",
    "name-cut": "a name that ends at the end of a line with '.' or '-' before a line that starts with a "
    "name character or with '.' or '-', or a line that starts with '.' or '-' after a line that ends in "
    "a name: the name may go on in the next line; or digits and dots at a line end and the start of the "
    "next lines that make an IPv4 address together: the address may be cut",
    "url-cut": "in PDF text, a URL that reaches the end of a line before a line that does not start with "
    "a value or a scheme (past a list number or a type cell), that starts with the full-width form of a "
    "URL character, or that is Chinese text when the URL ends in '/', '=', '?', '&', '-' or '_' or the "
    "Chinese text goes on with a file extension or path ('年度計畫 .rar', not a date or a port); in a web "
    "page, only before a "
    "line that goes on with a path, query or extension; a URL followed by a slash after a space; or a URL "
    "whose host does not end in a top-level domain; or a line that ends in a URL scheme ('hxxps://', or "
    "'hxxps' before a line that starts with '://'), which gives no URL: the URL may go on, or be cut inside "
    "its host or after its scheme",
    "file-extension": "a name whose top-level domain is also a common file extension, left out of the draft",
    "url-unparseable": "a URL without a host that can be a name or an address, or with another scheme "
    "after an ASCII separator: two URLs may be written together",
    "non-ascii": "a value read from writing with non-ASCII characters (full-width or CJK-bracket "
    "defanging, Unicode hyphens, soft hyphens, ligatures or deleted format characters), or a URL that "
    "stops before non-ASCII letters (after a space, only when it ends in a separator or the text goes on "
    "with a file extension or path) or before the full-width form of a URL character, or a value next to "
    "a spaced full-width or Unicode hyphen, or before a spaced full-width colon and digits: it may go on",
    "masked": "a masked value (an asterisk inside it, or 'xxx' standing alone), left out of the draft",
    "mask-next": "a value next to a mask character (* ＊ # ○ ●, or x after an address; also across a "
    "spaced dot or at sign, or across pypdf's space after a mask that is not a lone bullet), or with 'xxx' "
    "inside a label: it may be the visible part of a masked value",
    "own-address": "a value at the report's own address (original_url or final_url): often a page header "
    "printed inside the appendix",
    "loose-defang": "a full-width dot or at sign read between ASCII letters or digits outside any value "
    "('１．198.51.100.23' gives no address), or numbering read into a name or e-mail address "
    "('１．evil.example.com'): numbering may be glued to a value, which may be wrong or missing",
    "unread-defang": "a dot or at sign written in a way the reading does not know, between ASCII "
    "letters or digits; nothing was read from it",
}


def _location(part: dict[str, Any], page: int | None, line: int) -> str:
    """Where a line stands: its file (or "text", for a line between parts or without a recorded file),
    the PDF page, and the line on the page or in the file."""
    where = f"{part.get('file', 'text')}"
    return f"{where} page {page} line {line}" if page is not None else f"{where} line {line}"


def appendix_lines(
    text: str, report: dict[str, Any], parts: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """The lines of the appendix (see text_lines)."""
    start, end = appendix_span(text, report)
    if parts is None:
        parts = [{"format": source_format(report), "start": 0, "end": len(text)}]
    return text_lines(text, start, end, parts, source_format(report))


def text_lines(
    text: str, start: int, end: int, parts: list[dict[str, Any]], fmt: str
) -> list[dict[str, Any]]:
    """The lines of ``text`` from ``start`` to ``end``: number, start in the text, raw text, kind of
    its part (``fmt`` between parts), and where it stands in its source (file, PDF page, line on the
    page or in the file)."""
    parts = sorted(parts, key=lambda p: int(p["start"]))
    part_starts = [int(p["start"]) for p in parts]
    page_starts = [[int(s) for s in p.get("page_starts", [])] for p in parts]
    lines: list[dict[str, Any]] = []
    position = start
    key: tuple[int, int | None] | None = None
    line_number = 0
    while position < end or not lines:
        newline = text.find("\n", position, end)
        stop = end if newline == -1 else newline
        part_index = bisect.bisect_right(part_starts, position) - 1
        if part_index >= 0 and position >= int(parts[part_index]["end"]):
            part_index = -1  # between parts
        part = parts[part_index] if part_index >= 0 else {"format": fmt}
        page = None
        base = int(part.get("start", 0))
        if "page_starts" in part:
            starts = page_starts[part_index]
            page = max(bisect.bisect_right(starts, position), 1)
            base = starts[page - 1]
        if key != (part_index, page):
            key = (part_index, page)
            line_number = text.count("\n", base, position) + 1
        else:
            line_number += 1
        lines.append(
            {
                "n": len(lines) + 1,
                "start": position,
                "raw": text[position:stop],
                "format": str(part.get("format", fmt)),
                "file": part.get("file"),
                "page": page,
                "location": _location(part, page, line_number),
            }
        )
        if newline == -1:
            break
        position = newline + 1
    return lines


def _plainest(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return min(entries, key=lambda e: (CLASSES.index(e["class"]), e["line"]))


def draft_truth(
    text: str, report: dict[str, Any], parts: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """The draft ground truth of a report: every line of its appendix with the values read from it
    and their writing, the values of each type (each with its plainest writing, see below), the
    masked ones, and the warnings. Its SHA-256 (in "sha256") covers the text, the appendix markers,
    the list of top-level domains and everything the rules found, so a review made against it holds
    as long as the same draft comes out.

    A value written several ways in the appendix gets the class of its plainest writing (plain, ASCII
    defang, full-width or CJK-bracket defang), since a tool can find it from that one."""
    lines = appendix_lines(text, report, parts)
    readings = [read_line(line["raw"], line["format"]) for line in lines]
    results = [line_values(reading) for reading in readings]
    warnings = _Warnings()
    occurrences: dict[tuple[str, str], list[dict[str, Any]]] = {}
    masked: dict[str, list[dict[str, Any]]] = {}
    out_lines = []
    own_hosts = {
        url_host(normalise_url(str(report[key]))[0])
        for key in ("original_url", "final_url")
        if report.get(key)
    }
    own_hosts.discard("")
    # The hash type named by the label of each line's block of hashes: the label's own line and the
    # lines below it, until a line with text but neither a label nor a hash ends the block, so that a
    # label far above neither hides a hash cut in a later table nor flags the hashes of a later
    # section. A label naming several types (a table header "SHA256 MD5") names none.
    expected: list[str | None] = []
    block: str | None = None
    for reading, result in zip(readings, results, strict=True):
        labels = {
            _LABEL_TYPES[re.sub("[^A-Z0-9]", "", m.group(1).upper())]
            for m in _HASH_LABEL.finditer(reading.text)
        }
        if labels:
            block = labels.pop() if len(labels) == 1 else None
        elif reading.text.strip() and not any(e["type"] in _HASH_TYPES for e in result["found"]):
            block = None
        expected.append(block)
    for index, (line, reading, result) in enumerate(zip(lines, readings, results, strict=True)):
        n = line["n"]
        line_entries = []
        for entry in sorted(result["found"], key=lambda e: int(e["start"])):
            raw_start, raw_end = reading.span(entry["start"], entry["end"])
            writing = visible(reading.raw[raw_start:raw_end])
            klass = reading.writing_class(entry["start"], entry["end"], url=entry["type"] == "url")
            item = {"type": entry["type"], "value": entry["value"], "writing": writing, "class": klass}
            line_entries.append(item)
            occurrences.setdefault((entry["type"], entry["value"]), []).append(
                {**item, "line": n, "location": line["location"]}
            )
            if not reading.raw[raw_start:raw_end].isascii():
                warnings.add(
                    n,
                    "non-ascii",
                    f"{entry['type']} {entry['value']} read from {writing!r}",
                    [entry["value"]],
                )
            if (url_host(entry["value"]) if entry["type"] == "url" else entry["value"]) in own_hosts:
                warnings.add(
                    n,
                    "own-address",
                    f"{entry['type']} {entry['value']} is at the report's own address",
                    [entry["value"]],
                )
            if entry["type"] == "url" and not entry.get("parses", True):
                warnings.add(
                    n,
                    "url-unparseable",
                    f"URL without a host that can be a name or an address: {entry['value']!r}",
                    [entry["value"]],
                )
            elif entry["type"] == "url" and _JOINED_URL.search(entry["value"]):
                warnings.add(
                    n,
                    "url-unparseable",
                    f"two URLs may be joined in {entry['value']!r}: a scheme follows an ASCII separator",
                    [entry["value"]],
                )
            elif entry["type"] == "url" and not _host_has_tld(url_host(entry["value"])):
                warnings.add(
                    n,
                    "url-cut",
                    f"the host of the URL {entry['value']!r} does not end in a top-level domain: the URL "
                    "may be cut inside its host",
                    [entry["value"]],
                )
            if entry["type"] in _HASH_TYPES and expected[index] not in (None, entry["type"]):
                warnings.add(
                    n,
                    "hash-label",
                    f"{entry['type']} {entry['value']} under a {expected[index]} label",
                    [entry["value"]],
                )
            if entry["type"] == "url":
                _url_end_warnings(warnings, n, entry, reading)
            spaced = (
                _spaced_joiner(reading.raw, raw_start, raw_end) if entry["type"] not in _HASH_TYPES else ""
            )
            if spaced:
                warnings.add(
                    n,
                    "non-ascii",
                    f"{entry['type']} {entry['value']} is next to {spaced!r} with spaces around it (pypdf "
                    "puts them at a change of font): the value may go on across it",
                    [entry["value"]],
                )
            mask = _mask_next_to(reading.text, entry)
            if mask:
                warnings.add(
                    n,
                    "mask-next",
                    f"{entry['type']} {entry['value']} "
                    + (
                        "contains 'xxx': it may be the visible part of a masked value, or a word"
                        if mask == "xxx"
                        else f"is next to {mask!r}: it may be the visible part of a masked value, or the "
                        "mark may be a footnote or bullet"
                    ),
                    [entry["value"]],
                )
        for entry in result["masked"]:
            raw_start, raw_end = reading.span(entry["start"], entry["end"])
            masked.setdefault(entry["type"], []).append({"value": entry["value"], "line": n})
            warnings.add(
                n, "masked", f"masked {entry['type']} left out: {visible(reading.raw[raw_start:raw_end])!r}"
            )
        for entry in result["file names"]:
            warnings.add(
                n,
                "file-extension",
                f"{entry['value']} left out: its top-level domain is also a file extension",
                [entry["value"]],
            )
        for match in _UNREAD.finditer(reading.text):
            raw_start, raw_end = reading.span(match.start(), match.end() + 1)
            warnings.add(n, "unread-defang", f"not read: {visible(reading.raw[raw_start:raw_end])!r}")
        _loose_defang_warnings(warnings, n, reading, result)
        scheme = _SCHEME_AT_END.search(reading.text)
        if scheme and (
            scheme.group(1)
            or (index + 1 < len(readings) and readings[index + 1].text.lstrip().startswith(":/"))
        ):
            warnings.add(
                n,
                "url-cut",
                f"the line ends in the URL scheme {scheme.group().strip()!r}: the URL's host may be on the "
                "next line, and the draft has no URL for it",
            )
        _cut_warnings(warnings, index, lines, readings, results, expected)
        out_lines.append(
            {
                "n": n,
                "location": line["location"],
                "text": visible(line["raw"]),
                "values": line_entries,
                "warnings": warnings.by_line.get(n, []),
            }
        )
    values: dict[str, list[dict[str, Any]]] = {}
    for (kind, value), entries in sorted(occurrences.items()):
        best = _plainest(entries)
        values.setdefault(kind, []).append(
            {
                "value": value,
                "writing": best["writing"],
                "class": best["class"],
                "location": best["location"],
                "line": best["line"],
                "occurrences": len(entries),
            }
        )
    pages: list[dict[str, Any]] = []
    for line in lines:
        if line["file"] is None:
            continue
        if not pages or pages[-1]["file"] != line["file"]:
            pages.append({"file": line["file"], "format": line["format"], "pages": []})
        if line["page"] is not None and line["page"] not in pages[-1]["pages"][-1:]:
            pages[-1]["pages"].append(line["page"])  # lines come in page order
    draft: dict[str, Any] = {
        "id": report["id"],
        "text_sha256": text_sha256(text),
        "appendix": report["appendix"],
        "tlds_sha256": sha256(TLDS_FILE),
        "parts": pages,
        "lines": out_lines,
        "values": values,
        "masked": masked,
        "warnings": warnings.items,
    }
    draft["sha256"] = object_sha256(draft)
    return draft


_HASH_TYPES = ("md5", "sha1", "sha256")
# Another URL right after an ASCII separator in a URL: two URLs written together with no space.
# A URL scheme at the end of a line (as read: "hxxp[:]//" is "hxxp://"), which a word processor
# breaks before a host that does not fit: _URL needs a character after "//", so the URL is lost and
# its host drafted alone. A scheme without its colon counts only before a line that starts with it.
_SCHEME_AT_END = re.compile(
    r"(?<![A-Za-z0-9_])(?:https?|hxxps?|ftp|fxp)(:/{0,2})?\s*$", re.ASCII | re.IGNORECASE
)
_JOINED_URL = re.compile(r"[,;|\\](?:h[tx][tx]ps?|f[tx]p)://", re.IGNORECASE)


def _host_has_tld(host: str) -> bool:
    """Whether a URL's host is an address, or a name whose last label is a top-level domain (or
    onion) and none of whose labels starts or ends with a hyphen."""
    if not host or is_ip(host):
        return True
    labels = host.split(".")
    return (labels[-1] in top_level_domains() or labels[-1] == "onion") and not any(
        label.startswith("-") or label.endswith("-") for label in labels
    )


# Characters that mask part of a value ("ev*l", "○○abc.gov.tw", "198.51.100.2*"); for an address,
# letters x too ("203.0.113.1xx").
_MASKS = "*\uff0a#\u25cb\u25cf\u3007"
# Full-width forms of characters that go on inside a URL's path or query.
_FULL_WIDTH_URL = "\uff1f\uff1d\uff06\uff3f\uff5e\uff05\uff03\uff0b"


_JOINERS = "\uff0d\ufe63\u2010\u2011\u2212"


def _spaced_joiner(raw: str, start: int, end: int) -> str:
    """A full-width or Unicode hyphen with spaces between it and the value raw[start:end] and an ASCII
    letter or digit beyond it ("update － check.example.com"), or a full-width colon after the value
    with spaces and digits beyond it ("evil.example.com ： 8080"), as pypdf gives them where the font
    changes; or ""."""
    before = raw[max(0, start - 6) : start]
    stripped = before.rstrip(" \u3000")
    if stripped != before and stripped[-1:] and stripped[-1:] in _JOINERS:
        beyond = stripped[:-1].rstrip(" \u3000")[-1:]
        if beyond.isascii() and beyond.isalnum():
            return stripped[-1:]
    after = raw[end : end + 6]
    stripped = after.lstrip(" \u3000")
    if stripped[:1] and stripped[:1] in _JOINERS + "\uff1a":
        beyond = stripped[1:].lstrip(" \u3000")[:1]
        wanted = beyond.isdigit() if stripped[:1] == "\uff1a" else beyond.isalnum()
        if (stripped != after or stripped[1:2] in (" ", "\u3000")) and beyond.isascii() and wanted:
            return stripped[:1]
    return ""


def _mask_next_to(text: str, entry: dict[str, Any]) -> str:
    """The mask character right before a found value; or before it past the spaces pypdf puts at a font
    change, when a dot or at sign stands between ("ser*** ＠ example.org"), when the mask is two or more
    characters ("〇〇 abc.gov.tw"), or when a letter or digit stands before the mask ("ev ＊ l.example.com"),
    but not a lone bullet ("● value"); or right after the value (or after a dot and up to 64 letters,
    digits and hyphens that go on from it: "victim.example.com.t*"); or "xxx" inside it; or ""."""
    if entry["type"] in _HASH_TYPES:
        return ""
    masks = _MASKS + ("xX" if entry["type"] == "ipv4" else "")
    before = text[max(0, entry["start"] - 12) : entry["start"]]
    if before[-1:] and before[-1:] in masks:
        return before[-1:]
    spaced = before.rstrip(" \u3000")
    if spaced != before:
        if spaced[-1:] in (".", "@", "\uff0e", "\uff20"):
            spaced = spaced[:-1].rstrip(" \u3000")
            if spaced[-1:] and spaced[-1:] in masks:
                return spaced[-1:]
        elif spaced[-1:] and spaced[-1:] in _MASKS:
            run = len(spaced) - len(spaced.rstrip(_MASKS))
            ahead = spaced[: len(spaced) - run].rstrip(" \u3000")[-1:]
            if run >= 2 or (ahead.isascii() and ahead.isalnum()):
                return spaced[-1:]
    after = entry["end"]
    if text[after : after + 1] == "." and entry["type"] != "url":
        after += 1
        limit = min(len(text), after + 64)
        while after < limit and text[after].isascii() and (text[after].isalnum() or text[after] == "-"):
            after += 1
    following = text[after : after + 1]
    if following and following in masks:
        return following
    # "xxx" inside a label is a word ("foxxxy") or a mask ("mail.nxxxx.gov.tw"), which the reviewer
    # tells apart.
    return "xxx" if re.search("xxx", text[entry["start"] : entry["end"]], re.IGNORECASE) else ""


def _url_end_warnings(warnings: _Warnings, n: int, entry: dict[str, Any], reading: Reading) -> None:
    """Warnings for a URL that may go on past where the rules ended it: non-ASCII letters right after
    it (past spaces and format characters, and past punctuation the rules took off its end), the
    full-width form of a URL character with an ASCII URL character after it ("a.php？id=1", pypdf's
    "a.php ？ id=1"), or a slash after a space."""
    raw = reading.raw
    position = reading.span(entry["start"], entry["match_end"])[1]
    stop = min(len(raw), position + 64)
    spaced = False
    # Spaces (pypdf puts one where the font changes from Latin to CJK, and between table cells) and
    # format characters are passed over; a TAB, which ends a table cell, is not.
    while position < stop and (
        raw[position] in " \u00a0\u3000" or unicodedata.category(raw[position]) == "Cf"
    ):
        spaced = spaced or raw[position] in " \u00a0\u3000"
        position += 1
    following = raw[position : position + 1]
    gap = raw[position + 1 : position + 4]
    beyond = gap.lstrip(" \u00a0\u3000")[:1]
    at_end = not beyond and position + 4 >= len(raw)
    # After a space, Chinese text is often the next table cell (a description): only text that goes
    # on with a file extension or path, or a URL that ends in a separator, may be the rest of it.
    goes_on = not spaced or entry["value"][-1:] in "/=?&-_" or bool(_CJK_PATH_HEAD.match(raw, position))
    if following and following in _FULL_WIDTH_URL and (at_end or (beyond and re.match(_URL_CHAR, beyond))):
        warnings.add(
            n,
            "non-ascii",
            f"the URL {entry['value']!r} stops before {following!r}, the full-width form of a URL "
            "character: the path or query may go on",
            [entry["value"]],
        )
    elif following and not following.isascii() and following.isalpha() and goes_on:
        warnings.add(
            n,
            "non-ascii",
            f"the URL {entry['value']!r} stops before {following!r}: a path or query in non-ASCII letters "
            "may go on",
            [entry["value"]],
        )
    elif following in ("/", "\uff0f") and position > reading.span(entry["start"], entry["match_end"])[1]:
        warnings.add(
            n,
            "url-cut",
            f"the URL {entry['value']!r} is followed by a slash after a space: its path may go on",
            [entry["value"]],
        )


def _loose_defang_warnings(warnings: _Warnings, n: int, reading: Reading, result: dict[str, Any]) -> None:
    """One warning for a line with numbering glued to a value by a full-width dot: a full-width dot or
    at sign (bare or with spaces around it) read between ASCII letters or digits that is part of no
    value ("１．198.51.100.23" gives no address), or one after 1 to 3 digits at the start of a name or
    e-mail address that it is read into ("１．evil.example.com" gives 1.evil.example.com). Not a dot
    in a run of digits with at most two dots (a date or version, "１１３．０６．０１"), nor one right
    before a URL, which numbering cannot change."""
    text = reading.text
    covered = bytearray(len(text) + 1)
    for entry in result["found"] + result["masked"]:
        covered[entry["start"] : entry["end"]] = b"\x01" * (entry["end"] - entry["start"])
    url_starts = {entry["start"] for entry in result["found"] if entry["type"] == "url"}
    candidates = [
        index
        for index in range(1, len(text) - 1)
        if text[index] in ".@"
        and reading.kinds[index] == "cjk"
        and not covered[index]
        and text[index - 1].isascii()
        and text[index - 1].isalnum()
        and text[index + 1].isascii()
        and text[index + 1].isalnum()
        and index + 1 not in url_starts
        and not _date_or_version(text, index)
    ]
    for entry in result["found"]:
        numbering = _GLUED_NUMBER.match(text, entry["start"])
        if (
            entry["type"] in ("domain", "email")
            and numbering
            and (entry["start"] == 0 or text[entry["start"] - 1].isspace())
            and reading.kinds[numbering.end() - 1] == "cjk"
        ):
            candidates.append(numbering.end() - 1)
    forms = []
    for index in candidates:
        raw_start, raw_end = reading.origins[index]
        form = reading.raw[raw_start:raw_end]
        if form.strip(" \u3000") in ("\uff0e", "\uff20"):
            forms.append(visible(reading.raw[max(0, raw_start - 2) : raw_end + 2]))
    if forms:
        warnings.add(
            n,
            "loose-defang",
            f"full-width dots or at signs read as '.' or '@' between ASCII letters or digits outside any "
            f"value, or numbering read into a value ({len(forms)}, e.g. {forms[0]!r}): numbering may be "
            "glued to a value, which may be wrong or missing",
        )


# The digits and dots that start a line (a full-width dot there is not read: nothing before it).
_ADDRESS_HEAD = re.compile("\\s*([.\uff0e]?[0-9][0-9.]{0,14})")


def _trailing_address_run(text: str) -> tuple[int, str]:
    """Where the run of digits and dots (at most 15) at the end of a line starts, past white space, and
    the run; "" when it goes on from a letter or digit, or follows "/", ":" or "-" (a date, a port, a
    range)."""
    end = len(text)
    while end > 0 and end > len(text) - 64 and text[end - 1].isspace():
        end -= 1
    start = end
    while start > max(0, end - 15) and text[start - 1] in "0123456789.":
        start -= 1
    if start == end or not any(char.isdigit() for char in text[start:end]):
        return start, ""
    before = text[start - 1 : start]
    if before and ((before.isascii() and before.isalnum()) or before in "/:-"):
        return start, ""
    return start, text[start:end]


def _cut_address(index: int, readings: list[Reading]) -> str:
    """A message when the digits and dots at the end of line ``index`` and the start of the next lines
    (up to three; a line of digits and dots only lets the run go on) make an IPv4 address, of octets up
    to 255, that the first line does not end in whole, as a narrow cell breaks full-width digits
    anywhere ("１９８．５" / "１．１０" / "０．２３"); else "". Not when the line ends in a dot (name-cut
    flags that), nor when only a number without dots, written in ASCII, comes before a line that starts
    with a whole address (the last cell of a row before an address)."""
    reading = readings[index]
    start, tail = _trailing_address_run(reading.text)
    if not tail or tail.endswith(".") or tail.count(".") >= 3:
        return ""
    pieces = [tail]
    for following in readings[index + 1 : index + 4]:
        head = _ADDRESS_HEAD.match(following.text)
        if not head:
            break
        pieces.append(head.group(1).replace("\uff0e", "."))
        joined = "".join(pieces)
        address = _IPV4.search(joined)
        if address and address.start() < len(tail) < address.end():
            octets = address.group(0).split(".")
            whole_after = "." not in tail and bool(_IPV4.match(pieces[1]))
            written_full_width = "cjk" in reading.kinds[start : start + len(tail)]
            if all(int(octet) <= 255 for octet in octets) and (written_full_width or not whole_after):
                shown = " / ".join(pieces)
                return f"the lines end and start with {shown!r}: the address {address.group(0)} may be cut"
            return ""
        if following.text.strip() != head.group(1):
            break
    return ""


_GLUED_NUMBER = re.compile(r"[0-9]{1,3}\.(?=[A-Za-z0-9])")


def _date_or_version(text: str, index: int) -> bool:
    """Whether the dot at ``index`` is in a run of ASCII digits and dots that has a digit and at most
    two dots ("113.06.01", "v2.0", "No.1"; looked for up to 32 characters on each side)."""
    start = index
    while start > max(0, index - 32) and text[start - 1] in "0123456789.":
        start -= 1
    end = index + 1
    while end < min(len(text), index + 33) and text[end] in "0123456789.":
        end += 1
    run = text[start:end]
    return run.count(".") <= 2 and any(char.isdigit() for char in run)


def _cut_warnings(
    warnings: _Warnings,
    index: int,
    lines: list[dict[str, Any]],
    readings: list[Reading],
    results: list[dict[str, list[dict[str, Any]]]],
    expected: list[str | None],
) -> None:
    """Warnings for values that a line break may have cut: hex strings, names and URLs. Line ends and
    starts are found past any white space."""
    n = lines[index]["n"]
    text = readings[index].text
    after = readings[index + 1].text if index + 1 < len(lines) else None
    tail, head = _hex_tail(text), _hex_head(text)
    next_head = _hex_head(after) if after is not None else ""

    def hash_values(found: list[dict[str, Any]]) -> list[str]:
        return [e["value"] for e in found if e["type"] in ("md5", "sha1", "sha256")]

    # Hex digits at a line end and the next line's start that make a SHA-1 or SHA-256 together: a hash
    # cut in two. Not when both are whole MD5s under an MD5 label in effect, when both lines hold
    # another whole MD5 besides these (rows of a table of MD5s), or when both lines are 32-digit hex
    # strings and nothing else (flagged once per run below). A SHA-384 or SHA-512 cut into pieces of
    # scored lengths is not looked for: two whole hashes on adjacent lines look the same.
    only_hex = text.strip() == tail
    line_end = len(text.rstrip())
    if (
        after is not None
        and len(tail) >= 4
        and len(next_head) >= 4
        and len(tail) + len(next_head) in (40, 64)
    ):
        lead = len(after) - len(after.lstrip())
        whole = len(tail) == len(next_head) == 32
        confirmed = whole and expected[index] == "md5"
        row = (
            whole
            and any(e["type"] == "md5" and e["end"] < line_end for e in results[index]["found"])
            and any(e["type"] == "md5" and e["start"] > lead for e in results[index + 1]["found"])
        )
        in_run = whole and len(tail) == 32 and only_hex and after.strip() == next_head
        if not (confirmed or row or in_run):
            warnings.add(
                n,
                "hex-cut",
                f"the line ends in {len(tail)} hex digits and the next starts with {len(next_head)}, "
                f"{len(tail) + len(next_head)} together: {tail[-12:]} | {next_head[:12]}",
                [v for e in results[index]["found"] if e["end"] >= line_end for v in hash_values([e])]
                + [v for e in results[index + 1]["found"] if e["start"] <= lead for v in hash_values([e])],
            )
    # A run of lines that are each one 32-digit hex string, with no MD5 label in effect: two of them
    # may be the halves of one SHA-256.
    if (
        only_hex
        and len(tail) == 32
        and expected[index] != "md5"
        and (index == 0 or not _md5_line(readings[index - 1].text))
    ):
        run = index
        while run + 1 < len(lines) and _md5_line(readings[run + 1].text):
            run += 1
        if run > index:
            warnings.add(
                n,
                "hex-cut",
                f"{run - index + 1} lines of 32 hex digits each, with no MD5 label in effect (none above, a "
                "label naming several types, or a line of other text since the label): two may be the "
                "halves of a SHA-256",
                [v for i in range(index, run + 1) for v in hash_values(results[i]["found"])],
            )
    pieces = (
        [(tail, "the line is")] if only_hex else [(tail, "the line ends in"), (head, "the line starts with")]
    )
    for piece, where in pieces:
        if len(piece) >= 16 and len(piece) not in _HASH_LENGTHS:
            warnings.add(
                n, "hex-cut", f"{where} {len(piece)} hex digits, the length of no hash: {piece[:12]}..."
            )
    if after is None:
        return
    lead = len(after) - len(after.lstrip())
    starting = [e["value"] for e in results[index + 1]["found"] if e["start"] <= lead]
    address = _cut_address(index, readings)
    if address:
        warnings.add(n, "name-cut", address)
    cut = _NAME_CUT_TAIL.search(text)
    if cut and (_starts_with_name_character(after) or _NAME_CUT_HEAD.match(after)):
        first = after.split()[0] if after.strip() else ""
        warnings.add(
            n,
            "name-cut",
            f"the line ends in {cut.group(0).strip()!r} and the next starts with {first!r}",
            starting,
        )
    elif _NAME_CUT_HEAD.match(after) and _ends_in_name_character(text):
        warnings.add(
            n,
            "name-cut",
            f"the next line starts with {after.strip()[:20]!r} after a line that ends in a name",
        )
    urls = [e for e in results[index]["found"] if e["type"] == "url"]
    trimmed = len(text)  # the line's end before trailing white space and punctuation
    while trimmed and (text[trimmed - 1].isspace() or text[trimmed - 1] in ".,;:!?"):
        trimmed -= 1
    # The next item of a list or the next row of a table starts with a value or a scheme, past a list
    # number or a short cell ("2.", "(2)", "-", a 序號 "2", "URL", "IP").
    row = _ROW_HEAD.match(after)
    heads = (lead, row.end()) if row else (lead,)
    next_values = [e for e in results[index + 1]["found"] if e["start"] in heads]
    next_scheme = any(_SCHEME_START.match(after, head) for head in heads)
    first = after.lstrip()[:1]
    # HtmlText does not wrap lines, so in a web page only text that goes on with a URL's path, query
    # or extension can be the rest of a URL.
    wraps = lines[index]["format"] != "html"
    goes_on = (
        bool(re.match(r"\s*[\x21-\x7e]" if wraps else r"\s*[/?&=%#._\-]", after))
        # The full-width form of a URL character where Chromium broke the line ("＿ v2.exe").
        or (wraps and bool(urls) and bool(first) and first in _FULL_WIDTH_URL)
        # A path cut right before Chinese text that wraps to the next line: after a separator, or
        # before Chinese text that goes on with a file extension or path ("年度計畫 .rar").
        or (
            wraps
            and bool(urls)
            and not first.isascii()
            and first.isalpha()
            and (urls[-1]["value"][-1:] in "/=?&-_" or bool(_CJK_PATH_HEAD.match(after)))
        )
    )
    if urls and urls[-1]["end"] >= trimmed and goes_on and not next_values and not next_scheme:
        warnings.add(
            n,
            "url-cut",
            f"the URL {urls[-1]['value']!r} reaches the end of the line; the next starts with "
            f"{after.strip()[:20]!r}",
            [urls[-1]["value"]],
        )


def _md5_line(line: str) -> bool:
    """Whether a line is one 32-digit hex string and nothing else."""
    stripped = line.strip()
    return len(stripped) == 32 and _hex_tail(stripped) == stripped


# --------------------------------------------------------------------------- ground truth: rendering

# The review compares each line of the draft with images of the pages: pdftoppm (poppler) draws the
# PDF pages the appendix is on, and headless Chromium draws a web page (without its own styles, see
# below: the text the line rules read, not the page as its readers see it) or a text attachment,
# decoded as `text` decoded it, in screenshots of the whole page. Chromium runs with scripts off and
# every request other than the page itself refused, so a saved page cannot run code or reach the
# network; it runs without its sandbox only when this runs as root, where the sandbox cannot start.
# Set CHROMIUM to the browser's path if it is not chromium, chromium-browser or google-chrome on PATH.
_SCREENSHOT_WIDTH = 1200
_SCREENSHOT_TILE = 1600
_PAGE_URL = "http://report.invalid/page"
# <meta http-equiv="refresh"> and <meta http-equiv="Content-Security-Policy"> tags, taken out of a
# web page before it is drawn: with scripts off, a refresh in <noscript> applies too, and a page's own
# policy would refuse the style sheet below.
_META_TAKEN_OUT = re.compile(
    r"<meta\b[^>]{0,65536}?\bhttp-equiv\s*=\s*[\"']?\s*(?:refresh|content-security-policy)\b[^>]{0,65536}>",
    re.IGNORECASE,
)
_DOCTYPE = re.compile(r"<!doctype\b[^>]{0,1024}>", re.IGNORECASE)


def _after_doctype(page: str) -> int:
    """Where our style sheet goes: first in the page, after its doctype (past white space, comments and
    an XML declaration before it) so that the page keeps its mode; so that no unterminated comment or
    element at the end of the page takes it in. Linear: each comment is skipped with one search."""
    position = 0
    while True:
        while position < len(page) and page[position].isspace():
            position += 1
        if page.startswith("<!--", position):
            end, length = page.find("-->", position + 4), 3
        elif page.startswith("<?", position):
            end, length = page.find(">", position + 2), 1  # the HTML parser's bogus comment
        else:
            break
        if end == -1:
            return 0
        position = end + length
    doctype = _DOCTYPE.match(page, position)
    return doctype.end() if doctype else 0


# A web page is drawn without its own styles: it is served with a Content-Security-Policy that refuses
# every style sheet and style attribute of the page (and everything else but inline images), so that
# nothing the page hides, clips, overlays or scrolls is left out of the screenshots. One style sheet
# of ours, allowed by a nonce, shows what the browser's defaults hide although HtmlText reads it
# (hidden attributes, until-found included; closed <details> and <dialog>; popovers; SVG text that
# its own or its groups' fill, opacity, visibility or display attributes hide), hides what HtmlText
# drops (<noscript>, <iframe> and the like, which scripts being off would show; the alt text of
# images, which are refused; the values and placeholders of form fields), draws black text on white
# whatever colour scheme the page declares, and wraps long lines so that a page stays as wide as the
# screenshots. What it cannot show: the options of a <select> other than the chosen one, and SVG text
# that is moved or scaled out of view, of font size 0, or inside <defs>.
_REVEAL = (
    "[hidden]:not(script,style,template,noscript)"
    "{display:block!important;content-visibility:visible!important}"
    "details::details-content{display:block!important;content-visibility:visible!important}"
    "dialog,[popover]{display:block!important;position:static!important;inset:auto!important}"
    "noscript,iframe,noembed,noframes,datalist,rp,template{display:none!important}"
    ":root{color-scheme:only light!important;background:#fff!important}"
    "body,body *{color:#000!important;background:transparent!important;overflow-wrap:anywhere!important}"
    "body img{color:transparent!important}"
    "svg g:has(text),svg text,svg tspan,svg textPath{opacity:1!important}"
    "svg g:has(text){display:inline!important}"
    "svg text,svg tspan,svg textPath{fill:#000!important;fill-opacity:1!important;stroke:none!important;"
    "visibility:visible!important;"
    "display:inline!important}"
    "pre,xmp,listing,plaintext,textarea,code,td,th{white-space:pre-wrap!important}"
    "textarea{field-sizing:content!important;width:100%!important}"
    "input{color:transparent!important}"
    "input::placeholder,textarea::placeholder{color:transparent!important}"
    'img:not([src^="data:image/" i]),img[srcset],picture img{content:url("data:image/gif;base64,'
    'R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==")!important;'
    "outline:1px dashed #999!important}"
)


def reviewable_page(page_text: str) -> tuple[bytes, list[dict[str, str]]]:
    """A decoded web page as it is drawn for the review, and the headers it is served with."""
    import secrets

    nonce = secrets.token_hex(16)
    page = _META_TAKEN_OUT.sub("", page_text)
    at = _after_doctype(page)
    body = page[:at] + f'<style nonce="{nonce}">{_REVEAL}</style>' + page[at:]
    policy = f"default-src 'none'; img-src data:; style-src 'nonce-{nonce}'"
    headers = [
        {"name": "Content-Type", "value": "text/html; charset=utf-8"},
        {"name": "Content-Security-Policy", "value": policy},
    ]
    return body.encode("utf-8"), headers


_WHATWG_LABELS = {"cp950": "big5", "gb18030": "gb18030", "cp1252": "windows-1252"}


def render_tools() -> dict[str, str]:
    """The pdftoppm and Chromium that draw the pages, and their versions; stop if one is missing."""
    pdftoppm = shutil.which("pdftoppm")
    browser = os.environ.get("CHROMIUM") or next(
        (
            found
            for name in ("chromium", "chromium-browser", "google-chrome")
            if (found := shutil.which(name))
        ),
        None,
    )
    if pdftoppm is None or browser is None:
        raise SystemExit(
            "`truth` draws the appendix pages for the review with pdftoppm (poppler-utils) and headless "
            "Chromium; install them or set CHROMIUM, or run `truth --no-render` for the draft alone"
        )
    versions = {
        "pdftoppm": subprocess.run([pdftoppm, "-v"], capture_output=True, text=True).stderr.strip(),  # noqa: S603
        "chromium": subprocess.run([browser, "--version"], capture_output=True, text=True).stdout.strip(),  # noqa: S603
    }
    return {"pdftoppm_path": pdftoppm, "chromium_path": browser, **versions}


class _Browser:
    """Headless Chromium driven over the DevTools protocol on a pipe (file descriptors 3 and 4)."""

    def __init__(self, path: str, profile: Path) -> None:
        to_browser, self._out = os.pipe()
        self._in, from_browser = os.pipe()

        def descriptors() -> None:
            os.dup2(to_browser, 3)
            os.dup2(from_browser, 4)
            os.set_inheritable(3, True)
            os.set_inheritable(4, True)

        args = [
            path,
            "--headless",
            "--remote-debugging-pipe",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-first-run",
            "--blink-settings=scriptEnabled=false",
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=<-loopback>",
            f"--user-data-dir={profile}",
        ]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.append("--no-sandbox")
        self.process = subprocess.Popen(  # noqa: S603
            args,
            preexec_fn=descriptors,
            close_fds=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(to_browser)
        os.close(from_browser)
        self._buffer = b""
        self._last_id = 0
        self._events: list[dict[str, Any]] = []
        self.on_event: dict[str, Any] = {}

    def post(self, method: str, params: dict[str, Any] | None = None, session: str | None = None) -> int:
        self._last_id += 1
        message: dict[str, Any] = {"id": self._last_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        os.write(self._out, json.dumps(message).encode("utf-8") + b"\0")
        return self._last_id

    def send(self, method: str, params: dict[str, Any] | None = None, session: str | None = None) -> Any:
        message_id = self.post(method, params, session)
        reply = self.wait(lambda m: m.get("id") == message_id)
        if "error" in reply:
            raise SystemExit(f"Chromium refused {method}: {reply['error']}")
        return reply.get("result", {})

    def wait(self, wanted: Any, timeout: float = 60) -> dict[str, Any]:
        import select

        for index, message in enumerate(self._events):
            if wanted(message):
                return self._events.pop(index)
        deadline = datetime.now(UTC).timestamp() + timeout
        while True:
            while b"\0" in self._buffer:
                raw, self._buffer = self._buffer.split(b"\0", 1)
                message = json.loads(raw)
                handler = self.on_event.get(message.get("method", ""))
                if handler is not None:
                    handler(message)
                elif wanted(message):
                    return dict(message)
                elif "method" in message:
                    self._events.append(message)
            left = deadline - datetime.now(UTC).timestamp()
            if left <= 0:
                raise SystemExit("Chromium did not answer in time")
            ready, _, _ = select.select([self._in], [], [], left)
            if ready:
                chunk = os.read(self._in, 1 << 20)
                if not chunk:
                    raise SystemExit("Chromium stopped")
                self._buffer += chunk

    def close(self) -> None:
        try:
            self.post("Browser.close")
            self.process.wait(10)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait()
        finally:
            os.close(self._out)
            os.close(self._in)


def screenshots(browser_path: str, body: bytes, headers: list[dict[str, str]], prefix: Path) -> list[Path]:
    """Screenshots of a page (``body`` served with ``headers``), top to bottom, each at most
    _SCREENSHOT_TILE pixels high."""
    import base64

    with tempfile.TemporaryDirectory() as profile:
        browser = _Browser(browser_path, Path(profile))
        try:
            target = browser.send("Target.createTarget", {"url": "about:blank"})["targetId"]
            session = browser.send("Target.attachToTarget", {"targetId": target, "flatten": True})[
                "sessionId"
            ]

            def paused(event: dict[str, Any]) -> None:
                params = event["params"]
                if params["request"]["url"] == _PAGE_URL:
                    browser.post(
                        "Fetch.fulfillRequest",
                        {
                            "requestId": params["requestId"],
                            "responseCode": 200,
                            "responseHeaders": [
                                *headers,
                                {"name": "X-Content-Type-Options", "value": "nosniff"},
                            ],
                            "body": base64.b64encode(body).decode("ascii"),
                        },
                        session,
                    )
                else:
                    browser.post(
                        "Fetch.failRequest",
                        {"requestId": params["requestId"], "errorReason": "Aborted"},
                        session,
                    )

            browser.on_event["Fetch.requestPaused"] = paused
            browser.send("Emulation.setScriptExecutionDisabled", {"value": True}, session)
            browser.send(
                "Emulation.setDeviceMetricsOverride",
                {"width": _SCREENSHOT_WIDTH, "height": 900, "deviceScaleFactor": 1, "mobile": False},
                session,
            )
            browser.send("Fetch.enable", {"patterns": [{"urlPattern": "*"}]}, session)
            browser.send("Page.enable", {}, session)
            browser.post("Page.navigate", {"url": _PAGE_URL}, session)
            browser.wait(lambda m: m.get("method") == "Page.loadEventFired" and m.get("sessionId") == session)
            on_page(browser, session)
            size = browser.send("Page.getLayoutMetrics", {}, session)["cssContentSize"]
            width, height = max(int(size["width"]), 1), max(int(size["height"]), 1)
            paths = []
            for top in range(0, height, _SCREENSHOT_TILE):
                clip = {
                    "x": 0,
                    "y": top,
                    "width": width,
                    "height": min(_SCREENSHOT_TILE, height - top),
                    "scale": 1,
                }
                shot = browser.send(
                    "Page.captureScreenshot",
                    {"format": "png", "clip": clip, "captureBeyondViewport": True},
                    session,
                )
                path = prefix.with_name(f"{prefix.name}-screenshot-{len(paths) + 1:03d}.png")
                path.write_bytes(base64.b64decode(shot["data"]))
                paths.append(path)
            on_page(browser, session)
            return paths
        finally:
            browser.close()


def on_page(browser: _Browser, session: str) -> None:
    """Stop unless the browser still shows the page (a meta refresh may try to leave it)."""
    frame = browser.send("Page.getFrameTree", {}, session)["frameTree"]["frame"]
    if frame.get("url") != _PAGE_URL or frame.get("unreachableUrl"):
        raise SystemExit(f"the page was replaced by {frame.get('unreachableUrl') or frame.get('url')!r}")


def _source_entry(name: str, report: dict[str, Any], file: str) -> tuple[Path, dict[str, Any]]:
    """The source file of a part of the text (its path relative to eval-data/<set>) and its manifest
    entry (the report, or the attachment)."""
    if file == source_path(name, report).relative_to(DATA / name).as_posix():
        return source_path(name, report), report
    for attachment in report.get("attachments", []):
        if file == f"attachments/{attachment['file']}":
            return DATA / name / "attachments" / attachment["file"], attachment
    raise SystemExit(f"{report['id']}: no source file {file!r} in the manifest")


def render_images(
    name: str, report: dict[str, Any], draft: dict[str, Any], folder: Path, tools: dict[str, str]
) -> list[dict[str, str]]:
    """Draw the pages of the appendix for the review: each PDF page it is on, and every screenshot of
    each web page or text attachment it is in. Returns each image's label and file name."""
    for old in folder.glob("*.png"):
        old.unlink()
    images = []
    for number, part in enumerate(draft["parts"], start=1):
        path, entry = _source_entry(name, report, part["file"])
        if part["format"] == "pdf":
            for page in part["pages"]:
                out = folder / f"{number}-page-{page:04d}"
                cmd = [
                    tools["pdftoppm_path"],
                    "-r",
                    "110",
                    "-f",
                    str(page),
                    "-l",
                    str(page),
                    "-png",
                    "-singlefile",
                ]
                subprocess.run([*cmd, str(path), str(out)], check=True, capture_output=True)  # noqa: S603
                images.append({"label": f"{part['file']} page {page}", "file": f"{out.name}.png"})
            continue
        if part["format"] == "html":
            page_text = decode_html(path.read_bytes(), entry.get("http_charset"), charset_override(entry))[0]
            body, headers = reviewable_page(page_text)
        else:
            text = convert(path, "text", None, charset_override(entry))[0]
            body, headers = (
                text.encode("utf-8"),
                [{"name": "Content-Type", "value": "text/plain; charset=utf-8"}],
            )
        try:
            shots = screenshots(tools["chromium_path"], body, headers, folder / str(number))
        except SystemExit as exc:
            raise SystemExit(f"{part['file']}: {exc}") from None
        for shot in shots:
            index = int(shot.stem.rsplit("-", 1)[1])
            images.append({"label": f"{part['file']} screenshot {index}", "file": shot.name})
    return images


# --------------------------------------------------------------------------- ground truth: the review

# A review template, filled in by the reviewer: who and when, the images checked (every PDF page the
# appendix is on, and for each web page or text attachment the screenshots that show the appendix),
# whether every line was checked, a resolution for every warning ("confirmed": the draft is right
# there; "corrected": an entry below fixes it and names the warning), and the corrections. Values are
# in standard form (normalise) and of the shape of their type. An added value records its writing as
# the page shows it, its writing class and where it stands; an ambiguous entry its writing and where
# it stands. A draft value whose writing, class or place is wrong is removed and added again.
_TEMPLATE_INFO = {"id", "images", "help"}
_WARNING_FIELDS = ({"kind", "line", "message", "resolution", "note"}, set[str]())
_ADD_FIELDS = ({"type", "value", "writing", "class", "location", "reason"}, {"warnings"})
_REMOVE_FIELDS = ({"type", "value", "reason"}, {"warnings"})
_AMBIGUOUS_FIELDS = ({"type", "readings", "writing", "location", "reason", "from_draft"}, {"warnings"})
_VALUE_FIELDS = ({"value", "writing", "class", "location"}, set[str]())
RESOLUTIONS = ("confirmed", "corrected")
REVIEW_HELP = (
    "Check every line of the draft (review.html) against the images; list the images you checked in "
    "pages_checked (labels from 'images'), set checked_every_line to true, and give every warning a "
    "resolution: 'confirmed' (the draft is right) or 'corrected' (an add, remove or ambiguous entry "
    "fixes it and lists the warning in its 'warnings'), with a note. Corrections: add {type, value, "
    "writing, class, location, reason}; remove {type, value, reason}; ambiguous {type, readings (two or "
    "more), writing, location, reason, from_draft (whether a reading is a draft value)}. Values in "
    "standard form; class is plain, ascii-defang or fullwidth-cjk-defang. To correct a draft value's "
    "writing, class or place, remove it and add it again. Then run `review`."
)


def truth_folder(name: str, report: dict[str, Any]) -> Path:
    return DATA / name / "truth" / str(report["id"])


def draft_path(name: str, report: dict[str, Any]) -> Path:
    return DATA / name / "truth" / f"{report['id']}.draft.json"


def template_path(name: str, report: dict[str, Any]) -> Path:
    return DATA / name / "truth" / f"{report['id']}.review.json"


def draft_masked(draft: dict[str, Any]) -> dict[str, list[str]]:
    return {kind: sorted({e["value"] for e in entries}) for kind, entries in sorted(draft["masked"].items())}


# The shape of a value of each type, in standard form.
_TYPE_SHAPES = {
    "md5": re.compile("[0-9a-f]{32}"),
    "sha1": re.compile("[0-9a-f]{40}"),
    "sha256": re.compile("[0-9a-f]{64}"),
    "ipv4": re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"),
    "ipv6": re.compile("[0-9a-f.]*:[0-9a-f:.]*"),
    "domain": re.compile(r"[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*\.(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})"),
    "email": re.compile(r"[^@\s]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z0-9\-]{2,63}"),
    "url": re.compile(r"[a-z][a-z0-9+.\-]*://\S+"),
}


def _is_normalised(kind: str, value: Any) -> bool:
    return isinstance(value, str) and kind in TYPES and normalise(kind, value) == value


def _value_problem(kind: str, value: Any, shape: bool = True) -> str | None:
    """Why ``value`` is not a value of type ``kind`` in standard form (and, with ``shape``, of the
    shape of its type), or None."""
    if not isinstance(value, str):
        return "not a string"
    if normalise(kind, value) != value:
        return f"{value!r} is not in standard form; write {normalise(kind, value)!r}"
    if shape and not _TYPE_SHAPES[kind].fullmatch(value):
        return f"{value!r} is not a {kind}"
    return None


def _change_problems(where: str, changes: Any, fields: tuple[set[str], set[str]]) -> list[str]:
    if not isinstance(changes, list):
        return [f"{where}: not a list"]
    problems = []
    for index, change in enumerate(changes):
        at = f"{where}[{index}]"
        problems += _fields(at, change, fields)
        if not isinstance(change, dict):
            continue
        kind = change.get("type")
        if kind not in TYPES:
            problems.append(f"{at}: type must be one of {', '.join(TYPES)}")
            continue
        for key in ("reason", "writing", "location"):
            if key in fields[0]:
                problems += _text(f"{at}.{key}", change.get(key))
        if "class" in fields[0] and change.get("class") not in CLASSES:
            problems.append(f"{at}: class must be one of {', '.join(CLASSES)}")
        if "warnings" in change and not _strings(change["warnings"]):
            problems.append(f"{at}.warnings: not a list of warning ids")
        if "value" in fields[0]:
            # An added value must have the shape of its type; a removed one must be a value of the
            # draft (checked against it), whatever the rules gave.
            problem = _value_problem(kind, change.get("value"), shape="class" in fields[0])
            if problem:
                problems.append(f"{at}: {problem}")
        if "readings" in fields[0]:
            readings = change.get("readings")
            if not (_strings(readings) and len(set(readings)) == len(readings) > 1):
                problems.append(f"{at}.readings: not a list of two or more different readings")
            else:
                problems += [
                    f"{at}: reading {problem}"
                    for r in readings
                    if (problem := _value_problem(kind, r, shape=False))
                ]
            if not isinstance(change.get("from_draft"), bool):
                problems.append(f"{at}.from_draft: true or false")
    return problems


def _review_shape_problems(where: str, review: Any) -> list[str]:
    """Problems with the shape of a review (as in the manifest), without the draft."""
    problems = _fields(where, review, _REVIEW_FIELDS)
    if not isinstance(review, dict):
        return problems
    if not re.fullmatch(r"[0-9a-f]{64}", str(review.get("draft_sha256", ""))):
        problems.append(f"{where}.draft_sha256: not a SHA-256")
    problems += _text(f"{where}.reviewed_by", review.get("reviewed_by"))
    if not _UTC_TIME.fullmatch(str(review.get("reviewed_at", ""))):
        problems.append(f"{where}.reviewed_at: a UTC time such as 2026-10-09T13:45:04Z")
    if review.get("checked_every_line") is not True:
        problems.append(f"{where}.checked_every_line: every line must be checked against the page (true)")
    if not (_strings(review.get("pages_checked")) and review.get("pages_checked")):
        problems.append(f"{where}.pages_checked: the labels of the images checked")
    warnings = review.get("warnings")
    if not isinstance(warnings, dict):
        problems.append(f"{where}.warnings: not an object keyed by warning id")
        warnings = {}
    for warning_id, warning in warnings.items():
        at = f"{where}.warnings.{warning_id}"
        problems += _fields(at, warning, _WARNING_FIELDS)
        if isinstance(warning, dict):
            if warning.get("resolution") not in RESOLUTIONS:
                problems.append(f"{at}: resolution must be 'confirmed' or 'corrected'")
            problems += _text(f"{at}.note", warning.get("note"))
    problems += _change_problems(f"{where}.add", review.get("add"), _ADD_FIELDS)
    problems += _change_problems(f"{where}.remove", review.get("remove"), _REMOVE_FIELDS)
    problems += _change_problems(f"{where}.ambiguous", review.get("ambiguous"), _AMBIGUOUS_FIELDS)
    cited = {
        warning_id
        for change in ("add", "remove", "ambiguous")
        for entry in (review.get(change) if isinstance(review.get(change), list) else [])
        if isinstance(entry, dict) and _strings(entry.get("warnings", []))
        for warning_id in entry.get("warnings", [])
    }
    problems += [f"{where}: warning {w} is cited but does not exist" for w in sorted(cited - warnings.keys())]
    problems += [
        f"{where}.warnings.{w}: corrected, but no add, remove or ambiguous entry names it"
        for w, warning in sorted(warnings.items())
        if isinstance(warning, dict) and warning.get("resolution") == "corrected" and w not in cited
    ]
    values = review.get("values")
    if not isinstance(values, dict):
        problems.append(f"{where}.values: not an object keyed by type")
        values = {}
    for kind, entries in values.items():
        if kind not in TYPES or not isinstance(entries, list):
            problems.append(f"{where}.values.{kind}: not a type with a list of values")
            continue
        for index, entry in enumerate(entries):
            at = f"{where}.values.{kind}[{index}]"
            problems += _fields(at, entry, _VALUE_FIELDS)
            if isinstance(entry, dict):
                if problem := _value_problem(kind, entry.get("value")):
                    problems.append(f"{at}: not in standard form or not a {kind}: {problem}")
                if entry.get("class") not in CLASSES:
                    problems.append(f"{at}: class must be one of {', '.join(CLASSES)}")
    masked = review.get("masked")
    if not (isinstance(masked, dict) and all(k in TYPES and _strings(v) for k, v in masked.items())):
        problems.append(f"{where}.masked: not an object of lists of values keyed by type")
    return problems


def final_values(draft: dict[str, Any], review: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The reviewed ground truth: the draft's values, less those removed and the readings of ambiguous
    entries, plus those added; each with its writing, writing class and place."""
    values: dict[str, dict[str, dict[str, Any]]] = {
        kind: {
            e["value"]: {key: e[key] for key in ("value", "writing", "class", "location")} for e in entries
        }
        for kind, entries in draft["values"].items()
    }
    for entry in review["remove"]:
        values.get(entry["type"], {}).pop(entry["value"], None)
    for entry in review["ambiguous"]:
        for reading in entry["readings"]:
            values.get(entry["type"], {}).pop(reading, None)
    for entry in review["add"]:
        values.setdefault(entry["type"], {})[entry["value"]] = {
            key: entry[key] for key in ("value", "writing", "class", "location")
        }
    return {kind: [values[kind][v] for v in sorted(values[kind])] for kind in TYPES if values.get(kind)}


def image_labels_required(draft: dict[str, Any]) -> tuple[list[str], list[str]]:
    """The images a review must list: every PDF page the appendix is on, and for each web page or text
    attachment (whose screenshots are not tied to lines) the file, of which one screenshot at least."""
    pages = [
        f"{part['file']} page {page}"
        for part in draft["parts"]
        if part["format"] == "pdf"
        for page in part["pages"]
    ]
    files = [part["file"] for part in draft["parts"] if part["format"] != "pdf"]
    return pages, files


def review_problems(
    draft: dict[str, Any], review: dict[str, Any], images: list[str] | None = None
) -> list[str]:
    """Everything that keeps ``review`` (complete, as in the manifest) from being the review of
    ``draft``: a review of another draft, an unresolved or unknown warning, a correction that
    matches nothing or something already there, values that do not follow from the corrections, an
    image of the appendix not checked. ``images`` (at review time) are the labels of the images drawn."""
    problems = _review_shape_problems("review", review)
    if problems:
        return problems
    if review["draft_sha256"] != draft["sha256"]:
        return [
            f"the review was made against draft {review['draft_sha256'][:12]}, but the text, the appendix "
            f"markers, the list of top-level domains or the rules now give draft {draft['sha256'][:12]}; run "
            "`truth` and review the new draft"
        ]
    drafted_warnings = {w["id"]: w for w in draft["warnings"]}
    for warning_id, warning in drafted_warnings.items():
        resolved = review["warnings"].get(warning_id)
        if resolved is None:
            problems.append(f"warning {warning_id} has no resolution")
        elif [resolved[k] for k in ("kind", "line", "message")] != [
            warning[k] for k in ("kind", "line", "message")
        ]:
            problems.append(
                f"warning {warning_id}: the resolution is for another warning ({resolved['kind']}, line "
                f"{resolved['line']}) than the draft's ({warning['kind']}, line {warning['line']})"
            )
    problems += [
        f"warning {w} is not a warning of the draft" for w in review["warnings"] if w not in drafted_warnings
    ]
    in_draft = {kind: {e["value"] for e in entries} for kind, entries in draft["values"].items()}
    removed: set[tuple[str, str]] = set()
    for entry in review["remove"]:
        key = (entry["type"], entry["value"])
        if entry["value"] not in in_draft.get(entry["type"], set()):
            problems.append(f"remove: {entry['type']} {entry['value']!r} matches no value of the draft")
        if key in removed:
            problems.append(f"remove: {entry['type']} {entry['value']!r} is listed twice")
        removed.add(key)
    readings: set[tuple[str, str]] = set()
    for entry in review["ambiguous"]:
        drafted = [r for r in entry["readings"] if r in in_draft.get(entry["type"], set())]
        if entry["from_draft"] and not drafted:
            problems.append(
                f"ambiguous: no reading of {entry['readings']} is a value of the draft (from_draft is true)"
            )
        if not entry["from_draft"] and drafted:
            problems.append(f"ambiguous: {drafted} are values of the draft, but from_draft is false")
        problems += [
            f"ambiguous: reading {problem}"
            for r in entry["readings"]
            if r not in drafted and (problem := _value_problem(entry["type"], r))
        ]
        for reading in entry["readings"]:
            key = (entry["type"], reading)
            if key in readings:
                problems.append(f"ambiguous: {entry['type']} {reading!r} is a reading of two entries")
            if key in removed:
                problems.append(f"ambiguous: {entry['type']} {reading!r} is also removed")
            readings.add(key)
    added: set[tuple[str, str]] = set()
    for entry in review["add"]:
        key = (entry["type"], entry["value"])
        if entry["value"] in in_draft.get(entry["type"], set()) and key not in removed:
            problems.append(f"add: {entry['type']} {entry['value']!r} is already a value of the draft")
        if key in added or key in readings:
            problems.append(f"add: {entry['type']} {entry['value']!r} is added twice or also ambiguous")
        if _MASKED.search(entry["value"]):
            problems.append(f"add: {entry['value']!r} is masked; masked values are left out")
        if entry["type"] == "url" and not normalise_url(entry["value"])[1]:
            problems.append(f"add: the URL {entry['value']!r} has no host")
        added.add(key)
    pages, files = image_labels_required(draft)
    checked = review["pages_checked"]
    problems += [
        f"pages_checked: {label!r} (the appendix is on it) is not listed"
        for label in pages
        if label not in checked
    ]
    problems += [
        f"pages_checked: no screenshot of {file} is listed"
        for file in files
        if not any(label.startswith(f"{file} screenshot ") for label in checked)
    ]
    if images is not None:
        problems += [
            f"pages_checked: {label!r} is not an image that `truth` drew"
            for label in checked
            if label not in images
        ]
    if not problems:
        if review["values"] != final_values(draft, review):
            problems.append("values: not the draft's values with the corrections; run `review` again")
        if review["masked"] != draft_masked(draft):
            problems.append("masked: not the draft's masked values; run `review` again")
    hosts = {url_host(e["value"]): e["value"] for e in review["values"].get("url", [])}
    problems += [
        f"values: the URL {url!r} has no host that can be a name or an address; correct it or remove it"
        for host, url in hosts.items()
        if not is_host(host)
    ]
    names = {e["value"] for e in review["values"].get("domain", [])}
    problems += [
        f"remove: domain {e['value']!r} is the host of the URL {hosts[e['value']]!r}, which stays in the "
        "truth and makes it an indicator again; remove or correct the URL too, or keep the name"
        for e in review["remove"]
        if e["type"] == "domain" and e["value"] in hosts and e["value"] not in names
    ]
    problems += [
        f"ambiguous: reading {reading!r} is the host of the URL {hosts[reading]!r}, which stays in the truth "
        "and makes it an indicator; resolve the reading (add it as a name), or mark the URL ambiguous too"
        for e in review["ambiguous"]
        if e["type"] == "domain"
        for reading in e["readings"]
        if reading in hosts
    ]
    return problems


def write_template(
    name: str, report: dict[str, Any], draft: dict[str, Any], images: list[dict[str, str]]
) -> str:
    """Write the review template unless one for this draft exists. A template of another draft is
    kept under a name of its own (never over another file), and one kept earlier for this draft is
    moved back. Returns what was done."""
    path = template_path(name, report)
    labels = [image["label"] for image in images]
    note = ""
    if path.exists():
        old = json.loads(path.read_text(encoding="utf-8"))
        if old.get("draft_sha256") == draft["sha256"]:
            if labels and old.get("images") != labels:
                old["images"] = labels
                path.write_text(dump_json(old), "utf-8")
                return f"kept {path.name} (made for this draft), with the list of images drawn now"
            return f"kept {path.name} (made for this draft)"
        stem = f"{report['id']}.review.{str(old.get('draft_sha256', 'unknown'))[:12]}"
        kept = path.with_name(f"{stem}.json")
        number = 1
        while kept.exists():
            number += 1
            kept = path.with_name(f"{stem}-{number}.json")
        path.replace(kept)
        note = f"moved the template of another draft to {kept.name}; "
    earlier = sorted(path.parent.glob(f"{report['id']}.review.{draft['sha256'][:12]}*.json"))
    for candidate in earlier:
        kept_template = json.loads(candidate.read_text(encoding="utf-8"))
        if kept_template.get("draft_sha256") == draft["sha256"]:
            if labels:
                kept_template["images"] = labels
            path.write_text(dump_json(kept_template), "utf-8")
            candidate.unlink()
            return f"{note}moved {candidate.name}, kept earlier for this draft, back to {path.name}"
    template = {
        "id": report["id"],
        "help": REVIEW_HELP,
        "draft_sha256": draft["sha256"],
        "images": labels,
        "reviewed_by": "",
        "reviewed_at": "",
        "pages_checked": [],
        "checked_every_line": False,
        "warnings": {
            w["id"]: {
                "kind": w["kind"],
                "line": w["line"],
                "message": w["message"],
                "resolution": "",
                "note": "",
            }
            for w in draft["warnings"]
        },
        "add": [],
        "remove": [],
        "ambiguous": [],
    }
    path.write_text(dump_json(template), "utf-8")
    return f"{note}wrote {path.name}"


def write_review_page(
    path: Path, report: dict[str, Any], draft: dict[str, Any], images: list[dict[str, str]]
) -> None:
    """The review page: every line of the appendix with its values and warnings, beside the images."""
    e = html.escape
    warnings = {w["id"]: w for w in draft["warnings"]}
    kinds = sorted({w["kind"] for w in draft["warnings"]})
    rows = []
    for line in draft["lines"]:
        values = "<br>".join(
            f"{e(v['type'])} <b>{e(v['value'])}</b> <i>{e(v['class'])}</i>" for v in line["values"]
        )
        notes = "<br>".join(
            f"<span class=w>{e(w)} {e(warnings[w]['kind'])}</span>: {e(warnings[w]['message'])}"
            for w in line["warnings"]
        )
        rows.append(
            f"<tr id=L{line['n']}><td>L{line['n']}</td><td>{e(line['location'])}</td>"
            f"<td><pre>{e(line['text'])}</pre></td><td>{values}</td><td>{notes}</td></tr>"
        )
    shots = "".join(
        f"<figure><figcaption>{e(image['label'])}</figcaption>"
        f"<img src='{e(report['id'])}/{e(image['file'])}'></figure>"
        for image in images
    )
    page = f"""<!doctype html>
<meta charset="utf-8">
<title>Review {e(report["id"])}</title>
<style>
body {{ margin: 0; font: 13px/1.4 sans-serif; display: flex; height: 100vh; }}
#lines, #images {{ overflow: auto; height: 100vh; }}
#lines {{ width: 55%; }} #images {{ width: 45%; background: #eee; }}
table {{ border-collapse: collapse; }}
td {{ border-bottom: 1px solid #ccc; vertical-align: top; padding: 2px 4px; }}
pre {{ margin: 0; white-space: pre-wrap; word-break: break-all; }} .w {{ color: #b00; }}
img {{ max-width: 100%; border: 1px solid #999; }} figure {{ margin: 8px; }}
</style>
<div id=lines>
<h1>{e(report["id"])}</h1>
<p>Draft {e(draft["sha256"])}. {len(draft["lines"])} lines, {len(draft["warnings"])} warnings.
Check every line against the images; fill in {e(report["id"])}.review.json.</p>
<table>{"".join(rows)}</table>
<dl>{"".join(f"<dt>{e(k)}</dt><dd>{e(WARNING_KINDS[k])}</dd>" for k in kinds)}</dl>
</div>
<div id=images>{shots}</div>
"""
    path.write_text(page, "utf-8")


def command_truth(name: str) -> None:
    render = "--no-render" not in sys.argv
    tools = render_tools() if render else None
    failed = []
    for report in manifest(name):
        text, conversion = load_text(name, report)
        draft = draft_truth(text, report, conversion["parts"])
        folder = truth_folder(name, report)
        folder.mkdir(parents=True, exist_ok=True)
        draft_path(name, report).write_text(dump_json(draft), "utf-8")
        # The record of the images is written only once they are all drawn, so that a review is never
        # checked against images that a failed or skipped drawing left out.
        (folder / "images.json").unlink(missing_ok=True)
        images: list[dict[str, str]] = []
        if tools is not None:
            try:
                images = render_images(name, report, draft, folder, tools)
            except (SystemExit, subprocess.SubprocessError, OSError) as exc:
                failed.append(f"{report['id']}: {exc}")
                print(f"{report['id']}: DRAWING THE PAGES FAILED: {exc}")
                images = []
            else:
                record = {"draft_sha256": draft["sha256"], "tools": tools, "images": images}
                (folder / "images.json").write_text(dump_json(record), "utf-8")
        write_review_page(folder.with_name(f"{report['id']}.review.html"), report, draft, images)
        done = write_template(name, report, draft, images)
        counts = {kind: len(entries) for kind, entries in draft["values"].items()}
        kinds: dict[str, int] = {}
        for warning in draft["warnings"]:
            kinds[warning["kind"]] = kinds.get(warning["kind"], 0) + 1
        print(f"{report['id']}: draft {draft['sha256'][:12]}, {len(draft['lines'])} lines, values {counts}")
        print(f"    warnings: {kinds or 'none'}")
        print(f"    {len(images)} images; {done}")
    if failed:
        raise SystemExit("the pages of these reports could not be drawn:\n    " + "\n    ".join(failed))


def _images_drawn(name: str, report: dict[str, Any], draft: dict[str, Any]) -> list[str] | None:
    """The labels of the images drawn for this draft, or None unless every one of them is there."""
    folder = truth_folder(name, report)
    record_path = folder / "images.json"
    if not record_path.exists():
        return None
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if record.get("draft_sha256") != draft["sha256"]:
        return None
    if not all((folder / image["file"]).exists() for image in record["images"]):
        return None
    return [image["label"] for image in record["images"]]


def command_review(name: str) -> None:
    """Check the filled-in review templates against the drafts and write them into the manifest."""
    made = sorted(path.name for path in HERE.glob(f"results-{name}-*.json"))
    if made:
        raise SystemExit(
            f"set {name!r} has results already ({', '.join(made)}); the ground truth is reviewed and "
            "committed before any tool runs, not after"
        )
    data = load_manifest()
    reports = data["sets"].get(name)
    if reports is None:
        raise SystemExit(f"no set {name!r} in the manifest")
    problems: list[str] = []
    reviews = {}
    for report in reports:
        text, conversion = load_text(name, report)
        draft = draft_truth(text, report, conversion["parts"])
        path = template_path(name, report)
        if not path.exists():
            problems.append(f"{report['id']}: no review template; run `truth`")
            continue
        filled = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(filled, dict) or filled.get("id") != report["id"]:
            problems.append(f"{report['id']}: {path.name} is not the template of this report")
            continue
        core = {key: value for key, value in filled.items() if key not in _TEMPLATE_INFO}
        shape = _review_shape_problems(path.name, {**core, "values": {}, "masked": {}})
        if shape:
            problems += shape
            continue
        core["values"] = final_values(draft, core)
        core["masked"] = draft_masked(draft)
        images = _images_drawn(name, report, draft)
        if images is None:
            problems.append(
                f"{report['id']}: the pages of this draft were not drawn; run `truth` (with pdftoppm "
                "and Chromium)"
            )
            continue
        problems += [f"{report['id']}: {problem}" for problem in review_problems(draft, core, images)]
        reviews[report["id"]] = core
    if problems:
        raise SystemExit("the reviews are not complete:\n    " + "\n    ".join(problems))
    for report in reports:
        report["truth_review"] = reviews[report["id"]]
        counts = {kind: len(v) for kind, v in reviews[report["id"]]["values"].items()}
        classes: dict[str, int] = {}
        for entries in reviews[report["id"]]["values"].values():
            for entry in entries:
                classes[entry["class"]] = classes.get(entry["class"], 0) + 1
        print(f"{report['id']}: {counts}  writing classes {classes}")
    write_manifest(data)
    print(f"wrote the reviews into {MANIFEST.name}; commit it before `run`")


def load_reviewed_truth(
    name: str, report: dict[str, Any], text: str, conversion: dict[str, Any]
) -> dict[str, Any]:
    """The reviewed ground truth of ``report``: stop unless its review is in the manifest, complete,
    committed as it stands, and made against the draft that the current text and rules give."""
    review = report.get("truth_review")
    if review is None:
        raise SystemExit(
            f"{report['id']}: no reviewed ground truth in the manifest; run `truth` and `review`, and "
            "commit the manifest"
        )
    committed = committed_manifest() or {}
    committed_reports = committed.get("sets", {}).get(name, [])
    committed_review = next(
        (r.get("truth_review") for r in committed_reports if r.get("id") == report["id"]), None
    )
    if committed_review != review:
        raise SystemExit(
            f"{report['id']}: the review in the manifest is not committed as it stands; commit it"
        )
    draft = draft_truth(text, report, conversion["parts"])
    problems = review_problems(draft, review)
    if problems:
        raise SystemExit(f"{report['id']}: " + "; ".join(problems))
    truth: dict[str, set[str]] = {kind: set() for kind in TYPES}
    classes: dict[str, dict[str, str]] = {kind: {} for kind in TYPES}
    for kind, entries in review["values"].items():
        for entry in entries:
            truth[kind].add(entry["value"])
            classes[kind][entry["value"]] = entry["class"]
    # A URL in the appendix makes its host an indicator too (the tools get the same treatment). The
    # host's class is how the host itself is written: the plainest of its own entry and its writing
    # in every occurrence of each of its URLs (in the draft's lines, or as the review added it). An
    # address that is a URL's host and a value of its own is classed the same way.
    writings: dict[str, list[str]] = {}
    for line in draft["lines"]:
        for item in line["values"]:
            if item["type"] == "url":
                writings.setdefault(item["value"], []).append(item["writing"])
    for entry in review["add"]:
        if entry["type"] == "url":
            writings[entry["value"]] = [entry["writing"]]
    for entry in review["values"].get("url", []):
        host = url_host(entry["value"])
        if not host:
            continue
        kind = "domain" if not is_ip(host) else "ipv6" if ":" in host else "ipv4"
        if kind == "domain":
            truth["domain"].add(host)
        elif host not in truth[kind]:
            continue
        written = [host_class(w) for w in writings.get(entry["value"], [entry["writing"]])]
        classes[kind][host] = min([classes[kind].get(host, CLASSES[-1]), *written], key=CLASSES.index)
    ambiguous: dict[str, set[str]] = {}
    for entry in review["ambiguous"]:
        ambiguous.setdefault(entry["type"], set()).update(entry["readings"])
    for kind, readings in ambiguous.items():
        truth[kind] -= readings
    return {
        "truth": {kind: sorted(values) for kind, values in truth.items()},
        "classes": {kind: {v: classes[kind][v] for v in sorted(truth[kind])} for kind in TYPES},
        "ambiguous": {kind: sorted(readings) for kind, readings in ambiguous.items()},
        "masked": review["masked"],
        "draft_sha256": draft["sha256"],
        "review_sha256": object_sha256(review),
        "draft": draft,
        "review": review,
    }


# --------------------------------------------------------------------------- tools


def ttprism_identity() -> dict[str, str]:
    """The version and path of the TTPrism that `run` executes; stop unless it is this repository's,
    the same in a subprocess (python -I -m ttprism) as in this process (line_wrap_fragments)."""
    import ttprism

    code = "import importlib.metadata as m, ttprism; print(ttprism.__file__); print(m.version('ttprism'))"
    cmd = [sys.executable, "-I", "-c", code]
    path, version = subprocess.run(cmd, capture_output=True, check=True, text=True).stdout.splitlines()  # noqa: S603
    executed, imported = Path(path).resolve(), Path(str(ttprism.__file__)).resolve()
    if executed != imported or not executed.is_relative_to(ROOT / "src"):
        raise SystemExit(
            f"the TTPrism that runs ({executed}) is not this repository's src/ttprism ({imported}); "
            "install it with `uv pip install -e .`"
        )
    return {"version": version, "path": executed.relative_to(ROOT).as_posix()}


def run_ttprism(path: Path, flags: list[str]) -> dict[str, Any]:
    """TTPrism's values of each type, and its warnings and suppressed counts."""
    cmd = [sys.executable, "-I", "-m", "ttprism", "extract", "--input-format", "text", "-q", *flags]
    cmd.append(str(path))
    data = json.loads(subprocess.run(cmd, capture_output=True, check=True, text=True).stdout)  # noqa: S603
    out: dict[str, set[str]] = {kind: set() for kind in TYPES}
    for ioc in data["iocs"]:
        if ioc["type"] in out:
            out[ioc["type"]].add(ioc["value"])
    return {
        "values": {k: sorted(v) for k, v in out.items()},
        "warnings": data.get("warnings", []),
        "suppressed": data.get("suppressed", {}),
    }


def line_wrap_fragments(text: str) -> list[dict[str, str]]:
    """The names and e-mail addresses that TTPrism drops as line-wrap fragments, with the end of the
    line before each (its own extraction steps, in the same order, from the installed TTPrism)."""
    from ttprism import extract
    from ttprism.refang import refang

    joined = extract._rejoin_wrapped_lines(refang(text))
    fragments = []
    checks = (
        ("email", extract.EMAIL_RE, lambda s, e: extract._glued(joined, s - 1) or extract._glued(joined, e)),
        (
            "domain",
            extract.DOMAIN_RE,
            lambda s, e: extract._glued_before(joined, s) or extract._glued(joined, e),
        ),
    )
    for kind, regex, glued in checks:
        for match in regex.finditer(joined):
            start, end = match.span()
            if not glued(start, end) and extract._starts_wrapped_line(joined, start):
                line_before = joined[: joined.rfind("\n", 0, start)].rsplit("\n", 1)[-1]
                fragments.append(
                    {"type": kind, "fragment": match.group(0), "line_before_ends": line_before[-60:]}
                )
    return fragments


def run_iocextract(text: str) -> dict[str, list[str]]:
    import iocextract  # type: ignore[import-not-found]

    return {
        "url": sorted(set(iocextract.extract_urls(text, refang=True))),
        "domain": [],  # iocextract has no domain extractor
        "ipv4": sorted(set(iocextract.extract_ipv4s(text, refang=True))),
        "ipv6": sorted(set(iocextract.extract_ipv6s(text))),
        "email": sorted(set(iocextract.extract_emails(text, refang=True))),
        "md5": sorted(set(iocextract.extract_md5_hashes(text))),
        "sha1": sorted(set(iocextract.extract_sha1_hashes(text))),
        "sha256": sorted(set(iocextract.extract_sha256_hashes(text))),
    }


def run_ioc_finder(text: str) -> dict[str, list[str]]:
    from ioc_finder import find_iocs  # type: ignore[import-not-found]

    found = find_iocs(text)
    keys = {
        "url": "urls",
        "domain": "domains",
        "ipv4": "ipv4s",
        "ipv6": "ipv6s",
        "email": "email_addresses",
        "md5": "md5s",
        "sha1": "sha1s",
        "sha256": "sha256s",
    }
    return {kind: sorted(set(found.get(key, []))) for kind, key in keys.items()}


def _tool_error(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        last = (exc.stderr or "").strip().splitlines()[-1:]
        return f"exit status {exc.returncode}" + (f": {last[0][:300]}" if last else "")
    return f"{type(exc).__name__}: {str(exc)[:300]}"


def run_tools(text: str) -> tuple[dict[str, Values], dict[str, dict[str, Any]], dict[str, str]]:
    """Every tool's values in ``text``, TTPrism's warnings and suppressed counts, and the error of each
    tool that failed on it (which then has no values); one tool's failure never stops the others."""
    raw: dict[str, Values] = {}
    runs: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "report.txt"
        copy.write_bytes(text.encode("utf-8"))
        for tool, flags in SETTINGS.items():
            try:
                runs[tool] = run_ttprism(copy, flags)
                raw[tool] = runs[tool]["values"]
            except Exception as exc:  # any failure is this tool's error on this report
                errors[tool] = _tool_error(exc)
    for tool, function in (("iocextract", run_iocextract), ("ioc-finder", run_ioc_finder)):
        try:
            raw[tool] = function(text)
        except Exception as exc:  # e.g. iocextract's ValueError on a one-character host
            errors[tool] = _tool_error(exc)
    return raw, runs, errors


def outputs(raw: Values) -> Values:
    """Normalised, distinct values of each type."""
    return {kind: sorted({normalise(kind, v) for v in raw.get(kind, [])}) for kind in TYPES}


def git_commit() -> str:
    """HEAD, and which of the files the results depend on (PIPELINE_FILES) had uncommitted changes."""
    git = ["git", "-C", str(ROOT)]
    commit = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)  # noqa: S603
    paths = [path.relative_to(ROOT).as_posix() for path in PIPELINE_FILES]
    status = [*git, "status", "--porcelain", "--untracked-files=all", "--", *paths]
    dirty = subprocess.run(status, capture_output=True, text=True, check=True)  # noqa: S603
    changed = sorted(line[3:] for line in dirty.stdout.splitlines() if line.strip())
    return commit.stdout.strip() + (f"+uncommitted changes in {', '.join(changed)}" if changed else "")


def installed_distributions() -> list[str]:
    """Every distribution installed for this Python, as name==version (what pip freeze lists)."""
    found = {(d.metadata["Name"] or "?", d.version) for d in importlib.metadata.distributions()}
    return sorted(f"{name}=={version}" for name, version in found)


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def results_path(name: str, label: str) -> Path:
    return HERE / f"results-{name}-{label}.json"


def _class_counts(truth: dict[str, Any]) -> dict[str, int]:
    counts = dict.fromkeys(CLASSES, 0)
    for kind in TYPES:
        for value in truth["truth"][kind]:
            counts[truth["classes"][kind][value]] += 1
    return counts


def command_run(name: str, label: str) -> None:
    reports = manifest(name)
    # Every report's text and reviewed ground truth are checked before any tool runs.
    prepared = []
    for report in reports:
        text, conversion = load_text(name, report)
        prepared.append((report, text, conversion, load_reviewed_truth(name, report, text, conversion)))
    check_defang(name, {report["id"]: conversion["text_sha256"] for report, _, conversion, _ in prepared})
    # The ground truth is fixed before any tool runs: results made with another review of a report
    # mean that the review changed after the tools' outputs were seen.
    reviews = {report["id"]: truth["review_sha256"] for report, _, _, truth in prepared}
    for made in sorted(HERE.glob(f"results-{name}-*.json")):
        earlier = json.loads(made.read_text(encoding="utf-8"))
        changed = [
            entry["id"]
            for entry in earlier.get("reports", [])
            if entry.get("review_sha256") not in (None, reviews.get(entry["id"]))
        ]
        if changed:
            raise SystemExit(
                f"{made.name} was made with another review of {', '.join(changed)}; the ground truth "
                "cannot change after the tools have run"
            )
    commit = git_commit()
    if "+" in commit:
        print(f"WARNING: {commit.split('+', 1)[1]}")
    parser = html_parser_info()
    meta = {
        "set": name,
        "label": label,
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "ttprism_commit": commit,
        "ttprism": ttprism_identity(),
        "versions": {
            p: _version(p) for p in ("ttprism", "iocextract", "ioc-finder", "pypdf", "cryptography")
        },
        "python": parser["python"],
        "html_parser_sha256": parser["sha256"],
        "evaluate_sha256": sha256(SCRIPT),
        "tlds_sha256": sha256(TLDS_FILE),
        "installed": installed_distributions(),
        "ttprism_settings": {k: " ".join(v) or "(defaults)" for k, v in SETTINGS.items()},
    }
    entries = []
    for report, text, conversion, truth in prepared:
        fmt = source_format(report)
        raw, runs, errors = run_tools(text)
        values = {tool: outputs(raw.get(tool, {})) for tool in TOOLS}
        unparseable = {
            tool: bad
            for tool in TOOLS
            if (bad := [u for u in values[tool]["url"] if not normalise_url(u)[1]])
        }
        entry: dict[str, Any] = {
            "id": report["id"],
            "original_url": report["original_url"],
            "format": fmt,
            "source_sha256": conversion["source_sha256"],
            "text_sha256": conversion["text_sha256"],
            "conversion": {k: v for k, v in conversion.items() if k not in ("source_sha256", "text_sha256")},
            "draft_sha256": truth["draft_sha256"],
            "review_sha256": truth["review_sha256"],
            "truth_counts": {k: len(v) for k, v in truth["truth"].items() if v},
            "truth_classes": _class_counts(truth),
            "left_out": {
                "masked": {k: len(v) for k, v in truth["masked"].items()},
                "ambiguous": {k: len(v) for k, v in truth["ambiguous"].items()},
            },
            "ttprism": {
                tool: {"warnings": run["warnings"], "suppressed": run["suppressed"]}
                for tool, run in runs.items()
            },
            "errors": errors,
            "unparseable_urls": unparseable,
            "outputs": values,
        }
        print(f"{report['id']}: done")
        for tool, error in errors.items():
            print(f"    {tool} FAILED on this report: {error}")
        for tool, bad in unparseable.items():
            # Counts only: values next to a tool's name before the judging would unblind the sheet.
            print(f"    {tool}: {len(bad)} URL(s) without a host in standard form (in the results file)")
        if fmt == "html" and "ttprism-raw" in runs:
            fragments = line_wrap_fragments(text)
            entry["line_wrap_fragments"] = fragments
            counted = runs["ttprism-raw"]["suppressed"].get("line_wrap_fragment", 0)
            print(f"    line-wrap fragments dropped by TTPrism: {counted} (in the results file)")
            if len(fragments) != counted:
                print(f"    LISTED {len(fragments)} FRAGMENTS, BUT TTPRISM COUNTED {counted}")
        entries.append(entry)
    results = {"meta": meta, "reports": entries}
    results_path(name, label).write_text(dump_json(results) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- judgements

CATEGORIES = ("a", "b", "c")


def judgement_problems(data: Any) -> list[str]:
    """Everything wrong with judgements.json: {"about", "categories", "judgements": {"<set>/<id>":
    {type: {value in standard form: [category a, b or c, one-line reason]}}}}."""
    problems = _fields("judgements.json", data, ({"judgements"}, {"about", "categories"}))
    if not isinstance(data, dict):
        return problems
    judgements = data.get("judgements")
    if not isinstance(judgements, dict):
        return [*problems, "judgements.json: 'judgements' must be an object keyed by '<set>/<report id>'"]
    for key, kinds in judgements.items():
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", key):
            problems.append(f"judgements.json: {key!r} is not '<set>/<report id>'")
        if not isinstance(kinds, dict):
            problems.append(f"judgements.json: {key}: not an object keyed by type")
            continue
        for kind, values in kinds.items():
            if kind not in TYPES:
                problems.append(f"judgements.json: {key}: unknown type {kind!r} (one of {', '.join(TYPES)})")
                continue
            if not isinstance(values, dict):
                problems.append(f"judgements.json: {key}.{kind}: not an object keyed by value")
                continue
            for value, judgement in values.items():
                at = f"judgements.json: {key}.{kind}[{value!r}]"
                if normalise(kind, value) != value:
                    problems.append(f"{at}: not in standard form ({normalise(kind, value)!r})")
                if not (isinstance(judgement, list) and len(judgement) == 2):
                    problems.append(f"{at}: not [category, reason]")
                    continue
                category, reason = judgement
                if category not in CATEGORIES:
                    problems.append(f"{at}: category {category!r} is not 'a', 'b' or 'c'")
                if not (isinstance(reason, str) and reason.strip() and "\n" not in reason):
                    problems.append(f"{at}: the reason must be one line of text")
    return problems


def load_judgements() -> tuple[dict[str, Any], str | None]:
    """The judgements and the SHA-256 of judgements.json (None if there is none); stop if it is not
    valid."""
    if not JUDGEMENTS.exists():
        return {}, None
    data = json.loads(JUDGEMENTS.read_text(encoding="utf-8"))
    problems = judgement_problems(data)
    if problems:
        raise SystemExit("judgements.json is not valid:\n    " + "\n    ".join(problems))
    judgements: dict[str, Any] = data["judgements"]
    return judgements, sha256(JUDGEMENTS)


# --------------------------------------------------------------------------- scoring


def with_url_hosts(out: Values) -> set[str]:
    """Domain output plus the domain hosts of the URL output."""
    hosts = {url_host(u) for u in out["url"]}
    return set(out["domain"]) | {h for h in hosts if h and not is_ip(h)}


def found(truth: Values, out: Values) -> dict[str, set[str]]:
    """Ground-truth values a tool found, per type; "url-host" holds the hosts of the URLs."""
    hits = {}
    for kind in TYPES:
        expected = set(truth.get(kind, []))
        if expected:
            hits[kind] = expected & (with_url_hosts(out) if kind == "domain" else set(out[kind]))
    if truth.get("url"):
        hits["url-host"] = ({url_host(u) for u in truth["url"]} & {url_host(u) for u in out["url"]}) - {""}
    return hits


def expected_counts(truth: Values) -> dict[str, int]:
    counts = {kind: len(truth[kind]) for kind in TYPES if truth.get(kind)}
    if truth.get("url"):
        counts["url-host"] = len({url_host(u) for u in truth["url"]} - {""})
    return counts


class Lookup:
    """A report's ground truth (as load_reviewed_truth gives it) as sets, for classify."""

    __slots__ = ("ambiguous", "truth", "url_hosts")

    def __init__(self, truth: dict[str, Any]) -> None:
        self.truth = {kind: set(values) for kind, values in truth["truth"].items()}
        self.ambiguous = {kind: set(values) for kind, values in truth["ambiguous"].items()}
        self.url_hosts = {url_host(u) for u in truth["truth"].get("url", [])}


def classify(kind: str, value: str, lookup: Lookup, judged: dict[str, Any]) -> str | None:
    """'truth', 'masked', 'ambiguous', a judgement category, or None when the value still needs one."""
    if value in lookup.truth.get(kind, ()):
        return "truth"
    if _MASKED.search(value):
        return "masked"  # left out like masked ground-truth entries: the real value is not in the text
    # The address of an appendix URL counts as listed, as the host of a URL does for domains.
    if kind in ("ipv4", "ipv6") and value in lookup.url_hosts:
        return "truth"
    if value in lookup.ambiguous.get(kind, ()):
        return "ambiguous"
    if value in judged.get(kind, {}):
        category: str = judged[kind][value][0]
        return category
    return None


def ratio(hit: int, total: int) -> float | None:
    return round(hit / total, 4) if total else None


def totals_of(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Recall (by type and by writing class), precision and errors of each tool over ``reports``."""
    totals: dict[str, dict[str, Any]] = {}
    for report in reports:
        for tool, recall in report["recall"].items():
            total = totals.setdefault(
                tool,
                {
                    "recall": {},
                    "recall_by_class": {},
                    "precision": dict.fromkeys(report["precision"][tool], 0),
                    "errors": 0,
                },
            )
            for kind, (hit, expected) in recall.items():
                h, t = total["recall"].get(kind, (0, 0))
                total["recall"][kind] = (h + hit, t + expected)
            for klass, (hit, expected) in report.get("recall_by_class", {}).get(tool, {}).items():
                h, t = total["recall_by_class"].get(klass, (0, 0))
                total["recall_by_class"][klass] = (h + hit, t + expected)
            for category, value in report["precision"][tool].items():
                total["precision"][category] += value
            total["errors"] += int(tool in report.get("errors", {}))
            total["unjudged"] = total.get("unjudged", 0) + report.get("unjudged_by_tool", {}).get(tool, 0)
    for total in totals.values():
        p = total["precision"]
        n = p["truth"] + p["a"] + p["b"] + p["c"]
        p["judged_total"] = n
        p["strict"] = ratio(p["truth"] + p["a"], n)
        p["lenient"] = ratio(p["truth"] + p["a"] + p["b"], n)
        total["recall"] = {k: [h, t, ratio(h, t)] for k, (h, t) in sorted(total["recall"].items())}
        total["recall_by_class"] = {
            k: [*total["recall_by_class"][k], ratio(*total["recall_by_class"][k])]
            for k in CLASSES
            if k in total["recall_by_class"]
        }
    return totals


def print_totals(totals: dict[str, dict[str, Any]], status: str) -> None:
    for tool, total in totals.items():
        p = total["precision"]
        print(f"{tool:16s} [{status}] precision strict {p['strict']} lenient {p['lenient']}  {p}")
        print(
            "                 recall " + "  ".join(f"{k} {h}/{t}" for k, (h, t, _) in total["recall"].items())
        )
        print(
            "                 by writing "
            + "  ".join(f"{k} {h}/{t}" for k, (h, t, _) in total["recall_by_class"].items())
            + (f"  ERRORS on {total['errors']} report(s)" if total["errors"] else "")
        )


def _scored_truth(name: str, report: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """The reviewed ground truth of a report in the results (with its text and conversion record);
    stop if the text, the draft or the review changed since `run`."""
    text, conversion = load_text(name, report)
    truth = load_reviewed_truth(name, report, text, conversion)
    if (entry["text_sha256"], entry.get("draft_sha256"), entry.get("review_sha256")) != (
        conversion["text_sha256"],
        truth["draft_sha256"],
        truth["review_sha256"],
    ):
        raise SystemExit(f"{report['id']}: the text, the draft or the review changed since `run`; run again")
    return {**truth, "text": text, "conversion": conversion}


def _load_results(name: str, label: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    by_id = {report["id"]: report for report in manifest(name)}
    results: dict[str, Any] = json.loads(results_path(name, label).read_text(encoding="utf-8"))
    if sorted(by_id) != sorted(report["id"] for report in results["reports"]):
        raise SystemExit(f"the results do not cover the reports of set {name!r} in the manifest; run again")
    made_by = results["meta"].get("evaluate_sha256")
    if made_by != sha256(SCRIPT):
        raise SystemExit("another version of evaluate.py made these results; run them again")
    truths = {entry["id"]: _scored_truth(name, by_id[entry["id"]], entry) for entry in results["reports"]}
    check_defang(name, {entry["id"]: entry["text_sha256"] for entry in results["reports"]})
    return results, truths


def command_score(name: str, label: str) -> None:
    results, truths = _load_results(name, label)
    by_id = {report["id"]: report for report in manifest(name)}
    judgements, judgements_hash = load_judgements()
    unjudged_values: set[tuple[str, str, str]] = set()
    lost: dict[str, Values] = {}
    for report in results["reports"]:
        data = truths[report["id"]]
        truth = data["truth"]
        lookup = Lookup(data)
        key = f"{name}/{report['id']}"
        report["recall"], report["recall_by_class"], report["precision"] = {}, {}, {}
        hits_by_tool = {}
        report["unjudged_by_tool"] = {}
        for tool, out in report["outputs"].items():
            hits = hits_by_tool[tool] = found(truth, out)
            report["recall"][tool] = {k: [len(hits[k]), n] for k, n in expected_counts(truth).items()}
            by_class: dict[str, list[int]] = {}
            for kind in TYPES:
                for value in truth[kind]:
                    counts = by_class.setdefault(data["classes"][kind][value], [0, 0])
                    counts[0] += value in hits.get(kind, set())
                    counts[1] += 1
            report["recall_by_class"][tool] = {k: by_class[k] for k in CLASSES if k in by_class}
            counts = dict.fromkeys(("truth", "a", "b", "c", "masked", "ambiguous"), 0)
            for kind in TYPES:
                for value in out[kind]:
                    category = classify(kind, value, lookup, judgements.get(key, {}))
                    if category is None:
                        unjudged_values.add((key, kind, value))
                        report["unjudged_by_tool"][tool] = report["unjudged_by_tool"].get(tool, 0) + 1
                    else:
                        counts[category] += 1
            report["precision"][tool] = counts
        # What default filtering lost: comparable only when both TTPrism settings ran.
        if report.get("errors", {}).keys() & {"ttprism-raw", "ttprism-default"}:
            report["lost_by_default_filtering"] = "not comparable: a TTPrism setting failed on this report"
        else:
            dropped = {
                kind: sorted(hits_by_tool["ttprism-raw"][kind] - hits_by_tool["ttprism-default"][kind])
                for kind in hits_by_tool["ttprism-raw"]
            }
            report["lost_by_default_filtering"] = {k: v for k, v in dropped.items() if v}
            if report["lost_by_default_filtering"]:
                lost[report["id"]] = report["lost_by_default_filtering"]
        fmt = report.get("format", "pdf")
        report["writing"] = _writing_use(data, fmt, by_id[report["id"]], judgements.get(key, {}))
        for kind, value in body_fullwidth_values(data, fmt, by_id[report["id"]]):
            if classify(kind, value, lookup, judgements.get(key, {})) is None:
                unjudged_values.add((key, kind, value))
    unjudged: dict[str, dict[str, list[str]]] = {}
    for key, kind, value in sorted(unjudged_values):
        unjudged.setdefault(key, {}).setdefault(kind, []).append(value)
    count = len(unjudged_values)
    status = "final" if not count else f"provisional: {count} values not judged yet"
    formats = sorted({report.get("format", "pdf") for report in results["reports"]})
    results["status"] = status
    results["judgements_sha256"] = judgements_hash
    results["totals"] = totals_of(results["reports"])
    results["totals_by_format"] = {
        fmt: totals_of([r for r in results["reports"] if r.get("format", "pdf") == fmt]) for fmt in formats
    }
    for totals in (results["totals"], *results["totals_by_format"].values()):
        for total in totals.values():
            total["status"] = status
    using = [r["id"] for r in results["reports"] if r["writing"]["uses_fullwidth_cjk"]]
    results["reports_using_fullwidth_cjk"] = using
    results["lost_by_default_filtering"] = lost
    results["unjudged"] = unjudged
    results_path(name, label).write_text(dump_json(results) + "\n", encoding="utf-8")
    shown = "FINAL" if not count else "PROVISIONAL"
    print_totals(results["totals"], shown)
    if len(formats) > 1:
        for fmt in formats:
            print(f"--- {fmt} reports only")
            print_totals(results["totals_by_format"][fmt], shown)
    for report in results["reports"]:
        # The fragments are values that TTPrism dropped; shown only once the sheet is judged, so that
        # they do not tell the rater which tool found a value on it.
        for fragment in report.get("line_wrap_fragments", []) if not count else []:
            print(f"{report['id']}: line-wrap fragment {fragment['type']} {fragment['fragment']!r}")
        for tool, error in report.get("errors", {}).items():
            print(f"{report['id']}: {tool} failed: {error}")
    print(f"lost by default filtering: {lost}")
    print(
        f"reports that write indicators with full-width or CJK-bracket defanging: "
        f"{len(using)} of {len(results['reports'])} {using}"
    )
    if count:
        print(f"PROVISIONAL: {count} values still need a judgement (`judge {name} {label}`)")


def body_fullwidth_values(truth: dict[str, Any], fmt: str, report: dict[str, Any]) -> set[tuple[str, str]]:
    """(type, value) of each value the line rules find in the body (outside the appendix) that is
    written with full-width or CJK-bracket forms, and of the host of each URL found there whose host
    is written so."""
    text, parts = truth["text"], truth["conversion"]["parts"]
    start, end = appendix_span(text, report)
    found = set()
    for first, last in ((0, start), (end, len(text))):
        for kind, value, klass, writing in text_values(text, first, last, parts, fmt):
            if klass == CLASSES[2]:
                found.add((kind, value))
            host = url_host(value) if kind == "url" else ""
            if is_host(host) and host_class(writing) == CLASSES[2]:
                found.add(("domain" if not is_ip(host) else "ipv6" if ":" in host else "ipv4", host))
    return found


def _writing_use(
    truth: dict[str, Any], fmt: str, report: dict[str, Any], judged: dict[str, Any]
) -> dict[str, Any]:
    """How a report writes its indicators. It uses full-width or CJK-bracket writing when an indicator
    is written so at least once: a reviewed ground-truth value in an occurrence in the appendix (the
    draft's, unless the reviewer removed the value, or one the reviewer added), or a value in the body
    (or the host of a URL there) that is in the ground truth or that the rater judged an indicator (a;
    `judge` puts every such value outside the ground truth on the sheet). The two counts are of
    distinct indicators. The defang statistic's count inside any value the rules find is given beside
    them; it counts occurrences, and also values that are not indicators (version numbers, numbering,
    contact addresses)."""
    text, parts = truth["text"], truth["conversion"]["parts"]
    lookup = Lookup(truth)
    removed = {(e["type"], e["value"]) for e in truth["review"]["remove"]}
    # Both counts are of distinct indicators (type and value); a URL and its host count apart, each
    # when it is written so.
    in_appendix: set[tuple[str, str]] = set()
    written = [
        (item["type"], item["value"], item["class"], item["writing"])
        for line in truth["draft"]["lines"]
        for item in line["values"]
        if (item["type"], item["value"]) not in removed
    ] + [(e["type"], e["value"], e["class"], e["writing"]) for e in truth["review"]["add"]]
    for kind, value, klass, writing in written:
        if value not in lookup.truth.get(kind, ()):
            continue
        if klass == CLASSES[2]:
            in_appendix.add((kind, value))
        host = url_host(value) if kind == "url" else ""
        listed = host in lookup.truth.get("domain", ()) or host in lookup.url_hosts
        if host and listed and host_class(writing) == CLASSES[2]:
            in_appendix.add(("domain" if not is_ip(host) else "ipv6" if ":" in host else "ipv4", host))
    in_body = {
        (kind, value)
        for kind, value in body_fullwidth_values(truth, fmt, report)
        if classify(kind, value, lookup, judged) in ("truth", "a")
    }
    spans = value_spans(text, 0, len(text), parts, fmt)
    counts = _style_counts(defang_occurrences(text), spans)
    return {
        "fullwidth_cjk_indicators_in_appendix": len(in_appendix),
        "fullwidth_cjk_indicators_in_body": len(in_body),
        "fullwidth_cjk_in_any_value": sum(counts[style] for style in DEFANG_STYLES["fullwidth-cjk"]),
        "uses_fullwidth_cjk": bool(in_appendix or in_body),
    }


# --------------------------------------------------------------------------- blinded judging


def judging_path(name: str, label: str) -> Path:
    return DATA / name / "judging" / f"{label}.json"


_CONTEXT_WINDOW = 200


def _ascii_alnum(char: str) -> bool:
    return char.isascii() and char.isalnum()


_LINE_EDGE = " \t\u00a0\u3000.?,:;!-#"
# Characters that would make a hit part of a longer value of the type, before and after it.
_VALUE_CHARS = {
    "url": (
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "abcdefghijklmnopqrstuvwxyz0123456789!#$%*+,-./:;=?@\\^_{|}~&",
    ),
    "domain": ("abcdefghijklmnopqrstuvwxyz0123456789.-_", "abcdefghijklmnopqrstuvwxyz0123456789.-_"),
    "email": ("abcdefghijklmnopqrstuvwxyz0123456789.-_+%", "abcdefghijklmnopqrstuvwxyz0123456789.-_"),
    "ipv4": ("0123456789.", "0123456789"),
    # A URL's rest without its scheme stands on its own only when no "//", path or longer name comes
    # before it ("example.com" of "update.example.com"; an e-mail address's "@" may), and when it does
    # not go on into a longer name ("dl" of "dl.example.net", as a cut URL gives it).
    "bare": ("abcdefghijklmnopqrstuvwxyz0123456789/.-_", "abcdefghijklmnopqrstuvwxyz0123456789.-_"),
}


def _contexts(text: str, values: set[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
    """Up to three places in the text where each value occurs (as the line rules read them), each the
    value with up to 200 characters of its line on each side. A value that reaches the end of its
    line gets the start of the next line too, and one at the start of its line the end of the line
    before, since a line break may have cut it there. Occurrences inside a longer value are shown only
    when there is none other, marked so. A value written in no single line, as a tool built it, gets
    the lines where it occurs across a line break (a URL that a PDF wrapped), else where it occurs
    without its scheme (a scheme a tool added, "update[.]example[.]org" as
    "http://update.example.org"), else where its host occurs; such contexts are marked too."""
    raw_lines = text.split("\n")
    readings = [read_line(line, "pdf") for line in raw_lines]
    # Defanged schemes are read as normalise_url reads them, so that a URL written hxxp:// is found;
    # the replacements keep the length, so the reading's map to the line still holds.
    lowered = [re.sub("fxp(?=:)", "ftp", r.text.lower().replace("hxxp", "http")) for r in readings]
    joined = "\n".join(lowered)
    starts = [0]
    for line in lowered[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    # The readings joined without line breaks and the white space around them, with where each
    # line's stripped text starts in it and how much white space its start lost.
    flat_parts, flat_starts, lost, at = [], [], [], 0
    for line in lowered:
        part = line.strip()
        flat_starts.append(at)
        lost.append(len(line) - len(line.lstrip()))
        flat_parts.append(part)
        at += len(part)
    flat = "".join(flat_parts)

    def window(index: int, start: int, end: int) -> str:
        """The raw text of line ``index`` around its reading's characters start..end."""
        reading = readings[index]
        origins = reading.origins
        raw_start = origins[start][0] if start < len(origins) else len(reading.raw)
        raw_end = origins[end - 1][1] if 0 < end <= len(origins) else raw_start
        low, high = max(0, raw_start - _CONTEXT_WINDOW), min(len(reading.raw), raw_end + _CONTEXT_WINDOW)
        shown = visible(reading.raw[low:high]).strip()
        return ("…" if low > 0 else "") + shown + ("…" if high < len(reading.raw) else "")

    def place(first: int, start: int, last: int, end: int) -> str:
        """A context for a hit from line ``first`` offset ``start`` to line ``last`` offset ``end``."""
        if first == last:
            shown = window(first, start, end)
        else:
            shown = " / ".join(
                [window(first, start, len(lowered[first]))]
                + [window(i, 0, len(lowered[i])) for i in range(first + 1, last)]
                + [window(last, 0, end)]
            )
        # Past white space and the punctuation a tool leaves off a value (a "?" or "." before the break,
        # a hyphen pypdf gives for one the break hid).
        if (
            not lowered[last][end:].strip(_LINE_EDGE)
            and last + 1 < len(lowered)
            and lowered[last + 1].strip()
        ):
            shown += f" / (next line) {window(last + 1, 0, 0)}"
        if not lowered[first][:start].strip(_LINE_EDGE) and first > 0 and lowered[first - 1].strip():
            previous = len(lowered[first - 1])
            shown = f"(line before) {window(first - 1, previous, previous)} / {shown}"
        return shown

    def bounded(kind: str, position: int, length: int) -> bool:
        """Whether a hit is not part of a longer value: the characters around it would go on with it
        (a letter or digit, or a value's punctuation with a letter or digit beyond it; not sentence
        punctuation, nor a footnote number before a URL)."""
        before_chars, after_chars = _VALUE_CHARS.get(kind, ("abcdefghijklmnopqrstuvwxyz0123456789",) * 2)
        before = joined[max(0, position - 2) : position]
        after = joined[position + length : position + length + 2]
        if after[:1] and after[:1] in after_chars and (_ascii_alnum(after[:1]) or _ascii_alnum(after[1:2])):
            return False
        if kind == "url":
            return not (before[-1:].isascii() and before[-1:].isalpha())
        if kind == "bare":
            return not (
                before[-1:] == "/"
                or _ascii_alnum(before[-1:])
                or (before[-1:] in (".", "-", "_") and _ascii_alnum(before[:1]))
            )
        return not (
            before[-1:]
            and before[-1:] in before_chars
            and (_ascii_alnum(before[-1:]) or _ascii_alnum(before[:1]))
        )

    def in_lines(needle: str, kind: str) -> list[str]:
        """One place per line (its first hit standing alone, else its first hit inside a longer
        value), so that a line with the value several times, such as a web page's long paragraph,
        does not crowd out the value's other lines."""
        found: list[str] = []
        inside: list[str] = []
        inside_lines: set[int] = set()
        position = joined.find(needle) if needle else -1
        while position != -1 and len(found) < 3:
            line = bisect.bisect_right(starts, position) - 1
            offset = position - starts[line]
            if bounded(kind, position, len(needle)):
                found.append(place(line, offset, line, offset + len(needle)))
                if line + 1 >= len(starts):
                    break
                position = joined.find(needle, starts[line + 1])
                continue
            if len(inside) < 3 and line not in inside_lines:
                inside_lines.add(line)
                inside.append(f"(inside a longer value) {place(line, offset, line, offset + len(needle))}")
            position = joined.find(needle, position + 1)
        return found or inside

    def across(needle: str) -> list[str]:
        found: list[str] = []
        position = flat.find(needle) if needle else -1
        while position != -1 and len(found) < 3:
            first = bisect.bisect_right(flat_starts, position) - 1
            last = bisect.bisect_right(flat_starts, position + len(needle) - 1) - 1
            if last > first:
                start = position - flat_starts[first] + lost[first]
                end = position + len(needle) - flat_starts[last] + lost[last]
                found.append(f"(across a line break) {place(first, start, last, end)}")
            next_line = flat_starts[last + 1] if last + 1 < len(flat_starts) else len(flat)
            position = flat.find(needle, max(next_line, position + 1))
        return found

    contexts: dict[tuple[str, str], list[str]] = {}
    for kind, value in values:
        needle = value.lower()
        found = in_lines(needle, kind)
        inside = found if found and found[0].startswith("(inside") else []
        if not found or inside:
            found = across(needle)
        # Only a URL with a whole host can stand somewhere without the scheme a tool added: one whose
        # host is a bare word or number ("http://45", "https://api") was cut by a tool, and its places
        # inside the longer URL are what the rater needs.
        host = url_host(needle) if kind == "url" else ""
        whole_host = "." in host and _host_has_tld(host)
        if not found and kind == "url" and "://" in needle and whole_host:
            bare = needle.split("://", 1)[1]
            found = [
                f"(without its scheme) {c}" for c in in_lines(bare, "bare") if not c.startswith("(inside")
            ]
            if not found:
                found = [
                    f"(its host {host}) {c}" for c in in_lines(host, "domain") if not c.startswith("(inside")
                ]
        contexts[(kind, value)] = found or inside
    return contexts


def _outside_truth(
    name: str, results: dict[str, Any], truths: dict[str, dict[str, Any]], judgements: dict[str, Any]
) -> set[tuple[str, str, str]]:
    """(report, type, value) of every value that needs a judgement: extracted by a tool, or written
    with full-width or CJK-bracket forms in the body (for `uses`, see _writing_use); not in the ground
    truth, not masked or ambiguous, and not judged in ``judgements``."""
    by_id = {report["id"]: report for report in manifest(name)}
    items: set[tuple[str, str, str]] = set()
    for report in results["reports"]:
        truth = truths[report["id"]]
        lookup = Lookup(truth)
        judged = judgements.get(f"{name}/{report['id']}", {})
        body = body_fullwidth_values(truth, report.get("format", "pdf"), by_id[report["id"]])
        for kind, value in [(k, v) for out in report["outputs"].values() for k in TYPES for v in out[k]] + [
            *body
        ]:
            if classify(kind, value, lookup, judged) is None:
                items.add((report["id"], kind, value))
    return items


def command_judge(name: str, label: str) -> None:
    """Write a blinded sheet of the extracted values outside the ground truth (all tools together,
    without tool names, in a shuffled order), or with --import take the filled-in sheet into
    judgements.json."""
    results, truths = _load_results(name, label)
    path = judging_path(name, label)
    # What the tools found (not what `score` adds to the file, nor the date of the run): the sheet is
    # made from it.
    outputs_hash = object_sha256([[r["id"], r["outputs"]] for r in results["reports"]])
    judgements, _ = load_judgements()
    if "--import" in sys.argv:
        sheet = json.loads(path.read_text(encoding="utf-8"))
        if sheet.get("outputs_sha256") != outputs_hash:
            raise SystemExit("the tool outputs changed since the sheet was written; write it again")
        on_sheet = _outside_truth(name, results, truths, {})
        data = (
            json.loads(JUDGEMENTS.read_text(encoding="utf-8"))
            if JUDGEMENTS.exists()
            else {
                "about": "Judged by one person (the evaluator) on blinded sheets; each entry is "
                "[category, reason].",
                "categories": {
                    "a": "indicator named in the body of the report",
                    "b": "correct value, but not an indicator",
                    "c": "wrong value (cut, glued to other text, or not that type)",
                },
                "judgements": {},
            }
        )
        problems, taken = [], 0
        for item in sheet["items"]:
            category, reason = item.get("category", ""), item.get("reason", "")
            if not category:
                continue
            if (item.get("report"), item.get("type"), item.get("value")) not in on_sheet:
                problems.append(f"item {item['n']}: not a value the tools found outside the ground truth")
                continue
            if category not in CATEGORIES or not (
                isinstance(reason, str) and reason.strip() and "\n" not in reason
            ):
                problems.append(f"item {item['n']}: category a, b or c and a one-line reason")
                continue
            entry = data["judgements"].setdefault(f"{name}/{item['report']}", {}).setdefault(item["type"], {})
            if entry.get(item["value"], [category, reason]) != [category, reason]:
                problems.append(f"item {item['n']}: {item['value']!r} was judged differently before")
                continue
            entry[item["value"]] = [category, reason]
            taken += 1
        problems += judgement_problems(data)
        if problems:
            raise SystemExit("the sheet cannot be taken:\n    " + "\n    ".join(problems))
        JUDGEMENTS.write_text(dump_json(data) + "\n", encoding="utf-8")
        left = sum(1 for item in sheet["items"] if not item.get("category"))
        print(f"took {taken} judgements into {JUDGEMENTS.name}; {left} items on the sheet are not judged yet")
        return
    if path.exists():
        # A filled-in sheet is not written over before its judgements are taken.
        old_sheet = json.loads(path.read_text(encoding="utf-8"))
        pending = [
            item["n"]
            for item in old_sheet.get("items", [])
            if item.get("category")
            and judgements.get(f"{name}/{item['report']}", {}).get(item["type"], {}).get(item["value"])
            != [item.get("category"), item.get("reason")]
        ]
        if pending:
            raise SystemExit(
                f"{path} has {len(pending)} judged items not yet in {JUDGEMENTS.name}; take them with "
                "`judge --import` first, or move the sheet away"
            )
    items = _outside_truth(name, results, truths, judgements)
    by_id = {report["id"]: report for report in manifest(name)}
    contexts: dict[tuple[str, str, str], list[str]] = {}
    for report_id in sorted({item[0] for item in items}):
        text = load_text(name, by_id[report_id])[0]
        wanted = {(kind, value) for rid, kind, value in items if rid == report_id}
        for (kind, value), lines in _contexts(text, wanted).items():
            contexts[(report_id, kind, value)] = lines
    order = sorted(items)
    random.Random(int(outputs_hash, 16)).shuffle(order)  # noqa: S311 (an order, not a secret)
    sheet = {
        "set": name,
        "label": label,
        "outputs_sha256": outputs_hash,
        "help": "Judge each value from its context (one person, the evaluator): a = an indicator the report "
        "names outside the appendix, b = a correct value that is not an indicator, c = a wrong value; with "
        "a one-line reason. The tools that found each value are not shown. Then run `judge --import`.",
        "items": [
            {
                "n": number,
                "report": report_id,
                "type": kind,
                "value": value,
                "context": contexts.get((report_id, kind, value), []),
                "category": "",
                "reason": "",
            }
            for number, (report_id, kind, value) in enumerate(order, start=1)
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_json(sheet), "utf-8")
    print(f"{len(order)} values to judge in {path}")


# --------------------------------------------------------------------------- defang statistics

# How often each writing occurs, in the whole text and in the appendix of each report, counted with
# the forms ascii_reading reads ("all"; the full-width dot and at sign wherever they are, although
# they are read only after an ASCII letter or digit), and again only where the writing is part of a
# value the line rules find ("in values"). The second count leaves out "１．" numbering, dates and
# the full-width colon of body text where they are not part of a value, but still counts numbering
# read into a value ("１．evil.example.com") and values that are not indicators (version numbers,
# contact addresses); whether a report writes indicators so is decided by _writing_use. The
# styles cover exactly what ascii_reading reads, and a form is full-width or CJK when it has a
# non-ASCII character other than the spaces around it, as for the writing classes.
DEFANG_STYLES = {
    "ascii": ("[.]", "(.)", "[dot]", "hxxp", "[:]", "[@]", "[at]", "other ASCII ({.}, [/], [//])"),
    "fullwidth-cjk": (
        "【.】",
        "〔.〕",
        "［.］",
        "[。]",
        "（.）",
        "．",
        "＠",
        "：",
        "／",
        "－",
        "full-width letters and digits",
        "other full-width or CJK bracket forms",
    ),
}
_OTHER_ASCII = DEFANG_STYLES["ascii"][-1]
_OTHER_CJK = DEFANG_STYLES["fullwidth-cjk"][-1]
_STYLE_SINGLES = re.compile(
    "(?P<hxxp>(?<![A-Za-z])(?:[Hh][Xx][Xx][Pp][Ss]?|[Ff][Xx][Pp])" + _SCHEME_FOLLOWS + ")"
    "|(?P<colon>\uff1a)|(?P<slash>\uff0f)|(?P<hyphen>\uff0d)|(?P<dot>\uff0e)|(?P<at>\uff20)"
    "|(?P<alnum>[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]+)"
)
_SINGLE_STYLES = {
    "hxxp": "hxxp",
    "colon": "\uff1a",
    "slash": "\uff0f",
    "hyphen": "\uff0d",
    "dot": "\uff0e",
    "at": "\uff20",
    "alnum": "full-width letters and digits",
}
_BRACKET_STYLES = {"【": "【.】", "〔": "〔.〕", "［": "［.］", "（": "（.）"}


def _form_style(name: str, opening: str, form: str) -> str:
    """The style of a form that ascii_reading reads (its group name without the bracket number)."""
    ascii_form = form.replace(" ", "").replace("\u3000", "").isascii()
    if name in ("fwdot", "fwat"):
        return "\uff0e" if name == "fwdot" else "\uff20"
    if name == "dot":
        if ascii_form:
            return "[dot]" if "o" in form.lower() else {"[": "[.]", "(": "(.)"}.get(opening, _OTHER_ASCII)
        if "\u3002" in form and opening in "[(":
            return "[。]"
        return _BRACKET_STYLES.get(opening, _OTHER_CJK)
    if name == "at":
        return ("[at]" if "t" in form.lower() else "[@]") if ascii_form else "\uff20"
    if name == "fwscheme":
        return _OTHER_ASCII if ascii_form else "\uff1a" if "\uff1a" in form else "\uff0f"
    if name in ("scheme", "colon"):
        return "[:]" if ascii_form else "\uff1a"
    return _OTHER_ASCII if ascii_form else "\uff0f"  # slash, slashes


def defang_occurrences(text: str) -> list[tuple[int, int, str]]:
    """Each defang writing in ``text``: (start, end, style)."""
    found = []
    for match in _FORMS.finditer(text):
        group = match.lastgroup or ""
        name = group.rstrip("0123456789")
        opening = _BRACKETS[int(group[len(name) :])][0].replace("\\", "") if group != name else ""
        found.append((match.start(), match.end(), _form_style(name, opening, match.group(0))))
    form_starts = [start for start, _, _ in found]  # forms do not overlap one another
    for match in _STYLE_SINGLES.finditer(text):
        index = bisect.bisect_left(form_starts, match.end()) - 1
        if index >= 0 and found[index][1] > match.start():
            continue
        found.append((match.start(), match.end(), _SINGLE_STYLES[match.lastgroup or ""]))
    return sorted(found)


def _style_counts(
    occurrences: list[tuple[int, int, str]], spans: list[tuple[int, int]] | None
) -> dict[str, int]:
    """How often each style occurs; with ``spans``, only inside one of them."""
    counts = {style: 0 for styles in DEFANG_STYLES.values() for style in styles}
    starts: list[int] = []
    reach: list[int] = []  # the furthest end of the spans that start at or before each start
    for start, end in sorted(spans or []):
        starts.append(start)
        reach.append(max(end, reach[-1] if reach else end))
    for start, end, style in occurrences:
        if spans is not None:
            index = bisect.bisect_right(starts, start) - 1
            if index < 0 or reach[index] < end:
                continue
        counts[style] += 1
    return counts


def text_values(
    text: str, start: int, end: int, parts: list[dict[str, Any]], fmt: str
) -> list[tuple[str, str, str, str]]:
    """(type, value, writing class, writing) of each value the line rules find between ``start`` and
    ``end``."""
    found = []
    for line in text_lines(text, start, end, parts, fmt) if end > start else []:
        reading = read_line(line["raw"], line["format"])
        for entry in line_values(reading)["found"]:
            klass = reading.writing_class(entry["start"], entry["end"], url=entry["type"] == "url")
            raw_start, raw_end = reading.span(entry["start"], entry["end"])
            found.append((entry["type"], entry["value"], klass, reading.raw[raw_start:raw_end]))
    return found


def value_spans(
    text: str, start: int, end: int, parts: list[dict[str, Any]], fmt: str
) -> list[tuple[int, int]]:
    """Where in ``text`` the line rules find values between ``start`` and ``end``."""
    spans = []
    for line in text_lines(text, start, end, parts, fmt):
        reading = read_line(line["raw"], line["format"])
        for entry in line_values(reading)["found"]:
            raw_start, raw_end = reading.span(entry["start"], entry["end"])
            spans.append((line["start"] + raw_start, line["start"] + raw_end))
    return spans


def defang_path(name: str) -> Path:
    return HERE / f"defang-{name}.json"


def check_defang(name: str, texts: dict[str, str]) -> None:
    """Stop unless the set's defang statistic was made by this evaluate.py from each report's current
    text (``texts``: id to text SHA-256) and appendix markers, and is committed as it stands: the
    pre-registered counts must describe the same text and appendix as the reviewed ground truth and
    the results, and be fixed with the review before any tool runs."""
    path = defang_path(name)
    if not path.exists():
        raise SystemExit(f"{path.name} is missing; run `defang {name}` and commit it with the review")
    data = json.loads(path.read_text(encoding="utf-8"))
    recorded = {entry["id"]: entry for entry in data.get("reports", [])}
    stale = [
        report["id"]
        for report in manifest(name)
        if recorded.get(report["id"], {}).get("text_sha256") != texts.get(report["id"])
        or recorded.get(report["id"], {}).get("appendix_markers") != report["appendix"]
    ]
    if data.get("meta", {}).get("evaluate_sha256") != sha256(SCRIPT) or stale or len(recorded) != len(texts):
        raise SystemExit(
            f"{path.name} was made from another text, appendix markers or evaluate.py"
            + (f" ({', '.join(stale)})" if stale else "")
            + f"; run `defang {name}` again"
        )
    if committed_json(path) != data:
        raise SystemExit(
            f"{path.name} is not committed as it stands; `git add` it and commit it with the review"
        )


def command_defang(name: str) -> None:
    entries = []
    for report in manifest(name):
        text, conversion = load_text(name, report)
        fmt = source_format(report)
        start, end = appendix_span(text, report)
        occurrences = defang_occurrences(text)
        inside = [o for o in occurrences if start <= o[0] and o[1] <= end]
        whole_spans = value_spans(text, 0, len(text), conversion["parts"], fmt)
        appendix_spans = [s for s in whole_spans if start <= s[0] and s[1] <= end]
        entry = {
            "id": report["id"],
            "original_url": report["original_url"],
            "format": fmt,
            "text_sha256": conversion["text_sha256"],
            "appendix_markers": report["appendix"],
            "full_text": {
                "all": _style_counts(occurrences, None),
                "in_values": _style_counts(occurrences, whole_spans),
            },
            "appendix": {
                "all": _style_counts(inside, None),
                "in_values": _style_counts(inside, appendix_spans),
            },
        }
        entries.append(entry)
        used = {k: v for k, v in entry["full_text"]["in_values"].items() if v}
        print(f"{report['id']}: in values (whole text) {used or 'none'}")
    results = {
        "meta": {
            "set": name,
            "date": datetime.now(UTC).strftime("%Y-%m-%d"),
            "evaluate_sha256": sha256(SCRIPT),
            "styles": DEFANG_STYLES,
        },
        "reports": entries,
    }
    defang_path(name).write_text(dump_json(results) + "\n", encoding="utf-8")


def main() -> None:
    args = [arg for arg in sys.argv[1:] if not arg.startswith("--")]
    if len(args) < 2:
        raise SystemExit(__doc__)
    command, name, *rest = args
    commands: dict[str, Any] = {
        "text": command_text,
        "defang": command_defang,
        "truth": command_truth,
        "review": command_review,
    }
    labelled: dict[str, Any] = {"run": command_run, "judge": command_judge, "score": command_score}
    if command in commands:
        commands[command](name)
    elif command in labelled and rest:
        labelled[command](name, rest[0])
    else:
        raise SystemExit(f"unknown command {command!r}, or no label")


if __name__ == "__main__":
    main()
