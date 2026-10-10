"""Evaluate TTPrism, iocextract and ioc-finder on public Chinese-language threat reports.

Run from the repository root in a virtual environment with the pinned tools and TTPrism:

    uv venv -p 3.11 /tmp/eval
    uv pip install -p /tmp/eval/bin/python -r docs/research/2026-10-real-reports/requirements.txt -e .
    E=docs/research/2026-10-real-reports/evaluate.py
    /tmp/eval/bin/python -I $E text zh-cn             # PDF or HTML -> text, one method per format
    /tmp/eval/bin/python -I $E truth zh-cn [--show]   # ground truth from the appendix tables
    /tmp/eval/bin/python -I $E run zh-cn baseline     # run the tools on the same text
    /tmp/eval/bin/python -I $E score zh-cn baseline   # recall and precision

Source files go in eval-data/<set>/<format>/<id>.<format> (format "pdf" unless the manifest says
"html"), attachments in eval-data/<set>/attachments/; eval-data/ is git-ignored, and so are the
extracted text and the ground-truth values. Only this script, the manifest, the judgements and the
results (tool outputs and counts) are committed. The manifest is checked first: an unknown or missing
field stops every command, and `text` stops while the set has no selection rule.

Text: PDFs are read with pypdf (page.extract_text() per page, headers and footers included). Web
pages are decoded strictly and laid out by HtmlText below (Python's html.parser, no CSS); see
decode_html and HtmlText for the rules. html.parser changed in Python's 2025 security releases, and
older releases lose page content silently, so `text` first converts a few canary pages and stops on
any other Python. When a report's indicators are only in an attachment, its text follows the page
text, and the conversion records where each part starts. Line breaks are LF throughout. `text`
prints, for each report and each web page in it, how it was decoded and converted, and where the
appendix starts and ends; never an indicator count. Each step records the SHA-256 of what it was
made from, and the next one stops if that changed: `run` if the text, its source, an attachment or
this script changed since `text`; `run` and `score` if the text, this script or the report's
appendix markers and corrections changed since `truth`.

Ground truth: the values in each report's IOC appendix, found with the plain line rules below and
corrected by hand as the manifest lists (with a reason for each); none of the evaluated tools is used
for it. The appendix runs from its start marker (which must occur once, or the manifest names the
occurrence) to the first end marker after it. In the parts of it that came from a PDF, every soft
hyphen is read as a hyphen first, since pypdf's U+00AD is a drawn hyphen (as TTPrism reads it); in
the parts that came from a web page, format characters (Cf) are deleted, since a soft hyphen there
is an invisible break hint. The line rules take only ASCII letters and digits as part of a name, so
a name right after Chinese text is found, and read [.] and (.) as dots. Masked entries
("wiki.xxxx.com") and entries whose spelling the source leaves ambiguous are left out, and so are
tool outputs equal to them. A URL in the appendix adds its host to the domains; an e-mail address
does not.

Matching: domains lower-cased without a trailing dot; URLs refanged, with scheme and host
lower-cased, scored both as whole URLs and by host; e-mail addresses refanged and lower-cased;
hashes case-insensitive. Before domain recall, each tool's domain output gets the hosts of its URL
output. TTPrism runs with its defaults and raw (no reserved-value or allowlist filtering); the
comparison with the other tools uses raw. Its warnings and suppressed counts are kept in the
results; in a web page, which has no line breaks of its own, every name TTPrism drops as a line-wrap
fragment is listed.

Precision: an extracted value is right when it is in the ground truth; every other value has a
judgement in judgements.json (a: an indicator named in the body, b: a correct value that is not an
indicator, c: a wrong value). Strict precision counts a as right, lenient counts a and b. Totals are
given for all reports and for each source format.
"""

from __future__ import annotations

import _markupbase
import codecs
import hashlib
import html.entities
import html.parser
import importlib.metadata
import json
import re
import subprocess
import sys
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DATA = ROOT / "eval-data"
MANIFEST = HERE / "manifest.json"
JUDGEMENTS = HERE / "judgements.json"
SCRIPT = Path(__file__).resolve()
TYPES = ("url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256")
SETTINGS = {"ttprism-default": [], "ttprism-raw": ["--include-reserved", "--no-default-allowlist"]}
# What the results depend on besides the eval-data files: a run records whether any of these had
# uncommitted changes.
PIPELINE_FILES = (ROOT / "src", ROOT / "pyproject.toml", SCRIPT, MANIFEST, HERE / "requirements.txt")


# --------------------------------------------------------------------------- normalisation

_EMAIL_AT = re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE)


def light_refang(value: str) -> str:
    """Undo the defang styles that the appendix tables use; plain replacements only."""
    for old, new in (("[.]", "."), ("[:]", ":"), ("[://]", "://"), ("(.)", ".")):
        value = value.replace(old, new)
    return re.sub(r"(?i)^hxxp", "http", value)


def normalise(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "url":
        value = light_refang(value)
        parts = urlsplit(value)
        if parts.scheme and parts.netloc:
            prefix = f"{parts.scheme}://{parts.netloc}"
            return value.replace(prefix, prefix.lower(), 1)
        return value
    if kind == "domain":
        return light_refang(value).lower().rstrip(".")
    if kind in ("ipv4", "ipv6"):
        return light_refang(value).lower()
    if kind == "email":
        return _EMAIL_AT.sub("@", light_refang(value)).lower()
    return value.lower()


def url_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def is_ip(host: str) -> bool:
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
    {"format", "source", "collection_path", "collection_blob", "attachments", "truth_corrections"}
    | _SOURCE_FIELDS[1],
)
_ATTACHMENT_FIELDS = ({"file"} | _SOURCE_FIELDS[0], _SOURCE_FIELDS[1])
_APPENDIX_FIELDS = ({"start", "end"}, {"start_occurrence", "start_occurrence_reason"})
_SAVED_FIELDS = ({"kind", "method", "tool"}, {"reason", "note"})
_CHARSET_OVERRIDE_FIELDS = ({"charset", "reason"}, set[str]())
_CORRECTION_FIELDS = (set[str](), {"add", "remove", "ambiguous", "notes"})
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z")


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
    """Problems with where and how a source file was obtained, and with its charset override."""
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
    if "charset_override" in entry:
        override = entry["charset_override"]
        problems += _fields(f"{where}.charset_override", override, _CHARSET_OVERRIDE_FIELDS)
        if isinstance(override, dict):
            problems += _text(f"{where}.charset_override.reason", override.get("reason"))
            if _codec(str(override.get("charset", ""))) is None:
                problems.append(f"{where}.charset_override: unknown charset {override.get('charset')!r}")
    return problems


def _report_problems(where: str, report: Any) -> list[str]:
    problems = _fields(where, report, _REPORT_FIELDS)
    if not isinstance(report, dict):
        return problems
    problems += _source_problems(where, report)
    if report.get("format", "pdf") not in ("pdf", "html"):
        problems.append(f"{where}: format must be 'pdf' or 'html'")
    appendix = report.get("appendix")
    problems += _fields(f"{where}.appendix", appendix, _APPENDIX_FIELDS)
    if isinstance(appendix, dict) and "start_occurrence" in appendix:
        occurrence = appendix["start_occurrence"]
        if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence < 1:
            problems.append(f"{where}.appendix: start_occurrence must be a positive integer")
        reason = appendix.get("start_occurrence_reason")
        problems += _text(f"{where}.appendix.start_occurrence_reason", reason)
    for index, attachment in enumerate(report.get("attachments", [])):
        problems += _fields(f"{where}.attachments[{index}]", attachment, _ATTACHMENT_FIELDS)
        if isinstance(attachment, dict):
            problems += _source_problems(f"{where}.attachments[{index}]", attachment)
    if "truth_corrections" in report:
        corrections = report["truth_corrections"]
        problems += _fields(f"{where}.truth_corrections", corrections, _CORRECTION_FIELDS)
        if isinstance(corrections, dict):
            for change in ("add", "remove", "ambiguous"):
                unknown = sorted(set(corrections.get(change, {})) - set(TYPES))
                problems += [f"{where}.truth_corrections.{change}: unknown type {k!r}" for k in unknown]
            if corrections.keys() & {"add", "remove", "ambiguous"} and not corrections.get("notes"):
                problems.append(f"{where}.truth_corrections: every correction needs a reason in notes")
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
    for name in sorted(data.get("skipped", {}).keys() - sets.keys()):
        problems.append(f"skipped: unknown set {name!r}")
    for name, reports in sets.items():
        if not isinstance(rules.get(name), str):
            problems.append(f"selection_rule: set {name!r} needs a selection rule (a string)")
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


def selection_rule(name: str) -> str:
    rule: str = load_manifest()["selection_rule"].get(name, "")
    return rule


# --------------------------------------------------------------------------- inputs


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def truth_rules_sha256(report: dict[str, Any]) -> str:
    """The SHA-256 of what the ground truth takes from the manifest: the appendix markers and the
    hand corrections."""
    rules = {key: report.get(key) for key in ("appendix", "truth_corrections")}
    return hashlib.sha256(json.dumps(rules, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


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


def pdf_text(path: Path) -> tuple[str, int]:
    import pypdf  # type: ignore[import-not-found]

    reader = pypdf.PdfReader(str(path))
    return "\n".join(page.extract_text() or "" for page in reader.pages), len(reader.pages)


def read_text(path: Path) -> str:
    """A text file exactly as written (no newline translation)."""
    return path.read_bytes().decode("utf-8")


def attachment_format(path: Path) -> str:
    suffix = path.suffix.lower()
    return "pdf" if suffix == ".pdf" else "html" if suffix in (".html", ".htm") else "text"


def charset_override(entry: dict[str, Any]) -> str | None:
    override = entry.get("charset_override")
    return None if override is None else str(override["charset"])


def convert(
    path: Path, fmt: str, http_charset: str | None = None, override: str | None = None
) -> tuple[str, dict[str, Any]]:
    """The text of one source file (a PDF with pypdf, a web page with HtmlText, anything else as UTF-8
    text) and how it was made. Line breaks become LF, since pypdf can give CR and so can &#13; in a
    <pre>; the text that is hashed is then the text that every tool reads."""
    info: dict[str, Any] = {"format": fmt, "sha256": sha256(path)}
    if fmt == "pdf":
        text, info["pages"] = pdf_text(path)
        info["method"] = PDF_METHOD.format(version=importlib.metadata.version("pypdf"))
    elif fmt == "html":
        page, info["decoding"] = decode_html(path.read_bytes(), http_charset, override)
        text, counts = html_to_text(page)
        info["method"] = HTML_METHOD
        info.update(counts)
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
        text, source_info = convert(
            source_path(name, report), fmt, report.get("http_charset"), charset_override(report)
        )
        info: dict[str, Any] = {"format": fmt, "source_sha256": source_info.pop("sha256")}
        info["python"] = parser["python"]
        info["html_parser_sha256"] = parser["sha256"]
        info["evaluate_sha256"] = sha256(SCRIPT)
        if "charset_override" in report:
            info["charset_override"] = report["charset_override"]
        info.update(source_info)
        # Where each part of the text came from, so that only web-page text is treated as such.
        parts = [{"format": fmt, "start": 0, "end": len(text)}]
        for attachment in report.get("attachments", []):
            path = DATA / name / "attachments" / attachment["file"]
            extra, attachment_info = convert(
                path, attachment_format(path), attachment.get("http_charset"), charset_override(attachment)
            )
            if "charset_override" in attachment:
                attachment_info["charset_override"] = attachment["charset_override"]
            text += "\n\n"
            parts.append(
                {"format": attachment_info["format"], "start": len(text), "end": len(text) + len(extra)}
            )
            text += extra
            info.setdefault("attachments", []).append({"file": attachment["file"], **attachment_info})
        info["parts"] = parts
        info["text_sha256"] = text_sha256(text)
        out = text_path(name, report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(text.encode("utf-8"))
        conversion_path(name, report).write_text(json.dumps(info, ensure_ascii=False, indent=1), "utf-8")
        print(f"{report['id']}: {fmt}, {len(text)} characters")
        print(f"    source sha256 {info['source_sha256']}")
        print(f"    text sha256   {info['text_sha256']}")
        if fmt == "html":
            print_html_conversion("    ", info)
        for attachment in info.get("attachments", []):
            print(
                f"    attachment {attachment['file']} ({attachment['format']}) sha256 {attachment['sha256']}"
            )
            if attachment["format"] == "html":
                print_html_conversion("        ", attachment)
        describe_appendix(text, report)


def print_html_conversion(indent: str, info: dict[str, Any]) -> None:
    """Print how a web page was decoded and what its conversion counted (never an indicator count)."""
    decoding = info["decoding"]
    print(f"{indent}encoding {decoding['encoding']} ({decoding['chosen_by']})")
    print(f"{indent}declared {decoding['declared']}")
    if decoding["mismatch"]:
        print(f"{indent}DECLARED CHARSET DISAGREES: {'; '.join(decoding['mismatch'])}")
    print(
        f"{indent}U+FFFD: {info['replacement_characters']}, hidden characters kept: "
        f"{info['hidden_characters_kept']}, soft hyphens deleted: {info['soft_hyphens_deleted']}"
    )
    if info["unclosed_dropped_elements"]:
        unclosed = info["unclosed_dropped_elements"]
        print(f"{indent}UNCLOSED DROPPED ELEMENTS (the text after them is lost): {unclosed}")


def check_unchanged(name: str, report: dict[str, Any], conversion: dict[str, Any], text: str) -> None:
    """Stop if the text, its source, its attachments or this script changed since `text`."""
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
    if conversion.get("evaluate_sha256") != sha256(SCRIPT):
        raise SystemExit(f"{report['id']}: another version of evaluate.py made the text; run `text` again")


def describe_appendix(text: str, report: dict[str, Any]) -> None:
    """Print how often the appendix start marker occurs and the first and last line of the appendix."""
    count = len(list(_marker(report["appendix"]["start"]).finditer(text)))
    print(f"    appendix start marker found {count} time(s)")
    try:
        region = appendix(text, report)
    except SystemExit as exc:
        print(f"    APPENDIX NOT FOUND: {exc}")
        return
    lines = [line for line in region.splitlines() if line.strip()]
    print(f"    appendix first line: {lines[0]!r}")
    print(f"    appendix last line:  {lines[-1]!r}")


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
# its reason) replaces all of them, for a page that this order would decode wrongly.
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
        self.keep_cdata = False  # an end tag that html.parser will clear raw-text mode for is script data
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

    def clear_cdata_mode(self) -> None:
        if self.keep_cdata:
            self.keep_cdata = False  # the "</script>" was script data
            return
        super().clear_cdata_mode()

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
        if tag == "script" and self.cdata_elem == "script" and self.script_state == _SCRIPT_DOUBLE_ESCAPED:
            self.script_state = _SCRIPT_ESCAPED
            self.keep_cdata = True
            return
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


# --------------------------------------------------------------------------- ground truth

# The line rules. Only ASCII letters and digits (and, in hashes, only hex digits) count as part of a
# value, so a value right after Chinese text is found; re.ASCII also keeps IGNORECASE from matching
# the non-ASCII letters that fold to ASCII ones (U+017F, U+212A). A URL ends at white space (any
# Unicode white space, listed because re.ASCII would narrow \s) or a parenthesis, except one of "(.)".
_SPACE = "".join(re.escape(chr(code)) for code in range(0x3001) if chr(code).isspace())
_DOT = r"(?:\.|\[\.\]|\(\.\))"
_MD5 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
_SHA1 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_SHA256 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
_URL = re.compile(
    rf"(?<![A-Za-z0-9_])(?:https?|hxxps?|ftp)(?:://|\[:\]//)(?:[^{_SPACE}（）()]|\(\.\))+",
    re.ASCII | re.IGNORECASE,
)
_EMAIL = re.compile(
    rf"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+(?:@|\[@\]|\(@\)|\[at\]|\(at\))"
    rf"(?:[A-Za-z0-9\-]+{_DOT})+[A-Za-z]{{2,24}}(?![A-Za-z0-9_\-])",
    re.ASCII | re.IGNORECASE,
)
_IPV4 = re.compile(rf"(?<![0-9.])(?:[0-9]{{1,3}}{_DOT}){{3}}[0-9]{{1,3}}(?![0-9.])", re.ASCII)
_DOMAIN = re.compile(
    rf"(?<![A-Za-z0-9_.\-@/])(?:[A-Za-z0-9\-]+{_DOT})+[A-Za-z]{{2,24}}(?![A-Za-z0-9_\-])",
    re.ASCII | re.IGNORECASE,
)
_NOT_DOMAINS = re.compile(
    r"(?i)\.(?:exe|dll|doc|docx|xls|xlsx|pdf|pdb|rar|zip|7z|tmp|dat|lnk|bin|apk|jar|ps1|bat|vbs|js)$"
)
# Masked values: an asterisk, or a run of three or more x standing alone ("wiki.xxxx.com", "?p=xxx&").
_MASKED = re.compile(r"\*|(?<![a-z0-9])x{3,}(?![a-z0-9])", re.IGNORECASE)
# A masked host in the appendix: ASCII name characters around the mask, ending in a dot and letters.
_MASKED_TOKEN = re.compile(
    r"(?<![\w.\-])[\w*.\-]*(?:\*\*|xxx)[\w*.\-]*\.[a-z]{2,24}(?![\w\-])", re.ASCII | re.IGNORECASE
)


def _marker(marker: str) -> re.Pattern[str]:
    """A heading as a regex in which any run of white space (pypdf gives NBSP, too) matches any other."""
    pattern = r"\s+".join(re.escape(part) for part in marker.split())
    return re.compile(pattern + (r"\s" if marker[-1].isspace() else ""))


def appendix_span(text: str, report: dict[str, Any]) -> tuple[int, int]:
    """The appendix region: from the start marker to the first end marker after it. The start marker
    must occur once, unless the manifest says which occurrence (1-based) to use; a page whose side bar
    or table of contents repeats the heading would otherwise be cut at the wrong place."""
    starts = list(_marker(report["appendix"]["start"]).finditer(text))
    occurrence = report["appendix"].get("start_occurrence")
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
    end = _marker(report["appendix"]["end"]).search(text, start + 1)
    if end is None:
        raise SystemExit(f"{report['id']}: appendix end marker not found")
    return start, end.start()


def appendix_region(text: str, report: dict[str, Any], parts: list[dict[str, Any]] | None = None) -> str:
    """The appendix, read by where each part came from: in text from a PDF every soft hyphen is a
    hyphen (pypdf's U+00AD is a drawn hyphen), and from text from a web page format characters (Cf)
    are deleted (a soft hyphen there is an invisible break hint); other text is kept as it is.
    ``parts`` says where each part of the text came from; without it, all of it is the report's format."""
    start, end = appendix_span(text, report)
    if parts is None:
        parts = [{"format": source_format(report), "start": 0, "end": len(text)}]
    pieces = []
    position = start
    for part in sorted(parts, key=lambda p: int(p["start"])):
        first, last = max(int(part["start"]), position), min(int(part["end"]), end)
        if first >= last:
            continue
        pieces.append(text[position:first])  # the "\n\n" between parts
        piece = text[first:last]
        if part["format"] == "pdf":
            piece = piece.replace("\u00ad", "-")
        elif part["format"] == "html":
            piece = "".join(char for char in piece if unicodedata.category(char) != "Cf")
        pieces.append(piece)
        position = last
    pieces.append(text[position:end])
    return "".join(pieces)


def appendix(text: str, report: dict[str, Any]) -> str:
    start, end = appendix_span(text, report)
    return text[start:end]


Values = dict[str, list[str]]


def ground_truth(
    text: str, report: dict[str, Any], parts: list[dict[str, Any]] | None = None
) -> tuple[Values, Values, Values]:
    """Values of each type listed in the appendix, the masked ones, and the readings of ambiguous ones."""
    region = appendix_region(text, report, parts)
    found: dict[str, set[str]] = {kind: set() for kind in TYPES}
    masked: dict[str, set[str]] = {kind: set() for kind in TYPES}
    for regex, kind in ((_SHA256, "sha256"), (_SHA1, "sha1"), (_MD5, "md5")):
        for value in regex.findall(region):
            found[kind].add(normalise(kind, value))
    for value in _URL.findall(region):
        found["url"].add(normalise("url", value.rstrip(".,;")))
    rest = _URL.sub(" ", region)
    for value in _EMAIL.findall(rest):
        found["email"].add(normalise("email", value))
    rest = _EMAIL.sub(" ", rest)  # an address's domain is not listed as a domain of its own
    for value in _IPV4.findall(rest):
        found["ipv4"].add(normalise("ipv4", value))
    for value in _DOMAIN.findall(rest):
        if not _NOT_DOMAINS.search(value) and not re.fullmatch(r"[\d.\[\]()]+", value):
            found["domain"].add(normalise("domain", value))
    for masked_value in _MASKED_TOKEN.findall(region):
        if not _NOT_DOMAINS.search(masked_value):
            masked["domain"].add(masked_value.lower())
    corrections = report.get("truth_corrections", {})
    for kind, values in corrections.get("add", {}).items():
        found[kind].update(normalise(kind, v) for v in values)
    for kind, values in corrections.get("remove", {}).items():
        found[kind].difference_update(normalise(kind, v) for v in values)
    for kind in TYPES:
        for value in list(found[kind]):
            if _MASKED.search(value):
                found[kind].discard(value)
                masked[kind].add(value)
    # A URL in the appendix makes its host an indicator too (the tools get the same treatment).
    for url in found["url"]:
        host = url_host(url)
        if host and not is_ip(host):
            found["domain"].add(host)
    ambiguous: dict[str, set[str]] = {}
    for kind, entries in corrections.get("ambiguous", {}).items():
        readings = {normalise(kind, v) for entry in entries for v in entry}
        ambiguous[kind] = readings
        found[kind] -= readings
    return (
        {k: sorted(v) for k, v in found.items()},
        {k: sorted(v) for k, v in masked.items() if v},
        {k: sorted(v) for k, v in ambiguous.items() if v},
    )


def truth_path(name: str, report_id: str) -> Path:
    return DATA / name / "truth" / f"{report_id}.json"


def command_truth(name: str) -> None:
    for report in manifest(name):
        text = read_text(text_path(name, report))
        conversion = conversion_path(name, report)
        parts = (
            json.loads(conversion.read_text(encoding="utf-8")).get("parts") if conversion.exists() else None
        )
        truth, masked, ambiguous = ground_truth(text, report, parts)
        out = truth_path(name, report["id"])
        out.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "text_sha256": text_sha256(text),
            "evaluate_sha256": sha256(SCRIPT),
            "truth_rules_sha256": truth_rules_sha256(report),
            "truth": truth,
            "masked": masked,
            "ambiguous": ambiguous,
        }
        out.write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
        counts = {k: len(v) for k, v in truth.items() if v}
        print(
            f"{report['id']}: {counts}  masked: {masked}  ambiguous entries: "
            f"{ {k: len(v) for k, v in report.get('truth_corrections', {}).get('ambiguous', {}).items()} }"
        )
        if "--show" in sys.argv:
            for kind, values in truth.items():
                for value in values:
                    print(f"    {kind:7s} {value}")


def load_truth(name: str, report: dict[str, Any], text_hash: str) -> dict[str, Any]:
    """The ground truth of ``report``; stop unless it was built from the text with SHA-256
    ``text_hash``, by this evaluate.py, with the report's current appendix markers and corrections."""
    data: dict[str, Any] = json.loads(truth_path(name, report["id"]).read_text(encoding="utf-8"))
    changed = [
        what
        for what, recorded, current in (
            ("the text", data.get("text_sha256"), text_hash),
            ("evaluate.py", data.get("evaluate_sha256"), sha256(SCRIPT)),
            (
                "its appendix markers or corrections",
                data.get("truth_rules_sha256"),
                truth_rules_sha256(report),
            ),
        )
        if recorded != current
    ]
    if changed:
        raise SystemExit(
            f"{report['id']}: the ground truth was built from another version of {', '.join(changed)}; "
            "run `truth` again"
        )
    return data


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


def outputs(raw: dict[str, list[str]]) -> dict[str, list[str]]:
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


def results_path(name: str, label: str) -> Path:
    return HERE / f"results-{name}-{label}.json"


def command_run(name: str, label: str) -> None:
    reports = manifest(name)
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
            p: importlib.metadata.version(p) for p in ("ttprism", "iocextract", "ioc-finder", "pypdf")
        },
        "python": parser["python"],
        "html_parser_sha256": parser["sha256"],
        "evaluate_sha256": sha256(SCRIPT),
        "installed": installed_distributions(),
        "ttprism_settings": {k: " ".join(v) or "(defaults)" for k, v in SETTINGS.items()},
    }
    entries = []
    for report in reports:
        fmt = source_format(report)
        text = read_text(text_path(name, report))
        conversion = json.loads(conversion_path(name, report).read_text(encoding="utf-8"))
        check_unchanged(name, report, conversion, text)
        text_hash = conversion["text_sha256"]
        truth = load_truth(name, report, text_hash)
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "report.txt"
            copy.write_bytes(text.encode("utf-8"))
            runs = {tool: run_ttprism(copy, flags) for tool, flags in SETTINGS.items()}
        raw = {tool: run["values"] for tool, run in runs.items()}
        raw["iocextract"] = run_iocextract(text)
        raw["ioc-finder"] = run_ioc_finder(text)
        ambiguous = report.get("truth_corrections", {}).get("ambiguous", {})
        entry: dict[str, Any] = {
            "id": report["id"],
            "original_url": report["original_url"],
            "format": fmt,
            "source_sha256": conversion["source_sha256"],
            "text_sha256": text_hash,
            "conversion": {k: v for k, v in conversion.items() if k not in ("source_sha256", "text_sha256")},
            "truth_counts": {k: len(v) for k, v in truth["truth"].items() if v},
            "left_out": {
                "masked": {k: len(v) for k, v in truth["masked"].items()},
                "ambiguous": {k: len(v) for k, v in ambiguous.items()},
            },
            "ttprism": {
                tool: {"warnings": run["warnings"], "suppressed": run["suppressed"]}
                for tool, run in runs.items()
            },
            "outputs": {tool: outputs(values) for tool, values in raw.items()},
        }
        print(f"{report['id']}: done")
        if fmt == "html":
            fragments = line_wrap_fragments(text)
            entry["line_wrap_fragments"] = fragments
            counted = runs["ttprism-raw"]["suppressed"].get("line_wrap_fragment", 0)
            print(f"    line-wrap fragments dropped by TTPrism: {counted}")
            for fragment in fragments:
                print(
                    f"    {fragment['type']} {fragment['fragment']!r} after {fragment['line_before_ends']!r}"
                )
            if len(fragments) != counted:
                print(f"    LISTED {len(fragments)} FRAGMENTS, BUT TTPRISM COUNTED {counted}")
        entries.append(entry)
    results = {"meta": meta, "reports": entries}
    results_path(name, label).write_text(
        json.dumps(results, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )


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
        hits["url-host"] = {url_host(u) for u in truth["url"]} & {url_host(u) for u in out["url"]}
    return hits


def expected_counts(truth: Values) -> dict[str, int]:
    counts = {kind: len(truth[kind]) for kind in TYPES if truth.get(kind)}
    if truth.get("url"):
        counts["url-host"] = len({url_host(u) for u in truth["url"]})
    return counts


def classify(kind: str, value: str, truth: Values, ambiguous: set[str], judged: dict[str, Any]) -> str | None:
    """'truth', 'masked', 'ambiguous', a judgement category, or None when the value still needs one."""
    if value in truth.get(kind, []):
        return "truth"
    if _MASKED.search(value):
        return "masked"  # left out like masked ground-truth entries: the real value is not in the text
    # The address of an appendix URL counts as listed, as the host of a URL does for domains.
    if kind in ("ipv4", "ipv6") and value in {url_host(u) for u in truth.get("url", [])}:
        return "truth"
    if value in ambiguous:
        return "ambiguous"
    if value in judged.get(kind, {}):
        category: str = judged[kind][value][0]
        return category
    return None


def ratio(hit: int, total: int) -> float | None:
    return round(hit / total, 4) if total else None


def totals_of(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Recall and precision of each tool over ``reports`` (scored by command_score)."""
    totals: dict[str, dict[str, Any]] = {}
    for report in reports:
        for tool, recall in report["recall"].items():
            total = totals.setdefault(
                tool, {"recall": {}, "precision": dict.fromkeys(report["precision"][tool], 0)}
            )
            for kind, (hit, expected) in recall.items():
                h, t = total["recall"].get(kind, (0, 0))
                total["recall"][kind] = (h + hit, t + expected)
            for category, value in report["precision"][tool].items():
                total["precision"][category] += value
    for total in totals.values():
        p = total["precision"]
        n = p["truth"] + p["a"] + p["b"] + p["c"]
        p["judged_total"] = n
        p["strict"] = ratio(p["truth"] + p["a"], n)
        p["lenient"] = ratio(p["truth"] + p["a"] + p["b"], n)
        total["recall"] = {k: [h, t, ratio(h, t)] for k, (h, t) in sorted(total["recall"].items())}
    return totals


def print_totals(totals: dict[str, dict[str, Any]]) -> None:
    for tool, total in totals.items():
        p = total["precision"]
        print(f"{tool:16s} precision strict {p['strict']} lenient {p['lenient']}  {p}")
        print(
            "                 recall " + "  ".join(f"{k} {h}/{t}" for k, (h, t, _) in total["recall"].items())
        )


def command_score(name: str, label: str) -> None:
    by_id = {report["id"]: report for report in manifest(name)}
    results = json.loads(results_path(name, label).read_text(encoding="utf-8"))
    judgements = (
        json.loads(JUDGEMENTS.read_text(encoding="utf-8"))["judgements"] if JUDGEMENTS.exists() else {}
    )
    if sorted(by_id) != sorted(report["id"] for report in results["reports"]):
        raise SystemExit(f"the results do not cover the reports of set {name!r} in the manifest; run again")
    unjudged: dict[str, dict[str, list[str]]] = {}
    lost: dict[str, Values] = {}
    for report in results["reports"]:
        data = load_truth(name, by_id[report["id"]], report["text_sha256"])
        truth = data["truth"]
        ambiguous = {v for values in data["ambiguous"].values() for v in values}
        key = f"{name}/{report['id']}"
        report["recall"], report["precision"] = {}, {}
        hits_by_tool = {}
        for tool, out in report["outputs"].items():
            hits = hits_by_tool[tool] = found(truth, out)
            report["recall"][tool] = {k: [len(hits[k]), n] for k, n in expected_counts(truth).items()}
            counts = dict.fromkeys(("truth", "a", "b", "c", "masked", "ambiguous"), 0)
            for kind in TYPES:
                for value in out[kind]:
                    category = classify(kind, value, truth, ambiguous, judgements.get(key, {}))
                    if category is None:
                        unjudged.setdefault(key, {}).setdefault(kind, []).append(value)
                    else:
                        counts[category] += 1
            report["precision"][tool] = counts
        dropped = {
            kind: sorted(hits_by_tool["ttprism-raw"][kind] - hits_by_tool["ttprism-default"][kind])
            for kind in hits_by_tool["ttprism-raw"]
        }
        report["lost_by_default_filtering"] = {k: v for k, v in dropped.items() if v}
        if report["lost_by_default_filtering"]:
            lost[report["id"]] = report["lost_by_default_filtering"]
    formats = sorted({report.get("format", "pdf") for report in results["reports"]})
    results["totals"] = totals_of(results["reports"])
    results["totals_by_format"] = {
        fmt: totals_of([r for r in results["reports"] if r.get("format", "pdf") == fmt]) for fmt in formats
    }
    results["lost_by_default_filtering"] = lost
    results["unjudged"] = unjudged
    results_path(name, label).write_text(
        json.dumps(results, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print_totals(results["totals"])
    if len(formats) > 1:
        for fmt in formats:
            print(f"--- {fmt} reports only")
            print_totals(results["totals_by_format"][fmt])
    for report in results["reports"]:
        for fragment in report.get("line_wrap_fragments", []):
            print(f"{report['id']}: line-wrap fragment {fragment['type']} {fragment['fragment']!r}")
    print(f"lost by default filtering: {lost}")
    if unjudged:
        count = sum(len(v) for r in unjudged.values() for v in r.values())
        print(f"{count} extracted values still need a judgement (see 'unjudged' in the results file)")


def main() -> None:
    command, name, *rest = sys.argv[1:]
    if command == "text":
        command_text(name)
    elif command == "truth":
        command_truth(name)
    elif command == "run":
        command_run(name, rest[0])
    elif command == "score":
        command_score(name, rest[0])
    else:
        raise SystemExit(f"unknown command {command!r}")


if __name__ == "__main__":
    main()
