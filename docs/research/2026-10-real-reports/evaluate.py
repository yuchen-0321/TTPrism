"""Evaluate TTPrism, iocextract and ioc-finder on public Chinese-language threat reports.

Run from the repository root in a virtual environment with the pinned tools and TTPrism:

    uv venv -p 3.11 /tmp/eval
    uv pip install -p /tmp/eval/bin/python -r docs/research/2026-10-real-reports/requirements.txt -e .
    E=docs/research/2026-10-real-reports/evaluate.py
    /tmp/eval/bin/python -I $E text zh-cn             # PDF -> text with pypdf, headers and footers included
    /tmp/eval/bin/python -I $E truth zh-cn [--show]   # ground truth from the appendix tables
    /tmp/eval/bin/python -I $E run zh-cn baseline     # run the tools on the same text
    /tmp/eval/bin/python -I $E score zh-cn baseline   # recall and precision

PDFs go in eval-data/<set>/pdf/<id>.pdf; eval-data/ is git-ignored, and so are the extracted text
and the ground-truth values. Only this script, the manifest, the judgements and the results (tool
outputs and counts) are committed.

Ground truth: the values in each report's IOC appendix, found with the plain line rules below and
corrected by hand as the manifest lists (with a reason for each); none of the evaluated tools is used
for it. Masked entries ("wiki.xxxx.com") and entries whose spelling the PDF leaves ambiguous are left
out, and so are tool outputs equal to them. A URL in the appendix adds its host to the domains.

Matching: domains lower-cased without a trailing dot; URLs refanged, with scheme and host
lower-cased, scored both as whole URLs and by host; hashes case-insensitive. Before domain recall,
each tool's domain output gets the hosts of its URL output. TTPrism runs with its defaults and raw
(no reserved-value or allowlist filtering); the comparison with the other tools uses raw.

Precision: an extracted value is right when it is in the ground truth; every other value has a
judgement in judgements.json (a: an indicator named in the body, b: a correct value that is not an
indicator, c: a wrong value). Strict precision counts a as right, lenient counts a and b.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DATA = ROOT / "eval-data"
MANIFEST = HERE / "manifest.json"
JUDGEMENTS = HERE / "judgements.json"
TYPES = ("url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256")
SETTINGS = {"ttprism-default": [], "ttprism-raw": ["--include-reserved", "--no-default-allowlist"]}


# --------------------------------------------------------------------------- normalisation


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
    return value.lower()


def url_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+|[0-9a-f:]+", host)) and any(c in host for c in ".:")


# --------------------------------------------------------------------------- inputs


def manifest(name: str) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = json.loads(MANIFEST.read_text(encoding="utf-8"))["sets"][name]
    return reports


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_path(name: str, report: dict[str, Any]) -> Path:
    return DATA / name / "text" / f"{report['id']}.txt"


def command_text(name: str) -> None:
    import pypdf  # type: ignore[import-not-found]

    for report in manifest(name):
        pdf = DATA / name / "pdf" / f"{report['id']}.pdf"
        reader = pypdf.PdfReader(str(pdf))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        out = text_path(name, report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"{report['id']}: {len(reader.pages)} pages, {len(text)} characters, pdf {sha256(pdf)[:16]}")


# --------------------------------------------------------------------------- ground truth

_MD5 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
_SHA1 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_SHA256 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
_URL = re.compile(r"(?i)\b(?:https?|hxxps?|ftp)(?:://|\[:\]//)[^\s（）()]+")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}(?:\.|\[\.\])){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?i)(?<![\w.\-@/])(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,24}(?![\w\-])")
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


def appendix(text: str, report: dict[str, Any]) -> str:
    """The appendix region: from the last occurrence of the start marker to the end marker."""
    starts = list(_marker(report["appendix"]["start"]).finditer(text))
    if not starts:
        raise SystemExit(f"{report['id']}: appendix start marker not found")
    start = starts[-1].start()
    end = _marker(report["appendix"]["end"]).search(text, start + 1)
    if end is None:
        raise SystemExit(f"{report['id']}: appendix end marker not found")
    return text[start : end.start()]


Values = dict[str, list[str]]


def ground_truth(text: str, report: dict[str, Any]) -> tuple[Values, Values, Values]:
    """Values of each type listed in the appendix, the masked ones, and the readings of ambiguous ones."""
    region = appendix(text, report)
    found: dict[str, set[str]] = {kind: set() for kind in TYPES}
    masked: dict[str, set[str]] = {kind: set() for kind in TYPES}
    for regex, kind in ((_SHA256, "sha256"), (_SHA1, "sha1"), (_MD5, "md5")):
        for value in regex.findall(region):
            found[kind].add(normalise(kind, value))
    urls = _URL.findall(region)
    rest = _URL.sub(" ", region)
    for value in urls:
        found["url"].add(normalise("url", value.rstrip(".,;")))
    for value in _IPV4.findall(rest):
        found["ipv4"].add(normalise("ipv4", value))
    for value in _DOMAIN.findall(rest):
        if not _NOT_DOMAINS.search(value) and not re.fullmatch(r"[\d.\[\]]+", value):
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


def command_truth(name: str) -> None:
    for report in manifest(name):
        text = text_path(name, report).read_text(encoding="utf-8")
        truth, masked, ambiguous = ground_truth(text, report)
        out = DATA / name / "truth" / f"{report['id']}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        data = {"truth": truth, "masked": masked, "ambiguous": ambiguous}
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


# --------------------------------------------------------------------------- tools


def run_ttprism(path: Path, flags: list[str]) -> dict[str, list[str]]:
    cmd = [sys.executable, "-m", "ttprism", "extract", "--input-format", "text", "-q", *flags, str(path)]
    data = json.loads(subprocess.run(cmd, capture_output=True, check=True, text=True).stdout)  # noqa: S603
    out: dict[str, set[str]] = {kind: set() for kind in TYPES}
    for ioc in data["iocs"]:
        if ioc["type"] in out:
            out[ioc["type"]].add(ioc["value"])
    return {k: sorted(v) for k, v in out.items()}


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
    git = ["git", "-C", str(ROOT)]
    commit = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True)  # noqa: S603
    dirty = subprocess.run([*git, "status", "--porcelain", "src"], capture_output=True, text=True)  # noqa: S603
    return commit.stdout.strip() + ("+uncommitted changes in src/" if dirty.stdout.strip() else "")


def results_path(name: str, label: str) -> Path:
    return HERE / f"results-{name}-{label}.json"


def load_truth(name: str, report_id: str) -> dict[str, Values]:
    data: dict[str, Values] = json.loads(
        (DATA / name / "truth" / f"{report_id}.json").read_text(encoding="utf-8")
    )
    return data


def command_run(name: str, label: str) -> None:
    meta = {
        "set": name,
        "label": label,
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "ttprism_commit": git_commit(),
        "versions": {
            p: importlib.metadata.version(p) for p in ("ttprism", "iocextract", "ioc-finder", "pypdf")
        },
        "python": sys.version.split()[0],
        "ttprism_settings": {k: " ".join(v) or "(defaults)" for k, v in SETTINGS.items()},
    }
    reports = []
    for report in manifest(name):
        text = text_path(name, report).read_text(encoding="utf-8")
        truth = load_truth(name, report["id"])
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "report.txt"
            copy.write_text(text, encoding="utf-8")
            raw = {tool: run_ttprism(copy, flags) for tool, flags in SETTINGS.items()}
        raw["iocextract"] = run_iocextract(text)
        raw["ioc-finder"] = run_ioc_finder(text)
        ambiguous = report.get("truth_corrections", {}).get("ambiguous", {})
        reports.append(
            {
                "id": report["id"],
                "original_url": report["original_url"],
                "pdf_sha256": sha256(DATA / name / "pdf" / f"{report['id']}.pdf"),
                "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "truth_counts": {k: len(v) for k, v in truth["truth"].items() if v},
                "left_out": {
                    "masked": {k: len(v) for k, v in truth["masked"].items()},
                    "ambiguous": {k: len(v) for k, v in ambiguous.items()},
                },
                "outputs": {tool: outputs(values) for tool, values in raw.items()},
            }
        )
        print(f"{report['id']}: done")
    results = {"meta": meta, "reports": reports}
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


def command_score(name: str, label: str) -> None:
    results = json.loads(results_path(name, label).read_text(encoding="utf-8"))
    judgements = (
        json.loads(JUDGEMENTS.read_text(encoding="utf-8"))["judgements"] if JUDGEMENTS.exists() else {}
    )
    unjudged: dict[str, dict[str, list[str]]] = {}
    totals: dict[str, dict[str, Any]] = {}
    lost: dict[str, Values] = {}
    for report in results["reports"]:
        data = load_truth(name, report["id"])
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
            total = totals.setdefault(tool, {"recall": {}, "precision": dict.fromkeys(counts, 0)})
            for kind, n in expected_counts(truth).items():
                h, t = total["recall"].get(kind, (0, 0))
                total["recall"][kind] = (h + len(hits[kind]), t + n)
            for category, value in counts.items():
                total["precision"][category] += value
        dropped = {
            kind: sorted(hits_by_tool["ttprism-raw"][kind] - hits_by_tool["ttprism-default"][kind])
            for kind in hits_by_tool["ttprism-raw"]
        }
        report["lost_by_default_filtering"] = {k: v for k, v in dropped.items() if v}
        if report["lost_by_default_filtering"]:
            lost[report["id"]] = report["lost_by_default_filtering"]
    for total in totals.values():
        p = total["precision"]
        n = p["truth"] + p["a"] + p["b"] + p["c"]
        p["judged_total"] = n
        p["strict"] = ratio(p["truth"] + p["a"], n)
        p["lenient"] = ratio(p["truth"] + p["a"] + p["b"], n)
        total["recall"] = {k: [h, t, ratio(h, t)] for k, (h, t) in sorted(total["recall"].items())}
    results["totals"] = totals
    results["lost_by_default_filtering"] = lost
    results["unjudged"] = unjudged
    results_path(name, label).write_text(
        json.dumps(results, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    for tool, total in totals.items():
        p = total["precision"]
        print(f"{tool:16s} precision strict {p['strict']} lenient {p['lenient']}  {p}")
        print(
            "                 recall " + "  ".join(f"{k} {h}/{t}" for k, (h, t, _) in total["recall"].items())
        )
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
