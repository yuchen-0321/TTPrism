"""High-level pipeline: input -> IOCs + ATT&CK techniques -> AnalysisResult."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ttprism.allowlist import Allowlist, url_host
from ttprism.attack import TECHNIQUE_ID_RE, AttackCatalog, RuleSet, TechniqueAccumulator
from ttprism.cape import looks_like_cape, parse_cape
from ttprism.extract import extract_into, find_technique_ids, host_address, is_reserved_domain, is_reserved_ip
from ttprism.inputs import (
    DEFAULT_MAX_BYTES,
    InputError,
    decode_text,
    load_json,
    printable,
    read_bytes,
)
from ttprism.models import IOC, AnalysisResult, IOCCollector, IOCType, sort_iocs
from ttprism.refang import cut_between_values, refang, refang_soft_hyphens_as_hints


@dataclass
class AnalysisOptions:
    allowlist: Allowlist = field(default_factory=Allowlist.default)
    rules: RuleSet = field(default_factory=RuleSet.default)
    catalog: AttackCatalog = field(default_factory=AttackCatalog.default)
    include_reserved: bool = False
    """Keep private, loopback and documentation addresses and example/test domains."""


def _is_reserved(ioc_type: IOCType, value: str) -> bool:
    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return is_reserved_ip(value)
    if ioc_type == IOCType.DOMAIN:
        return is_reserved_domain(value)
    if ioc_type == IOCType.EMAIL:
        return is_reserved_domain(value.rpartition("@")[2])
    if ioc_type == IOCType.URL:
        host = url_host(value)
        if host == "localhost":
            return True
        address = host_address(host)
        return is_reserved_ip(address) if address is not None else is_reserved_domain(host)
    return False


def _filter(collector: IOCCollector, options: AnalysisOptions, stats: Counter[str]) -> list[IOC]:
    kept = []
    for ioc_type, value, sources in collector:
        if not options.include_reserved and _is_reserved(ioc_type, value):
            stats["reserved"] += 1
        elif options.allowlist.matches(ioc_type, value):
            stats["allowlisted"] += 1
        else:
            kept.append(IOC(ioc_type, value, tuple(sorted(sources))))
    return sort_iocs(kept)


def _finish(
    input_format: str,
    collector: IOCCollector,
    techniques: TechniqueAccumulator,
    options: AnalysisOptions,
    stats: Counter[str],
    warnings: list[str],
) -> AnalysisResult:
    iocs = _filter(collector, options, stats)
    if techniques.unknown:
        unknown = sorted(techniques.unknown)
        ids = ", ".join(unknown[:20]) + (f" and {len(unknown) - 20} more" if len(unknown) > 20 else "")
        warnings.append(f"technique IDs not in ATT&CK {options.catalog.version} were ignored: {ids}")
    return AnalysisResult(
        input_format=input_format,
        iocs=iocs,
        techniques=techniques.results(),
        attack_version=options.catalog.version,
        suppressed={k: v for k, v in sorted(stats.items()) if v},
        warnings=[*options.rules.warnings, *warnings],
    )


def analyze_text(text: str, options: AnalysisOptions | None = None) -> AnalysisResult:
    """Extract IOCs and ATT&CK technique IDs from a report (plain text or Markdown)."""
    options = options or AnalysisOptions()
    stats: Counter[str] = Counter()
    refanged = refang(text)
    collector = IOCCollector()
    extract_into(collector, refanged, "text", stats)
    techniques = TechniqueAccumulator(options.catalog)
    for technique_id in find_technique_ids(refanged):
        techniques.add_reported(technique_id, f"named in text: {technique_id}")
    result = _finish("text", collector, techniques, options, stats, [])
    if "\u00ad" in text:
        result.warnings.extend(_soft_hyphen_warning(text, collector, result.iocs, options))
    return result


# The soft-hyphen check extracts the text a second time; it reads at most this much of it.
MAX_SOFT_HYPHEN_CHECK_CHARS = 8 * 1024 * 1024


# A part of a long text is cut within this many characters before MAX_SOFT_HYPHEN_CHECK_CHARS.
_CUT_WINDOW = 65536


def _checked_part(text: str) -> str:
    """At most MAX_SOFT_HYPHEN_CHECK_CHARS characters from the start of ``text``, cut where no value
    can go on (see :func:`~ttprism.refang.cut_between_values`) within the last _CUT_WINDOW characters
    before the limit, so that none is cut in two and reported in part as if the soft hyphens had
    changed it. Without such a place, the text is cut at the limit."""
    limit = MAX_SOFT_HYPHEN_CHECK_CHARS
    cut = cut_between_values(text, limit, _CUT_WINDOW)
    return text[:limit] if cut is None else cut


def _soft_hyphen_warning(
    text: str, collector: IOCCollector, iocs: list[IOC], options: AnalysisOptions
) -> list[str]:
    """A warning when deleting every soft hyphen, as the break hints of a web page are, would change
    the values reported, where refang reads them as hyphens. At most the first
    MAX_SOFT_HYPHEN_CHECK_CHARS characters are extracted a second time in that reading; the count is
    the larger of the values it would report besides and, if that was the whole text, the reported
    values it lacks. Lookups go to ``collector``, so the cost does not grow with the rest of the text.
    """
    checked = _checked_part(text)
    hinted = refang_soft_hyphens_as_hints(checked)
    if hinted is None:
        return []
    other = IOCCollector()
    extract_into(other, hinted, "text")
    count = sum(1 for ioc in _filter(other, options, Counter()) if (ioc.type, ioc.value) not in collector)
    truncated = len(checked) < len(text)
    if not truncated:
        count = max(count, sum(1 for ioc in iocs if (ioc.type, ioc.value) not in other))
    if not count:
        return []
    where = f" (from the first {len(checked):,} characters)" if truncated else ""
    return [
        f"{count} extracted value(s){where} would differ if the soft hyphens (U+00AD) were deleted instead "
        "of read as hyphens. Text taken from a PDF has a soft hyphen where the page shows a hyphen; text "
        "copied from a web page (&shy;) has them as invisible break hints, which would make KB-Auto read "
        "KBAuto."
    ]


def analyze_cape(report: Mapping[str, Any], options: AnalysisOptions | None = None) -> AnalysisResult:
    """Extract IOCs from a CAPE report and map its behaviour to ATT&CK."""
    options = options or AnalysisOptions()
    parsed = parse_cape(report)
    stats = parsed.stats
    techniques = TechniqueAccumulator(options.catalog)
    for technique_id, signature in parsed.reported_ttps:
        if TECHNIQUE_ID_RE.fullmatch(technique_id):
            techniques.add_reported(technique_id, f"CAPE signature {signature}: {technique_id}")
        else:
            stats["non_technique_ttp"] += 1
    for rule, evidence in options.rules.evaluate(parsed.behavior):
        techniques.add_rule(rule, evidence)
    return _finish("cape", parsed.iocs, techniques, options, stats, parsed.warnings)


def analyze_file(
    path: str | Path,
    options: AnalysisOptions | None = None,
    *,
    input_format: str = "auto",
    encoding: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> AnalysisResult:
    """Read ``path`` ("-" for stdin) and analyze it as text or a CAPE report.

    ``input_format`` is ``"auto"``, ``"text"`` or ``"cape"``. In auto mode a
    JSON document that looks like a CAPE report is parsed as one; anything
    else is treated as text, with a warning if it looked like JSON.
    """
    if input_format not in ("auto", "text", "cape"):
        raise ValueError(f"unknown input format: {input_format}")
    text, warnings = decode_text(read_bytes(path, max_bytes), encoding)
    # The name goes into the output as is: no surrogates (unencodable) or terminal controls.
    input_name = printable(str(path))

    if input_format == "cape" or (input_format == "auto" and text.lstrip().startswith("{")):
        try:
            data = load_json(text)
        except InputError as exc:
            if input_format == "cape":
                raise
            warnings.append(f"input looks like JSON but could not be parsed ({exc}); analyzed as text")
            data = None
        if looks_like_cape(data) and isinstance(data, Mapping):
            result = analyze_cape(data, options)
            result.warnings[:0] = warnings
            result.input_name = input_name
            return result
        if input_format == "cape":
            raise InputError(f"{path}: not a CAPE report (no 'info' and behaviour/network sections)")
        if data is not None:
            warnings.append("JSON input is not a CAPE report; analyzing it as text")

    result = analyze_text(text, options)
    result.warnings[:0] = warnings
    result.input_name = input_name
    return result
