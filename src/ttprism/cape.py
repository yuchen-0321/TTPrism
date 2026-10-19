"""Parser for CAPE sandbox ``report.json`` files.

Only known fields are read, each one type-checked, so a malformed or hostile
report can at worst produce fewer results. Nothing in the report is executed,
decompressed or fetched.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from ttprism.attack import Behavior
from ttprism.extract import extract_into, normalize_domain, normalize_ip
from ttprism.models import IOCCollector, IOCType
from ttprism.refang import cut_between_values, refang

# A field longer than this is left out, and a command line cut at a blank where refang cannot join
# a value across it; either way it is counted under suppressed (truncated_fields).
MAX_FIELD_CHARS = 8192
# Upper bounds on what one report can feed into rule matching. Real CAPE runs
# stay far below these; a crafted report cannot make matching cost explode.
MAX_ITEMS = 10_000
MAX_SIGNATURE_CHARS = 200
MAX_API_CHARS = 100
# IOC extraction and rule matching each look at the first command lines up to this many characters
# in total (8 Mi, about 1,000 lines of MAX_FIELD_CHARS), which bounds their cost at about 3 s and
# 1 s per MB of commands even for pathological text. The lines left out are counted under
# suppressed (truncated_ioc_commands, truncated_rule_commands) and named in a warning. The
# structured fields (network, hashes, signatures) are not affected.
MAX_IOC_COMMAND_CHARS = 8 * 1024 * 1024
MAX_RULE_COMMAND_CHARS = 8 * 1024 * 1024
_HASH_FIELDS = (("md5", IOCType.MD5), ("sha1", IOCType.SHA1), ("sha256", IOCType.SHA256))
_DNS_ADDRESS_TYPES = {"A", "AAAA"}


@dataclass
class CapeReport:
    iocs: IOCCollector
    behavior: Behavior
    reported_ttps: list[tuple[str, str]] = field(default_factory=list)  # (technique, signature)
    stats: Counter[str] = field(default_factory=Counter)
    warnings: list[str] = field(default_factory=list)


def looks_like_cape(data: object) -> bool:
    return (
        isinstance(data, dict)
        and isinstance(data.get("info"), dict)
        and any(k in data for k in ("behavior", "network", "signatures", "target"))
    )


def _dicts(value: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, list):
        yield from (v for v in value if isinstance(v, dict))


def _strings(value: Any, stats: Counter[str]) -> Iterator[str]:
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                continue
            if len(item) > MAX_FIELD_CHARS:
                stats["truncated_fields"] += 1
            else:
                yield item


def _str(value: Any, stats: Counter[str]) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if len(value) > MAX_FIELD_CHARS:
        stats["truncated_fields"] += 1
        return None
    return value


def _command(value: str, stats: Counter[str]) -> str | None:
    """A command line, cut at a blank that refang does not join a value across if it is longer than
    MAX_FIELD_CHARS (or left out if it has no such place)."""
    if len(value) > MAX_FIELD_CHARS:
        stats["truncated_fields"] += 1
        return cut_between_values(value, MAX_FIELD_CHARS, MAX_FIELD_CHARS) or None
    return value


def _dict(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _add_hashes(collector: IOCCollector, info: Mapping[str, Any], source: str, stats: Counter[str]) -> None:
    for key, ioc_type in _HASH_FIELDS:
        value = _str(info.get(key), stats)
        if value and len(value) == {"md5": 32, "sha1": 40, "sha256": 64}[key]:
            lowered = value.lower()
            if all(c in "0123456789abcdef" for c in lowered):
                collector.add(ioc_type, lowered, source)


def _add_host(collector: IOCCollector, value: str | None, source: str) -> None:
    if not value:
        return
    ip = normalize_ip(value)
    if ip is not None:
        collector.add(ip[0], ip[1], source)
        return
    domain = normalize_domain(value)
    if domain is not None:
        collector.add(IOCType.DOMAIN, domain, source)


def _add_url(collector: IOCCollector, value: str | None, source: str, stats: Counter[str]) -> None:
    if not value:
        return
    scratch = IOCCollector()
    # Masked names are kept, as in the other network fields: the sandbox saw this connection.
    extract_into(scratch, value, source, stats, drop_masked=False)
    for ioc_type, ioc_value, _ in scratch:
        if ioc_type in (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6):
            collector.add(ioc_type, ioc_value, source)


def parse_cape(report: Mapping[str, Any]) -> CapeReport:
    iocs = IOCCollector()
    behavior = Behavior()
    stats: Counter[str] = Counter()

    # Files: the submitted sample, dropped files, extracted payloads.
    _add_hashes(iocs, _dict(_dict(report.get("target")).get("file")), "cape:target", stats)
    for dropped in _dicts(report.get("dropped")):
        _add_hashes(iocs, dropped, "cape:dropped", stats)
    for payload in _dicts(_dict(report.get("CAPE")).get("payloads")):
        _add_hashes(iocs, payload, "cape:payload", stats)

    # Network. Masked names (wiki.xxxx.com) are not dropped here: these are the sandbox's own records
    # of connections, not a report's way of hiding a value.
    network = _dict(report.get("network"))
    # Current CAPE stores hosts as objects; older Cuckoo-style reports as strings.
    for host_entry in _dicts(network.get("hosts")):
        _add_host(iocs, _str(host_entry.get("ip"), stats), "cape:network.hosts")
    for host_ip in _strings(network.get("hosts"), stats):
        _add_host(iocs, host_ip, "cape:network.hosts")
    for entry in _dicts(network.get("domains")):
        _add_host(iocs, _str(entry.get("domain"), stats), "cape:network.domains")
        _add_host(iocs, _str(entry.get("ip"), stats), "cape:network.domains")
    for query in _dicts(network.get("dns")):
        _add_host(iocs, _str(query.get("request"), stats), "cape:network.dns")
        for answer in _dicts(query.get("answers")):
            answer_type = answer.get("type")
            if isinstance(answer_type, str) and answer_type in _DNS_ADDRESS_TYPES:
                _add_host(iocs, _str(answer.get("data"), stats), "cape:network.dns")
    for request in _dicts(network.get("http")):
        _add_url(iocs, _str(request.get("uri"), stats), "cape:network.http", stats)
        _add_host(iocs, _host_without_port(_str(request.get("host"), stats)), "cape:network.http")
    for key in ("http_ex", "https_ex"):
        for request in _dicts(network.get(key)):
            http_host = _host_without_port(_str(request.get("host"), stats))
            if not http_host:
                continue
            _add_host(iocs, http_host, "cape:network.http")
            uri = request.get("uri")
            if isinstance(uri, str) and len(uri) > MAX_FIELD_CHARS:
                stats["truncated_fields"] += 1
                continue
            scheme = "https" if key == "https_ex" else "http"
            path = uri if isinstance(uri, str) and uri else "/"
            path = path if path.startswith("/") else "/" + path
            _add_url(iocs, f"{scheme}://{http_host}{path}", "cape:network.http", stats)

    # Behaviour.
    behavior_section = _dict(report.get("behavior"))
    summary = _dict(behavior_section.get("summary"))
    # Repeats are dropped before long lines are cut, so that each distinct line is cut only once.
    raw_commands: dict[str, None] = {}
    executed = summary.get("executed_commands")
    for command in executed if isinstance(executed, list) else []:
        if isinstance(command, str) and command:
            raw_commands[command] = None
    dropped_apis: set[str] = set()
    long_apis: set[str] = set()
    for process in _dicts(behavior_section.get("processes")):
        command = _dict(process.get("environ")).get("CommandLine")
        if isinstance(command, str) and command:
            raw_commands[command] = None
        for call in _dicts(process.get("calls")):
            api = call.get("api")
            if not isinstance(api, str) or api in behavior.apis:
                continue
            if len(api) > MAX_API_CHARS:
                long_apis.add(api)
            elif len(behavior.apis) < MAX_ITEMS:
                behavior.apis.add(api)
            else:
                dropped_apis.add(api)
    if dropped_apis:
        stats["truncated_apis"] += len(dropped_apis)
    if long_apis:
        stats["long_api_names"] += len(long_apis)
    commands = dict.fromkeys(line for raw in raw_commands if (line := _command(raw, stats)))
    command_lines = _capped(list(commands), "commands", stats)
    warnings: list[str] = []
    behavior.commands = _size_capped(
        command_lines,
        MAX_RULE_COMMAND_CHARS,
        "rule_commands",
        "matched against the ATT&CK rules",
        stats,
        warnings,
    )
    behavior.registry_writes = _capped(
        list(dict.fromkeys(_strings(summary.get("write_keys"), stats))), "registry_writes", stats
    )
    searched = _size_capped(
        command_lines, MAX_IOC_COMMAND_CHARS, "ioc_commands", "searched for IOCs", stats, warnings
    )
    for command in searched:
        # Download cradles and C2 URLs often appear only on the command line.
        extract_into(iocs, refang(command), "cape:commands", stats)

    signatures = []
    for sig in _dicts(report.get("signatures")):
        name = sig.get("name")
        if not isinstance(name, str) or not name:
            continue
        if len(name) > MAX_SIGNATURE_CHARS:
            stats["long_signature_names"] += 1
        else:
            signatures.append(name)
    behavior.signatures = _capped(signatures, "signatures", stats)

    reported_ttps = _capped(_reported_ttps(report, stats), "ttps", stats)
    return CapeReport(
        iocs=iocs, behavior=behavior, reported_ttps=reported_ttps, stats=stats, warnings=warnings
    )


_T = TypeVar("_T")


def _capped(items: list[_T], name: str, stats: Counter[str]) -> list[_T]:
    if len(items) > MAX_ITEMS:
        stats[f"truncated_{name}"] += len(items) - MAX_ITEMS
        return items[:MAX_ITEMS]
    return items


def _size_capped(
    commands: list[str], limit: int, name: str, purpose: str, stats: Counter[str], warnings: list[str]
) -> list[str]:
    """The first ``commands`` that total at most ``limit`` characters."""
    total = 0
    for kept, command in enumerate(commands):
        total += len(command)
        if total > limit:
            dropped = len(commands) - kept
            stats[f"truncated_{name}"] += dropped
            warnings.append(
                f"{dropped} command line(s) after the first {limit:,} characters of commands were not "
                f"{purpose}"
            )
            return commands[:kept]
    return commands


def _host_without_port(host: str | None) -> str | None:
    if not host:
        return None
    if host.startswith("["):
        return host.split("]", 1)[0] + "]"
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def _reported_ttps(report: Mapping[str, Any], stats: Counter[str]) -> list[tuple[str, str]]:
    """TTPs that CAPE's own signatures attached, in either report layout.

    Current CAPE writes ``[{"signature": s, "ttps": [...]}]``; older versions
    wrote one ``{"signature": s, "ttp": t}`` object per pair. Signature names
    are cut to MAX_SIGNATURE_CHARS: each pair becomes a line of evidence. A pair
    that the cut makes equal to one of another signature is counted (merged_ttps).
    """
    found: dict[tuple[str, str], set[str]] = {}
    for entry in _dicts(report.get("ttps")):
        name = entry.get("signature")
        name = name if isinstance(name, str) and name else "?"
        signature = name[:MAX_SIGNATURE_CHARS]
        ttps = list(_strings([entry.get("ttp")], stats))
        ttps.extend(_strings(entry.get("ttps"), stats))
        for ttp in ttps:
            names = found.setdefault((ttp, signature), set())
            if names and name not in names:
                stats["merged_ttps"] += 1
            names.add(name)
    return list(found)
