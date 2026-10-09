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
from ttprism.refang import refang

MAX_FIELD_CHARS = 8192
# Upper bounds on what one report can feed into rule matching. Real CAPE runs
# stay far below these; a crafted report cannot make matching cost explode.
MAX_ITEMS = 10_000
MAX_SIGNATURE_CHARS = 200
# Rule matching looks at the first commands up to this many characters in total (8 Mi, about 1,000
# commands of MAX_FIELD_CHARS); the rest are counted under suppressed as truncated_rule_commands.
# IOCs are still extracted from every command.
MAX_RULE_COMMAND_CHARS = 8 * 1024 * 1024
_HASH_FIELDS = (("md5", IOCType.MD5), ("sha1", IOCType.SHA1), ("sha256", IOCType.SHA256))
_DNS_ADDRESS_TYPES = {"A", "AAAA"}


@dataclass
class CapeReport:
    iocs: IOCCollector
    behavior: Behavior
    reported_ttps: list[tuple[str, str]] = field(default_factory=list)  # (technique, signature)
    stats: Counter[str] = field(default_factory=Counter)


def looks_like_cape(data: object) -> bool:
    return (
        isinstance(data, dict)
        and isinstance(data.get("info"), dict)
        and any(k in data for k in ("behavior", "network", "signatures", "target"))
    )


def _dicts(value: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, list):
        yield from (v for v in value if isinstance(v, dict))


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, list):
        yield from (v[:MAX_FIELD_CHARS] for v in value if isinstance(v, str))


def _str(value: Any) -> str | None:
    return value[:MAX_FIELD_CHARS] if isinstance(value, str) and value else None


def _dict(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _add_hashes(collector: IOCCollector, info: Mapping[str, Any], source: str) -> None:
    for key, ioc_type in _HASH_FIELDS:
        value = _str(info.get(key))
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


def _add_url(collector: IOCCollector, value: str | None, source: str) -> None:
    if not value:
        return
    scratch = IOCCollector()
    extract_into(scratch, value, source)
    for ioc_type, ioc_value, _ in scratch:
        if ioc_type in (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6):
            collector.add(ioc_type, ioc_value, source)


def parse_cape(report: Mapping[str, Any]) -> CapeReport:
    iocs = IOCCollector()
    behavior = Behavior()
    stats: Counter[str] = Counter()

    # Files: the submitted sample, dropped files, extracted payloads.
    _add_hashes(iocs, _dict(_dict(report.get("target")).get("file")), "cape:target")
    for dropped in _dicts(report.get("dropped")):
        _add_hashes(iocs, dropped, "cape:dropped")
    for payload in _dicts(_dict(report.get("CAPE")).get("payloads")):
        _add_hashes(iocs, payload, "cape:payload")

    # Network.
    network = _dict(report.get("network"))
    # Current CAPE stores hosts as objects; older Cuckoo-style reports as strings.
    for host_entry in _dicts(network.get("hosts")):
        _add_host(iocs, _str(host_entry.get("ip")), "cape:network.hosts")
    for host_ip in _strings(network.get("hosts")):
        _add_host(iocs, host_ip, "cape:network.hosts")
    for entry in _dicts(network.get("domains")):
        _add_host(iocs, _str(entry.get("domain")), "cape:network.domains")
        _add_host(iocs, _str(entry.get("ip")), "cape:network.domains")
    for query in _dicts(network.get("dns")):
        _add_host(iocs, _str(query.get("request")), "cape:network.dns")
        for answer in _dicts(query.get("answers")):
            answer_type = answer.get("type")
            if isinstance(answer_type, str) and answer_type in _DNS_ADDRESS_TYPES:
                _add_host(iocs, _str(answer.get("data")), "cape:network.dns")
    for request in _dicts(network.get("http")):
        _add_url(iocs, _str(request.get("uri")), "cape:network.http")
        _add_host(iocs, _host_without_port(_str(request.get("host"))), "cape:network.http")
    for key in ("http_ex", "https_ex"):
        for request in _dicts(network.get(key)):
            http_host = _host_without_port(_str(request.get("host")))
            if not http_host:
                continue
            _add_host(iocs, http_host, "cape:network.http")
            scheme = "https" if key == "https_ex" else "http"
            path = _str(request.get("uri")) or "/"
            path = path if path.startswith("/") else "/" + path
            _add_url(iocs, f"{scheme}://{http_host}{path}", "cape:network.http")

    # Behaviour.
    behavior_section = _dict(report.get("behavior"))
    summary = _dict(behavior_section.get("summary"))
    commands = dict.fromkeys(_strings(summary.get("executed_commands")))
    dropped_apis: set[str] = set()
    for process in _dicts(behavior_section.get("processes")):
        command_line = _str(_dict(process.get("environ")).get("CommandLine"))
        if command_line:
            commands[command_line] = None
        for call in _dicts(process.get("calls")):
            api = call.get("api")
            if not isinstance(api, str) or len(api) > 100 or api in behavior.apis:
                continue
            if len(behavior.apis) < MAX_ITEMS:
                behavior.apis.add(api)
            else:
                dropped_apis.add(api)
    if dropped_apis:
        stats["truncated_apis"] += len(dropped_apis)
    command_lines = _capped(list(commands), "commands", stats)
    behavior.commands = _size_capped(command_lines, stats)
    behavior.registry_writes = _capped(
        list(dict.fromkeys(_strings(summary.get("write_keys")))), "registry_writes", stats
    )
    for command in command_lines:
        # Download cradles and C2 URLs often appear only on the command line.
        extract_into(iocs, refang(command), "cape:commands", stats)

    signatures = [
        s
        for sig in _dicts(report.get("signatures"))
        if (s := _str(sig.get("name"))) and len(s) <= MAX_SIGNATURE_CHARS
    ]
    behavior.signatures = _capped(signatures, "signatures", stats)

    reported_ttps = _capped(_reported_ttps(report), "ttps", stats)
    return CapeReport(iocs=iocs, behavior=behavior, reported_ttps=reported_ttps, stats=stats)


_T = TypeVar("_T")


def _capped(items: list[_T], name: str, stats: Counter[str]) -> list[_T]:
    if len(items) > MAX_ITEMS:
        stats[f"truncated_{name}"] += len(items) - MAX_ITEMS
        return items[:MAX_ITEMS]
    return items


def _size_capped(commands: list[str], stats: Counter[str]) -> list[str]:
    """The first ``commands`` that total at most MAX_RULE_COMMAND_CHARS characters."""
    total = 0
    for kept, command in enumerate(commands):
        total += len(command)
        if total > MAX_RULE_COMMAND_CHARS:
            stats["truncated_rule_commands"] += len(commands) - kept
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


def _reported_ttps(report: Mapping[str, Any]) -> list[tuple[str, str]]:
    """TTPs that CAPE's own signatures attached, in either report layout.

    Current CAPE writes ``[{"signature": s, "ttps": [...]}]``; older versions
    wrote one ``{"signature": s, "ttp": t}`` object per pair. Signature names
    are cut to MAX_SIGNATURE_CHARS: each pair becomes a line of evidence.
    """
    found: dict[tuple[str, str], None] = {}
    for entry in _dicts(report.get("ttps")):
        signature = (_str(entry.get("signature")) or "?")[:MAX_SIGNATURE_CHARS]
        if isinstance(entry.get("ttp"), str):
            found[(entry["ttp"][:MAX_FIELD_CHARS], signature)] = None
        found.update(((t, signature), None) for t in _strings(entry.get("ttps")))
    return list(found)
