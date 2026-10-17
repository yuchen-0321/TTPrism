"""Result types shared by the extractor, the ATT&CK mapper and the exporters."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IOCType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


_TYPE_ORDER = {t: i for i, t in enumerate(IOCType)}
HASH_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})


@dataclass(frozen=True)
class IOC:
    type: IOCType
    value: str
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"type": str(self.type), "value": self.value, "sources": list(self.sources)}


@dataclass(frozen=True)
class TechniqueMatch:
    """One ATT&CK technique found in, or inferred from, the input.

    ``reported`` is true when the input itself names the technique (a report
    citing T1059.001, or a sandbox signature carrying a TTP). ``rules`` lists
    the TTPrism mapping rules that inferred it from observed behaviour.
    ``original_ids`` holds outdated IDs from the input that were resolved to
    this technique through ATT&CK's revocation history.
    """

    technique_id: str
    name: str
    tactics: tuple[str, ...]
    status: str
    reported: bool
    rules: tuple[str, ...]
    confidence: str | None
    evidence: tuple[str, ...]
    original_ids: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return attack_url(self.technique_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.technique_id,
            "name": self.name,
            "tactics": list(self.tactics),
            "status": self.status,
            "reported": self.reported,
            "rules": list(self.rules),
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "original_ids": list(self.original_ids),
            "url": self.url,
        }


@dataclass
class AnalysisResult:
    input_format: str
    iocs: list[IOC]
    techniques: list[TechniqueMatch]
    attack_version: str
    suppressed: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    input_name: str | None = None

    def iocs_of(self, ioc_type: IOCType) -> list[str]:
        return [i.value for i in self.iocs if i.type == ioc_type]


def attack_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


class IOCCollector:
    """Deduplicates IOCs and remembers every place each one was seen."""

    def __init__(self) -> None:
        self._items: dict[tuple[IOCType, str], set[str]] = {}

    def add(self, ioc_type: IOCType, value: str, source: str) -> None:
        self._items.setdefault((ioc_type, value), set()).add(source)

    def update(self, other: IOCCollector) -> None:
        for key, sources in other._items.items():
            self._items.setdefault(key, set()).update(sources)

    def __iter__(self) -> Iterator[tuple[IOCType, str, frozenset[str]]]:
        for (ioc_type, value), sources in self._items.items():
            yield ioc_type, value, frozenset(sources)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: object) -> bool:
        return key in self._items


def sort_iocs(iocs: list[IOC]) -> list[IOC]:
    return sorted(iocs, key=lambda i: (_TYPE_ORDER[i.type], i.value))
