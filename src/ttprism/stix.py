"""STIX 2.1 bundle output.

Each IOC becomes an ``indicator`` with a STIX pattern, each CVE a
``vulnerability``, and each technique an ``attack-pattern`` that references
MITRE ATT&CK. A ``grouping`` ties the objects of one analysis together.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from ttprism._version import __version__
from ttprism.models import AnalysisResult, IOCType

_PATTERNS = {
    IOCType.URL: "url:value",
    IOCType.DOMAIN: "domain-name:value",
    IOCType.IPV4: "ipv4-addr:value",
    IOCType.IPV6: "ipv6-addr:value",
    IOCType.EMAIL: "email-addr:value",
    IOCType.MD5: "file:hashes.MD5",
    IOCType.SHA1: "file:hashes.'SHA-1'",
    IOCType.SHA256: "file:hashes.'SHA-256'",
}


def _timestamp(moment: datetime) -> str:
    moment = moment.astimezone(UTC)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


def stix_string(value: str) -> str:
    """Quote ``value`` as a STIX patterning string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def to_stix_bundle(
    result: AnalysisResult,
    *,
    now: datetime | None = None,
    new_id: Callable[[], uuid.UUID] = uuid.uuid4,
) -> dict[str, Any]:
    ts = _timestamp(now or datetime.now(UTC))
    common = {"spec_version": "2.1", "created": ts, "modified": ts}
    origin = f"Extracted by TTPrism {__version__} from {result.input_format} input"
    objects: list[dict[str, Any]] = []

    for ioc in result.iocs:
        if ioc.type == IOCType.CVE:
            objects.append(
                {
                    "type": "vulnerability",
                    "id": f"vulnerability--{new_id()}",
                    **common,
                    "name": ioc.value,
                    "external_references": [{"source_name": "cve", "external_id": ioc.value}],
                }
            )
            continue
        objects.append(
            {
                "type": "indicator",
                "id": f"indicator--{new_id()}",
                **common,
                "name": ioc.value,
                "description": f"{origin} ({', '.join(ioc.sources)}).",
                "pattern": f"[{_PATTERNS[ioc.type]} = {stix_string(ioc.value)}]",
                "pattern_type": "stix",
                "valid_from": ts,
            }
        )

    for technique in result.techniques:
        objects.append(
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{new_id()}",
                **common,
                "name": technique.name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique.technique_id,
                        "url": technique.url,
                    }
                ],
            }
        )

    if objects:
        name = f"TTPrism analysis of {result.input_name}" if result.input_name else "TTPrism analysis"
        objects.append(
            {
                "type": "grouping",
                "id": f"grouping--{new_id()}",
                **common,
                "name": name,
                "context": "suspicious-activity",
                "object_refs": [o["id"] for o in objects],
            }
        )

    bundle: dict[str, Any] = {"type": "bundle", "id": f"bundle--{new_id()}"}
    if objects:  # STIX lists must not be empty; an empty bundle omits "objects".
        bundle["objects"] = objects
    return bundle
