from __future__ import annotations

import itertools
import uuid
from datetime import UTC, datetime
from typing import Any

import stix2

from ttprism import IOC, AnalysisOptions, AnalysisResult, IOCType, analyze_cape, analyze_text, to_stix_bundle
from ttprism.stix import stix_string


def test_bundle_validates_with_stix2(cape_report: dict[str, Any], raw_options: AnalysisOptions) -> None:
    result = analyze_cape(cape_report, raw_options)
    bundle = to_stix_bundle(result)
    parsed = stix2.parse(bundle, allow_custom=False)
    types = {o.type for o in parsed.objects}
    assert types == {"indicator", "attack-pattern", "grouping"}
    patterns = {o.pattern for o in parsed.objects if o.type == "indicator"}
    assert "[domain-name:value = 'update-check.example']" in patterns
    sha256 = "8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05"
    assert f"[file:hashes.'SHA-256' = '{sha256}']" in patterns
    grouping = next(o for o in parsed.objects if o.type == "grouping")
    assert len(grouping.object_refs) == len(parsed.objects) - 1


def test_cves_become_vulnerabilities() -> None:
    result = analyze_text("CVE-2023-23397 and T1566.001")
    parsed = stix2.parse(to_stix_bundle(result), allow_custom=False)
    vulnerability = next(o for o in parsed.objects if o.type == "vulnerability")
    assert vulnerability.name == "CVE-2023-23397"
    assert vulnerability.external_references[0].source_name == "cve"
    attack_pattern = next(o for o in parsed.objects if o.type == "attack-pattern")
    assert attack_pattern.external_references[0].external_id == "T1566.001"
    assert attack_pattern.external_references[0].url == "https://attack.mitre.org/techniques/T1566/001/"


def test_pattern_escaping() -> None:
    assert stix_string("http://evil.com/a'b\\c") == "'http://evil.com/a\\'b\\\\c'"
    result = AnalysisResult("text", [IOC(IOCType.URL, "http://evil.com/it's\\x", ("text",))], [], "19.2")
    parsed = stix2.parse(to_stix_bundle(result), allow_custom=False)
    indicator = next(o for o in parsed.objects if o.type == "indicator")
    assert indicator.pattern == "[url:value = 'http://evil.com/it\\'s\\\\x']"


def test_deterministic_ids_and_timestamps() -> None:
    counter = itertools.count()
    result = AnalysisResult("text", [IOC(IOCType.DOMAIN, "evil.com", ("text",))], [], "19.2")
    bundle = to_stix_bundle(
        result,
        now=datetime(2026, 10, 8, 12, 0, 0, 123456, tzinfo=UTC),
        new_id=lambda: uuid.UUID(int=next(counter)),
    )
    indicator = bundle["objects"][0]
    assert indicator["id"] == "indicator--00000000-0000-0000-0000-000000000000"
    assert indicator["created"] == "2026-10-08T12:00:00.123Z"


def test_empty_result() -> None:
    bundle = to_stix_bundle(AnalysisResult("text", [], [], "19.2"))
    assert "objects" not in bundle
    # stix2 cannot auto-detect the version of an empty bundle, so name it.
    stix2.parse(bundle, allow_custom=False, version="2.1")
