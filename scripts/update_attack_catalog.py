#!/usr/bin/env python3
"""Regenerate src/ttprism/data/attack_enterprise.json from MITRE's STIX data.

The catalog is a compact index of Enterprise ATT&CK techniques: ID, name,
tactics, and whether the technique was revoked (and by what) or deprecated.
TTPrism uses it to validate mapping rules and to normalise outdated technique
IDs found in reports and sandbox output.

Usage:
    python scripts/update_attack_catalog.py                    # download latest
    python scripts/update_attack_catalog.py --input enterprise-attack.json

Source: https://github.com/mitre-attack/attack-stix-data
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "ttprism" / "data" / "attack_enterprise.json"
NOTICE = (
    "© {year} The MITRE Corporation. This work is reproduced and distributed "
    "with the permission of The MITRE Corporation."
)


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def build_catalog(bundle: dict[str, Any]) -> dict[str, Any]:
    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}

    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    version = str(collection["x_mitre_version"])

    tactics = {}
    for o in objects:
        if o["type"] == "x-mitre-tactic" and not o.get("x_mitre_deprecated") and not o.get("revoked"):
            tactics[o["x_mitre_shortname"]] = {"id": _external_id(o), "name": o["name"]}

    revoked_by: dict[str, str] = {}
    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            source = by_stix_id.get(o["source_ref"])
            target = by_stix_id.get(o["target_ref"])
            if source and target and source["type"] == target["type"] == "attack-pattern":
                source_id, target_id = _external_id(source), _external_id(target)
                if source_id and target_id:
                    revoked_by[source_id] = target_id

    techniques: dict[str, dict[str, Any]] = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        tid = _external_id(o)
        if tid is None:
            continue
        entry: dict[str, Any] = {"name": o["name"]}
        if o.get("revoked"):
            entry["status"] = "revoked"
            if tid in revoked_by:
                entry["revoked_by"] = revoked_by[tid]
        elif o.get("x_mitre_deprecated"):
            entry["status"] = "deprecated"
        else:
            entry["tactics"] = [
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
        # If an ID appears twice, keep the active object.
        if tid in techniques and "status" not in techniques[tid]:
            continue
        techniques[tid] = entry

    return {
        "domain": "enterprise-attack",
        "attack_version": version,
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "source_modified": collection.get("modified"),
        "notice": NOTICE.format(year=str(collection.get("modified", ""))[:4] or "2026"),
        "tactics": dict(sorted(tactics.items(), key=lambda kv: kv[1]["id"] or "")),
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, help="local enterprise-attack.json instead of downloading")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    if args.input:
        bundle = json.loads(args.input.read_text(encoding="utf-8"))
    else:
        if not args.url.startswith("https://"):
            parser.error("--url must be an https:// URL")
        with urllib.request.urlopen(args.url, timeout=120) as response:  # noqa: S310 (https checked)
            bundle = json.load(response)

    catalog = build_catalog(bundle)
    args.output.write_text(
        json.dumps(catalog, ensure_ascii=False, indent=1, sort_keys=False) + "\n", encoding="utf-8"
    )
    active = sum(1 for t in catalog["techniques"].values() if "status" not in t)
    print(
        f"ATT&CK {catalog['attack_version']}: {len(catalog['techniques'])} techniques "
        f"({active} active) -> {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
