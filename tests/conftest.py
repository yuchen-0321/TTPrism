from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, settings

from ttprism import Allowlist, AnalysisOptions, RuleSet

DATA = Path(__file__).parent / "data"

# Property-based tests run 200 examples each; HYPOTHESIS_PROFILE=fuzz runs 20,000.
settings.register_profile("ci", max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile(
    "fuzz", max_examples=20_000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))


@pytest.fixture
def data_dir() -> Path:
    return DATA


@pytest.fixture
def cape_report() -> dict[str, Any]:
    result: dict[str, Any] = json.loads((DATA / "cape_report.json").read_text(encoding="utf-8"))
    return result


@pytest.fixture
def raw_options() -> AnalysisOptions:
    """No allowlist and keep reserved values: tests see everything the extractor finds."""
    return AnalysisOptions(allowlist=Allowlist.empty(), include_reserved=True)


@pytest.fixture
def no_rules_options() -> AnalysisOptions:
    return AnalysisOptions(allowlist=Allowlist.empty(), rules=RuleSet.empty(), include_reserved=True)
