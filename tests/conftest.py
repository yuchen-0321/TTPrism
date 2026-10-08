from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ttprism import Allowlist, AnalysisOptions, RuleSet

DATA = Path(__file__).parent / "data"


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
