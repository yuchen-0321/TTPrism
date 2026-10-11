"""docs/research/2026-10-real-reports/evaluate.py, loaded once for the tests of the evaluation."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

SCRIPT = Path(__file__).resolve().parents[1] / "docs/research/2026-10-real-reports/evaluate.py"


def _load() -> ModuleType:
    if "evaluate_reports" in sys.modules:
        return sys.modules["evaluate_reports"]
    spec = importlib.util.spec_from_file_location("evaluate_reports", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


evaluate = _load()
