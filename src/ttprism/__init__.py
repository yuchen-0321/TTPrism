"""TTPrism: extract IOCs from threat reports and sandbox output, map behaviour to MITRE ATT&CK.

Quick start::

    import ttprism

    result = ttprism.analyze_text("C2: c2【.】example.com, see T1071.001",
                                  ttprism.AnalysisOptions(include_reserved=True))
    for ioc in result.iocs:
        print(ioc.type, ioc.value)
"""

from ttprism._version import __version__
from ttprism.allowlist import Allowlist, AllowlistError
from ttprism.analyze import AnalysisOptions, analyze_cape, analyze_file, analyze_text
from ttprism.attack import AttackCatalog, Behavior, RuleError, RuleSet
from ttprism.export import to_csv, to_dict, to_json
from ttprism.extract import extract_iocs
from ttprism.inputs import InputError
from ttprism.models import IOC, AnalysisResult, IOCType, TechniqueMatch
from ttprism.refang import defang, refang
from ttprism.stix import to_stix_bundle

__all__ = [
    "IOC",
    "Allowlist",
    "AllowlistError",
    "AnalysisOptions",
    "AnalysisResult",
    "AttackCatalog",
    "Behavior",
    "IOCType",
    "InputError",
    "RuleError",
    "RuleSet",
    "TechniqueMatch",
    "__version__",
    "analyze_cape",
    "analyze_file",
    "analyze_text",
    "defang",
    "extract_iocs",
    "refang",
    "to_csv",
    "to_dict",
    "to_json",
    "to_stix_bundle",
]
