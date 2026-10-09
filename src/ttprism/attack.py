"""MITRE ATT&CK technique catalog and YAML mapping rules.

Rule files live in ``rules/attack/`` and look like::

    attack_version: "19.2"
    rules:
      - id: cmd.vssadmin-delete-shadows
        technique: T1490
        confidence: high            # low | medium | high (default: medium)
        description: Shadow copies deleted from the command line
        references: [https://attack.mitre.org/techniques/T1490/]
        match:                      # the rule fires if ANY matcher matches
          signatures: ["deletes_shadow_copies"]           # sandbox signature names, * and ? globs
          apis: ["NtUnmapViewOfSection"]                  # an API was called ("A|B" = either)
          apis_all: [["VirtualAllocEx", "WriteProcessMemory|NtWriteVirtualMemory"]]
                                                          # every API in one inner list was called
          commands: ["vssadmin delete shadows", ["wmic", "shadowcopy", "delete"]]
                                                          # command line contains the phrase
                                                          # (or every phrase of an inner list)
          exclude_commands: ["/?"]                        # command lines that match this (same
                                                          # syntax) are ignored by `commands`
          registry: ['\\currentversion\\run\\']          # a written registry key contains this
                                                          # (or every part of an inner list)

Command lines and phrases are lower-cased, cmd.exe caret escapes are removed,
Unicode dashes become "-" and whitespace is collapsed. Each command line is
then matched in two views, one with quotes turned into spaces and one with
quotes deleted (cmd.exe runs s"c"htasks as schtasks); an inner list matches
if all its phrases occur in the same view. A phrase must not be part of a
longer word: where it starts or ends with a letter, digit or "_", the
neighbouring character must not be one. Registry patterns are plain
case-insensitive substrings.
"""

from __future__ import annotations

import fnmatch
import functools
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

from ttprism._yaml import ConfigError, load_yaml_file, load_yaml_text
from ttprism.inputs import printable
from ttprism.models import TechniqueMatch

TECHNIQUE_ID_RE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
_RULE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_GLOB_RE = re.compile(r"[A-Za-z0-9_.*?-]{1,100}")
_API_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_@]{0,99}")
_CONFIDENCE = ("low", "medium", "high")
_VERSION_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}")
_RULE_KEYS = {"id", "technique", "confidence", "description", "references", "match"}
_MATCH_KEYS = {"signatures", "apis", "apis_all", "commands", "exclude_commands", "registry"}
MAX_EVIDENCE = 20
MAX_EVIDENCE_CHARS = 200


class RuleError(ConfigError):
    pass


# --------------------------------------------------------------------------- catalog


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...] = ()
    status: str = "active"  # active | revoked | deprecated
    revoked_by: str | None = None


@dataclass(frozen=True)
class AttackCatalog:
    version: str
    techniques: dict[str, Technique]
    tactic_names: dict[str, str] = field(default_factory=dict)

    @classmethod
    def default(cls) -> AttackCatalog:
        return _default_catalog()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackCatalog:
        techniques = {
            tid: Technique(
                id=tid,
                name=entry["name"],
                tactics=tuple(entry.get("tactics", ())),
                status=entry.get("status", "active"),
                revoked_by=entry.get("revoked_by"),
            )
            for tid, entry in data["techniques"].items()
        }
        tactics = {short: t["name"] for short, t in data.get("tactics", {}).items()}
        return cls(version=str(data["attack_version"]), techniques=techniques, tactic_names=tactics)

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def resolve(self, technique_id: str) -> Technique | None:
        """Follow revoked-by links to the technique that replaces ``technique_id``.

        Returns None for IDs the catalog does not know. A revoked technique with
        no known replacement is returned as-is.
        """
        technique = self.techniques.get(technique_id)
        seen = {technique_id}
        while technique is not None and technique.status == "revoked" and technique.revoked_by:
            successor = self.techniques.get(technique.revoked_by)
            if successor is None or successor.id in seen:
                break
            seen.add(successor.id)
            technique = successor
        return technique


@functools.cache
def _default_catalog() -> AttackCatalog:
    text = resources.files("ttprism").joinpath("data/attack_enterprise.json").read_text("utf-8")
    return AttackCatalog.from_dict(json.loads(text))


# --------------------------------------------------------------------------- behaviour


@dataclass
class Behavior:
    """Observations from a sandbox run that mapping rules are evaluated against."""

    signatures: list[str] = field(default_factory=list)
    apis: set[str] = field(default_factory=set)
    commands: list[str] = field(default_factory=list)
    registry_writes: list[str] = field(default_factory=list)


_CommandViews = tuple[str, str]


@dataclass(frozen=True)
class _PreparedBehavior:
    """Case-folded views of a Behavior, computed once per analysis rather than per rule."""

    apis: frozenset[str]
    commands: tuple[tuple[str, _CommandViews], ...]  # (as reported, normalised views)
    registry_writes: tuple[str, ...]


_CARET_RE = re.compile(r"\^(?=.)")
_SPACE_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"\w")
_NEVER_RE = re.compile(r"(?!)")
_DASHES = {"\u2013": "-", "\u2014": "-", "\u2015": "-"}  # PowerShell reads these as "-"
_QUOTES_AS_SPACES = str.maketrans({**_DASHES, '"': " ", "'": " "})
_QUOTES_DELETED = str.maketrans({**_DASHES, '"': None, "'": None})


def normalize_command(command: str, *, delete_quotes: bool = False) -> str:
    """Lower-case, drop cmd.exe carets, fold Unicode dashes to "-" and collapse whitespace.

    Quotes become spaces, or are deleted with ``delete_quotes``.
    """
    table = _QUOTES_DELETED if delete_quotes else _QUOTES_AS_SPACES
    command = _CARET_RE.sub("", command.lower()).translate(table)
    return _SPACE_RE.sub(" ", command).strip()


def _command_views(command: str) -> _CommandViews:
    spaced = normalize_command(command)
    joined = normalize_command(command, delete_quotes=True)
    # Reuse the object when both views agree so matching can skip the second one.
    return (spaced, spaced if joined == spaced else joined)


def _phrase_re(phrase: str) -> re.Pattern[str]:
    """Regex for a normalised phrase that is not part of a longer word ("_" counts as a letter).

    Same as (?<!\\w)phrase(?!\\w), but with the literal first so the regex engine uses its fast
    literal search. The phrase is escaped, so matching is linear. "" never matches.
    """
    if not phrase:
        return _NEVER_RE
    literal = re.escape(phrase)
    left = rf"(?<!\w{literal})" if _WORD_RE.match(phrase[0]) else ""
    right = r"(?!\w)" if _WORD_RE.match(phrase[-1]) else ""
    return re.compile(literal + left + right)


_Phrases = tuple[tuple[str, re.Pattern[str]], ...]  # (normalised phrase, its regex)


def _contains_all(phrases: _Phrases, text: str) -> bool:
    # The substring test is much faster than a regex search and rules out most phrases.
    return all(phrase in text and pattern.search(text) for phrase, pattern in phrases)


@dataclass(frozen=True)
class _PhraseList:
    """One inner list of command phrases, compiled for both command views."""

    spaced: _Phrases
    joined: _Phrases  # the same object as ``spaced`` unless a phrase contains quotes

    @classmethod
    def compile(cls, phrases: tuple[str, ...]) -> _PhraseList:
        def view(delete_quotes: bool) -> _Phrases:
            normalised = (normalize_command(p, delete_quotes=delete_quotes) for p in phrases)
            return tuple((p, _phrase_re(p)) for p in normalised)

        spaced, joined = view(False), view(True)
        return cls(spaced, spaced if joined == spaced else joined)

    def matches(self, views: _CommandViews) -> bool:
        """Every phrase occurs in the same view of the command line."""
        spaced, joined = views
        if _contains_all(self.spaced, spaced):
            return True
        if joined is spaced and self.joined is self.spaced:
            return False
        return _contains_all(self.joined, joined)


def _printable(text: str) -> str:
    """Make attacker-controlled text safe to show in a terminal or spreadsheet."""
    # Cut first so the cost does not grow with the input; the substitution is one-to-one.
    cleaned = printable(text[: MAX_EVIDENCE_CHARS + 1])
    if len(cleaned) > MAX_EVIDENCE_CHARS:
        cleaned = cleaned[: MAX_EVIDENCE_CHARS - 1] + "…"
    return cleaned


# --------------------------------------------------------------------------- rules


@dataclass(frozen=True)
class Rule:
    id: str
    technique: str
    confidence: str
    description: str
    references: tuple[str, ...]
    signatures: tuple[str, ...] = ()
    apis: tuple[frozenset[str], ...] = ()
    apis_all: tuple[tuple[frozenset[str], ...], ...] = ()
    commands: tuple[tuple[str, ...], ...] = ()  # phrases as written in the rule file
    exclude_commands: tuple[tuple[str, ...], ...] = ()
    registry: tuple[tuple[str, ...], ...] = ()
    source: str = ""

    @functools.cached_property
    def _signature_res(self) -> tuple[re.Pattern[str], ...]:
        return tuple(re.compile(fnmatch.translate(g), re.IGNORECASE) for g in self.signatures)

    @functools.cached_property
    def _command_lists(self) -> tuple[_PhraseList, ...]:
        return tuple(_PhraseList.compile(phrases) for phrases in self.commands)

    @functools.cached_property
    def _exclusion_lists(self) -> tuple[_PhraseList, ...]:
        return tuple(_PhraseList.compile(phrases) for phrases in self.exclude_commands)

    def evaluate(self, behavior: Behavior, prepared: _PreparedBehavior) -> list[str]:
        """Return evidence strings if the rule matches ``behavior``, else []."""
        evidence: list[str] = []
        for name in behavior.signatures:
            if any(p.fullmatch(name) for p in self._signature_res):
                evidence.append(f"signature: {name}")
        apis_lower = prepared.apis
        for alternatives in self.apis:
            hit = alternatives & apis_lower
            if hit:
                evidence.append("api: " + ", ".join(sorted(hit)))
        for group in self.apis_all:
            hits = [alternatives & apis_lower for alternatives in group]
            if all(hits):
                evidence.append("apis: " + ", ".join(sorted(frozenset().union(*hits))))
        if self.commands:
            commands = prepared.commands
            if self.exclude_commands:
                exclusions = self._exclusion_lists
                commands = tuple((o, v) for o, v in commands if not any(x.matches(v) for x in exclusions))
            for phrases in self._command_lists:
                for original, views in commands:
                    if phrases.matches(views):
                        evidence.append(f"command: {original}")
                        break
        for parts in self.registry:
            for original, key in zip(behavior.registry_writes, prepared.registry_writes, strict=True):
                if all(part in key for part in parts):
                    evidence.append(f"registry: {original}")
                    break
        return [_printable(e) for e in evidence]


def _string_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise RuleError(f"{where}: expected a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise RuleError(f"{where}: expected non-empty strings, got {item!r}")
    return [item.strip() for item in value]


def _api_alternatives(entry: str, where: str) -> frozenset[str]:
    names = [n.strip() for n in entry.split("|")]
    for name in names:
        if not _API_RE.fullmatch(name):
            raise RuleError(f"{where}: not an API name: {name!r}")
    return frozenset(n.lower() for n in names)


def _phrases(entry: Any, where: str) -> tuple[str, ...]:
    items = [entry] if isinstance(entry, str) else entry
    phrases = _string_list(items, where)
    for phrase in phrases:
        if len(phrase) > 200:
            raise RuleError(f"{where}: phrase longer than 200 characters")
    return tuple(phrases)


def _phrase_lists(value: Any, where: str) -> list[tuple[str, ...]]:
    if not isinstance(value, list) or not value:
        raise RuleError(f"{where}: expected a non-empty list")
    return [_phrases(entry, where) for entry in value]


def _command_phrase_lists(value: Any, where: str) -> tuple[tuple[str, ...], ...]:
    lists = _phrase_lists(value, where)
    for phrase in (p for phrases in lists for p in phrases):
        if not normalize_command(phrase) or not normalize_command(phrase, delete_quotes=True):
            raise RuleError(f"{where}: phrase {phrase!r} is empty once quotes and ^ are removed")
    return tuple(lists)


def _parse_rule(raw: Any, where: str, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: each rule must be a mapping")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise RuleError(f"{where}: unknown keys: {', '.join(sorted(map(repr, unknown)))}")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not _RULE_ID_RE.fullmatch(rule_id):
        raise RuleError(f"{where}: 'id' must match {_RULE_ID_RE.pattern}")
    where = f"{where} ({rule_id})"
    technique = raw.get("technique")
    if not isinstance(technique, str) or not TECHNIQUE_ID_RE.fullmatch(technique):
        raise RuleError(f"{where}: 'technique' must be an ATT&CK technique ID such as T1059.001")
    confidence = raw.get("confidence", "medium")
    if confidence not in _CONFIDENCE:
        raise RuleError(f"{where}: 'confidence' must be one of {', '.join(_CONFIDENCE)}")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise RuleError(f"{where}: 'description' must be a string")
    references = _string_list(raw["references"], f"{where}: references") if "references" in raw else []

    match = raw.get("match")
    if not isinstance(match, dict) or not match:
        raise RuleError(f"{where}: 'match' must be a non-empty mapping")
    unknown = set(match) - _MATCH_KEYS
    if unknown:
        raise RuleError(f"{where}: unknown matchers: {', '.join(sorted(map(repr, unknown)))}")
    if "exclude_commands" in match and "commands" not in match:
        raise RuleError(f"{where}: 'exclude_commands' only applies together with 'commands'")

    signatures = _string_list(match["signatures"], f"{where}: signatures") if "signatures" in match else []
    for glob in signatures:
        if not _GLOB_RE.fullmatch(glob):
            raise RuleError(f"{where}: signature patterns may use letters, digits, _ . - * ?: {glob!r}")
    apis = (
        tuple(_api_alternatives(e, f"{where}: apis") for e in _string_list(match["apis"], f"{where}: apis"))
        if "apis" in match
        else ()
    )
    apis_all: list[tuple[frozenset[str], ...]] = []
    if "apis_all" in match:
        groups = match["apis_all"]
        if not isinstance(groups, list) or not groups:
            raise RuleError(f"{where}: apis_all: expected a non-empty list of lists")
        for group in groups:
            entries = _string_list(group, f"{where}: apis_all")
            apis_all.append(tuple(_api_alternatives(e, f"{where}: apis_all") for e in entries))
    commands = _command_phrase_lists(match["commands"], f"{where}: commands") if "commands" in match else ()
    exclude_commands = (
        _command_phrase_lists(match["exclude_commands"], f"{where}: exclude_commands")
        if "exclude_commands" in match
        else ()
    )
    registry = (
        [
            tuple(p.lower() for p in parts)
            for parts in _phrase_lists(match.get("registry"), f"{where}: registry")
        ]
        if "registry" in match
        else []
    )

    return Rule(
        id=rule_id,
        technique=technique,
        confidence=confidence,
        description=description.strip(),
        references=tuple(references),
        signatures=tuple(signatures),
        apis=apis,
        apis_all=tuple(apis_all),
        commands=commands,
        exclude_commands=exclude_commands,
        registry=tuple(registry),
        source=source,
    )


def _rule_files(path: Path | Traversable) -> list[Path | Traversable]:
    if path.is_file():
        return [path]
    return sorted((p for p in path.iterdir() if p.name.endswith((".yaml", ".yml"))), key=lambda p: p.name)


@dataclass
class RuleSet:
    rules: list[Rule]
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def empty(cls) -> RuleSet:
        return cls(rules=[])

    @classmethod
    def default(cls) -> RuleSet:
        ruleset = _default_ruleset()
        return cls(rules=list(ruleset.rules), warnings=list(ruleset.warnings))

    @classmethod
    def load(cls, paths: Iterable[str | Path | Traversable], catalog: AttackCatalog | None = None) -> RuleSet:
        """Load rule files or directories of ``*.yaml`` files.

        Structural problems raise :class:`RuleError`. Rules that reference
        revoked, deprecated or unknown techniques load with a warning so an
        ATT&CK update never stops analysis; ``ttprism validate-rules`` treats
        those warnings as failures.
        """
        catalog = catalog or AttackCatalog.default()
        rules: list[Rule] = []
        warnings: list[str] = []
        seen: dict[str, str] = {}
        for base in paths:
            base = Path(base) if isinstance(base, str) else base
            if not base.is_file() and not base.is_dir():
                raise RuleError(f"{base}: no such file or directory")
            for file in _rule_files(base):
                file_rules, file_warnings = _load_rule_file(file, catalog)
                for rule in file_rules:
                    if rule.id in seen:
                        raise RuleError(f"{file}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})")
                    seen[rule.id] = str(file)
                rules.extend(file_rules)
                warnings.extend(file_warnings)
        return cls(rules=rules, warnings=warnings)

    def extend(self, other: RuleSet) -> None:
        ids = {r.id for r in self.rules}
        for rule in other.rules:
            if rule.id in ids:
                raise RuleError(f"duplicate rule id {rule.id!r}")
        self.rules.extend(other.rules)
        self.warnings.extend(other.warnings)

    def evaluate(self, behavior: Behavior) -> list[tuple[Rule, list[str]]]:
        prepared = _PreparedBehavior(
            apis=frozenset(a.lower() for a in behavior.apis),
            commands=tuple((c, _command_views(c)) for c in behavior.commands),
            registry_writes=tuple(k.lower() for k in behavior.registry_writes),
        )
        results = []
        for rule in self.rules:
            evidence = rule.evaluate(behavior, prepared)
            if evidence:
                results.append((rule, evidence))
        return results


def _load_rule_file(file: Path | Traversable, catalog: AttackCatalog) -> tuple[list[Rule], list[str]]:
    if isinstance(file, Path):
        data = load_yaml_file(file, RuleError)
    else:
        data = load_yaml_text(file.read_text(encoding="utf-8"), str(file), RuleError)
    where = str(file)
    if not isinstance(data, dict) or set(data) - {"attack_version", "rules"}:
        raise RuleError(f"{where}: expected a mapping with 'attack_version' and 'rules'")
    version = data.get("attack_version")
    if not isinstance(version, str):
        raise RuleError(f"{where}: 'attack_version' must be a quoted string, e.g. \"19.2\"")
    if not _VERSION_RE.fullmatch(version):
        raise RuleError(f"{where}: 'attack_version' must be an ATT&CK version number such as \"19.2\"")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuleError(f"{where}: 'rules' must be a list")

    warnings = []
    if version != catalog.version:
        warnings.append(
            f"{where}: written for ATT&CK {version}, catalog is {catalog.version}; review the mappings"
        )
    rules = [_parse_rule(raw, f"{where}: rule {i + 1}", where) for i, raw in enumerate(raw_rules)]
    for rule in rules:
        technique = catalog.get(rule.technique)
        if technique is None:
            warnings.append(f"{where}: {rule.id}: {rule.technique} is not in ATT&CK {catalog.version}")
        elif technique.status == "revoked":
            replacement = catalog.resolve(rule.technique)
            hint = f"; use {replacement.id}" if replacement and replacement.id != rule.technique else ""
            warnings.append(f"{where}: {rule.id}: {rule.technique} is revoked{hint}")
        elif technique.status == "deprecated":
            warnings.append(f"{where}: {rule.id}: {rule.technique} is deprecated")
    return rules, warnings


def default_rules_path() -> Path | Traversable:
    """Bundled rules: inside the wheel, or ``rules/attack`` in a source checkout."""
    packaged = resources.files("ttprism").joinpath("rules/attack")
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[2] / "rules" / "attack"


@functools.cache
def _default_ruleset() -> RuleSet:
    return RuleSet.load([default_rules_path()])


# --------------------------------------------------------------------------- results


_CONFIDENCE_RANK = {c: i for i, c in enumerate(_CONFIDENCE)}


@dataclass
class _Entry:
    technique: Technique
    reported: bool = False
    rules: list[str] = field(default_factory=list)
    confidence: str | None = None
    evidence: list[str] = field(default_factory=list)
    original_ids: list[str] = field(default_factory=list)


class TechniqueAccumulator:
    """Merges techniques named by the input with techniques inferred by rules."""

    def __init__(self, catalog: AttackCatalog) -> None:
        self.catalog = catalog
        self._entries: dict[str, _Entry] = {}
        self.unknown: dict[str, int] = {}

    def _entry(self, technique_id: str) -> _Entry | None:
        technique = self.catalog.resolve(technique_id)
        if technique is None:
            self.unknown[technique_id] = self.unknown.get(technique_id, 0) + 1
            return None
        entry = self._entries.setdefault(technique.id, _Entry(technique))
        if technique.id != technique_id and technique_id not in entry.original_ids:
            entry.original_ids.append(technique_id)
        return entry

    def _add_evidence(self, entry: _Entry, evidence: Iterable[str]) -> None:
        for item in evidence:
            if len(entry.evidence) >= MAX_EVIDENCE:
                return
            if item not in entry.evidence:
                entry.evidence.append(item)

    def add_reported(self, technique_id: str, evidence: str) -> None:
        entry = self._entry(technique_id)
        if entry is not None:
            entry.reported = True
            self._add_evidence(entry, [_printable(evidence)])

    def add_rule(self, rule: Rule, evidence: list[str]) -> None:
        entry = self._entry(rule.technique)
        if entry is None:
            return
        if rule.id not in entry.rules:
            entry.rules.append(rule.id)
        if entry.confidence is None or _CONFIDENCE_RANK[rule.confidence] > _CONFIDENCE_RANK[entry.confidence]:
            entry.confidence = rule.confidence
        self._add_evidence(entry, evidence)

    def results(self) -> list[TechniqueMatch]:
        return [
            TechniqueMatch(
                technique_id=e.technique.id,
                name=e.technique.name,
                tactics=e.technique.tactics,
                status=e.technique.status,
                reported=e.reported,
                rules=tuple(e.rules),
                confidence=e.confidence,
                evidence=tuple(e.evidence),
                original_ids=tuple(e.original_ids),
            )
            for _, e in sorted(self._entries.items())
        ]
