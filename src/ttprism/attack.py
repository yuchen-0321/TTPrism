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
                                                          # one command contains the phrase
                                                          # (or every phrase of an inner list)
          chained_commands: [["ping", "del"]]             # the same, over all commands chained
                                                          # on one line with & && ||
          exclude_commands: ["/?"]                        # commands that match this (same
                                                          # syntax) are ignored by `commands`
          registry: ['\\currentversion\\run\\']          # a written registry key contains this
                                                          # (or every part of an inner list)

A command line is split into the commands cmd.exe chains with &, && and ||.
Commands and phrases are lower-cased, cmd.exe caret escapes are removed,
Unicode dashes become "-", glued switches are split and whitespace is
collapsed. Each command is then matched in two views, one with quotes turned
into spaces and one with quotes deleted (cmd.exe runs s"c"htasks as
schtasks); an inner list matches if all its phrases occur in the same view of
one command. A phrase must not be part of a longer word: where it starts or
ends with a letter, digit or "_", the neighbouring character must not be one,
and a switch ("-enc", "/c") must be a word of its own. Registry patterns are
plain case-insensitive substrings. rules/attack/README.md has the details.

Phrase lists are filed under the word runs every match of them contains, so a
command is tested only against the lists whose words it has; the result is the
same as testing every list (tests/reference_matcher.py keeps that matcher).
"""

from __future__ import annotations

import fnmatch
import functools
import json
import re
import string
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
_MATCH_KEYS = {
    "signatures",
    "apis",
    "apis_all",
    "commands",
    "chained_commands",
    "exclude_commands",
    "registry",
}
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


# Matches of the rules' command phrase lists in one Behavior, keyed by id() of the shared, cached
# _PhraseList: the (line, command) pairs each list matches, and for chained_commands lists the
# lines it matches as a whole, both in order.
_CommandHits = dict[int, list[tuple[int, int]]]
_LineHits = dict[int, list[int]]


@dataclass(frozen=True)
class _PreparedBehavior:
    """Case-folded views of a Behavior and its command matches, computed once per analysis."""

    apis: frozenset[str]
    registry_writes: tuple[str, ...]
    command_hits: _CommandHits
    line_hits: _LineHits


MAX_CHAINED_COMMANDS = 32
# The quote right after "cmd /c" (or /k, /r) is one that cmd.exe strips: what it encloses is a
# command line, where "&" chains commands.
_CMD_QUOTE_RE = re.compile(r'(?:\A|[\s"\\])(?:cmd(?:\.exe)?)?/[ckr]\s*\Z', re.IGNORECASE)
# "<arg>" in a phrase stands for one argument: "net start <arg>" matches "net start updsvc" but not a
# bare "net start", "net start > x", "net start 2>nul" or "('net start')"; "net share <arg>=" matches
# "net share C=C:\\". The argument cannot start like a switch or a redirection, and is bounded.
_ARG = "<arg>"
_ARG_RE = r"(?![0-9]?>)[^\s&|<>/;()=\-][^\s&|<>;()=]{0,259}"
# cmd /c"s""chtasks ..." runs s""chtasks: the quote after the switch must not glue the command to it.
# The pattern starts with the "/", so the regex engine can skip to the next one; the lookbehinds
# look at what comes before it.
_SWITCH_QUOTE_RE = re.compile(
    r'/(?:(?<![\w/:]/)|(?<=cmd/)|(?<=cmd\.exe/)|(?<=/\w/)|(?<=:on/)|(?<=:off/))([ckr])"'
)
# cmd.exe takes switches glued to the command or to each other: "del/f/q", "cmd /q/c",
# "ipconfig/flushdns", "c:\\windows\\system32\\cmd.exe/c". Such a word is split, so that every switch
# starts a word. URLs are left alone: their slashes follow a host, or a path with "." or ":".
_GLUED_SWITCHES_RE = re.compile(
    r"(?<![^\s&|\\])([a-z0-9_]{1,32}(?:\.exe)?)?((?:/[a-z0-9?][a-z0-9?:]{0,31}){1,16})(?![^\s&|])"
)
# The last "/" of a match of _GLUED_SWITCHES_RE that changes anything: after a character of a name
# or a switch, or after "&", "|" or "\\", and followed by a switch that ends the match. Only words
# that contain one can change.
_GLUED_SLASH_RE = re.compile(r"/(?<=[a-z0-9_?:&|\\]/)[a-z0-9?][a-z0-9?:]{0,31}+(?![^\s&|])")
# _GLUED_SWITCHES_RE without its boundaries, for one piece of a word between separators.
_GLUED_WORD_RE = re.compile(r"([a-z0-9_]{1,32}(?:\.exe)?)?((?:/[a-z0-9?][a-z0-9?:]{0,31}){1,16})")
_SEPARATOR_RE = re.compile(r"([&|\\])")
# A run of quotes between two characters that are neither whitespace nor quotes, which deleting the
# quotes joins: only then can the joined view differ from the spaced one. Longer runs count too.
_JOINING_QUOTE_RES = (
    re.compile(r'"(?<=[^\s"\']")(?:["\']{0,64}(?=[^\s"\'])|["\']{64})'),
    re.compile(r"'(?<=[^\s\"']')(?:[\"']{0,64}(?=[^\s\"'])|[\"']{64})"),
)
# The same between two word characters: only then does deleting the quotes join two word runs.
_MERGING_QUOTE_RES = (
    re.compile(r'"(?<=\w")(?:["\']{0,64}(?=\w)|["\']{64})'),
    re.compile(r"'(?<=\w')(?:[\"']{0,64}(?=\w)|[\"']{64})"),
)
_CARET_RE = re.compile(r"\^(?=.)")
_WORD_RE = re.compile(r"\w")
_WORD_RUN_RE = re.compile(r"\w{1,1000}")
_NEVER_RE = re.compile(r"(?!)")
_DASHES = {"\u2013": "-", "\u2014": "-", "\u2015": "-"}  # PowerShell reads these as "-"
_QUOTES_AS_SPACES = str.maketrans({**_DASHES, '"': " ", "'": " "})
_QUOTES_DELETED = str.maketrans({**_DASHES, '"': None, "'": None})
# The same for ASCII text, where lower-casing is one more entry in the table. These are byte tables:
# bytes.translate is several times faster than str.translate.
_ASCII_LOWER = bytes.maketrans(string.ascii_uppercase.encode(), string.ascii_lowercase.encode())
_ASCII_QUOTES_AS_SPACES = bytes.maketrans(
    (string.ascii_uppercase + "\"'").encode(), (string.ascii_lowercase + "  ").encode()
)
_ASCII_NON_WORD = str.maketrans({c: " " for c in map(chr, range(128)) if not _WORD_RE.match(c)})


def normalize_command(command: str, *, delete_quotes: bool = False) -> str:
    """Lower-case, drop cmd.exe carets, fold Unicode dashes to "-", split glued switches and
    collapse whitespace.

    Quotes become spaces, or are deleted with ``delete_quotes``.
    """
    if "^" in command:
        command = _CARET_RE.sub("", command)
    return _joined_view(command) if delete_quotes else _spaced_view(command)


def _spaced_view(command: str) -> str:
    """:func:`normalize_command` of a command without carets."""
    return _split_glued_switches(" ".join(_spaced_words(command)))


def _spaced_words(command: str) -> list[str]:
    """The words of a command without carets, lower-cased, with quotes as spaces."""
    if command.isascii():
        return command.encode("ascii").translate(_ASCII_QUOTES_AS_SPACES).decode("ascii").split()
    return command.lower().translate(_QUOTES_AS_SPACES).split()


def _joined_view(command: str) -> str:
    """:func:`normalize_command` with ``delete_quotes`` of a command without carets."""
    if command.isascii():
        if '"' in command:
            command = _SWITCH_QUOTE_RE.sub(r"/\1 ", _ascii_lower_deleting(command, b""))
        text = _ascii_lower_deleting(command, b"\"'")
    else:
        command = command.lower()
        if '"' in command:
            command = _SWITCH_QUOTE_RE.sub(r"/\1 ", command)
        text = command.translate(_QUOTES_DELETED)
    return _split_glued_switches(" ".join(text.split()))


def _ascii_lower_deleting(text: str, delete: bytes) -> str:
    """ASCII ``text`` lower-cased, without the characters in ``delete``."""
    return text.encode("ascii").translate(_ASCII_LOWER, delete).decode("ascii")


def _split_glued_switches(text: str) -> str:
    """Apply _GLUED_SWITCHES_RE to ``text``, whose words are separated by single spaces.

    A match never spans a space, so each word is rewritten on its own, and only words with a slash
    that the regex can split off can change.
    """
    found = _GLUED_SLASH_RE.search(text)
    pieces: list[str] = []
    done = 0
    while found is not None:
        start = text.rfind(" ", 0, found.start()) + 1
        end = text.find(" ", found.end())
        if end == -1:
            end = len(text)
        if _SEPARATOR_RE.search(text, start, end) is None:
            # The usual case: the match, if any, is the whole word, and its name has no "/".
            match = _GLUED_WORD_RE.fullmatch(text, start, end)
            word = text[start:end].replace("/", " /").lstrip(" ") if match else None
        else:
            word = _split_glued_word(text[start:end])
        if word is not None:
            pieces += (text[done:start], word)
            done = end
        found = _GLUED_SLASH_RE.search(text, end)
    if not pieces:
        return text
    pieces.append(text[done:])
    return "".join(pieces)


def _split_glued_word(word: str) -> str | None:
    """``word`` (no whitespace) with _GLUED_SWITCHES_RE applied, or None if that changes nothing.

    A match starts after "&", "|", "\\" or at the start, ends before "&", "|" or at the end, and
    has none of these inside: it is a whole piece of the word between them.
    """
    pieces = _SEPARATOR_RE.split(word) if "&" in word or "|" in word or "\\" in word else [word]
    changed = False
    for i in range(0, len(pieces), 2):
        if "/" in pieces[i] and (i + 1 == len(pieces) or pieces[i + 1] != "\\"):
            match = _GLUED_WORD_RE.fullmatch(pieces[i])
            if match:
                pieces[i] = _split_switches(match)
                changed = True
    # A space put before a leading "/" collapses with the one before the word.
    return " ".join("".join(pieces).split()) if changed else None


def _split_switches(match: re.Match[str]) -> str:
    return (match.group(1) or "") + match.group(2).replace("/", " /")


def _split_chain(command: str) -> list[str]:
    """The commands cmd.exe runs one after another for "a & b", "a && b" or "a || b".

    "^&" and an "&" in double quotes are literal, except in the quotes that "cmd /c" strips. A single
    "|" is a pipe within one command, so a PowerShell pipeline stays together, and a line break may
    continue a PowerShell command, so it does not split either. At most MAX_CHAINED_COMMANDS
    commands; the rest stays in the last one.
    """
    if "&" not in command and "||" not in command:
        return [command] if command.strip() else []
    parts: list[str] = []
    start = index = 0
    quoted = False
    following = dict.fromkeys('"^&|', -2)  # where each character occurs next; -1: nowhere

    def next_of(chars: str, index: int) -> int:
        best = -1
        for char in chars:
            position = following[char]
            if position != -1 and position < index:
                position = following[char] = command.find(char, index)
            if position != -1 and (best == -1 or position < best):
                best = position
        return best

    while len(parts) < MAX_CHAINED_COMMANDS - 1:
        # Inside quotes only the closing quote counts.
        index = next_of('"' if quoted else '"^&|', index)
        if index == -1:
            break
        char = command[index]
        if char == '"':
            if quoted or not _CMD_QUOTE_RE.search(command, max(0, index - 16), index):
                quoted = not quoted
            index += 1
        elif char == "^":
            index += 2  # escapes the next character
        elif char == "&" or command.startswith("||", index):
            size = 2 if command.startswith(("&&", "||"), index) else 1
            parts.append(command[start:index])
            start = index = index + size
        else:
            index += 1  # a single "|"
    parts.append(command[start:])
    return [part for part in parts if part.strip()]


def _word_runs(text: str) -> list[str]:
    """The runs of word characters in ``text`` (runs over 1,000 characters come in pieces)."""
    if text.isascii():
        return text.translate(_ASCII_NON_WORD).split()
    return _WORD_RUN_RE.findall(text)


class _View:
    """A command in the two normalised views that phrases are matched in.

    The joined view (quotes deleted) is computed only when a phrase list needs it, and is the same
    object as the spaced view when the two are equal.
    """

    __slots__ = (
        "_command",
        "_deleted",
        "_joined",
        "_words",
        "joined_memo",
        "merges",
        "same",
        "spaced",
        "spaced_memo",
    )

    def __init__(self, command: str) -> None:
        if "^" in command:
            command = _CARET_RE.sub("", command)
        self._command = command
        self._words = _spaced_words(command)
        self.spaced = _split_glued_switches(" ".join(self._words))
        # Deleting a quote instead of spacing it changes nothing next to whitespace or at either
        # end, and joins word runs only between two word characters.
        quoted = '"' in command or "'" in command
        lowered = command if command.isascii() or not quoted else command.lower()
        self.same = not quoted or not any(regex.search(lowered) for regex in _JOINING_QUOTE_RES)
        self.merges = not self.same and any(regex.search(lowered) for regex in _MERGING_QUOTE_RES)
        self._joined: str | None = self.spaced if self.same else None
        self._deleted: str | None = None
        # Phrase results in each view, by id of the phrase regex (see _contains_all).
        self.spaced_memo: dict[int, bool] = {}
        self.joined_memo: dict[int, bool] = {}

    def spaced_runs(self) -> list[str]:
        """The word runs of the spaced view, some more than once."""
        words = self._words
        # Long commands repeat words; splitting the glued switches adds no runs.
        return _word_runs(" ".join(set(words)) if len(words) > 64 else self.spaced)

    @property
    def joined(self) -> str:
        if self._joined is None:
            joined = _joined_view(self._command)
            self._joined = self.spaced if joined == self.spaced else joined
        return self._joined

    @property
    def deleted(self) -> str:
        """The command lower-cased, with quotes deleted and dashes folded: every run of
        non-space characters of the joined view occurs in it."""
        if self._deleted is None:
            command = self._command
            if command.isascii():
                self._deleted = _ascii_lower_deleting(command, b"\"'")
            else:
                self._deleted = command.lower().translate(_QUOTES_DELETED)
        return self._deleted


def _phrase_re(phrase: str) -> re.Pattern[str]:
    """Regex for a normalised phrase that is not part of a longer word ("_" counts as a letter).

    Same as (?<!\\w)phrase(?!\\w), but with the literal first so the regex engine uses its fast
    literal search. A phrase starting with "-" or "/" is a switch and must start a word: it follows
    whitespace or the start of the command, so "/en" in a URL path or "-encoded" in "url-encoded"
    does not match. "<arg>" stands for one argument. The phrase is escaped and every repetition is
    bounded, so matching is linear. "" never matches.
    """
    pieces = phrase.split(_ARG)
    text = pieces[0]
    if not text:
        return _NEVER_RE
    literal = re.escape(text)
    if text[0] in "-/":
        left = rf"(?<!\S{literal})"
    elif _WORD_RE.match(text[0]):
        left = rf"(?<!\w{literal})"
    else:
        left = ""
    rest = "".join(_ARG_RE + re.escape(piece) for piece in pieces[1:])
    last = pieces[-1]
    if len(pieces) == 1 and text[0] in "-/" and _WORD_RE.match(text[-1]):
        right = r"(?![^\s:])"  # a switch ends a word: not "/en" in "'/en-us/'"
    else:
        right = r"(?!\w)" if last and _WORD_RE.match(last[-1]) else ""
    return re.compile(literal + left + rest + right)


def _phrase_literal(phrase: str) -> str:
    """The text before the first "<arg>": a substring every match contains."""
    return phrase.split(_ARG, 1)[0].strip()


def _phrase_anchors(phrase: str) -> set[str]:
    """Runs of word characters that every match of a normalised phrase has as whole runs.

    These are the runs before the first "<arg>": _phrase_re keeps a word character from coming
    right before the phrase, a non-word character inside the phrase ends a run, and so does the
    end of a phrase without "<arg>" (which must be followed by a non-word character there). The
    run just before an "<arg>" can continue into the argument, so it is left out.
    """
    text, arg, _ = phrase.partition(_ARG)
    return {m.group() for m in _WORD_RUN_RE.finditer(text) if m.end() < len(text) or not arg}


_Phrases = tuple[tuple[str, re.Pattern[str]], ...]  # (normalised phrase, its regex)


def _contains_all(phrases: _Phrases, text: str, memo: dict[int, bool]) -> bool:
    """Every phrase occurs in ``text``. ``memo`` keeps the result for each phrase regex, since lists
    share phrases."""
    for phrase, pattern in phrases:
        found = memo.get(id(pattern))
        if found is None:
            # The substring test is much faster than a regex search and rules out most phrases.
            found = memo[id(pattern)] = phrase in text and pattern.search(text) is not None
        if not found:
            return False
    return True


@dataclass(frozen=True, eq=False)
class _PhraseList:
    """One inner list of command phrases, compiled for both command views."""

    spaced: _Phrases
    joined: _Phrases  # the same object as ``spaced`` unless a phrase contains quotes
    # Word runs that a view must have for the list to match it (see _phrase_anchors).
    spaced_anchors: frozenset[str]
    joined_anchors: frozenset[str]
    # The words of the joined phrases' literals: each occurs in a command they match, with its
    # quotes deleted (see _View.deleted).
    joined_words: tuple[str, ...]

    @classmethod
    @functools.cache
    def compile(cls, phrases: tuple[str, ...]) -> _PhraseList:
        """Compiled once per distinct list, so that rules with the same list share it."""

        def view(delete_quotes: bool) -> tuple[_Phrases, frozenset[str]]:
            normalised = [normalize_command(p, delete_quotes=delete_quotes) for p in phrases]
            compiled = tuple((_phrase_literal(p), _phrase_re(p)) for p in normalised)
            return compiled, frozenset().union(*map(_phrase_anchors, normalised))

        spaced, spaced_anchors = view(False)
        joined, joined_anchors = view(True)
        if joined == spaced:
            joined, joined_anchors = spaced, spaced_anchors
        words = tuple(dict.fromkeys(word for literal, _ in joined for word in literal.split()))
        return cls(spaced, joined, spaced_anchors, joined_anchors, words)

    def matches(self, view: _View) -> bool:
        """Every phrase occurs in the same view of the command."""
        if _contains_all(self.spaced, view.spaced, view.spaced_memo):
            return True
        if view.same:
            return self.joined is not self.spaced and _contains_all(
                self.joined, view.spaced, view.spaced_memo
            )
        # Before computing the joined view: each word of each phrase must occur in the command.
        deleted = view.deleted
        if not all(word in deleted for word in self.joined_words):
            return False
        joined = view.joined
        if joined is view.spaced:
            return self.joined is not self.spaced and _contains_all(self.joined, joined, view.spaced_memo)
        return _contains_all(self.joined, joined, view.joined_memo)


class _ListIndex:
    """Phrase lists filed under one of their anchors, so a command is only tested against lists
    whose anchors all occur in it."""

    def __init__(self, lists: Iterable[_PhraseList]) -> None:
        self.lists = tuple(dict.fromkeys(lists))
        self.anchors = frozenset().union(*(p.spaced_anchors | p.joined_anchors for p in self.lists))
        self._filed: dict[str, list[tuple[frozenset[str], _PhraseList]]] = {}
        always: dict[int, _PhraseList] = {}
        for phrases in self.lists:
            # Under the anchors of the spaced phrases, and of the joined ones if they differ.
            for anchors in dict.fromkeys((phrases.spaced_anchors, phrases.joined_anchors)):
                if anchors:
                    # The longest anchor: short ones ("c", "exe") occur in most commands.
                    key = max(sorted(anchors), key=len)
                    self._filed.setdefault(key, []).append((anchors, phrases))
                else:
                    always[id(phrases)] = phrases
        self._keys = frozenset(self._filed)
        self._always = tuple(always.values())

    def matching(self, command: str) -> list[_PhraseList]:
        """The lists that match ``command``."""
        view = _View(command)
        candidates = self._candidates(self.anchors.intersection(view.spaced_runs()), {})
        if view.merges:
            # The joined view has word runs the spaced one does not.
            self._candidates(self.anchors.intersection(_word_runs(view.joined)), candidates)
        return [p for p in candidates.values() if p.matches(view)]

    def _candidates(self, present: frozenset[str], into: dict[int, _PhraseList]) -> dict[int, _PhraseList]:
        for key in self._keys.intersection(present):
            for anchors, phrases in self._filed[key]:
                if anchors <= present:
                    into[id(phrases)] = phrases
        for phrases in self._always:
            into[id(phrases)] = phrases
        return into


class _CommandMatcher:
    """Finds the lines and chained commands that the phrase lists of a set of rules match."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        rules = list(rules)
        command_lists = [p for r in rules for p in (*r._command_lists, *r._exclusion_lists)]
        line_lists = [p for r in rules for p in r._chained_lists]
        self._commands = _ListIndex(command_lists)
        self._lines = _ListIndex(line_lists)
        self._single = _ListIndex([*command_lists, *line_lists])  # a line of one command

    def match(self, commands: Iterable[str]) -> tuple[_CommandHits, _LineHits]:
        command_hits: _CommandHits = {}
        line_hits: _LineHits = {}
        # Reports repeat commands; the result depends only on the text.
        single: dict[str, list[_PhraseList]] = {}
        chained: dict[str, list[_PhraseList]] = {}
        for number, line in enumerate(commands):
            parts = _split_chain(line)
            if len(parts) <= 1:
                found = single.get(line)
                if found is None:
                    found = single[line] = self._single.matching(line)
                for phrases in found:
                    command_hits.setdefault(id(phrases), []).append((number, 0))
                    line_hits.setdefault(id(phrases), []).append(number)
                continue
            for part_number, part in enumerate(parts):
                found = chained.get(part)
                if found is None:
                    found = chained[part] = self._commands.matching(part)
                for phrases in found:
                    command_hits.setdefault(id(phrases), []).append((number, part_number))
            if self._lines.lists:
                for phrases in self._line_matches(line):
                    line_hits.setdefault(id(phrases), []).append(number)
        return command_hits, line_hits

    def _line_matches(self, line: str) -> list[_PhraseList]:
        """The chained_commands lists that match a line of several commands as a whole."""
        # Every word run of either view of the line occurs in the line with carets and quotes
        # deleted: a cheap test before normalising the whole line again.
        text = _CARET_RE.sub("", line) if "^" in line else line
        if text.isascii():
            text = _ascii_lower_deleting(text, b"\"'")
        else:
            text = text.lower().translate(_QUOTES_DELETED)
        candidates = [
            p
            for p in self._lines.lists
            if all(a in text for a in p.spaced_anchors) or all(a in text for a in p.joined_anchors)
        ]
        if not candidates:
            return []
        view = _View(line)
        return [p for p in candidates if p.matches(view)]


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
    chained_commands: tuple[tuple[str, ...], ...] = ()
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
    def _chained_lists(self) -> tuple[_PhraseList, ...]:
        return tuple(_PhraseList.compile(phrases) for phrases in self.chained_commands)

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
        if self.commands or self.chained_commands:
            # Each command of a chained line is matched on its own; an exclusion drops only the
            # commands it matches. chained_commands match the whole line, unless a part is excluded.
            excluded: set[tuple[int, int]] = set()
            for exclusion in self._exclusion_lists:
                excluded.update(prepared.command_hits.get(id(exclusion), ()))
            for phrases in self._command_lists:
                for line, part in prepared.command_hits.get(id(phrases), ()):
                    if (line, part) not in excluded:
                        evidence.append(f"command: {behavior.commands[line]}")
                        break
            if self._chained_lists:
                broken = {line for line, _ in excluded}
                for phrases in self._chained_lists:
                    for line in prepared.line_hits.get(id(phrases), ()):
                        if line not in broken:
                            evidence.append(f"command: {behavior.commands[line]}")
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
        for normalised in (normalize_command(phrase), normalize_command(phrase, delete_quotes=True)):
            if not normalised.replace(_ARG, "").strip():
                raise RuleError(f"{where}: phrase {phrase!r} is empty once quotes and ^ are removed")
            if not _phrase_literal(normalised):
                raise RuleError(f"{where}: phrase {phrase!r}: '<arg>' cannot start a phrase")
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
    if "exclude_commands" in match and "commands" not in match and "chained_commands" not in match:
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
    chained_commands = (
        _command_phrase_lists(match["chained_commands"], f"{where}: chained_commands")
        if "chained_commands" in match
        else ()
    )
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
        chained_commands=chained_commands,
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
    # The command matcher for the rules it was built from (kept, so their ids stay unique).
    _matcher: tuple[tuple[Rule, ...], _CommandMatcher] | None = field(
        default=None, init=False, repr=False, compare=False
    )

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
        rules = tuple(self.rules)
        if (
            self._matcher is None
            or len(self._matcher[0]) != len(rules)
            or any(a is not b for a, b in zip(self._matcher[0], rules, strict=True))
        ):
            self._matcher = (rules, _CommandMatcher(rules))
        command_hits, line_hits = self._matcher[1].match(behavior.commands)
        prepared = _PreparedBehavior(
            apis=frozenset(a.lower() for a in behavior.apis),
            registry_writes=tuple(k.lower() for k in behavior.registry_writes),
            command_hits=command_hits,
            line_hits=line_hits,
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
