"""The command matcher of TTPrism 0.1 before it was indexed: the reference implementation.

FROZEN REFERENCE IMPLEMENTATION. Change it only together with a deliberate change to what command
phrases match (their semantics), never to follow a refactoring or an optimisation of ttprism.attack.

``ttprism.attack`` matches command phrases with an index over the words of each command; this module
keeps the straightforward matcher it replaced, unchanged, so that tests can check that both give
the same result for any rule set and behaviour. It is not used by the package.
"""

from __future__ import annotations

import bisect
import functools
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from ttprism.attack import Behavior, Rule, RuleSet, _printable

_CommandViews = tuple[str, str]
# (as reported, normalised views of the whole line, normalised views of each chained command)
# The views of the commands of a chained line joined by "\n", and where each one starts, for the
# spaced and the joined view: finding a phrase there tells which commands can match it.
_ChainIndex = tuple[str, list[int], str, list[int]]
_PreparedCommand = tuple[str, _CommandViews, tuple[_CommandViews, ...], _ChainIndex | None]


@dataclass(frozen=True)
class _PreparedBehavior:
    """Case-folded views of a Behavior, computed once per analysis rather than per rule."""

    apis: frozenset[str]
    commands: tuple[_PreparedCommand, ...]
    registry_writes: tuple[str, ...]
    # (id of an exclusion list, line number) -> commands it matches; rules share exclusion lists.
    excluded: dict[tuple[int, int], set[int]] = field(default_factory=dict, compare=False)


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
_SWITCH_QUOTE_RE = re.compile(r'(?:(?<![\w/:])|(?<=cmd)|(?<=cmd\.exe)|(?<=/\w)|(?<=:on)|(?<=:off))(/[ckr])"')
# cmd.exe takes switches glued to the command or to each other: "del/f/q", "cmd /q/c",
# "ipconfig/flushdns", "c:\\windows\\system32\\cmd.exe/c". Such a word is split, so that every switch
# starts a word. URLs are left alone: their slashes follow a host, or a path with "." or ":".
_GLUED_SWITCHES_RE = re.compile(
    r"(?<![^\s&|\\])([a-z0-9_]{1,32}(?:\.exe)?)?((?:/[a-z0-9?][a-z0-9?:]{0,31}){1,16})(?![^\s&|])"
)
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
    command = _CARET_RE.sub("", command.lower())
    if delete_quotes:
        command = _SWITCH_QUOTE_RE.sub(r"\1 ", command).translate(_QUOTES_DELETED)
    else:
        command = command.translate(_QUOTES_AS_SPACES)
    command = _GLUED_SWITCHES_RE.sub(_split_switches, command)
    return _SPACE_RE.sub(" ", command).strip()


def _split_switches(match: re.Match[str]) -> str:
    return (match.group(1) or "") + match.group(2).replace("/", " /")


def _command_views(command: str) -> _CommandViews:
    spaced = normalize_command(command)
    joined = normalize_command(command, delete_quotes=True)
    # Reuse the object when both views agree so matching can skip the second one.
    return (spaced, spaced if joined == spaced else joined)


def _prepare_command(command: str) -> _PreparedCommand:
    views = _command_views(command)
    parts = _split_chain(command)
    if len(parts) <= 1:
        return command, views, (views,), None
    chain = tuple(_command_views(p) for p in parts)
    return command, views, chain, _chain_index(chain)


def _chain_index(chain: tuple[_CommandViews, ...]) -> _ChainIndex:
    def with_starts(texts: list[str]) -> tuple[str, list[int]]:
        starts, total = [], 0
        for text in texts:
            starts.append(total)
            total += len(text) + 1
        return "\n".join(texts), starts

    spaced, spaced_starts = with_starts([views[0] for views in chain])
    if all(views[1] is views[0] for views in chain):
        return spaced, spaced_starts, spaced, spaced_starts
    joined, joined_starts = with_starts([views[1] for views in chain])
    return spaced, spaced_starts, joined, joined_starts


def _split_chain(command: str) -> list[str]:
    """The commands cmd.exe runs one after another for "a & b", "a && b" or "a || b".

    "^&" and an "&" in double quotes are literal, except in the quotes that "cmd /c" strips. A single
    "|" is a pipe within one command, so a PowerShell pipeline stays together, and a line break may
    continue a PowerShell command, so it does not split either. At most MAX_CHAINED_COMMANDS
    commands; the rest stays in the last one.
    """
    parts: list[str] = []
    start = index = 0
    quoted = False
    while index < len(command) and len(parts) < MAX_CHAINED_COMMANDS - 1:
        char = command[index]
        if char == '"':
            if quoted or not _CMD_QUOTE_RE.search(command, max(0, index - 16), index):
                quoted = not quoted
        elif quoted:
            pass
        elif char == "^":
            index += 1  # escapes the next character
        elif char == "&" or command[index : index + 2] == "||":
            size = 2 if command[index : index + 2] in ("&&", "||") else 1
            parts.append(command[start:index])
            start = index = index + size
            continue
        index += 1
    parts.append(command[start:])
    return [part for part in parts if part.strip()]


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
    @functools.cache
    def compile(cls, phrases: tuple[str, ...]) -> _PhraseList:
        """Compiled once per distinct list, so that rules with the same list share it."""

        def view(delete_quotes: bool) -> _Phrases:
            normalised = (normalize_command(p, delete_quotes=delete_quotes) for p in phrases)
            return tuple((_phrase_literal(p), _phrase_re(p)) for p in normalised)

        spaced, joined = view(False), view(True)
        return cls(spaced, spaced if joined == spaced else joined)

    def matches_any(self, chain: tuple[_CommandViews, ...], index: _ChainIndex) -> bool:
        """:meth:`matches` for any command of a chain."""
        return any(self.matches(chain[part]) for part in self._candidates(index))

    def matching(self, chain: tuple[_CommandViews, ...], index: _ChainIndex) -> set[int]:
        """The positions of the commands of a chain that :meth:`matches`."""
        return {part for part in self._candidates(index) if self.matches(chain[part])}

    def _candidates(self, index: _ChainIndex) -> Iterator[int]:
        """The commands of a chain that contain the first phrase, each once.

        The cost depends on how often that phrase occurs, not on how many commands there are.
        """
        spaced, spaced_starts, joined, joined_starts = index
        tried: set[int] = set()
        views = ((self.spaced[0][0], spaced, spaced_starts), (self.joined[0][0], joined, joined_starts))
        for literal, text, starts in views:
            position = text.find(literal)
            while position != -1:
                part = bisect.bisect_right(starts, position) - 1
                if part not in tried:
                    tried.add(part)
                    yield part
                if part + 1 == len(starts):
                    break
                position = text.find(literal, starts[part + 1])
            if joined is spaced and self.joined is self.spaced:
                break

    def matches(self, views: _CommandViews) -> bool:
        """Every phrase occurs in the same view of the command line."""
        spaced, joined = views
        if _contains_all(self.spaced, spaced):
            return True
        if joined is spaced and self.joined is self.spaced:
            return False
        return _contains_all(self.joined, joined)


def _compiled(rule: Rule) -> tuple[tuple[_PhraseList, ...], ...]:
    return tuple(
        tuple(_PhraseList.compile(phrases) for phrases in lists)
        for lists in (rule.commands, rule.chained_commands, rule.exclude_commands)
    )


def _evaluate_rule(rule: Rule, behavior: Behavior, prepared: _PreparedBehavior) -> list[str]:
    command_lists, chained_lists, exclusion_lists = _compiled(rule)
    evidence: list[str] = []
    for name in behavior.signatures:
        if any(p.fullmatch(name) for p in rule._signature_res):
            evidence.append(f"signature: {name}")
    apis_lower = prepared.apis
    for alternatives in rule.apis:
        hit = alternatives & apis_lower
        if hit:
            evidence.append("api: " + ", ".join(sorted(hit)))
    for group in rule.apis_all:
        hits = [alternatives & apis_lower for alternatives in group]
        if all(hits):
            evidence.append("apis: " + ", ".join(sorted(frozenset().union(*hits))))
    if rule.commands or rule.chained_commands:
        # Each command of a chained line is matched on its own; an exclusion drops only the
        # commands it matches. chained_commands match the whole line, unless a part is excluded.
        lines: Iterable[tuple[str, _CommandViews, tuple[_CommandViews, ...], _ChainIndex | None, bool]]
        if rule.exclude_commands:
            exclusions = exclusion_lists
            lines = []
            for number, (original, views, chain, index) in enumerate(prepared.commands):
                if index is None:
                    excluded = {0} if any(x.matches(chain[0]) for x in exclusions) else set()
                else:
                    excluded = set()
                    for exclusion in exclusions:
                        memo = (id(exclusion), number)
                        if (matched := prepared.excluded.get(memo)) is None:
                            matched = prepared.excluded[memo] = exclusion.matching(chain, index)
                        excluded |= matched
                if excluded:
                    chain = tuple(c for part, c in enumerate(chain) if part not in excluded)
                    index = _chain_index(chain) if len(chain) > 1 else None
                lines.append((original, views, chain, index, not excluded))
        else:
            lines = [(*command, True) for command in prepared.commands]
        for phrases in command_lists:
            for original, _, chain, index, _ in lines:
                if index is not None:
                    found = phrases.matches_any(chain, index)
                else:  # one command, or none left after exclusions
                    found = bool(chain) and phrases.matches(chain[0])
                if found:
                    evidence.append(f"command: {original}")
                    break
        for phrases in chained_lists:
            for original, views, _, _, whole in lines:
                if whole and phrases.matches(views):
                    evidence.append(f"command: {original}")
                    break
    for parts in rule.registry:
        for original, key in zip(behavior.registry_writes, prepared.registry_writes, strict=True):
            if all(part in key for part in parts):
                evidence.append(f"registry: {original}")
                break
    return [_printable(e) for e in evidence]


def reference_evaluate(rules: RuleSet, behavior: Behavior) -> list[tuple[Rule, list[str]]]:
    """``RuleSet.evaluate`` as it was before the command index."""
    prepared = _PreparedBehavior(
        apis=frozenset(a.lower() for a in behavior.apis),
        commands=tuple(_prepare_command(c) for c in behavior.commands),
        registry_writes=tuple(k.lower() for k in behavior.registry_writes),
    )
    results = []
    for rule in rules.rules:
        evidence = _evaluate_rule(rule, behavior, prepared)
        if evidence:
            results.append((rule, evidence))
    return results
