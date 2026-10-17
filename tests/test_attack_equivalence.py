"""The indexed command matcher gives the same results as the straightforward one it replaced.

``reference_matcher`` keeps the matcher of TTPrism 0.1 before the index: every phrase list tried on
both views of every command. The index only decides which lists to try, and normalisation was
rewritten with faster string operations; neither may change a result.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

import command_corpus
import reference_matcher
from ttprism.attack import Behavior, Rule, RuleSet, _split_chain, normalize_command

BUNDLED = RuleSet.default()

# Words of the bundled rules and the characters that normalisation and chaining treat specially.
RULE_WORDS = sorted(
    {
        word
        for rule in BUNDLED.rules
        for lists in (rule.commands, rule.chained_commands, rule.exclude_commands)
        for phrases in lists
        for phrase in phrases
        for word in phrase.split()
    }
)
SPECIAL = [
    *"\"'^&|/\\:=-.,;()<>%$*?_ \t\n\r",
    *"\u2013\u2014\u00a0\u2028\u0130\u03a3\u212a\u00e9\u4e2d\u200b",
    "&&",
    "||",
    "cmd",
    "cmd.exe",
    "/c",
    '/c"',
    "/q/c",
    "/v:on",
    ":off",
    "del/f/q",
    "\\cmd.exe/c",
    "c:\\windows\\system32\\",
    "2>nul",
    "x",
    "a1",
    "https://www.example.com/en-us/a",
]
token = st.one_of(st.sampled_from(RULE_WORDS), st.sampled_from(SPECIAL))
gap = st.sampled_from(["", "", " ", " ", "  ", '"', "'", "^", "&", " & ", "\t"])


@st.composite
def commands(draw: Any) -> str:
    tokens = draw(st.lists(token, max_size=24))
    text = "".join(t + draw(gap) for t in tokens)
    return text.upper() if draw(st.booleans()) and draw(st.booleans()) else text


def outcome(results: list[tuple[Rule, list[str]]]) -> list[tuple[str, list[str]]]:
    return [(rule.id, evidence) for rule, evidence in results]


def assert_same(rules: RuleSet, command_lines: list[str]) -> None:
    behavior = Behavior(commands=command_lines)
    assert outcome(rules.evaluate(behavior)) == outcome(reference_matcher.reference_evaluate(rules, behavior))


@pytest.mark.parametrize(
    "lines",
    [
        command_corpus.normal(20),
        command_corpus.varied(20),
        command_corpus.printable(20),
        command_corpus.short(400),
    ],
    ids=["normal", "varied", "printable", "short"],
)
def test_corpora_match_like_the_reference(lines: list[str]) -> None:
    assert_same(BUNDLED, lines)


@given(st.lists(commands(), min_size=1, max_size=6))
def test_bundled_rules_match_like_the_reference(command_lines: list[str]) -> None:
    assert_same(BUNDLED, command_lines)


# Rule phrases built from the same pieces, with arguments, quotes and switches.
phrase_piece = st.one_of(
    st.sampled_from(RULE_WORDS),
    st.sampled_from(["<arg>", '"x"', "'", "^", "/c", "-e", "$", "\\", "c:", "=", "\u2013x", "\u0130", "a"]),
)
phrase = st.lists(phrase_piece, min_size=1, max_size=3).map(" ".join)
phrase_lists = st.lists(st.lists(phrase, min_size=1, max_size=3).map(tuple), max_size=3).map(tuple)


@st.composite
def rule_sets(draw: Any) -> RuleSet:
    rules = [
        Rule(
            id=f"r{i}",
            technique="T1059",
            confidence="low",
            description="",
            references=("https://attack.mitre.org/techniques/T1059/",),
            commands=draw(phrase_lists),
            chained_commands=draw(phrase_lists),
            exclude_commands=draw(phrase_lists),
        )
        for i in range(draw(st.integers(1, 5)))
    ]
    return RuleSet(rules=rules)


@given(rule_sets(), st.lists(commands(), min_size=1, max_size=5))
def test_any_rules_match_like_the_reference(rules: RuleSet, command_lines: list[str]) -> None:
    assert_same(rules, command_lines)


@given(st.lists(st.one_of(token, gap), max_size=40).map("".join))
def test_normalisation_and_chaining_match_the_reference(command: str) -> None:
    for delete_quotes in (False, True):
        assert normalize_command(command, delete_quotes=delete_quotes) == reference_matcher.normalize_command(
            command, delete_quotes=delete_quotes
        )
    assert _split_chain(command) == reference_matcher._split_chain(command)


def test_matcher_follows_changes_to_the_rules() -> None:
    rules = RuleSet(rules=list(BUNDLED.rules))
    behavior = Behavior(commands=["vssadmin delete shadows /all"])
    assert rules.evaluate(behavior)
    rules.rules[:] = [r for r in rules.rules if "vssadmin" not in str(r.commands)]
    assert not any("vssadmin" in str(r.commands) for r, _ in rules.evaluate(behavior))
    assert_same(rules, behavior.commands)
