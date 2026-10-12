"""The ground truth of the real-report evaluation: its line rules, warnings, review, and the steps after it.

docs/research/2026-10-real-reports/evaluate.py drafts the ground truth from each report's IOC appendix,
and a reviewer checks the draft line by line before any tool runs. These tests fix the draft's rules
and the checks of the review, run and score before the held-out reports are seen. Fixtures use
reserved names and documentation addresses only.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from research_evaluate import evaluate
from timing import seconds_per_mb


def report(fmt: str = "pdf", **appendix: Any) -> dict[str, Any]:
    return {"id": "t01", "format": fmt, "appendix": {"start": "IOCs", "end": "END", **appendix}}


def draft(lines: list[str], fmt: str = "pdf") -> dict[str, Any]:
    text = "IOCs\n" + "\n".join(lines) + "\nEND"
    result: dict[str, Any] = evaluate.draft_truth(text, report(fmt))
    return result


def values(lines: list[str], fmt: str = "pdf") -> dict[str, list[str]]:
    return {kind: [e["value"] for e in entries] for kind, entries in draft(lines, fmt)["values"].items()}


def warnings(lines: list[str], fmt: str = "pdf") -> list[tuple[int, str]]:
    """(index in ``lines``, kind) of each warning."""
    return [(w["line"] - 2, w["kind"]) for w in draft(lines, fmt)["warnings"]]


# --------------------------------------------------------------------------- reading defang styles


@pytest.mark.parametrize(
    ("raw", "expected", "writing"),
    [
        ("update-check【.】example.com", "update-check.example.com", "fullwidth-cjk-defang"),
        ("１９８．５１．１００．２３", "198.51.100.23", "fullwidth-cjk-defang"),
        ("198【.】51【.】100【.】25", "198.51.100.25", "fullwidth-cjk-defang"),
        ("attacker［＠］mail．example．org", "attacker@mail.example.org", "fullwidth-cjk-defang"),
        ("evil〔.〕example[。]com", "evil.example.com", "fullwidth-cjk-defang"),
        ("evil（.）example【 . 】com", "evil.example.com", "fullwidth-cjk-defang"),  # pypdf's spaces
        ("evil 【.】 example.com", "evil.example.com", "fullwidth-cjk-defang"),
        ("ｈｔｔｐ\uff1a／／evil．example．com／ａ", "http://evil.example.com/a", "fullwidth-cjk-defang"),
        ("update－check.example.com", "update-check.example.com", "fullwidth-cjk-defang"),
        ("evil[.]example(.)com{.}net", "evil.example.com.net", "ascii-defang"),
        ("evil[dot]example(DOT)com{dot}net", "evil.example.com.net", "ascii-defang"),
        ("evil [ . ] example.com", "evil.example.com", "ascii-defang"),
        ("hxxp[:]//evil[.]example.com[/]a", "hxxp://evil.example.com/a", "ascii-defang"),
        ("hxxps[://]a.example.com", "hxxps://a.example.com", "ascii-defang"),
        ("http:[//]a.example.com", "http://a.example.com", "ascii-defang"),
        ("hxxp://a.example.com", "hxxp://a.example.com", "ascii-defang"),
        ("ops[at]example.org", "ops@example.org", "ascii-defang"),
        ("ops{at}example.org", "ops@example.org", "ascii-defang"),
        ("ops (at) example.org", "ops@example.org", "ascii-defang"),
        ("ops [@] example.org", "ops@example.org", "ascii-defang"),
        ("update\u2010check\u2011a\u2212b\ufe63c.example.com", "update-check-a-b-c.example.com", "plain"),
        ("plain.example.com", "plain.example.com", "plain"),
    ],
)
def test_defang_styles_are_read_as_ascii(raw: str, expected: str, writing: str) -> None:
    reading = evaluate.ascii_reading(raw)
    assert reading.text == expected
    assert reading.writing_class(0, len(reading.text), url="://" in expected) == writing


def test_a_reading_knows_where_each_character_came_from() -> None:
    raw = "IP １９８．５１ 和 evil【.】example.com"
    reading = evaluate.ascii_reading(raw)
    start = reading.text.index("evil")
    span = reading.span(start, start + len("evil.example.com"))
    assert raw[span[0] : span[1]] == "evil【.】example.com"
    span = reading.span(3, 3 + len("198.51"))
    assert raw[span[0] : span[1]] == "１９８．５１"


def test_a_bare_ideographic_full_stop_ends_a_value_and_is_warned_about() -> None:
    # "。" ends Chinese sentences, so it is not read as a dot; between ASCII letters it is flagged.
    assert values(["請連線至 evil.example.com。另外"]) == {"domain": ["evil.example.com"]}
    assert values(["evil。example。com"]) == {}
    assert warnings(["evil。example。com"]) == [(0, "unread-defang"), (0, "unread-defang")]
    assert warnings(["evil〖.〗example.com", "evil<.>example.com"]) == [
        (0, "unread-defang"),
        (1, "unread-defang"),
    ]


# --------------------------------------------------------------------------- one standard form


def test_the_truth_and_the_tools_share_one_standard_form() -> None:
    forms = [
        "HTTP://Evil.Example.COM/Path?A=1",
        "hxxp://evil[.]example[.]com/Path?A=1",
        "HXXP://EVIL.EXAMPLE.COM/Path?A=1",
        "http://evil【.】example．com/Path?A=1",
    ]
    assert {evaluate.normalise("url", form) for form in forms} == {"http://evil.example.com/Path?A=1"}
    assert evaluate.normalise("url", "HXXPS://a.example.com") == "https://a.example.com"
    assert evaluate.normalise("url", "fxp://a.example.com/x") == "ftp://a.example.com/x"
    assert evaluate.normalise("domain", "Evil[.]Example.COM.") == "evil.example.com"
    assert evaluate.normalise("email", "Ops[at]Example[.]org") == "ops@example.org"
    assert evaluate.normalise("md5", "D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"
    # The truth's values come out of normalise too.
    assert values(["HTTP://Evil.Example.COM/Path?A=1"])["url"] == ["http://evil.example.com/Path?A=1"]


@pytest.mark.parametrize(
    "url", ["http://[/]x", "http://", "not a url", "http://[2001:db8::1", "://x", "http://u@[x"]
)
def test_a_url_that_cannot_be_parsed_is_kept_and_flagged(url: str) -> None:
    value, parses = evaluate.normalise_url(url)
    assert not parses
    assert evaluate.url_host(value) == ""


@given(st.text())
@settings(max_examples=300, deadline=None)
def test_normalising_never_raises(value: str) -> None:
    for kind in evaluate.TYPES:
        evaluate.normalise(kind, value)
    evaluate.url_host(evaluate.normalise("url", value))


def test_a_url_with_an_ipv6_host_has_that_host() -> None:
    assert evaluate.url_host("http://[2001:DB8::1]:8080/a") == "2001:db8::1"
    assert evaluate.url_host("http://user@a.example.com:8080/a") == "a.example.com"


# --------------------------------------------------------------------------- line rules


def test_values_right_after_chinese_text_are_found() -> None:
    assert values(["網域evil.example.com，位址198.51.100.7，網址http://203.0.113.9/a.exe下載"]) == {
        "domain": ["evil.example.com"],
        "ipv4": ["198.51.100.7"],
        "url": ["http://203.0.113.9/a.exe"],
    }
    # Only ASCII letters and digits are part of a name: not U+017F, which IGNORECASE folds to "s".
    assert values(["evil.\u017fx.com"]) == {"domain": ["x.com"]}


def test_where_a_url_ends() -> None:
    lines = [
        '網址"http://a.example.com/x"結束',
        "<http://b.example.com/y>",
        "[http://c.example.com/z]",
        "curl http://d.example.com/a.ps1&&powershell",
        "'http://e.example.com/q'",
        "http://f.example.com/a?b=1&c=2",
        "(http://g.example.com/p)",
        "http://h.example.com/a.php?id=1，样本",
        "https://i.example.com/x、https://j.example.net/y",
        "see http://k.example.com/r.",
    ]
    assert values(lines)["url"] == [
        "http://a.example.com/x",
        "http://b.example.com/y",
        "http://c.example.com/z",
        "http://d.example.com/a.ps1",
        "http://e.example.com/q",
        "http://f.example.com/a?b=1&c=2",
        "http://g.example.com/p",
        "http://h.example.com/a.php?id=1",
        "http://k.example.com/r",
        "https://i.example.com/x",
        "https://j.example.net/y",
    ]


def test_an_address_before_a_full_stop_is_found() -> None:
    assert values(["C2 is 198.51.100.7. Backup 203[.]0[.]113[.]9."]) == {
        "ipv4": ["198.51.100.7", "203.0.113.9"]
    }


def test_email_addresses_are_found_and_their_domains_are_not_names() -> None:
    assert values(
        ["郵件ops@example.org, admin[@]example.net, info[at]example.com, x(@)evil(.)example.com"]
    ) == {
        "email": ["admin@example.net", "info@example.com", "ops@example.org", "x@evil.example.com"],
    }
    assert values(["first[.]last@a.example.com, b(.)c [at] b.example.net, d＠c.example.org"]) == {
        "email": ["b.c@b.example.net", "d@c.example.org", "first.last@a.example.com"],
    }


def test_a_name_needs_a_top_level_domain_of_the_iana_list() -> None:
    # File names are not names; a top-level domain that is also an extension is left out, flagged.
    lines = [
        "setup.msi invoice.iso stage.scr loader.exe a.dll",
        "payload.zip run.sh libc.so",
        "c2.example.com",
    ]
    assert values(lines) == {"domain": ["c2.example.com"]}
    assert warnings(lines) == [(1, "file-extension")] * 3
    assert "zip" in evaluate.top_level_domains()
    assert "msi" not in evaluate.top_level_domains()


def test_each_part_is_read_by_its_kind() -> None:
    # In text from a PDF every soft hyphen is a drawn hyphen; other format characters are deleted,
    # except those that separate two names (U+2063, the end of a bidi isolate), which become spaces.
    piece = "update\u00adcheck.example.org up\u200bdate.example.net a.example.com\u2063b.example.com"
    assert evaluate.read_line(piece, "text").text == evaluate.read_line(piece, "pdf").text
    assert evaluate.read_line(piece, "pdf").text == (
        "update-check.example.org update.example.net a.example.com b.example.com"
    )
    assert (
        evaluate.read_line("a.example.com\u2069\u2066b.example.com", "html").text
        == "a.example.com b.example.com"
    )
    lines = ["up\u200bdate.example.com", "198.51.100.\u200b7", "d41d8cd98f00\u2060b204e9800998ecf8427e"]
    assert values(lines, "html") == {
        "domain": ["update.example.com"],
        "ipv4": ["198.51.100.7"],
        "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
    }


def test_soft_hyphens_in_pdf_text_are_hyphens() -> None:
    lines = [
        "update\u00adcheck.example.com",
        "xn\u00ad\u00adbcher-kva.example.com",
        "http://198.51.100.7/a.php?id=\u00ad1",
        "https://gitlab.example.com/g/t/\u00ad/raw/main/a.ps1",
    ]
    assert values(lines) == {
        "domain": ["update-check.example.com", "xn--bcher-kva.example.com"],
        "url": ["http://198.51.100.7/a.php?id=-1", "https://gitlab.example.com/g/t/-/raw/main/a.ps1"],
    }


def test_masked_values_are_left_out_and_flagged() -> None:
    result = draft(["wiki.xxxx.com", "evil.**.example.org", "http://a.example.com/?p=xxx&q=1"])
    assert result["values"] == {}
    assert result["masked"] == {
        "domain": [{"value": "wiki.xxxx.com", "line": 2}, {"value": "evil.**.example.org", "line": 3}],
        "url": [{"value": "http://a.example.com/?p=xxx&q=1", "line": 4}],
    }
    assert [w["kind"] for w in result["warnings"]] == ["masked"] * 3


def test_a_value_written_several_ways_gets_its_plainest_writing() -> None:
    result = draft(["evil【.】example.com", "evil[.]example.com", "然後 198.51.100.7", "evil.example.com"])
    (entry,) = result["values"]["domain"]
    assert (entry["class"], entry["writing"], entry["line"], entry["occurrences"]) == (
        "plain",
        "evil.example.com",
        5,
        3,
    )
    entry = draft(["evil【.】example.com", "evil[.]example.com"])["values"]["domain"][0]
    assert (entry["class"], entry["writing"]) == ("ascii-defang", "evil[.]example.com")


# --------------------------------------------------------------------------- warnings


def test_a_hash_cut_by_a_line_break_is_flagged() -> None:
    # A SHA-256 in a narrow cell, broken in two halves that look like two MD5s.
    cut = ["loader.dll e3b0c44298fc1c149afbf4c8996fb924", "27ae41e4649b934ca495991b7852b855"]
    result = draft(cut)
    (warning,) = result["warnings"]
    assert warning["kind"] == "hex-cut"
    assert warning["values"] == ["e3b0c44298fc1c149afbf4c8996fb924", "27ae41e4649b934ca495991b7852b855"]
    # 40 + 24 digits: a "SHA-1" and a piece of no hash length.
    assert ("hex-cut") in {
        kind
        for _, kind in warnings(
            ["x.dll e3b0c44298fc1c149afbf4c8996fb92427ae41e4", "649b934ca495991b7852b855"]
        )
    }
    # A list of whole MD5s under an MD5 label, and a table of names and hashes, are not flagged; a list
    # of 32-digit lines with no MD5 label is flagged once.
    md5s = ["d41d8cd98f00b204e9800998ecf8427e", "0cc175b9c0f1b6a831c399e269772661"]
    assert warnings(["MD5", *md5s]) == []
    assert warnings(md5s) == [(0, "hex-cut")]
    assert (
        warnings(["a.dll d41d8cd98f00b204e9800998ecf8427e", "b.dll 0cc175b9c0f1b6a831c399e269772661"]) == []
    )


def test_a_hash_unlike_its_label_is_flagged() -> None:
    assert warnings(["SHA256", "d41d8cd98f00b204e9800998ecf8427e"]) == [(1, "hash-label")]
    assert warnings(["SHA-256: d41d8cd98f00b204e9800998ecf8427e"]) == [(0, "hash-label")]
    assert warnings(["MD5", "d41d8cd98f00b204e9800998ecf8427e"]) == []
    assert warnings(["MD5 SHA256", "a.dll d41d8cd98f00b204e9800998ecf8427e"]) == []


def test_a_name_cut_by_a_line_break_is_flagged() -> None:
    lines = ["C2 backup-telemetry-service.", "example.com"]
    result = draft(lines)
    assert [(w["kind"], w["values"]) for w in result["warnings"]] == [("name-cut", ["example.com"])]
    assert warnings(["update-", "check.example.com"]) == [(0, "name-cut")]
    assert warnings(["KB-Auto-\u00ad", "win.example.com"]) == [(0, "name-cut"), (0, "non-ascii")][:1]
    assert warnings(["backup-telemetry-service", ".example.com"]) == [(0, "name-cut")]
    assert warnings(["說明。", "example.com"]) == []


def test_a_url_cut_by_a_line_break_is_flagged() -> None:
    assert warnings(["http://a.example.com/very/long/pa", "th/file.php"]) == [(0, "url-cut")]
    assert warnings(["http://a.example.com/x", "http://b.example.com/y"]) == []
    assert warnings(["http://a.example.com/x", "evil.example.com"]) == []
    assert warnings(["http://a.example.com/x", "下載器"]) == []


def test_a_value_read_from_non_ascii_writing_is_flagged() -> None:
    result = draft(["update-check【.】example.com", "１９８．５１．１００．２３", "plain.example.com"])
    assert [(w["line"], w["kind"]) for w in result["warnings"]] == [(2, "non-ascii"), (3, "non-ascii")]
    assert result["warnings"][1]["values"] == ["198.51.100.23"]


def test_a_url_without_a_host_is_flagged() -> None:
    assert warnings(["http://[/]x"]) == [(0, "url-unparseable")]


# --------------------------------------------------------------------------- the appendix and its lines


def test_the_appendix_start_marker_must_be_unique() -> None:
    page = "IOCs\nside bar\nbody\nIOCs\na.example.com\nEND"
    with pytest.raises(SystemExit, match="found 2 times"):
        evaluate.appendix(page, report("html"))
    assert evaluate.appendix(page, report("html", start_occurrence=2)) == "IOCs\na.example.com\n"
    assert evaluate.appendix(page, report("html", start_occurrence=1)).startswith("IOCs\nside bar")
    with pytest.raises(SystemExit, match="start_occurrence 3"):
        evaluate.appendix(page, report("html", start_occurrence=3))


def test_an_appendix_can_run_to_the_end_of_the_text() -> None:
    entry = {"id": "t01", "format": "pdf", "appendix": {"start": "IOCs", "end_of_text": True}}
    assert evaluate.appendix("body\nIOCs\na.example.com\nEND\nb.example.com", entry) == (
        "IOCs\na.example.com\nEND\nb.example.com"
    )


def test_each_line_knows_its_page_and_line() -> None:
    page_1 = "header\nIOCs\na.example.com"
    page_2 = "b.example.com\nEND"
    attachment = "c.example.com"
    text = page_1 + "\n" + page_2 + "\n\n" + attachment
    parts = [
        {
            "format": "pdf",
            "file": "pdf/t01.pdf",
            "start": 0,
            "end": len(page_1) + 1 + len(page_2),
            "page_starts": [0, len(page_1) + 1],
        },
        {
            "format": "text",
            "file": "attachments/iocs.txt",
            "start": len(text) - len(attachment),
            "end": len(text),
        },
    ]
    entry = {"id": "t01", "format": "pdf", "appendix": {"start": "IOCs", "end_of_text": True}}
    result = evaluate.draft_truth(text, entry, parts)
    assert [line["location"] for line in result["lines"]] == [
        "pdf/t01.pdf page 1 line 2",
        "pdf/t01.pdf page 1 line 3",
        "pdf/t01.pdf page 2 line 1",
        "pdf/t01.pdf page 2 line 2",
        "text line 6",
        "attachments/iocs.txt line 1",
    ]
    assert result["parts"] == [
        {"file": "pdf/t01.pdf", "format": "pdf", "pages": [1, 2]},
        {"file": "attachments/iocs.txt", "format": "text", "pages": []},
    ]


def test_the_draft_hash_covers_what_the_review_depends_on() -> None:
    first = draft(["a.example.com"])
    assert draft(["a.example.com"])["sha256"] == first["sha256"]
    assert draft(["b.example.com"])["sha256"] != first["sha256"]
    other_markers = evaluate.draft_truth(
        "IOCs\na.example.com\nSTOP", {**report(), "appendix": {"start": "IOCs", "end": "STOP"}}
    )
    assert other_markers["sha256"] != first["sha256"]


@pytest.mark.parametrize(
    "unit",
    [
        "a【.】",
        "１．",
        "a[.]",
        "x",
        "a-",
        "0",
        "a@",
        "http://",
        "a.",
        "**",
        "a\n",
        "d41d8cd98f00b204e9800998ecf8427e\n",
        "a.\n",
        "a〖.〗",
    ],
)
def test_the_draft_costs_linear_time(unit: str) -> None:
    def cost(size: int) -> float:
        body = unit * (size // len(unit.encode()))
        return seconds_per_mb(lambda: draft([body]), size / 1_000_000)

    small, large = cost(40_000), cost(160_000)
    assert large < 2.5 * small, unit  # quadratic would be 4 times


# --------------------------------------------------------------------------- the review


def complete_review(result: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """A complete review of the draft ``result``, with ``changes``."""
    pages, files = evaluate.image_labels_required(result)
    review: dict[str, Any] = {
        "draft_sha256": result["sha256"],
        "reviewed_by": "tester",
        "reviewed_at": "2026-10-11T00:00:00Z",
        "pages_checked": pages + [f"{file} screenshot 1" for file in files] or ["(no images)"],
        "checked_every_line": True,
        "warnings": {
            w["id"]: {
                "kind": w["kind"],
                "line": w["line"],
                "message": w["message"],
                "resolution": "confirmed",
                "note": "as on the page",
            }
            for w in result["warnings"]
        },
        "add": [],
        "remove": [],
        "ambiguous": [],
    }
    review.update(changes)
    review["values"] = evaluate.final_values(result, review)
    review["masked"] = evaluate.draft_masked(result)
    return review


CUT = [
    "loader.dll e3b0c44298fc1c149afbf4c8996fb924",
    "27ae41e4649b934ca495991b7852b855",
    "evil[.]example.com",
]
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def corrected_cut(result: dict[str, Any]) -> dict[str, Any]:
    """The review of the CUT draft that a reviewer makes from the page."""
    review = complete_review(
        result,
        remove=[
            {
                "type": "md5",
                "value": "e3b0c44298fc1c149afbf4c8996fb924",
                "reason": "half of a SHA-256",
                "warnings": ["W1"],
            },
            {
                "type": "md5",
                "value": "27ae41e4649b934ca495991b7852b855",
                "reason": "half of a SHA-256",
                "warnings": ["W1"],
            },
        ],
        add=[
            {
                "type": "sha256",
                "value": SHA256,
                "writing": SHA256,
                "class": "plain",
                "location": "pdf/t01.pdf page 1 line 2",
                "reason": "the cell wraps it",
                "warnings": ["W1"],
            },
        ],
    )
    review["warnings"]["W1"].update(resolution="corrected", note="one SHA-256 in a narrow cell")
    review["values"] = evaluate.final_values(result, review)
    return review


def test_a_complete_review_gives_the_final_values() -> None:
    result = draft(CUT)
    review = corrected_cut(result)
    assert evaluate.review_problems(result, review) == []
    assert review["values"] == {
        "domain": [
            {
                "value": "evil.example.com",
                "writing": "evil[.]example.com",
                "class": "ascii-defang",
                "location": "text line 4",
            }
        ],
        "sha256": [
            {"value": SHA256, "writing": SHA256, "class": "plain", "location": "pdf/t01.pdf page 1 line 2"}
        ],
    }


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (
            lambda r: (r["warnings"].pop("W1"), [e.pop("warnings") for e in r["remove"] + r["add"]]),
            "warning W1 has no resolution",
        ),
        (
            lambda r: r["warnings"]["W1"].update(resolution=""),
            "resolution must be 'confirmed' or 'corrected'",
        ),
        (lambda r: r["warnings"]["W1"].update(note=""), "warnings.W1.note"),
        (
            lambda r: r["warnings"].update(W9={**r["warnings"]["W1"], "resolution": "confirmed"}),
            "W9 is not a warning of the draft",
        ),
        (lambda r: [e.pop("warnings") for e in r["remove"] + r["add"]], "corrected, but no add, remove"),
        (lambda r: r["remove"][0].update(warnings=["W7"]), "warning W7 is cited but does not exist"),
        (lambda r: r["remove"][0].update(value="00" * 16), "matches no value of the draft"),
        (lambda r: r["remove"][0].update(value="E3B0C44298FC1C149AFBF4C8996FB924"), "write 'e3b0c442"),
        (lambda r: r["remove"].append(dict(r["remove"][0])), "is listed twice"),
        (
            lambda r: r["add"].append({**r["add"][0], "type": "domain", "value": "evil.example.com"}),
            "already a value of the draft",
        ),
        (lambda r: r["add"][0].update(value="Evil.example.com", type="domain"), "not in standard form"),
        (lambda r: r["add"][0].update(type="url", value="http:///x"), "has no host"),
        (lambda r: r["add"][0].update(type="domain", value="wiki.xxxx.com"), "masked values are left out"),
        (lambda r: r["add"][0].update(**{"class": "other"}), "class must be one of"),
        (lambda r: r["add"][0].pop("location"), "missing field 'location'"),
        (
            lambda r: r["ambiguous"].append(
                {
                    "type": "domain",
                    "readings": ["a.example.com", "b.example.com"],
                    "writing": "a",
                    "location": "x",
                    "reason": "r",
                    "from_draft": True,
                }
            ),
            "no reading of",
        ),
        (
            lambda r: r["ambiguous"].append(
                {
                    "type": "domain",
                    "readings": ["evil.example.com", "evil.example.net"],
                    "writing": "a",
                    "location": "x",
                    "reason": "r",
                    "from_draft": False,
                }
            ),
            "are values of the draft, but from_draft is false",
        ),
        (
            lambda r: r["ambiguous"].append(
                {
                    "type": "domain",
                    "readings": ["evil.example.com"],
                    "writing": "a",
                    "location": "x",
                    "reason": "r",
                    "from_draft": True,
                }
            ),
            "two or more different readings",
        ),
        (lambda r: r.update(pages_checked=["something else"]), "pdf/t01.pdf page 1' (the appendix is on it)"),
        (lambda r: r.update(checked_every_line=False), "every line must be checked"),
        (lambda r: r.update(reviewed_at="yesterday"), "reviewed_at"),
        (lambda r: r.update(draft_sha256="0" * 64), "review the new draft"),
        (lambda r: r["values"].pop("sha256"), "not the draft's values with the corrections"),
    ],
)
def test_review_problems_are_reported(change: Any, problem: str) -> None:
    text = "IOCs\n" + "\n".join(CUT) + "\nEND"
    first = len("IOCs\n") + len(CUT[0]) + len(CUT[1]) + 2
    parts = [{"format": "pdf", "file": "pdf/t01.pdf", "start": 0, "end": first, "page_starts": [0]}]
    result = evaluate.draft_truth(text, report(), parts)
    review = corrected_cut(result)
    review["add"][0]["location"] = "pdf/t01.pdf page 1 line 2"
    review["values"] = evaluate.final_values(result, review)
    assert evaluate.review_problems(result, review) == []
    change(review)
    found = evaluate.review_problems(result, review)
    assert any(problem in item for item in found), found


def test_an_ambiguous_entry_takes_its_readings_out_of_the_truth() -> None:
    result = draft(["qqmailsoft-", "warepatch.example.com"])
    assert values(["qqmailsoft-", "warepatch.example.com"]) == {"domain": ["warepatch.example.com"]}
    entry = {
        "type": "domain",
        "readings": ["qqmailsoft-warepatch.example.com", "qqmailsoftwarepatch.example.com"],
        "writing": "qqmailsoft- / warepatch.example.com",
        "location": "? line 2",
        "reason": "the cell wraps",
        "from_draft": False,
        "warnings": ["W1"],
    }
    remove = {"type": "domain", "value": "warepatch.example.com", "reason": "a fragment", "warnings": ["W1"]}
    review = complete_review(result, ambiguous=[entry], remove=[remove])
    review["warnings"]["W1"].update(resolution="corrected")
    review["values"] = evaluate.final_values(result, review)
    assert evaluate.review_problems(result, review) == []
    assert review["values"] == {}


# --------------------------------------------------------------------------- truth, review, run and score


@pytest.fixture
def reviewed_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A set "t" of one web page, drafted (without images) and with a filled-in review template."""
    entry = {
        "id": "t01",
        "title": "t",
        "publisher": "p",
        "published": "2026-01-01",
        "original_url": "https://example.com/r",
        "url_source": "test",
        "format": "html",
        "appendix": {"start": "IOCs", "end": "END"},
        "retrieved": "2026-10-09T13:45:04Z",
        "final_url": "https://example.com/r",
        "saved": {"kind": "server", "method": "curl -L", "tool": "curl 8.5.0"},
    }
    data = {
        "description": "",
        "fields": {},
        "text_conversion": {},
        "selection_rule": {"t": "all"},
        "sets": {"t": [entry]},
    }
    (tmp_path / "t" / "html").mkdir(parents=True)
    page = "<h2>IOCs</h2><p>evil【.】example.com</p><p>hxxp://198.51.100.7/a.exe</p><p>c2.example.net</p><p>END</p>"
    (tmp_path / "t" / "html" / "t01.html").write_text(page, encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    committed: dict[str, Any] = {"data": json.loads(json.dumps(data))}
    monkeypatch.setattr(evaluate, "DATA", tmp_path)
    monkeypatch.setattr(evaluate, "HERE", tmp_path)
    monkeypatch.setattr(evaluate, "MANIFEST", manifest)
    monkeypatch.setattr(evaluate, "JUDGEMENTS", tmp_path / "judgements.json")
    monkeypatch.setattr(evaluate, "committed_manifest", lambda: committed["data"])
    monkeypatch.setattr(evaluate, "check_html_parser", evaluate.html_parser_info)
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "truth", "t", "--no-render"])
    evaluate.command_text("t")
    evaluate.command_defang("t")
    evaluate.command_truth("t")
    result = json.loads((tmp_path / "t" / "truth" / "t01.draft.json").read_text(encoding="utf-8"))
    images = {
        "draft_sha256": result["sha256"],
        "images": [{"label": "html/t01.html screenshot 1", "file": "1.png"}],
    }
    (tmp_path / "t" / "truth" / "t01" / "images.json").write_text(json.dumps(images), encoding="utf-8")
    (tmp_path / "t" / "truth" / "t01" / "1.png").write_bytes(b"")
    template_file = tmp_path / "t" / "truth" / "t01.review.json"
    template = json.loads(template_file.read_text(encoding="utf-8"))
    template.update(
        reviewed_by="tester",
        reviewed_at="2026-10-11T00:00:00Z",
        pages_checked=["html/t01.html screenshot 1"],
        checked_every_line=True,
    )
    for warning in template["warnings"].values():
        warning.update(resolution="confirmed", note="as on the page")
    template_file.write_text(json.dumps(template), encoding="utf-8")
    return {"tmp": tmp_path, "committed": committed, "draft": result, "template": template_file}


def commit(reviewed_set: dict[str, Any]) -> None:
    reviewed_set["committed"]["data"] = json.loads(evaluate.MANIFEST.read_text(encoding="utf-8"))


def test_review_stops_on_an_unresolved_warning(reviewed_set: dict[str, Any]) -> None:
    template = json.loads(reviewed_set["template"].read_text(encoding="utf-8"))
    assert len(template["warnings"]) == 1  # the full-width defang
    template["warnings"]["W1"]["resolution"] = ""
    reviewed_set["template"].write_text(json.dumps(template), encoding="utf-8")
    with pytest.raises(SystemExit, match="resolution must be 'confirmed' or 'corrected'"):
        evaluate.command_review("t")


def test_run_needs_a_committed_review_of_the_current_draft(reviewed_set: dict[str, Any]) -> None:
    with pytest.raises(SystemExit, match="no reviewed ground truth"):
        evaluate.command_run("t", "after")
    evaluate.command_review("t")
    stored = json.loads(evaluate.MANIFEST.read_text(encoding="utf-8"))["sets"]["t"][0]["truth_review"]
    assert stored["values"]["domain"][0] == {
        "value": "c2.example.net",
        "writing": "c2.example.net",
        "class": "plain",
        "location": "html/t01.html line 7",
    }
    with pytest.raises(SystemExit, match="not committed as it stands"):
        evaluate.command_run("t", "after")
    commit(reviewed_set)
    entry = evaluate.manifest("t")[0]
    text, conversion = evaluate.load_text("t", entry)
    truth = evaluate.load_reviewed_truth("t", entry, text, conversion)
    assert truth["truth"]["domain"] == ["c2.example.net", "evil.example.com"]
    assert truth["truth"]["url"] == ["http://198.51.100.7/a.exe"]
    assert truth["classes"]["domain"] == {
        "c2.example.net": "plain",
        "evil.example.com": "fullwidth-cjk-defang",
    }
    # Other appendix markers give another draft, which the review does not cover.
    data = json.loads(evaluate.MANIFEST.read_text(encoding="utf-8"))
    data["sets"]["t"][0]["appendix"]["end"] = "c2.example.net"
    evaluate.MANIFEST.write_text(json.dumps(data), encoding="utf-8")
    commit(reviewed_set)
    entry = evaluate.manifest("t")[0]
    with pytest.raises(SystemExit, match="review the new draft"):
        evaluate.load_reviewed_truth("t", entry, text, conversion)


def test_review_comes_before_any_tool_runs(reviewed_set: dict[str, Any]) -> None:
    (reviewed_set["tmp"] / "results-t-after.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit, match="has results already"):
        evaluate.command_review("t")


def fake_tools(monkeypatch: pytest.MonkeyPatch, iocextract_fails: bool) -> None:
    empty = {kind: [] for kind in evaluate.TYPES}

    def ttprism(path: Path, flags: list[str]) -> dict[str, Any]:
        found = {
            **empty,
            "domain": ["c2.example.net", "evil.example.com", "report.example.org"],
            "url": ["http://198.51.100.7/a.exe"],
        }
        return {"values": found, "warnings": [], "suppressed": {}}

    def iocextract(text: str) -> dict[str, list[str]]:
        if iocextract_fails:
            raise ValueError("netloc 'a\uff1a' contains invalid characters under NFKC normalization")
        return {**empty, "url": ["HXXP://198.51.100.7/a.exe", "http://[/]x"]}

    monkeypatch.setattr(evaluate, "run_ttprism", ttprism)
    monkeypatch.setattr(evaluate, "run_iocextract", iocextract)
    monkeypatch.setattr(evaluate, "run_ioc_finder", lambda text: {**empty, "domain": ["c2.example.net"]})
    monkeypatch.setattr(
        evaluate, "ttprism_identity", lambda: {"version": "0", "path": "src/ttprism/__init__.py"}
    )
    monkeypatch.setattr(evaluate, "line_wrap_fragments", lambda text: [])


def test_a_tool_that_fails_on_a_report_is_recorded_and_the_run_goes_on(
    reviewed_set: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evaluate.command_review("t")
    commit(reviewed_set)
    fake_tools(monkeypatch, iocextract_fails=True)
    evaluate.command_run("t", "after")
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    (entry,) = results["reports"]
    assert entry["errors"] == {
        "iocextract": "ValueError: netloc 'a\uff1a' contains invalid characters under NFKC normalization"
    }
    assert entry["outputs"]["iocextract"] == {kind: [] for kind in evaluate.TYPES}
    assert entry["truth_classes"] == {"plain": 1, "ascii-defang": 1, "fullwidth-cjk-defang": 1}
    assert "iocextract FAILED on this report" in capsys.readouterr().out
    evaluate.command_score("t", "after")
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["totals"]["iocextract"]["errors"] == 1
    assert results["totals"]["iocextract"]["recall"]["domain"] == [0, 2, 0.0]


def test_score_is_provisional_until_every_value_is_judged(
    reviewed_set: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    evaluate.command_review("t")
    commit(reviewed_set)
    fake_tools(monkeypatch, iocextract_fails=False)
    evaluate.command_run("t", "after")
    # Values next to a tool's name would unblind the sheet: run prints counts only.
    assert "http:///x" not in capsys.readouterr().out
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["reports"][0]["unparseable_urls"] == {"iocextract": ["http:///x"]}
    evaluate.command_score("t", "after")
    out = capsys.readouterr().out
    assert "[PROVISIONAL]" in out
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["status"] == "provisional: 2 values not judged yet"
    raw = results["totals"]["ttprism-raw"]
    assert raw["recall_by_class"] == {
        "plain": [1, 1, 1.0],
        "ascii-defang": [1, 1, 1.0],
        "fullwidth-cjk-defang": [1, 1, 1.0],
    }
    assert results["totals"]["ioc-finder"]["recall_by_class"]["fullwidth-cjk-defang"] == [0, 1, 0.0]
    assert results["reports_using_fullwidth_cjk"] == ["t01"]
    assert results["reports"][0]["writing"]["fullwidth_cjk_indicators_in_appendix"] == 1
    # The blinded sheet: every value outside the truth once, without the tools that found it.
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "judge", "t", "after"])
    evaluate.command_judge("t", "after")
    sheet_file = reviewed_set["tmp"] / "t" / "judging" / "after.json"
    sheet = json.loads(sheet_file.read_text(encoding="utf-8"))
    assert sorted((i["type"], i["value"]) for i in sheet["items"]) == [
        ("domain", "report.example.org"),
        ("url", "http:///x"),
    ]
    assert "ttprism" not in sheet_file.read_text(encoding="utf-8")
    for item in sheet["items"]:
        item.update(category="b" if item["type"] == "domain" else "c", reason="from the page")
    sheet_file.write_text(json.dumps(sheet), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "judge", "t", "after", "--import"])
    evaluate.command_judge("t", "after")
    evaluate.command_score("t", "after")
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["status"] == "final"
    assert results["judgements_sha256"] == evaluate.sha256(evaluate.JUDGEMENTS)
    assert results["totals"]["ttprism-raw"]["precision"]["lenient"] == 1.0
    # A judgement that disagrees with an earlier one is not taken.
    sheet["items"][0]["category"] = "a"
    sheet_file.write_text(json.dumps(sheet), encoding="utf-8")
    with pytest.raises(SystemExit, match="judged differently before"):
        evaluate.command_judge("t", "after")


@pytest.mark.parametrize(
    ("judgements", "problem"),
    [
        (
            {"judgements": {"t/t01": {"domain": {"a.example.com": ["d", "x"]}}}},
            "category 'd' is not 'a', 'b' or 'c'",
        ),
        ({"judgements": {"t/t01": {"domain": {"a.example.com": ["a", ""]}}}}, "the reason must be one line"),
        ({"judgements": {"t/t01": {"domain": {"a.example.com": "a"}}}}, "not [category, reason]"),
        ({"judgements": {"t/t01": {"host": {}}}}, "unknown type 'host'"),
        ({"judgements": {"t01": {}}}, "is not '<set>/<report id>'"),
        ({"judgements": {"t/t01": {"domain": {"A.example.com": ["a", "x"]}}}}, "not in standard form"),
        ({"judgments": {}}, "unknown field 'judgments'"),
    ],
)
def test_judgements_are_checked(
    judgements: dict[str, Any], problem: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert any(problem in item for item in evaluate.judgement_problems(judgements))
    path = tmp_path / "judgements.json"
    path.write_text(json.dumps(judgements), encoding="utf-8")
    monkeypatch.setattr(evaluate, "JUDGEMENTS", path)
    with pytest.raises(SystemExit, match=r"judgements\.json is not valid"):
        evaluate.load_judgements()


def test_the_committed_judgements_are_valid() -> None:
    data = json.loads(Path(evaluate.HERE / "judgements.json").read_text(encoding="utf-8"))
    assert evaluate.judgement_problems(data) == []


# --------------------------------------------------------------------------- defang statistics


def test_defang_styles_are_counted_in_the_text_and_in_values() -> None:
    text = "１．背景 ２０２０年\nC2 evil【.】example.com 與 198[.]51[.]100[.]7，hxxp://a[.]example.net/x\nops［＠］example.org"
    occurrences = evaluate.defang_occurrences(text)
    everywhere = evaluate._style_counts(occurrences, None)
    spans = evaluate.value_spans(text, 0, len(text), [{"format": "pdf", "start": 0, "end": len(text)}], "pdf")
    in_values = evaluate._style_counts(occurrences, spans)
    assert {k: v for k, v in everywhere.items() if v} == {
        "【.】": 1,
        "[.]": 4,
        "hxxp": 1,
        "＠": 1,
        "．": 1,
        "full-width letters and digits": 2,
    }
    # Numbering ("１．") and dates in full-width digits are not part of any value.
    assert {k: v for k, v in in_values.items() if v} == {"【.】": 1, "[.]": 4, "hxxp": 1, "＠": 1}


# --------------------------------------------------------------------------- decoding and PDFs


def test_damaged_utf8_is_decoded_leniently_only_when_the_manifest_says_so(tmp_path: Path) -> None:
    page = b"<p>evil.example.com \xff\xfe</p>"
    with pytest.raises(SystemExit, match="cannot decode"):
        evaluate.decode_html(page, override="utf-8")
    text, info = evaluate.decode_html(page, override="utf-8:replace")
    assert text == "<p>evil.example.com \ufffd\ufffd</p>"
    assert info["replacement_characters_inserted"] == 2
    plain = tmp_path / "iocs.txt"
    plain.write_bytes(b"a.example.com \xff \xef\xbf\xbd\n")  # one damaged byte, one real U+FFFD
    text, info = evaluate.convert(plain, "text", override="utf-8:replace")
    assert info["replacement_characters_inserted"] == 1
    assert text == "a.example.com \ufffd \ufffd\n"


def test_a_pdf_with_only_an_owner_password_is_read(tmp_path: Path) -> None:
    pypdf = pytest.importorskip("pypdf")
    pytest.importorskip("cryptography")
    from test_pdf_soft_hyphens import build_pdf

    plain = tmp_path / "plain.pdf"
    plain.write_bytes(build_pdf([b"C2: update\\255check.example.com"]))
    writer = pypdf.PdfWriter(clone_from=str(plain))
    writer.encrypt(user_password="", owner_password="owner", algorithm="AES-256")  # noqa: S106
    encrypted = tmp_path / "owner.pdf"
    with encrypted.open("wb") as out:
        writer.write(out)
    text, info = evaluate.pdf_text(encrypted)
    assert "update\u00adcheck.example.com" in text
    assert info["encryption"].startswith("decrypted with the empty user password")
    writer = pypdf.PdfWriter(clone_from=str(plain))
    writer.encrypt(user_password="secret", owner_password="owner", algorithm="AES-256")  # noqa: S106
    with encrypted.open("wb") as out:
        writer.write(out)
    with pytest.raises(SystemExit, match="encrypted with a user password"):
        evaluate.pdf_text(encrypted)


# --------------------------------------------------------------------------- review round 6

SPLIT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_spaced_full_width_dots_and_at_signs_are_read() -> None:
    # pypdf puts spaces around full-width punctuation between ASCII runs.
    assert values(["update-check ． example ． com", "attacker ＠ mail ． example ． org"]) == {
        "domain": ["update-check.example.com"],
        "email": ["attacker@mail.example.org"],
    }
    assert values(["hxxps://update-check ． example ． com/a.exe"])["url"] == [
        "https://update-check.example.com/a.exe"
    ]


def test_spaces_around_a_form_do_not_decide_its_class() -> None:
    for raw in (
        "evil\u3000[.]\u3000example.com",
        "evil[\u3000.\u3000]example.com",
        "ops\u3000[at]\u3000example.org",
    ):
        reading = evaluate.ascii_reading(raw)
        assert reading.writing_class(0, len(reading.text)) == "ascii-defang", raw
    styles = [
        style
        for _, _, style in evaluate.defang_occurrences("evil\u3000[.]\u3000example.com a\u3000[at]\u3000b")
    ]
    assert styles == ["[.]", "[at]"]


def test_hxx_or_fxp_inside_a_plain_value_is_plain() -> None:
    result = draft(["fxpro-login.example.com", "user@fxpmail.example.org", "http://example.com/fxp/a.exe"])
    assert {e["class"] for entries in result["values"].values() for e in entries} == {"plain"}
    assert draft(["hxxp://a.example.com/x"])["values"]["url"][0]["class"] == "ascii-defang"


@pytest.mark.parametrize(
    "lines",
    [
        # An MD5 and a SHA-256 column: the narrow SHA-256 cell breaks in two halves.
        ["檔名 MD5 SHA-256", "stage.dll d41d8cd98f00b204e9800998ecf8427e " + SPLIT[:32], SPLIT[32:]],
        # A label that names SHA-256 with a space, and no label at all.
        ["SHA 256", SPLIT[:32], SPLIT[32:]],
        ["雜湊值 說明", SPLIT[:32], SPLIT[32:], "下載器"],
        # The next cell follows the second half on its line.
        ["雜湊值 說明", SPLIT[:32], SPLIT[32:] + " 下載器"],
        # pypdf's no-break space at the line end.
        ["loader.dll " + SPLIT[:32] + "\u00a0", SPLIT[32:]],
        ["x.dll " + SPLIT[:40], SPLIT[40:]],
    ],
)
def test_every_split_sha256_is_flagged(lines: list[str]) -> None:
    result = draft(lines)
    flagged = {v for w in result["warnings"] if w["kind"] == "hex-cut" for v in w["values"]}
    assert flagged, result["warnings"]
    assert flagged <= {v for entries in result["values"].values() for v in (e["value"] for e in entries)}


def test_tables_of_whole_hashes_are_not_flagged() -> None:
    md5 = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72",
    ]
    assert (
        warnings(["Android MD5 Windows MD5", f"{md5[0]}    {md5[1]}", f"{md5[2]}    {md5[0]}", md5[1]]) == []
    )
    assert warnings([f"{SPLIT} {SPLIT}", f"{SPLIT} {SPLIT}"]) == []


def test_line_ends_are_found_past_no_break_spaces() -> None:
    assert warnings(["C2 backup-telemetry-service.\u00a0", "example.com"]) == [(0, "name-cut")]
    assert warnings(["http://a.example.com/very/long/pa\u00a0", "th/file.php"]) == [(0, "url-cut")]
    assert warnings(["backup-telemetry-service\u00a0", "\u00a0.example.com"]) == [(0, "name-cut")]


def test_a_name_cut_between_two_punctuation_marks_is_flagged() -> None:
    # cn06's 163mailboxdownload- / .servehttp.com
    assert warnings(["163mailboxdownload-", ".servehttp.com"]) == [(0, "name-cut")]
    assert warnings(["update-check.", ".example.com"]) == [(0, "name-cut")]


def test_a_url_that_stops_at_chinese_text_is_flagged() -> None:
    result = draft(["hxxp://evil[.]example[.]com/files/公文通知.rar"])
    assert result["values"]["url"][0]["value"] == "http://evil.example.com/files/"
    assert [w["kind"] for w in result["warnings"]] == ["non-ascii"]
    assert warnings(["http://evil.example.com/a.exe。"]) == []


def test_the_masked_check_is_linear_in_masked_names() -> None:
    for unit in ("xxx.com ", "wiki.xxxx.com、"):

        def cost(size: int, unit: str = unit) -> float:
            body = unit * (size // len(unit.encode()))
            return seconds_per_mb(lambda: draft([body]), size / 1_000_000, repeat=2)

        assert cost(160_000) < 2.5 * cost(40_000), unit


def test_lines_on_many_pages_cost_linear_time() -> None:
    def cost(lines: int) -> float:
        text = "IOCs\n" + "a.example.com 198.51.100.1\n" * lines + "END"
        starts = [i for i, char in enumerate(text) if char == "\n"][::2]
        parts = [
            {"format": "pdf", "file": "pdf/t.pdf", "start": 0, "end": len(text), "page_starts": [0, *starts]}
        ]
        return seconds_per_mb(lambda: evaluate.text_lines(text, 0, len(text), parts, "pdf"), len(text) / 1e6)

    assert cost(40_000) < 2.5 * cost(10_000)


def test_a_review_resolves_the_draft_s_own_warnings() -> None:
    result = draft(CUT)
    review = corrected_cut(result)
    review["warnings"]["W1"]["line"] = 7
    assert any("the resolution is for another warning" in p for p in evaluate.review_problems(result, review))


def test_removing_the_host_of_a_kept_url_is_refused() -> None:
    result = draft(["http://cdn.example.com/a.exe", "cdn.example.com"])
    review = complete_review(result, remove=[{"type": "domain", "value": "cdn.example.com", "reason": "r"}])
    assert any("is the host of the URL" in p for p in evaluate.review_problems(result, review))


def test_a_url_without_a_host_cannot_stay_in_the_truth() -> None:
    result = draft(["http://[/]x"])
    review = complete_review(result)
    assert any("has no host" in p for p in evaluate.review_problems(result, review))
    assert (
        evaluate.found({"url": ["http:///x"]}, {kind: [] for kind in evaluate.TYPES} | {"url": ["x/y"]})[
            "url-host"
        ]
        == set()
    )
    assert evaluate.expected_counts({"url": ["http:///x"]})["url-host"] == 0


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("md5", SPLIT),
        ("ipv4", "relay.example.com"),
        ("email", "not-an-address"),
        ("domain", "nodot"),
        ("sha1", "zz"),
    ],
)
def test_a_corrected_value_must_have_the_shape_of_its_type(kind: str, value: str) -> None:
    result = draft(["c2.example.com"])
    entry = {"type": kind, "value": value, "writing": value, "class": "plain", "location": "x", "reason": "r"}
    review = complete_review(result)
    review["add"] = [entry]
    assert any(f"is not a {kind}" in p for p in evaluate.review_problems(result, review))


def test_a_url_host_is_classed_by_how_the_host_is_written() -> None:
    assert evaluate.host_class("hxxp://stage.example.net/b") == "plain"
    assert evaluate.host_class("http：//cjk.example.org/c") == "plain"
    assert evaluate.host_class("http://evil[.]example.com/a") == "ascii-defang"
    assert evaluate.host_class("http://１９８.51.100.1:80/x") == "fullwidth-cjk-defang"


def test_write_template_never_loses_a_filled_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evaluate, "DATA", tmp_path)
    (tmp_path / "t" / "truth").mkdir(parents=True)
    entry = report()
    a, b = draft(["a.example.com"]), draft(["b.example.com"])
    path = evaluate.template_path("t", entry)
    evaluate.write_template("t", entry, a, [])
    filled = {**json.loads(path.read_text(encoding="utf-8")), "reviewed_by": "reviewer of a"}
    path.write_text(json.dumps(filled), encoding="utf-8")
    for current in (b, a, b, a):
        evaluate.write_template("t", entry, current, [{"label": "pdf/t01.pdf page 1", "file": "1.png"}])
    template = json.loads(path.read_text(encoding="utf-8"))
    assert (template["draft_sha256"], template["reviewed_by"]) == (a["sha256"], "reviewer of a")
    assert template["images"] == ["pdf/t01.pdf page 1"]


def test_judging_and_lost_values_after_errors(
    reviewed_set: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluate.command_review("t")
    commit(reviewed_set)
    fake_tools(monkeypatch, iocextract_fails=False)

    def failing(path: Path, flags: list[str]) -> dict[str, Any]:
        if not flags:
            raise RuntimeError("default failed")
        return {
            "values": {kind: ["c2.example.net"] if kind == "domain" else [] for kind in evaluate.TYPES},
            "warnings": [],
            "suppressed": {},
        }

    monkeypatch.setattr(evaluate, "run_ttprism", failing)
    evaluate.command_run("t", "after")
    evaluate.command_score("t", "after")
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["reports"][0]["lost_by_default_filtering"].startswith("not comparable")
    assert results["lost_by_default_filtering"] == {}
    assert {total["status"] for total in results["totals"].values()} == {results["status"]}
    assert results["totals"]["iocextract"]["unjudged"] == 1
    # A filled-in sheet is not written over, and only its own items are taken.
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "judge", "t", "after"])
    evaluate.command_judge("t", "after")
    sheet_file = reviewed_set["tmp"] / "t" / "judging" / "after.json"
    sheet = json.loads(sheet_file.read_text(encoding="utf-8"))
    sheet["items"][0].update(category="c", reason="r")
    sheet_file.write_text(json.dumps(sheet), encoding="utf-8")
    with pytest.raises(SystemExit, match=r"not yet in judgements\.json"):
        evaluate.command_judge("t", "after")
    sheet["items"][0]["value"] = "edited.example.com"
    sheet_file.write_text(json.dumps(sheet), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["evaluate.py", "judge", "t", "after", "--import"])
    with pytest.raises(SystemExit, match="not a value the tools found"):
        evaluate.command_judge("t", "after")


def test_the_review_cannot_change_after_the_tools_ran(
    reviewed_set: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluate.command_review("t")
    commit(reviewed_set)
    fake_tools(monkeypatch, iocextract_fails=False)
    evaluate.command_run("t", "after")
    data = json.loads(evaluate.MANIFEST.read_text(encoding="utf-8"))
    data["sets"]["t"][0]["truth_review"]["reviewed_by"] = "someone else"
    evaluate.MANIFEST.write_text(json.dumps(data), encoding="utf-8")
    commit(reviewed_set)
    with pytest.raises(SystemExit, match="cannot change after the tools have run"):
        evaluate.command_run("t", "again")


def test_contexts_find_urls_written_with_hxxp() -> None:
    text = "攻擊者也使用 hxxp://body.example.com/x 作為下載點。\nfxp://files.example.net/a"
    contexts = evaluate._contexts(
        text, {("url", "http://body.example.com/x"), ("url", "ftp://files.example.net/a")}
    )
    assert all(contexts.values()), contexts


def test_the_writing_classes_and_the_defang_styles_cover_the_same_characters() -> None:
    for raw, style in (
        ("update－check.example.com", "－"),
        ("http://203.0.113.9／a.php", "／"),
        ("http：//a.example.com", "："),
    ):
        reading = evaluate.ascii_reading(raw)
        assert reading.writing_class(0, len(reading.text)) == "fullwidth-cjk-defang"
        assert style in [s for _, _, s in evaluate.defang_occurrences(raw)]


# --------------------------------------------------------------------------- review round 7


def test_numbering_with_a_full_width_dot_stays_apart_from_the_value() -> None:
    # pypdf gives a space after "．" where the page has none.
    assert values(["１． 198.51.100.23", "３． evil.example.com", "網域． bad.example.net"]) == {
        "domain": ["bad.example.net", "evil.example.com"],
        "ipv4": ["198.51.100.23"],
    }
    # ASCII numbering before a spaced full-width dot is read with it, and flagged.
    assert "loose-defang" in {kind for _, kind in warnings(["2 ． 203.0.113.5"])}


def test_two_spaces_around_a_form_are_read() -> None:
    assert values(["evil 【 . 】  example.com", "198  【.】  51 【.】 100 【.】 25"]) == {
        "domain": ["evil.example.com"],
        "ipv4": ["198.51.100.25"],
    }


def test_spaced_colon_and_slash_forms_are_read_or_flagged() -> None:
    assert values(["https ：／／ evil ． example ． com"])["url"] == ["https://evil.example.com"]
    assert values(["hxxps 【 : 】 //evil.example.com/a.exe"])["url"] == ["https://evil.example.com/a.exe"]
    assert values(["https://evil.example.com 【 / 】 b.php"])["url"] == ["https://evil.example.com/b.php"]
    result = draft(["hxxps ： //update-check ． example ． com ／ a.exe"])
    assert result["values"]["url"][0]["value"] == "https://update-check.example.com"
    assert "url-cut" in {w["kind"] for w in result["warnings"]}


def test_ligatures_are_read_as_their_letters() -> None:
    result = draft(["conﬁg-update.example.com", "ﬂash@example.org"])
    assert {k: [e["value"] for e in v] for k, v in result["values"].items()} == {
        "domain": ["config-update.example.com"],
        "email": ["flash@example.org"],
    }
    assert [w["kind"] for w in result["warnings"]] == ["non-ascii", "non-ascii"]


def test_an_asterisk_inside_a_label_masks_the_value() -> None:
    result = draft(["ev*l.example.com", "a*b@example.org", "evil.*.com", "*.example.net"])
    assert result["values"] == {}
    assert sorted(e["value"] for entries in result["masked"].values() for e in entries) == [
        "*.example.net",
        "a*b@example.org",
        "ev*l.example.com",
        "evil.*.com",
    ]


def test_a_hash_label_covers_only_its_own_block() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    lines = ["MD5：", md5, "Hash:", "loader.dll " + SPLIT[:32], SPLIT[32:]]
    assert ("hex-cut") in {kind for _, kind in warnings(lines)}
    assert warnings(["SHA\u00a0256", md5]) == [(1, "hash-label")]
    assert warnings(["SHA–256", md5]) == [(1, "hash-label")]


def test_whole_hashes_on_adjacent_lines_are_not_flagged() -> None:
    sha256s = [hashlib.sha256(bytes([i])).hexdigest() for i in range(5)]
    md5s = [hashlib.md5(bytes([i])).hexdigest() for i in range(5)]  # noqa: S324
    sha1s = [hashlib.sha1(bytes([i])).hexdigest() for i in range(5)]  # noqa: S324
    # Lists without a label, past a page header, rows of several hashes, mixed lists.
    assert warnings(["雜湊值", *sha256s]) == []
    assert warnings(["SHA256", *sha256s[:2], "TLP:CLEAR", "某資安公司 12 / 20", *sha256s[2:]]) == []
    assert (
        warnings(["MD5 SHA1 SHA256", *(" ".join(row) for row in zip(md5s, sha1s, sha256s, strict=True))])
        == []
    )
    assert warnings(["SHA256 MD5", *(" ".join(row) for row in zip(sha256s, md5s, strict=True))]) == []
    assert warnings([md5s[0], sha256s[0], md5s[1], sha256s[1]]) == []
    assert warnings([f"{SPLIT} {SPLIT}", f"{SPLIT} {SPLIT}"]) == []
    # A SHA-512 cut into two pieces of SHA-256 length looks the same and is not looked for (6.8); cut
    # into pieces of other lengths, it is flagged.
    sha512 = SPLIT + SPLIT[::-1]
    assert warnings(["loader.dll " + sha512[:64], sha512[64:]]) == []
    assert {kind for _, kind in warnings(["loader.dll " + sha512[:50], sha512[50:]])} == {"hex-cut"}


def test_a_sha256_in_a_narrow_cell_before_an_md5_cell_is_flagged() -> None:
    # Chromium centres cells: the second half of the SHA-256 shares a line with the MD5 cell.
    sha256, md5 = hashlib.sha256(b"loader").hexdigest(), hashlib.md5(b"loader").hexdigest()  # noqa: S324
    found = warnings(["SHA256 MD5", sha256[:32], f"{sha256[32:]} {md5}"])
    assert ("hex-cut") in {kind for _, kind in found}
    # A half followed by other text on its line is flagged by a SHA-256 label in its block only (6.8).
    found = warnings(["SHA-256", f"{sha256[:32]} loader.dll", sha256[32:]])
    assert [kind for _, kind in found].count("hash-label") == 2
    assert warnings(["SHA-256", "Windows 版本", f"{sha256[:32]} loader.dll", sha256[32:]]) == []


def test_urls_cut_before_chinese_text_are_flagged() -> None:
    for lines in (
        ["hxxp://evil[.]example[.]com/files/ 公文通知 .rar"],
        ["http://evil.example.com/search?公文通知"],
        ["http://evil.example.com/files/\u200b公文通知.rar"],
        ["http://evil.example.com/files/", "公文通知.rar"],
    ):
        assert warnings(lines), lines
    assert warnings(["http://a.example.com/x", "下載器"]) == []
    assert warnings(["網址\thttp://203.0.113.9/x.php\t回報"]) == []


def test_a_url_without_a_host_can_be_removed() -> None:
    result = draft(["hxxp://..."])
    assert result["values"]["url"][0]["value"] == "http://"
    remove = [{"type": "url", "value": "http://", "reason": "nothing after the scheme", "warnings": ["W1"]}]
    review = complete_review(result, remove=remove)
    review["warnings"]["W1"]["resolution"] = "corrected"
    review["values"] = evaluate.final_values(result, review)
    assert evaluate.review_problems(result, review) == []


def test_a_name_can_be_corrected_while_a_url_has_it_as_its_host() -> None:
    result = draft(["c2[.]example[.]org", "http://c2.example.org/gate.php"])
    review = complete_review(
        result,
        remove=[{"type": "domain", "value": "c2.example.org", "reason": "wrong place"}],
        add=[
            {
                "type": "domain",
                "value": "c2.example.org",
                "writing": "c2[.]example[.]org",
                "class": "ascii-defang",
                "location": "pdf/t01.pdf page 2 line 3",
                "reason": "its place",
            }
        ],
    )
    assert evaluate.review_problems(result, review) == []


def test_a_url_host_is_classed_by_its_plainest_writing_in_any_occurrence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "IOCs\nhttp://evil[.]example.net/a.exe\nhxxp://evil.example.net/a.exe\nEND"
    entry = {**report(), "id": "t01"}
    parts = [{"format": "pdf", "start": 0, "end": len(text)}]
    result = evaluate.draft_truth(text, entry, parts)
    entry["truth_review"] = complete_review(result)
    monkeypatch.setattr(evaluate, "committed_manifest", lambda: {"sets": {"t": [entry]}})
    truth = evaluate.load_reviewed_truth("t", entry, text, {"parts": parts})
    assert truth["classes"]["domain"]["evil.example.net"] == "plain"


def test_a_report_uses_full_width_writing_only_for_indicators() -> None:
    text = "版本７．０．０．１ 與 ｗｗｗ．example．org\nIOCs\nc2.example.net\nEND"
    entry = report()
    parts = [{"format": "pdf", "start": 0, "end": len(text)}]
    result = evaluate.draft_truth(text, entry, parts)
    review = complete_review(result)
    truth = {
        "text": text,
        "conversion": {"parts": parts},
        "draft": result,
        "review": review,
        "truth": {"domain": ["c2.example.net"]},
        "ambiguous": {},
    }
    use = evaluate._writing_use(truth, "pdf", entry, {})
    assert (use["uses_fullwidth_cjk"], use["fullwidth_cjk_in_any_value"]) == (False, 10)
    judged = {"ipv4": {"7.0.0.1": ["a", "an indicator"]}}
    assert evaluate._writing_use(truth, "pdf", entry, judged)["uses_fullwidth_cjk"] is True


@pytest.mark.parametrize(
    ("unit", "end", "after"),
    [
        (".", "", "next"),  # the line end found past a run of punctuation
        ("d41d8cd98f00b204e9800998ecf8427e ", "ab12  ", "cd34" + "0" * 32 + " x"),  # the hashes at a cut
    ],
)
def test_the_line_end_rules_cost_linear_time(unit: str, end: str, after: str) -> None:
    # _cut_warnings alone, since the rest of the draft costs far more per line than these rules.
    def cost(size: int) -> float:
        readings = [evaluate.ascii_reading(unit * (size // len(unit)) + end), evaluate.ascii_reading(after)]
        results = [evaluate.line_values(reading) for reading in readings]
        lines = [{"n": 2, "format": "pdf"}, {"n": 3, "format": "pdf"}]

        def run() -> None:
            evaluate._cut_warnings(evaluate._Warnings(), 0, lines, readings, results, [None, None])

        return seconds_per_mb(run, size / 1_000_000, repeat=3)

    assert cost(800_000) < 2.5 * cost(200_000), unit


# --------------------------------------------------------------------------- review round 8


def test_a_url_stopping_at_a_full_width_url_character_is_flagged() -> None:
    for line in ("http://evil.example.com/a.php？id=1", "http://evil.example.com/a.php ？ id=1"):
        result = draft([line])
        assert result["values"]["url"][0]["value"] == "http://evil.example.com/a.php"
        assert [w["kind"] for w in result["warnings"]] == ["non-ascii"], line
    # At the end of a line (Chromium breaks a narrow cell there) it is flagged too; before Chinese text
    # it is punctuation.
    assert warnings(["http://evil.example.com/a.php？"]) == [(0, "non-ascii")]
    assert warnings(["http://evil.example.com/b？是"]) == []


def test_numbering_glued_to_a_value_is_flagged() -> None:
    for fmt in ("pdf", "html"):
        for line in ("１．198.51.100.23", "1．198.51.100.23", "１．１９８．５１．１００．２３"):
            result = draft([line], fmt)
            assert [w["kind"] for w in result["warnings"]] == ["loose-defang"], (fmt, line)
    # After Chinese text a full-width dot is punctuation, not part of a name.
    assert values(["網域．bad.example.net", "聯絡＠example.org"]) == {
        "domain": ["bad.example.net", "example.org"]
    }
    assert warnings(["１．攻擊手法"]) == []
    # Glued to a name, the number is read into it.
    assert sorted(warnings(["２．evil．example．com"])) == [(0, "loose-defang"), (0, "non-ascii")]


def test_the_defang_statistic_counts_hxxp_before_spaced_and_bracketed_colons() -> None:
    for raw in (
        "hxxps ： //update-check ． example ． com",
        "hxxp(:)//evil[.]example[.]com",
        "hxxp ://a.example.com",
    ):
        assert "hxxp" in [s for _, _, s in evaluate.defang_occurrences(raw)], raw
    assert [s for _, _, s in evaluate.defang_occurrences("https:／／evil.example.com/a")] == ["／"]


def test_file_globs_are_not_masked_names() -> None:
    result = draft(["C:\\Users\\*\\AppData\\Startup\\*.lnk", "%TEMP%\\*.vbs", "/var/www/*.php", "*.zip"])
    assert (result["values"], result["masked"], result["warnings"]) == ({}, {}, [])
    # A lone asterisk before a name is a mark, not a mask: the name stays, with a warning.
    result = draft(["*evil.example.com"])
    assert result["values"]["domain"][0]["value"] == "evil.example.com"
    assert [w["kind"] for w in result["warnings"]] == ["mask-next"]


def test_values_next_to_a_mask_character_are_flagged() -> None:
    for line in (
        "198.51.100.2*",
        "1*8.51.100.23",
        "203.0.113.1xx",
        "evil.example.co*",
        "mail.example.gov.**",
        "○○abc.gov.tw",
        "ev＊l.example.com",
        "http://ev＊l.example.com/a",
    ):
        assert "mask-next" in {kind for _, kind in warnings([line])}, line
    assert warnings(["evil.example.com", "198.51.100.23"]) == []


def test_names_after_other_schemes_are_found() -> None:
    lines = [
        "${jndi:ldap://evil.example.com:1389/a}",
        "tcp://c2[.]example[.]net:443",
        "wss://ws.example.org/s",
    ]
    assert values(lines) == {"domain": ["c2.example.net", "evil.example.com", "ws.example.org"]}


def test_a_space_after_the_scheme_is_read() -> None:
    result = draft(["https:// evil.example.com/a", "http ://b.example.com/x"])
    assert {(e["value"], e["class"]) for e in result["values"]["url"]} == {
        ("https://evil.example.com/a", "ascii-defang"),
        ("http://b.example.com/x", "ascii-defang"),
    }


def test_urls_cut_before_a_chinese_file_name_are_flagged() -> None:
    for lines in (
        ["hxxp://evil[.]example[.]com/files/2023", "年度計畫 .rar 釣魚文件"],
        ["hxxp://evil[.]example[.]com/upload/112", "年度預算.zip"],
    ):
        assert (0, "url-cut") in warnings(lines), lines
    assert warnings(["http://a.example.com/x", "下載器"]) == []
    assert warnings(["http://a.example.com/x", "中繼站 hxxp://b[.]example[.]com/y"]) == []


def test_an_ambiguous_name_that_a_kept_url_has_as_its_host_is_refused() -> None:
    result = draft(["C2 網域 update-", "check.example.com", "下載網址 http://update-check.example.com/a.exe"])
    review = complete_review(
        result,
        remove=[{"type": "domain", "value": "check.example.com", "reason": "a fragment"}],
        ambiguous=[
            {
                "type": "domain",
                "readings": ["update-check.example.com", "updatecheck.example.com"],
                "from_draft": False,
                "writing": "update- / check.example.com",
                "location": "pdf/t01.pdf page 1 line 2",
                "reason": "wrapped at a hyphen",
            }
        ],
    )
    problems = evaluate.review_problems(result, review)
    assert any("is the host of the URL" in p and p.startswith("ambiguous") for p in problems), problems


def test_a_url_whose_host_cannot_be_a_name_is_flagged_and_refused() -> None:
    result = draft(["C2：hxxp://a[.]example[.]com,hxxp://b[.]example[.]com"])
    assert [w["kind"] for w in result["warnings"]] == ["url-unparseable"]
    problems = evaluate.review_problems(result, complete_review(result))
    assert any("no host that can be a name or an address" in p for p in problems), problems
    assert evaluate.normalise_url("http://[2001:db8::1]/a")[1]
    assert evaluate.normalise_url("http://intranet/")[1]


def reviewed_truth(text: str, **changes: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = {**report(), "id": "t01"}
    parts = [{"format": "pdf", "start": 0, "end": len(text)}]
    result = evaluate.draft_truth(text, entry, parts)
    review = complete_review(result, **changes)
    truth = {
        "text": text,
        "conversion": {"parts": parts},
        "draft": result,
        "review": review,
        "truth": {k: [e["value"] for e in v] for k, v in review["values"].items()},
        "ambiguous": {},
    }
    return truth, entry


def test_a_body_writing_of_a_ground_truth_indicator_counts_as_use() -> None:
    truth, entry = reviewed_truth(
        "中繼站為 c2【.】example【.】net 與 hxxp://c3．example．org/a\nIOCs\nc2[.]example[.]net\nEND"
    )
    truth["truth"]["url"] = ["http://c3.example.org/b"]
    truth["truth"]["domain"].append("c3.example.org")
    use = evaluate._writing_use(truth, "pdf", entry, {})
    assert (use["fullwidth_cjk_indicators_in_body"], use["uses_fullwidth_cjk"]) == (2, True)


def test_a_value_the_reviewer_reclassed_does_not_count_as_use() -> None:
    text = "IOCs\nc2【.】example【.】net\nEND"
    add = {
        "type": "domain",
        "value": "c2.example.net",
        "writing": "c2.example.net",
        "class": "plain",
        "location": "pdf/t01.pdf page 1 line 2",
        "reason": "the page shows ASCII",
        "warnings": ["W1"],
    }
    remove = {"type": "domain", "value": "c2.example.net", "reason": "class", "warnings": ["W1"]}
    truth, entry = reviewed_truth(text, add=[add], remove=[remove])
    assert evaluate._writing_use(truth, "pdf", entry, {})["uses_fullwidth_cjk"] is False


def test_full_width_body_values_outside_the_truth_need_a_judgement() -> None:
    truth, entry = reviewed_truth("聯絡 ｗｗｗ．example．org 取得\nIOCs\nc2.example.net\nEND")
    assert evaluate.body_fullwidth_values(truth, "pdf", entry) == {("domain", "www.example.org")}


def test_contexts_of_values_a_tool_built() -> None:
    text = "C2 為 update-check[.]example[.]org\n參考 https://blog.example.com/2026/\nreport.html 一文"
    contexts = evaluate._contexts(
        text,
        {
            ("url", "http://update-check.example.org"),
            ("url", "https://blog.example.com/2026/report.html"),
            ("url", "http://only-host.example.net/x"),
        },
    )
    assert contexts[("url", "http://update-check.example.org")][0].startswith("(without its scheme)")
    assert contexts[("url", "https://blog.example.com/2026/report.html")][0].startswith(
        "(across a line break)"
    )
    assert contexts[("url", "http://only-host.example.net/x")] == []


# --------------------------------------------------------------------------- review round 9


def test_a_mask_before_a_full_width_at_sign_or_dot_is_read_like_its_ascii_form() -> None:
    result = draft(["ser***＠example.org", "*．example．net", "evil．*．com"])
    assert result["values"] == {}
    assert sorted(e["value"] for entries in result["masked"].values() for e in entries) == [
        "*.example.net",
        "evil.*.com",
    ]
    # pypdf's spaces: the name after the at sign is read, and flagged.
    result = draft(["寄件者 ser*** ＠ example.org"])
    assert result["values"]["domain"][0]["value"] == "example.org"
    assert [w["kind"] for w in result["warnings"]] == ["mask-next"]


def test_the_host_after_another_scheme_with_user_info_is_a_name() -> None:
    assert values(["ssh://root@c2.example.net", "socks5://user:pass@proxy.example.com:1080"]) == {
        "domain": ["c2.example.net", "proxy.example.com"]
    }


def test_url_rows_are_not_flagged_but_cuts_are() -> None:
    # A description cell after a URL, a numbered list, a 序號 or type column: no cut.
    assert warnings(["hxxps://cdn0[.]example[.]com/static/js/app0.js 植入惡意 JavaScript 的網頁"]) == []
    assert warnings(["1. hxxp://a[.]example[.]com/x", "2. hxxp://b[.]example[.]com/y"]) == []
    assert warnings(["(1) hxxp://a[.]example[.]com/x", "(2) hxxp://b[.]example[.]com/y"]) == []
    assert warnings(["URL\thxxp://a[.]example[.]com/x", "IP\t198[.]51[.]100[.]1"]) == []
    assert warnings(["http://a.example.com/x", "next text"], "html") == []
    # A Chinese file name with digits, a full-width URL character where Chromium broke the line.
    for lines in (
        ["hxxp://evil[.]example[.]com/files/112", "年第 1 季報告 .pdf"],
        ["http://evil.example.com/login.php ？", "id=1234"],
        ["http://evil.example.com/update", "＿ v2.exe"],
    ):
        assert warnings(lines)[:1] in ([(0, "url-cut")], [(0, "non-ascii")]), lines


def test_a_url_cut_inside_its_host_is_flagged() -> None:
    result = draft(["hxxp://update-check[.]ex", "ample[.]com/a.exe"])
    assert (0, "url-cut") in [(w["line"] - 2, w["kind"]) for w in result["warnings"]]
    assert warnings(["http://198.51.100.7/a", "hxxp://abc.onion/x"]) == []


def test_urls_joined_after_a_port_or_a_path_are_flagged() -> None:
    for line in (
        "C2：hxxp://198[.]51[.]100[.]7:8080,hxxp://198[.]51[.]100[.]8:8080",
        "hxxp://a[.]example[.]com/a.php;hxxps://b[.]example[.]com/b",
    ):
        assert [kind for _, kind in warnings([line])] == ["url-unparseable"], line
    assert warnings(["http://a.example.com/r?u=http://b.example.com/"]) == []


def test_an_ambiguous_address_that_a_kept_url_has_as_its_host_is_allowed() -> None:
    result = draft(["198.51.100.23", "http://198.51.100.23/a"])
    review = complete_review(
        result,
        ambiguous=[
            {
                "type": "ipv4",
                "readings": ["198.51.100.23", "198.51.100.28"],
                "from_draft": True,
                "writing": "198.51.100.23",
                "location": "pdf/t01.pdf page 1 line 2",
                "reason": "the last digit is unclear on the page",
            }
        ],
    )
    assert not [p for p in evaluate.review_problems(result, review) if "host of the URL" in p]


def test_xxx_inside_a_label_is_not_a_mask() -> None:
    result = draft(["foxxxy.example.com", "mail.nxxxx.gov.tw"])
    assert (sorted(e["value"] for e in result["values"]["domain"]), result["masked"]) == (
        ["foxxxy.example.com", "mail.nxxxx.gov.tw"],
        {},
    )


def test_dates_versions_and_numbered_urls_are_not_loose_defang() -> None:
    lines = ["c2[.]example[.]net\t１１３．０６．０１", "v2．0 惡意程式", "No．1 evil[.]example[.]com"]
    lines += ["１．hxxp://evil[.]example[.]com/a", "表４．２ 中繼站"]
    assert [kind for _, kind in warnings(lines, "html")] == []


def test_contexts_show_the_value_in_a_window_and_the_next_line_at_a_wrap() -> None:
    long_line = "說明" * 300 + " 中繼站 evil.example.net 用於回報。" + "結尾" * 300
    text = f"{long_line}\n參考 https://blog.example.com/2026/\nreport.html 一文\nfoo.example.com.cn"
    contexts = evaluate._contexts(
        text,
        {
            ("domain", "evil.example.net"),
            ("url", "https://blog.example.com/2026/"),
            ("domain", "example.com"),
        },
    )
    (window,) = contexts[("domain", "evil.example.net")]
    assert "evil.example.net" in window
    assert len(window) < 500
    assert window.startswith("…")
    assert window.endswith("…")
    assert "(next line) report.html" in contexts[("url", "https://blog.example.com/2026/")][0]
    assert contexts[("domain", "example.com")][0].startswith("(inside a longer value)")


# --------------------------------------------------------------------------- review round 10


def test_a_full_width_address_cut_by_a_line_break_is_flagged() -> None:
    for lines in (
        ["C2 位址 １９８．５１．１", "００．２３"],
        ["２０３．０．１１", "３．１５７"],
        ["１９８．５１", "．１００．２３"],
    ):
        assert warnings(lines) == [(0, "name-cut")], lines
    # Whole addresses in numbered rows, dates and versions are not cut addresses.
    assert warnings(["1 198.51.100.23", "2 198.51.100.24", "3 198.51.100.25"]) == []
    assert warnings(["c2[.]example[.]net 113.06.01", "evil[.]example[.]com 113.06.02"]) == []


def test_bullets_and_words_before_a_value_are_not_masks() -> None:
    lines = [
        "● update[.]example[.]com",
        "○ c2[.]example[.]net",
        "* evil[.]example[.]org",
        "Linux 198.51.100.23",
    ]
    assert warnings(lines) == []
    assert [kind for _, kind in warnings(["mail.nxxxx.gov.tw"])] == ["mask-next"]


def test_more_list_and_row_heads_are_skipped() -> None:
    for first, second in (
        ("1 、 hxxp://a[.]example[.]com/x.js", "2 、 hxxp://b[.]example[.]com/y.js"),
        ("(1)hxxp://a[.]example[.]com/x", "(2)hxxp://b[.]example[.]com/y"),
        ("一、 hxxp://198[.]51[.]100[.]1:8080/", "二、 hxxp://198[.]51[.]100[.]2:8080/"),
        ("C2 hxxp://c2-1[.]example[.]net/gate.php", "C2 198[.]51[.]100[.]1"),
        ("SHA256 hxxp://a[.]example[.]com/x", "SHA-1 hxxp://b[.]example[.]com/y"),
    ):
        assert warnings([first, second]) == [], first
    # A description with a date after a URL is not the rest of it.
    assert warnings(["hxxps://cdn0[.]example[.]com/app.js 釣魚網頁 2024.05.01"]) == []


def test_numbering_glued_to_a_name_starting_with_a_digit_is_flagged() -> None:
    for line in ("１．123456789@qq.com", "２．360safe-update.example.com"):
        assert sorted(kind for _, kind in warnings([line])) == ["loose-defang", "non-ascii"], line


def test_a_page_without_a_doctype_that_starts_with_comments_costs_linear_time() -> None:
    def cost(junctions: int) -> float:
        page = "<!-- banner -->\n" + "<!-- a -->\n<!-- b -->\n" * junctions + "<p>x</p>"
        return seconds_per_mb(lambda: evaluate.reviewable_page(page), len(page) / 1_000_000, repeat=3)

    assert cost(40_000) < 2.5 * cost(10_000)
    body, _ = evaluate.reviewable_page("<!-- saved -->\n<!DOCTYPE html><p>x</p>")
    assert body.startswith(b"<!-- saved -->\n<!DOCTYPE html><style nonce=")


def test_contexts_of_values_before_punctuation() -> None:
    text = (
        "上傳網址為 http://198.51.100.24/do/index.php?id=ssss：\n參考 hxxps://a.example.com/auth.php?\nsid=1"
    )
    contexts = evaluate._contexts(
        text,
        {("url", "http://198.51.100.24/do/index.php?id=ssss"), ("url", "https://a.example.com/auth.php")},
    )
    assert not contexts[("url", "http://198.51.100.24/do/index.php?id=ssss")][0].startswith("(inside")
    assert "(next line) sid=1" in contexts[("url", "https://a.example.com/auth.php")][0]


# --------------------------------------------------------------------------- review round 11


def test_an_address_cut_into_three_pieces_is_flagged() -> None:
    assert warnings(["１９８．５", "１．１０", "０．２３"]) == [(0, "name-cut")]
    assert warnings(["C2 位址 １９８．５", "１．１０", "０．２３", "中繼站"]) == [(0, "name-cut")]


def test_a_number_ending_a_row_before_an_address_is_not_a_cut() -> None:
    for lines in (
        ["evil[.]example[.]com 2023/9/5", "91.92.109.18 中繼站"],
        ["evil[.]example[.]com 7", "91.92.109.18"],
        ["c2 1", "98.51.100.23"],
        ["port 80", "203.0.113.5"],
    ):
        assert [kind for _, kind in warnings(lines)] == [], lines


def test_type_cells_are_a_list_and_cut_url_rests_are_not_cells() -> None:
    assert warnings(["C&C hxxp://a[.]example[.]com/x", "C&C hxxp://b[.]example[.]com/y"]) == []
    assert warnings(["hxxp://a[.]example[.]com/l", "ogin2 198[.]51[.]100[.]7"]) == [(0, "url-cut")]


def test_dates_and_ports_after_a_description_are_not_paths_but_digit_extensions_are() -> None:
    for line in (
        "hxxps://cdn0[.]example[.]com/app.js 釣魚網頁 113/05/01",
        "hxxps://cdn0[.]example[.]com/app.js 釣魚網頁 2024-05-01",
        "hxxps://cdn0[.]example[.]com/app.js 連線埠 443/tcp",
    ):
        assert warnings([line]) == [], line
    assert warnings(["hxxp://evil[.]example[.]com/files/113 年度計畫 .7z 釣魚文件"]) == [(0, "non-ascii")]
    assert warnings(["hxxp://evil[.]example[.]com/files/113", "年度計畫 .7z 釣魚文件"]) == [(0, "url-cut")]


def test_full_width_masks_across_pypdf_spaces_are_flagged() -> None:
    for line in ("〇〇 abc.gov.tw", "ev ＊ l.example.com", "1 ＊ 8.51.100.23"):
        assert [kind for _, kind in warnings([line])] == ["mask-next"], line
    assert warnings(["● update[.]example[.]com"]) == []


def test_contexts_prefer_whole_places_and_ignore_cjk_after_punctuation() -> None:
    text = "下載網址為 http://198.51.100.7/view/index.php?id=8600：該網址會回傳設定檔。\n"
    text += "C2 網域 evil[.]example[.]com 已停用\n下載位址 hxxp://evil[.]example[.]com/a.exe"
    contexts = evaluate._contexts(
        text, {("url", "http://198.51.100.7/view/index.php?id=8600"), ("url", "http://evil.example.com")}
    )
    assert not contexts[("url", "http://198.51.100.7/view/index.php?id=8600")][0].startswith("(inside")
    assert contexts[("url", "http://evil.example.com")][0].startswith("(without its scheme) C2")


def test_the_style_sheet_goes_after_an_xml_declaration_and_doctype() -> None:
    body, _ = evaluate.reviewable_page('<?xml version="1.0"?>\n<!DOCTYPE html><p>x</p>')
    assert body.startswith(b'<?xml version="1.0"?>\n<!DOCTYPE html><style nonce=')


# --------------------------------------------------------------------------- release-gate review


def test_a_spaced_hyphen_or_colon_next_to_a_value_is_flagged() -> None:
    for line in (
        "網域： update － check.example.com",
        "update ‐ check.example.com",
        "網址： http://evil.example.com ： 8080/gate.php",
    ):
        assert [kind for _, kind in warnings([line])] == ["non-ascii"], line
    assert warnings(["evil.example.com － 中繼站"]) == []


def test_onion_names_and_names_after_a_full_width_slash_are_found() -> None:
    assert values(["abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvw[.]onion"]) == {
        "domain": ["abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvw.onion"]
    }
    assert values(["198.51.100.23／evil.example.com"]) == {
        "domain": ["evil.example.com"],
        "ipv4": ["198.51.100.23"],
    }


def test_a_cut_url_is_not_shown_as_standing_without_its_scheme() -> None:
    text = "下載點 hxxps://dl【.】example.net/a.exe\nC2 為 update[.]example[.]org"
    contexts = evaluate._contexts(text, {("url", "https://dl"), ("url", "http://update.example.org")})
    assert contexts[("url", "https://dl")][0].startswith("(inside a longer value)")
    assert contexts[("url", "http://update.example.org")][0].startswith("(without its scheme)")


def test_the_use_counts_are_of_distinct_indicators() -> None:
    text = "IOCs\nc2【.】example【.】net\nc2【.】example【.】net\nhxxp://c2【.】example【.】net/a\nEND"
    truth, entry = reviewed_truth(text)
    truth["truth"]["domain"] = ["c2.example.net"]
    use = evaluate._writing_use(truth, "pdf", entry, {})
    assert use["fullwidth_cjk_indicators_in_appendix"] == 2  # the name, and the URL


def test_run_and_score_stop_on_a_defang_statistic_of_other_markers(
    reviewed_set: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluate.command_review("t")
    commit(reviewed_set)
    fake_tools(monkeypatch, iocextract_fails=False)
    path = evaluate.defang_path("t")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["reports"][0]["appendix_markers"] = {"start": "IOCs", "start_occurrence": 2}
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemExit, match="run `defang t` again"):
        evaluate.command_run("t", "after")
    evaluate.command_defang("t")
    evaluate.command_run("t", "after")
    path.unlink()
    with pytest.raises(SystemExit, match="is missing"):
        evaluate.command_score("t", "after")


def test_contexts_of_cut_urls_and_values_after_a_label_colon() -> None:
    text = "網址 hxxps://dl【.】example.net/a.exe\n網域 dl【.】example.net\n網域：update[.]example[.]org"
    contexts = evaluate._contexts(text, {("url", "https://dl"), ("url", "http://update.example.org")})
    assert contexts[("url", "https://dl")] == [
        "(inside a longer value) 網址 hxxps://dl【.】example.net/a.exe"
    ]
    assert contexts[("url", "http://update.example.org")][0].startswith("(without its scheme) 網域：")


def test_an_address_host_counts_in_the_appendix_as_in_the_body() -> None:
    text = "C2 為 hxxp://198【.】51【.】100【.】7/a\nIOCs\nhxxp://198【.】51【.】100【.】7/a\nEND"
    truth, entry = reviewed_truth(text)
    use = evaluate._writing_use(truth, "pdf", entry, {})
    assert use["fullwidth_cjk_indicators_in_appendix"] == use["fullwidth_cjk_indicators_in_body"] == 2


def test_lone_surrogates_from_pypdf_are_replaced_and_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Page:
        def __init__(self, text: str) -> None:
            self.text = text

        def extract_text(self) -> str:
            return self.text

    class Reader:
        is_encrypted = False

        def __init__(self, path: str) -> None:
            # A Big5 user-defined character (造字) as pypdf gives it, and an unmapped CID.
            self.pages = [Page("附錄 黃\udcfa@先生"), Page("evil.example.com\ud802")]

    fake = type(sys)("pypdf")
    fake.PdfReader = Reader  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pypdf", fake)
    text, info = evaluate.pdf_text(tmp_path / "t.pdf")
    assert text == "附錄 黃�@先生\nevil.example.com�"
    assert info["lone_surrogates_replaced"] == {"1": 1, "2": 1}
    assert evaluate.text_sha256(text)


def test_cut_urls_with_a_bare_host_keep_their_own_line() -> None:
    text = "本次事件共發現 45 個惡意樣本，透過 Windows API 呼叫。\nURL\thxxp://45【.】77【.】12【.】3/update/a.exe\n"
    text += "URL\thxxps://api【.】example【.】net/v1/beacon"
    contexts = evaluate._contexts(text, {("url", "http://45"), ("url", "https://api")})
    assert contexts[("url", "http://45")] == [
        "(inside a longer value) URL\thxxp://45【.】77【.】12【.】3/update/a.exe"
    ]
    assert contexts[("url", "https://api")][0].startswith("(inside a longer value) URL\thxxps://api")
