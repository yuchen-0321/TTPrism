"""The ground truth of the real-report evaluation: its line rules, warnings, review, and the steps after it.

docs/research/2026-10-real-reports/evaluate.py drafts the ground truth from each report's IOC appendix,
and a reviewer checks the draft line by line before any tool runs. These tests fix the draft's rules
and the checks of the review, run and score before the held-out reports are seen. Fixtures use
reserved names and documentation addresses only.
"""

from __future__ import annotations

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
    assert reading.writing_class(0, len(reading.text)) == writing


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
    # A list of whole hashes, and a table of names and hashes, are not flagged.
    assert warnings(["d41d8cd98f00b204e9800998ecf8427e", "0cc175b9c0f1b6a831c399e269772661"]) == []
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
    evaluate.command_truth("t")
    result = json.loads((tmp_path / "t" / "truth" / "t01.draft.json").read_text(encoding="utf-8"))
    images = {
        "draft_sha256": result["sha256"],
        "images": [{"label": "html/t01.html screenshot 1", "file": "1.png"}],
    }
    (tmp_path / "t" / "truth" / "t01" / "images.json").write_text(json.dumps(images), encoding="utf-8")
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
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["reports"][0]["unparseable_urls"] == {"iocextract": ["http:///x"]}
    evaluate.command_score("t", "after")
    out = capsys.readouterr().out
    assert "[PROVISIONAL]" in out
    results = json.loads((reviewed_set["tmp"] / "results-t-after.json").read_text(encoding="utf-8"))
    assert results["status"] == "provisional: 2 extracted values not judged yet"
    raw = results["totals"]["ttprism-raw"]
    assert raw["recall_by_class"] == {
        "plain": [1, 1, 1.0],
        "ascii-defang": [1, 1, 1.0],
        "fullwidth-cjk-defang": [1, 1, 1.0],
    }
    assert results["totals"]["ioc-finder"]["recall_by_class"]["fullwidth-cjk-defang"] == [0, 1, 0.0]
    assert results["reports_with_fullwidth_cjk_values"] == ["t01"]
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
    assert info["replaced_bytes"] == 2
    plain = tmp_path / "iocs.txt"
    plain.write_bytes(b"a.example.com \xff \xef\xbf\xbd\n")  # one damaged byte, one real U+FFFD
    text, info = evaluate.convert(plain, "text", override="utf-8:replace")
    assert info["replaced_bytes"] == 1
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
