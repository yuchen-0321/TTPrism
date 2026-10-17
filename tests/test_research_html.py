"""The HTML-to-text conversion and appendix rules of the real-report evaluation script.

docs/research/2026-10-real-reports/evaluate.py turns web pages into the text that every tool reads,
so its rules are fixed and tested before the pages are seen. Fixtures use reserved names and
documentation addresses only.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from research_evaluate import evaluate
from timing import seconds_per_mb


def text(page: str) -> str:
    converted: str = evaluate.html_to_text(page)[0]
    return converted


def counts(page: str) -> dict[str, Any]:
    info: dict[str, Any] = evaluate.html_to_text(page)[1]
    return info


# --------------------------------------------------------------------------- layout


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        # Inline elements and <wbr> add nothing, so a name split by markup stays one name.
        ("<p>C2: <span>update-check</span><b>.example</b>.com</p>", "C2: update-check.example.com"),
        ("<p>update<wbr>check.example.com</p>", "updatecheck.example.com"),
        ('<p><a href="http://198.51.100.7/x">198.51.100.7</a> and <code>203.0.113.9</code></p>',
         "198.51.100.7 and 203.0.113.9"),
        # Blocks start and end lines, <p> an empty line, <br> a line break.
        ("<div>a.example.com</div><div>b.example.com</div>", "a.example.com\nb.example.com"),
        ("<p>a.example.com</p><p>b.example.com</p>", "a.example.com\n\nb.example.com"),
        ("<p>a.example.com<br>b.example.com<br/>c.example.com</p>",
         "a.example.com\nb.example.com\nc.example.com"),
        ("<ul><li>a.example.com<li>b.example.com</ul>", "a.example.com\nb.example.com"),
        ("<h2>IOCs</h2><p>a.example.com</p>", "IOCs\n\na.example.com"),
        ("<div><p>a</p></div><div>b</div>", "a\n\nb"),
        ("text<div>block</div>more", "text\nblock\nmore"),
        # White space in the source is folded to one space, line breaks included.
        ("<p>update-\ncheck.example.com</p>", "update- check.example.com"),
        ("<p>  a.example.com \n\n\t b.example.com  </p>", "a.example.com b.example.com"),
        ("<span>a </span> <span> b</span>", "a b"),
        ("<p>a</p>\n\n   <p>b</p>", "a\n\nb"),
        # <pre> keeps its line breaks and spaces, except one right after the start tag.
        ("<pre>\nhxxp://198.51.100.7/a-\nb.exe\n  x  y</pre>", "hxxp://198.51.100.7/a-\nb.exe\n  x  y"),
        ("<pre><code>a.example.com\nb.example.com</code></pre>", "a.example.com\nb.example.com"),
        ("<p>a</p><pre><code>\nkept</code></pre>", "a\n\n\nkept"),  # not right after <pre>
        # Entities are decoded; attributes are never read.
        ("<p>&lt;a.example.com&gt; &amp; b.example.com</p>", "<a.example.com> & b.example.com"),
        ('<p><img src="x.png" alt="evil.example.com" title="t.example.com">seen.example.com</p>',
         "seen.example.com"),
        ('<p><a href="https://hidden.example.com/" title="t">link</a></p>', "link"),
    ],
)  # fmt: skip
def test_layout(page: str, expected: str) -> None:
    assert text(page) == expected


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        (
            "<table><tr><th>No.</th><th>IP</th></tr><tr><td>1</td><td>198.51.100.7</td></tr>"
            "<tr><td>2</td><td>203.0.113.9</td></tr></table>",
            "No.\tIP\n1\t198.51.100.7\n2\t203.0.113.9",
        ),
        (
            "<table>\n  <tr>\n    <td> 1 </td>\n    <td> a.example.com </td>\n  </tr>\n"
            "  <tr>\n    <td>2</td>\n    <td>b.example.com</td>\n  </tr>\n</table>",
            "1\ta.example.com\n2\tb.example.com",
        ),
        # Blocks inside a cell; implied end tags; an empty last cell.
        (
            "<table><tr><td><p>1</p></td><td><div>a.example.com</div></td></tr>"
            "<tr><td>2<td>b.example.com<tr><td>3</td><td></td></tr><tr><td>4</td></tr></table>",
            "1\ta.example.com\n2\tb.example.com\n3\n4",
        ),
        ("<p>before</p><table><tr><td>a</td></tr></table><p>after</p>", "before\n\na\n\nafter"),
        (
            "<table><tr><td>x<table><tr><td>a</td><td>b</td></tr></table></td><td>y</td></tr></table>",
            "x\na\tb\ty",  # the next cell of the outer row
        ),
    ],
)
def test_tables(page: str, expected: str) -> None:
    assert text(page) == expected


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        # An end tag for an element opened outside a table does not reach into it.
        (
            '<div class="entry"><table><tr><td><div>198.51.100.7</div></div></td><td>203.0.113.9</td>'
            "<td>evil.example.com</td></tr></table></div>",
            "198.51.100.7\t203.0.113.9\tevil.example.com",
        ),
        (
            "<span><table><tr><td>a.example.com</span></td><td>198.51.100.7</td><td>203.0.113.9</td></tr></table>",
            "a.example.com\t198.51.100.7\t203.0.113.9",
        ),
        (
            "<html><body><table><tr><td>a.example.com</td><td>1</td></tr></body>"
            "<tr><td>b.example.com</td><td>c.example.com</td></tr></table>",
            "a.example.com\t1\nb.example.com\tc.example.com",
        ),
        (
            "<ul><li>x<table><tr><td><li>a.example.com</td><td>198.51.100.7</td></tr></table></ul>",
            "x\na.example.com\t198.51.100.7",
        ),
        ("<html><body><pre>a\n</body>\nb\nc</pre>", "a\n\nb\nc"),
        # Empty cells keep their TABs and do not take the row's line break.
        (
            "<table><tr><td>1</td><td>a.example.com</td></tr><tr><td></td><td>b.example.com</td></tr></table>",
            "1\ta.example.com\n\tb.example.com",
        ),
        ('<h2>C2</h2><table><tr><td><img src="f.png"></td><td>evil.example.com</td></tr></table>',
         "C2\n\tevil.example.com"),
        ("<table><tr><td>1</td><td></td><td>x.example.com</td></tr></table>", "1\t\tx.example.com"),
        ("<table><tr><td>a</td><td><div></div></td><td>b</td></tr></table>", "a\t\tb"),
    ],
)  # fmt: skip
def test_table_structure_survives_stray_tags(page: str, expected: str) -> None:
    assert text(page) == expected


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        # Nothing inside a dropped element counts, not even its tags.
        ("<p>see <noscript><div>leak.example.com</div></noscript> more</p>", "see more"),
        ("<head><noscript><div>leak.example.com</div></noscript></head><body><p>kept</p>", "kept"),
        ("<p>x<template><div>leak.example.com</div></template></p>", "x"),
        ("<ul><li>a<noscript><li>leak.example.com</li></noscript></ul>", "a"),
        ("evil.example<noscript><br></noscript>.com", "evil.example.com"),
        ('<p>see <iframe src="x"><p>fallback.example.com</p></iframe> more</p>', "see more"),
        ("<template><template>a</template>b</template>c", "c"),
        ("<svg><title>t</title><desc>Created with Sketch.</desc></svg>Blog", "Blog"),
        ("<svg><metadata>meta.example.com</metadata></svg>Blog", "Blog"),
        # The same on every Python release: raw text, escapable raw text, an unterminated tag or comment.
        ("<xmp>hxxp://evil.example.com/a.php?x=1&amp;y=2</xmp>", "hxxp://evil.example.com/a.php?x=1&amp;y=2"),
        ('<textarea><a href="x">evil.example.com</a> &amp; x</textarea>',
         '<a href="x">evil.example.com</a> & x'),
        ("<textarea>if (a<b) { x.example.com }</textarea>", "if (a<b) { x.example.com }"),
        ("<p>keep.example.com</p><!-- unclosed c.example.org", "keep.example.com"),
        ('<p>before <a href="x>link</a> and more.example.com', "before"),
        ("<p>a<br/>b</p><xmp/>c", "a\nb\n\nc"),
    ],
)  # fmt: skip
def test_dropped_and_raw_text_elements(page: str, expected: str) -> None:
    assert text(page) == expected


def test_no_line_break_of_the_source_reaches_the_tools() -> None:
    page = (
        "<html>\n<body>\n<p>C2:\nupdate-\ncheck.example.com,\r\nfiles-\n.example.net</p>\n</body>\n</html>\n"
    )
    converted = text(evaluate.decode_html(page.encode())[0])
    assert converted == "C2: update- check.example.com, files- .example.net"


# --------------------------------------------------------------------------- characters


def test_soft_hyphens_are_deleted_and_other_format_characters_kept() -> None:
    page = "<p>update&shy;check.example.com up\u00addate.example.net a\u200bb&nbsp;c&#8203;d</p>"
    assert text(page) == "updatecheck.example.com update.example.net a\u200bb\u00a0c\u200bd"
    assert counts(page)["soft_hyphens_deleted"] == 2


def test_soft_hyphens_in_preformatted_text_are_deleted() -> None:
    assert text("<pre>update&shy;check.example.com</pre>") == "updatecheck.example.com"


def test_replacement_characters_are_counted() -> None:
    assert counts("<p>a&#0;b �</p>")["replacement_characters"] == 2


# --------------------------------------------------------------------------- dropped and hidden content


@pytest.mark.parametrize(
    "page",
    [
        "<head><title>t.example.com</title><style>.a{}</style></head><body><p>kept.example.com</p></body>",
        "<head><title>t.example.com</title><body><p>kept.example.com</p>",  # no </head>
        "<title>t.example.com</title><p>kept.example.com</p>",
        "<p>kept.example.com</p><script>var c2 = 's.example.com';</script>",
        "<p>kept.example.com</p><noscript>n.example.com</noscript><template><p>t.example.com</p></template>",
        '<p>kept.example.com</p><iframe src="x">i.example.com</iframe><!-- c.example.com -->',
        '<iframe src="x"/><p>kept.example.com</p>',
        "<!DOCTYPE html><html><head><meta charset=utf-8></head><body>kept.example.com</body></html>",
    ],
)
def test_dropped_content(page: str) -> None:
    assert text(page) == "kept.example.com"


def test_text_in_the_head_starts_the_body() -> None:
    assert text("<head><title>t</title>kept.example.com") == "kept.example.com"


@pytest.mark.parametrize(
    ("page", "hidden"),
    [
        ("<p>shown</p><div hidden>a.example.com</div>", 13),
        ('<p>shown</p><div style="color: red; DISPLAY : none">a.example.com</div>', 13),
        ('<p>shown</p><div style="visibility:hidden">a.example.com</div>', 13),
        ("<details><summary>shown</summary>a.example.com</details>", 13),
        ("<details open><summary>shown</summary>a.example.com</details>", 0),
        ("<p>shown</p><p>a.example.com</p>", 0),
    ],
)
def test_hidden_content_is_kept_and_counted(page: str, hidden: int) -> None:
    assert "a.example.com" in text(page)
    assert counts(page)["hidden_characters_kept"] == hidden


def test_unclosed_dropped_elements_are_reported() -> None:
    assert counts("<p>a</p><noscript><p>lost.example.com</p>")["unclosed_dropped_elements"] == ["noscript"]
    assert counts("<p>a</p>")["unclosed_dropped_elements"] == []


# --------------------------------------------------------------------------- decoding


def test_utf8_wins_over_a_wrong_declaration() -> None:
    page = '<meta charset="big5"><p>樣本</p>'.encode()
    decoded, info = evaluate.decode_html(page)
    assert decoded == '<meta charset="big5"><p>樣本</p>'
    assert info["encoding"] == "utf-8"
    assert info["mismatch"] == ["meta declares big5"]


def test_declared_big5_is_decoded_as_cp950() -> None:
    page = b'<meta http-equiv="Content-Type" content="text/html; charset=big5"><p>' + "樣本".encode("cp950")
    decoded, info = evaluate.decode_html(page)
    assert decoded.endswith("<p>樣本")
    assert (info["encoding"], info["chosen_by"], info["mismatch"]) == ("cp950", "declared in meta", [])


def test_the_http_header_comes_before_meta() -> None:
    page = b'<meta charset="gb18030"><p>' + "樣本".encode("cp950")
    decoded, info = evaluate.decode_html(page, http_charset="big5")
    assert decoded.endswith("<p>樣本")
    assert (info["encoding"], info["chosen_by"]) == ("cp950", "declared in http")
    assert info["mismatch"] == ["meta declares gb18030"]


@pytest.mark.parametrize("label", ["gb2312", "GBK", "x-gbk", "gb18030"])
def test_gbk_labels_decode_as_browsers_do(label: str) -> None:
    # Browsers decode the GBK labels as GB 18030, which has characters that Python's gbk lacks.
    body = "样本 C2 价格 \U00020000"
    page = f'<meta http-equiv="Content-Type" content="text/html; charset={label}"><p>'.encode() + body.encode(
        "gb18030"
    )
    decoded, info = evaluate.decode_html(page)
    assert decoded.endswith(body)
    assert (info["encoding"], info["chosen_by"], info["mismatch"]) == ("gb18030", "declared in meta", [])


def test_undeclared_big5_falls_back_to_cp950() -> None:
    decoded, info = evaluate.decode_html("<p>樣本".encode("cp950"))
    assert decoded == "<p>樣本"
    assert (info["encoding"], info["chosen_by"]) == ("cp950", "Big5 fallback")


def test_a_byte_order_mark_decides() -> None:
    decoded, info = evaluate.decode_html(b"\xef\xbb\xbf<p>a</p>")
    assert decoded == "<p>a</p>"
    assert info["chosen_by"] == "byte-order mark"


def test_line_breaks_are_normalised() -> None:
    assert evaluate.decode_html(b"<pre>a\r\nb\rc</pre>")[0] == "<pre>a\nb\nc</pre>"


def test_nothing_is_decoded_leniently() -> None:
    # Not UTF-8 and not cp950 (0x80 is no lead byte there): the run stops instead of guessing.
    with pytest.raises(SystemExit, match="cannot decode"):
        evaluate.decode_html(b"<p>\x80\x80\x80</p>")
    with pytest.raises(SystemExit, match="cannot decode"):
        evaluate.decode_html(b'<meta charset="big5"><p>\x80\x80</p>')


# --------------------------------------------------------------------------- the conversion record


def test_line_wrap_fragments_are_listed() -> None:
    fragments = evaluate.line_wrap_fragments("C2 list 2019-\nevil.example.com and ops-\nteam@example.org")
    assert [(f["type"], f["fragment"]) for f in fragments] == [
        ("email", "team@example.org"),
        ("domain", "evil.example.com"),
    ]
    assert fragments[1]["line_before_ends"] == "C2 list 2019-"


def test_attachments_are_read_by_their_kind(tmp_path: Path) -> None:
    page = tmp_path / "iocs.html"
    page.write_bytes(b"<p>a.example.com</p><p>198.51.100.7</p>")
    plain = tmp_path / "iocs.txt"
    plain.write_text("b.example.com\n", encoding="utf-8")
    assert evaluate.attachment_format(page) == "html"
    assert evaluate.attachment_format(plain) == "text"
    assert evaluate.attachment_format(tmp_path / "iocs.PDF") == "pdf"
    assert evaluate.convert(page, "html")[0] == "a.example.com\n\n198.51.100.7"
    assert evaluate.convert(plain, "text")[0] == "b.example.com\n"
    plain.write_bytes(b"\xff")
    with pytest.raises(UnicodeDecodeError):
        evaluate.convert(plain, "text")  # no lenient decoding here either


def test_converted_text_has_only_lf_line_breaks(tmp_path: Path) -> None:
    plain = tmp_path / "a.txt"
    plain.write_bytes(b"a\r\nb\rc")
    page = tmp_path / "a.html"
    page.write_bytes(b"<pre>x&#13;y</pre>")
    assert evaluate.convert(plain, "text")[0] == "a\nb\nc"
    assert evaluate.convert(page, "html")[0] == "x\ny"


def test_text_records_every_part_and_run_checks_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    entry = {
        "id": "t01",
        "format": "html",
        "appendix": {"start": "IOCs", "end": "END"},
        "attachments": [{"file": "iocs.html"}],
    }
    (tmp_path / "t" / "html").mkdir(parents=True)
    (tmp_path / "t" / "attachments").mkdir()
    (tmp_path / "t" / "html" / "t01.html").write_bytes(b"<p>Report</p>")
    attachment = tmp_path / "t" / "attachments" / "iocs.html"
    attachment.write_bytes(b'<meta charset="big5"><h2>IOCs</h2><p>a.example.com</p><p hidden>END</p>')
    monkeypatch.setattr(evaluate, "DATA", tmp_path)
    monkeypatch.setattr(evaluate, "manifest", lambda name: [entry])
    monkeypatch.setattr(evaluate, "selection_rule", lambda name: "every test page")
    monkeypatch.setattr(evaluate, "check_html_parser", evaluate.html_parser_info)
    evaluate.command_text("t")
    out = capsys.readouterr().out
    assert "attachment iocs.html (html)" in out
    assert "DECLARED CHARSET DISAGREES" not in out  # ASCII only
    assert "hidden characters kept: 3" in out
    conversion = json.loads((tmp_path / "t" / "text" / "t01.conversion.json").read_text(encoding="utf-8"))
    whole = evaluate.read_text(tmp_path / "t" / "text" / "t01.txt")
    assert whole == "Report\n\nIOCs\n\na.example.com\n\nEND"
    assert [(p["format"], p["file"]) for p in conversion["parts"]] == [
        ("html", "html/t01.html"),
        ("html", "attachments/iocs.html"),
    ]
    assert conversion["attachments"][0]["decoding"]["chosen_by"] == "valid UTF-8"
    assert conversion["python"] == sys.version
    assert set(conversion["html_parser_sha256"]) == {"html/parser.py", "_markupbase.py", "html/entities.py"}
    evaluate.check_unchanged("t", entry, conversion, whole)
    attachment.write_bytes(b"<p>changed</p>")
    with pytest.raises(SystemExit, match="changed since"):
        evaluate.check_unchanged("t", entry, conversion, whole)
    attachment.unlink()
    with pytest.raises(SystemExit, match="changed since"):
        evaluate.check_unchanged("t", entry, conversion, whole)
    attachment.write_bytes(b'<meta charset="big5"><h2>IOCs</h2><p>a.example.com</p><p hidden>END</p>')
    monkeypatch.setattr(
        evaluate, "sha256", lambda path: "0" * 64 if path == evaluate.SCRIPT else digest(path)
    )
    with pytest.raises(SystemExit, match=r"another version of evaluate\.py"):
        evaluate.check_unchanged("t", entry, conversion, whole)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_text_needs_a_selection_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate, "manifest", lambda name: [])
    monkeypatch.setattr(evaluate, "selection_rule", lambda name: " ")
    with pytest.raises(SystemExit, match="no selection rule"):
        evaluate.command_text("t")


# --------------------------------------------------------------------------- the Python release


def test_text_stops_when_html_parser_gets_a_canary_wrong(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate, "_CANARIES", (("<p>a</p><p>b</p>", "a b"),))
    assert evaluate.html_parser_problems() == ["'<p>a</p><p>b</p>' gave 'a\\n\\nb', not 'a b'"]
    with pytest.raises(SystemExit, match="2025 security fixes"):
        evaluate.check_html_parser()
    monkeypatch.setattr(
        evaluate, "html_to_text", mock.Mock(side_effect=AssertionError("expected name token"))
    )
    assert evaluate.html_parser_problems() == [
        "'<p>a</p><p>b</p>' gave 'AssertionError: expected name token', not 'a b'"
    ]


@pytest.mark.skipif(
    bool(evaluate.html_parser_problems()), reason="html.parser without the 2025 security fixes"
)
def test_canaries_pass_on_a_fixed_python() -> None:
    info = evaluate.check_html_parser()
    assert info["python"] == sys.version
    assert all(len(value) == 64 for value in info["sha256"].values())


# --------------------------------------------------------------------------- more layout


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        # SVG draws each <text> apart.
        ("<svg><text>evil.example.com</text><text>198.51.100.7</text></svg>",
         "evil.example.com\n198.51.100.7"),
        ("<p>a<text>b</text>c</p>", "abc"),  # not in an <svg>
        # Text in a table outside its cells gets a line of its own; the row goes on after it.
        ("<table><tr>note<td>a.example.com</td><td>198.51.100.7</td></tr></table>",
         "note\na.example.com\t198.51.100.7"),
        ("<table><tr><td>a.example.com</td>evil<span>.example</span>.com<td>198.51.100.7</td></tr></table>",
         "a.example.com\nevil.example.com\n\t198.51.100.7"),
        ("<table><tr><td>1</td><td>a</td></tr>IOCs<tr><td>2</td><td>b</td></tr></table>", "1\ta\nIOCs\n2\tb"),
        # A "</script>" in a comment in a script that opens another "<script>" does not end the script.
        ("<p>a<script><!-- document.write('<script>x</script>'); leak.example.com --></script>b</p>", "ab"),
        ("<p>a<script><!-- x --></script>b<script>y</script>c</p>", "abc"),
        ("<p>a<script><!--<script></script>--></script>b</p>", "ab"),
        # Only "</script" and one character leave the doubly escaped state; the rest is script data.
        ("<p>A<script><!--<script></script --><script>x</script>B.example.com</p>", "AB.example.com"),
        ("<p>A<script><!--<script></script x='<script>'></script>B.example.com</p>", "A"),
        # "<!-->" and "<!--->" are empty comments.
        ("<p>a</p><!--><p>b</p><!-- y --><p>c</p>", "a\n\nb\n\nc"),
        ("<p>a</p><!---><p>b</p><!-- y --><p>c</p>", "a\n\nb\n\nc"),
        ("<p>a</p><!-- x --!><p>b</p><!-- y --><p>c</p>", "a\n\nb\n\nc"),
        # NUL is dropped, and shown as U+FFFD in raw text; <datalist> and <rp> are not shown.
        ("<p>a\0b</p><xmp>c\0d</xmp>", "ab\n\nc\ufffdd"),
        ("<p>a<datalist><option>leak.example.com</datalist>b</p>", "ab"),
        ("<ruby>evil<rp>(</rp><rt>x</rt><rp>)</rp></ruby>.example.com", "evilx.example.com"),
        ("<ruby>a<rp>(<rt>b<rp>)</ruby>c.example.com", "abc.example.com"),
    ],
)  # fmt: skip
def test_layout_of_browser_rules(page: str, expected: str) -> None:
    assert text(page) == expected


def test_conversion_time_grows_linearly_with_nesting() -> None:
    # Unclosed elements nest ever deeper; no event may look through all open elements.
    for unit in ("<div>x", "<table><tr><td>x", "<details><summary>x", "<span hidden>x"):
        small = seconds_per_mb(lambda u=unit: evaluate.html_to_text(u * 4000), 1, repeat=3)
        large = seconds_per_mb(lambda u=unit: evaluate.html_to_text(u * 16000), 1, repeat=3)
        assert large < 8 * small, unit  # quadratic would be 16 times


# --------------------------------------------------------------------------- decoding, more


def test_a_meta_charset_in_a_comment_is_ignored() -> None:
    page = b'<!-- <meta charset="gb18030"> --><meta charset="big5"><p>' + "樣本".encode("cp950")
    decoded, info = evaluate.decode_html(page)
    assert decoded.endswith("<p>樣本")
    assert info["declared"]["meta"] == "big5"
    assert evaluate.decode_html(b'<!--> <meta charset="gb18030"><p>a')[1]["declared"]["meta"] == "gb18030"
    assert evaluate.decode_html(b'<!-- <meta charset="gb18030"><p>a')[1]["declared"]["meta"] is None


def test_a_charset_override_replaces_the_decoding_order() -> None:
    page = "<p>樣本".encode()  # valid UTF-8, also valid GB 18030
    decoded, info = evaluate.decode_html(page, override="gb18030")
    assert decoded != "<p>樣本"
    assert (info["encoding"], info["chosen_by"]) == ("gb18030", "charset override in the manifest")
    assert evaluate.decode_html(b"\xef\xbb\xbf<p>a", override="utf-8")[0] == "<p>a"
    with pytest.raises(SystemExit, match="cannot decode"):
        evaluate.decode_html(b"<p>\x80\x80\x80", override="utf-8")
    with pytest.raises(SystemExit, match="unknown charset override"):
        evaluate.decode_html(b"<p>a", override="no-such-charset")


# --------------------------------------------------------------------------- what each step was made from


def test_score_stops_on_results_of_another_evaluate_py(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"meta": {"evaluate_sha256": "0" * 64}, "reports": []}), encoding="utf-8")
    monkeypatch.setattr(evaluate, "manifest", lambda name: [])
    monkeypatch.setattr(evaluate, "results_path", lambda name, label: results)
    with pytest.raises(SystemExit, match=r"another version of evaluate\.py made these results"):
        evaluate.command_score("t", "after")


def test_text_needs_a_committed_selection_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    head = {"selection_rule": {"t": "written before"}}

    def fake_run(cmd: list[str], **kwargs: Any) -> mock.Mock:
        if "--show-toplevel" in cmd:
            return mock.Mock(returncode=0, stdout=str(evaluate.ROOT) + "\n")
        assert cmd[-1] == "HEAD:docs/research/2026-10-real-reports/manifest.json"
        return mock.Mock(returncode=0, stdout=json.dumps(head))

    monkeypatch.setattr(evaluate, "load_manifest", lambda: {"selection_rule": {"t": "edited later"}})
    monkeypatch.setattr(evaluate.subprocess, "run", fake_run)
    with pytest.raises(SystemExit, match="not committed as it stands"):
        evaluate.selection_rule("t")
    head["selection_rule"]["t"] = "edited later"
    assert evaluate.selection_rule("t") == "edited later"


def test_the_executed_ttprism_is_this_repository() -> None:
    identity = evaluate.ttprism_identity()
    assert identity["path"] == "src/ttprism/__init__.py"
    assert identity["version"] == importlib.metadata.version("ttprism")


def test_run_executes_ttprism_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_run(cmd: list[str], **kwargs: Any) -> mock.Mock:
        calls.append(cmd)
        return mock.Mock(stdout='{"iocs": []}')

    monkeypatch.setattr(evaluate.subprocess, "run", fake_run)
    evaluate.run_ttprism(Path("report.txt"), [])
    assert calls[0][:4] == [sys.executable, "-I", "-m", "ttprism"]


def test_the_commit_check_covers_every_file_the_results_depend_on(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_run(cmd: list[str], **kwargs: Any) -> mock.Mock:
        calls.append(cmd)
        return mock.Mock(
            stdout=" M docs/research/2026-10-real-reports/manifest.json\n" if "status" in cmd else "abc\n"
        )

    monkeypatch.setattr(evaluate.subprocess, "run", fake_run)
    assert (
        evaluate.git_commit() == "abc+uncommitted changes in docs/research/2026-10-real-reports/manifest.json"
    )
    status = calls[1]
    assert status[status.index("--") + 1 :] == [
        "src",
        "pyproject.toml",
        "docs/research/2026-10-real-reports/evaluate.py",
        "docs/research/2026-10-real-reports/manifest.json",
        "docs/research/2026-10-real-reports/iana-tlds.txt",
        "docs/research/2026-10-real-reports/requirements.txt",
    ]


def test_installed_distributions_are_listed() -> None:
    assert f"pytest=={importlib.metadata.version('pytest')}" in evaluate.installed_distributions()


# --------------------------------------------------------------------------- the manifest


def test_the_committed_manifest_is_valid() -> None:
    data = json.loads(evaluate.MANIFEST.read_text(encoding="utf-8"))
    assert evaluate.manifest_problems(data) == []
    assert data["selection_rule"]["zh-cn"]


def valid_manifest() -> dict[str, Any]:
    entry = {
        "id": "t01",
        "title": "t",
        "publisher": "p",
        "published": "2026-01-01",
        "original_url": "https://example.com/r",
        "url_source": "test",
        "appendix": {"start": "IOCs", "end": "END"},
        "retrieved": "2026-10-09T13:45:04Z",
        "final_url": "https://example.com/r",
        "saved": {"kind": "server", "method": "curl -L", "tool": "curl 8.5.0"},
    }
    return {
        "description": "",
        "fields": {},
        "text_conversion": {},
        "selection_rule": {"t": ""},
        "sets": {"t": [entry]},
    }


def review_entry() -> dict[str, Any]:
    return {
        "draft_sha256": "0" * 64,
        "reviewed_by": "tester",
        "reviewed_at": "2026-10-11T00:00:00Z",
        "pages_checked": ["pdf/t01.pdf page 1"],
        "checked_every_line": True,
        "warnings": {},
        "add": [],
        "remove": [],
        "ambiguous": [],
        "values": {"domain": [value_entry()]},
        "masked": {},
    }


def value_entry(value: str = "a.example.com") -> dict[str, str]:
    return {"value": value, "writing": value, "class": "plain", "location": "pdf/t01.pdf page 1 line 2"}


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda m: m.update(extra=1), "manifest: unknown field 'extra'"),
        (lambda m: m["sets"]["t"][0].update(html_source="server"), "unknown field 'html_source'"),
        (lambda m: m["sets"]["t"][0].pop("retrieved"), "missing field 'retrieved'"),
        (lambda m: m["sets"]["t"][0].update(retrieved="2026-10-09 13:45"), "retrieved must be a UTC time"),
        (lambda m: m["sets"]["t"][0].update(final_url="example.com/r"), "final_url must be an http(s) URL"),
        (lambda m: m["sets"]["t"][0]["saved"].update(kind="rendered"), "saved.reason"),
        (lambda m: m["sets"]["t"][0]["saved"].update(kind="cache"), "kind must be 'server' or 'rendered'"),
        (lambda m: m["sets"]["t"][0]["saved"].pop("tool"), "missing field 'tool'"),
        (lambda m: m["sets"]["t"][0].update(charset_override={"charset": "big5"}), "missing field 'reason'"),
        (
            lambda m: m["sets"]["t"][0].update(charset_override={"charset": "x", "reason": "r"}),
            "unknown charset",
        ),
        (lambda m: m["sets"]["t"][0]["appendix"].update(start_occurrence=2), "start_occurrence_reason"),
        (lambda m: m["sets"]["t"][0]["appendix"].update(stop="x"), "appendix: unknown field 'stop'"),
        (
            lambda m: m["sets"]["t"][0].update(legacy_truth_corrections={"add": {"domain": ["a.example"]}}),
            "notes",
        ),
        (
            lambda m: m["sets"]["t"][0].update(attachments=[{"file": "a.html"}]),
            "attachments[0]: missing field",
        ),
        (lambda m: m["sets"]["t"].append(dict(m["sets"]["t"][0])), "id 't01' occurs twice"),
        (lambda m: m["selection_rule"].pop("t"), "needs a selection rule"),
        (
            lambda m: m["sets"]["t"][0].update(
                legacy_truth_corrections={"remove": {"domain": "a.example"}, "notes": ["r"]}
            ),
            "not a list of values",
        ),
        (
            lambda m: m["sets"]["t"][0].update(
                legacy_truth_corrections={"ambiguous": {"domain": ["a", "b"]}, "notes": ["r"]}
            ),
            "two or more readings",
        ),
        (
            lambda m: m["sets"]["t"][0].update(legacy_truth_corrections={"notes": "r"}),
            "not a list of reasons",
        ),
        (lambda m: m["sets"]["t"][0].update(format="html", http_charset="gb-2312"), "unknown http_charset"),
        (
            lambda m: m["sets"]["t"][0].update(charset_override={"charset": "gbk", "reason": "r"}),
            "a PDF has no charset",
        ),
        (lambda m: m["sets"]["t"][0]["appendix"].update(start=""), "appendix.start"),
        (lambda m: m.update(skipped={"t": [{"titel": "x"}]}), "skipped.t[0]: unknown field 'titel'"),
        (lambda m: m["sets"]["t"][0].update(truth_corrections={}), "unknown field 'truth_corrections'"),
        (
            lambda m: m["sets"]["t"][0]["appendix"].update(end_of_text=True),
            "either an end marker or end_of_text",
        ),
        (lambda m: m["sets"]["t"][0]["appendix"].pop("end"), "either an end marker or end_of_text"),
        (
            lambda m: m["sets"]["t"][0]["appendix"].update(end_of_text=False),
            "end_of_text can only be true",
        ),
        (
            lambda m: m["sets"]["t"][0].update(
                format="html", charset_override={"charset": "big5:replace", "reason": "r"}
            ),
            "no other lenient decoding",
        ),
        (lambda m: m["sets"]["t"][0].update(truth_review={}), "truth_review: missing field 'values'"),
        (
            lambda m: m["sets"]["t"][0].update(truth_review={**review_entry(), "checked_every_line": False}),
            "every line must be checked",
        ),
        (
            lambda m: m["sets"]["t"][0].update(
                truth_review={**review_entry(), "values": {"domain": [value_entry("Evil.Example.com")]}}
            ),
            "values.domain[0]: not in standard form",
        ),
        (
            lambda m: m["sets"]["t"][0].update(
                truth_review={**review_entry(), "values": {"domain": [{**value_entry(), "class": "x"}]}}
            ),
            "class must be one of",
        ),
        (
            lambda m: m["sets"]["t"][0].update(
                truth_review={**review_entry(), "remove": [{"type": "domain", "value": "A.example.com"}]}
            ),
            "missing field 'reason'",
        ),
    ],
)
def test_manifest_problems_are_reported(change: Any, problem: str) -> None:
    data = valid_manifest()
    assert evaluate.manifest_problems(data) == []
    data["sets"]["t"][0]["truth_review"] = review_entry()
    assert evaluate.manifest_problems(data) == []
    del data["sets"]["t"][0]["truth_review"]
    change(data)
    assert any(problem in found for found in evaluate.manifest_problems(data)), evaluate.manifest_problems(
        data
    )


def test_a_charset_override_decodes_a_text_attachment(tmp_path: Path) -> None:
    plain = tmp_path / "iocs.txt"
    plain.write_bytes("樣本 a.example.com\n".encode("gbk"))
    with pytest.raises(UnicodeDecodeError):
        evaluate.convert(plain, "text")
    text, info = evaluate.convert(plain, "text", override="gbk")
    assert text == "樣本 a.example.com\n"
    assert info["method"] == "text decoded as gb18030 (charset override in the manifest)"
