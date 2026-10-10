"""The HTML-to-text conversion and appendix rules of the real-report evaluation script.

docs/research/2026-10-real-reports/evaluate.py turns web pages into the text that every tool reads,
so its rules are fixed and tested before the pages are seen. Fixtures use reserved names and
documentation addresses only.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "docs/research/2026-10-real-reports/evaluate.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("evaluate_reports", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


evaluate = _load()


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


# --------------------------------------------------------------------------- appendix and ground truth


def report(start: str, end: str = "END", **appendix: Any) -> dict[str, Any]:
    return {"id": "t01", "format": "html", "appendix": {"start": start, "end": end, **appendix}}


def test_appendix_start_marker_must_be_unique() -> None:
    page = "IOCs\nside bar\nbody\nIOCs\na.example.com\nEND"
    with pytest.raises(SystemExit, match="found 2 times"):
        evaluate.appendix(page, report("IOCs"))
    assert evaluate.appendix(page, report("IOCs", start_occurrence=2)) == "IOCs\na.example.com\n"
    assert evaluate.appendix(page, report("IOCs", start_occurrence=1)).startswith("IOCs\nside bar")
    with pytest.raises(SystemExit, match="start_occurrence 3"):
        evaluate.appendix(page, report("IOCs", start_occurrence=3))


def test_ground_truth_of_a_web_page_ignores_format_characters() -> None:
    page = "IOCs\nup\u200bdate.example.com\n198.51.100.\u200b7\nd41d8cd98f00\u2060b204e9800998ecf8427e\nEND"
    truth, _, _ = evaluate.ground_truth(page, report("IOCs"))
    assert truth["domain"] == ["update.example.com"]
    assert truth["ipv4"] == ["198.51.100.7"]
    assert truth["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_line_wrap_fragments_are_listed() -> None:
    fragments = evaluate.line_wrap_fragments("C2 list 2019-\nevil.example.com and ops-\nteam@example.org")
    assert [(f["type"], f["fragment"]) for f in fragments] == [
        ("email", "team@example.org"),
        ("domain", "evil.example.com"),
    ]
    assert fragments[1]["line_before_ends"] == "C2 list 2019-"


def test_totals_are_split_by_format() -> None:
    def scored(fmt: str, hit: int) -> dict[str, Any]:
        precision = {"truth": hit, "a": 0, "b": 0, "c": 1 - hit, "masked": 0, "ambiguous": 0}
        return {"format": fmt, "recall": {"t": {"md5": [hit, 1]}}, "precision": {"t": precision}}

    reports = [scored("pdf", 1), scored("html", 0)]
    assert evaluate.totals_of(reports)["t"]["recall"] == {"md5": [1, 2, 0.5]}
    assert evaluate.totals_of([r for r in reports if r["format"] == "html"])["t"]["recall"] == {
        "md5": [0, 1, 0.0]
    }


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


def test_text_from_a_pdf_keeps_its_soft_hyphens_in_the_ground_truth() -> None:
    # A web page's format characters are deleted from the appendix; a PDF attachment's are not, since
    # pypdf's U+00AD there is a drawn hyphen.
    page = "IOCs\nup\u00addate.example.com"
    attachment = "KB\u00adAuto.example.net\nEND"
    whole = page + "\n\n" + attachment
    parts = [
        {"format": "html", "start": 0, "end": len(page)},
        {"format": "pdf", "start": len(page) + 2, "end": len(whole)},
    ]
    region = evaluate.appendix_region(whole, report("IOCs"), parts)
    assert region == "IOCs\nupdate.example.com\n\nKB\u00adAuto.example.net\n"


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
    evaluate.command_text("t")
    out = capsys.readouterr().out
    assert "attachment iocs.html (html)" in out
    assert "DECLARED CHARSET DISAGREES" not in out  # ASCII only
    assert "hidden characters kept: 3" in out
    conversion = json.loads((tmp_path / "t" / "text" / "t01.conversion.json").read_text(encoding="utf-8"))
    whole = evaluate.read_text(tmp_path / "t" / "text" / "t01.txt")
    assert whole == "Report\n\nIOCs\n\na.example.com\n\nEND"
    assert [p["format"] for p in conversion["parts"]] == ["html", "html"]
    assert conversion["attachments"][0]["decoding"]["chosen_by"] == "valid UTF-8"
    evaluate.check_unchanged("t", entry, conversion, whole)
    attachment.write_bytes(b"<p>changed</p>")
    with pytest.raises(SystemExit, match="changed since"):
        evaluate.check_unchanged("t", entry, conversion, whole)
    attachment.unlink()
    with pytest.raises(SystemExit, match="changed since"):
        evaluate.check_unchanged("t", entry, conversion, whole)
