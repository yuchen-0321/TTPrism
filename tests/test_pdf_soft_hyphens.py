"""The same PDF must give the same IOCs whether pypdf or pdftotext turned it into text.

A PDF whose WinAnsi font draws a hyphen with code 0xAD comes out of pypdf with U+00AD and out of
pdftotext with "-". TTPrism reads every soft hyphen as a hyphen, so both texts give the same IOCs.
pdftotext is compared in -raw mode, which keeps the lines as drawn: by default it also joins a line
that ends in a hyphen (either kind) to the next and drops the hyphen, which is layout reconstruction
that no reading of pypdf's lines can repeat. Its default text is compared on the first lines, whose
soft hyphens are all inside a line.

data/winansi_soft_hyphens.json records what pypdf 6.20.0 and pdftotext 24.02.0 give for the PDF that
build_pdf(LINES) writes; when both tools are installed, the comparison is also made on a fresh run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ttprism import AnalysisOptions, AnalysisResult, IOCType, analyze_text

DATA = Path(__file__).parent / "data" / "winansi_soft_hyphens.json"

# Lines of the page, as PDF string bytes: \255 is code 0xAD.
LINES = [
    b"C2: update\\255check.example-host.example",
    b"Punycode: xn\\255\\255bcher-kva.example",
    b"Raw file: https://gitlab.example.com/group/tool/\\255/raw/main/a.ps1",
    b"Query: http://198.51.100.7/a.php?id=\\2551",
    b"Exploit: CVE\\2552017\\25511882",
    b"Range: 198.51.100.1\\255198.51.100.9",
    b"CLSID {0F1E2D3C\\2554B5A\\2556978\\2558796\\255A5B4C3D2E1F0}",
    b"Mail: ops\\255team@example.org",
    b"Payload: http://198.51.100.7/1/update\\255",
    b"win.exe",
    b"C2 update\\255",
    b"check-server.example.com",
    b"Hard: http://198.51.100.7/1/update-",
    b"win.exe",
    b"Soft then dot: c2.example\\255",
    b".com now",
    b"Two soft: a\\255\\255",
    b"b.example.com",
    b"Soft space: up\\255 ",
    b"date.example.com",
    b"Dot soft: files.\\255",
    b"example.net",
    b"Hard, two soft: http://198.51.100.7/KB-\\255\\255",
    b"Auto.exe",
]
# The first lines have soft hyphens only inside them.
MID_LINE = 8


def build_pdf(lines: list[bytes]) -> bytes:
    """A one-page PDF that draws ``lines`` in Helvetica with the WinAnsi encoding."""
    content = (
        b"BT /F1 11 Tf 14 TL 50 760 Td " + b" ".join(b"(" + line + b") Tj T*" for line in lines) + b" ET"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def analyze(text: str) -> AnalysisResult:
    return analyze_text(text, AnalysisOptions(include_reserved=True))


def same_iocs(first: str, second: str) -> None:
    one, two = analyze(first), analyze(second)
    assert (one.iocs, one.suppressed) == (two.iocs, two.suppressed)


def first_lines(text: str) -> str:
    return "\n".join(text.split("\n")[:MID_LINE])


def test_recorded_pypdf_and_pdftotext_texts_give_the_same_iocs() -> None:
    recorded = json.loads(DATA.read_text(encoding="ascii"))
    assert "\u00ad" in recorded["pypdf"]
    assert "\u00ad" not in recorded["pdftotext_raw"]
    same_iocs(recorded["pypdf"], recorded["pdftotext_raw"])
    same_iocs(first_lines(recorded["pypdf"]), first_lines(recorded["pdftotext_default"]))
    values = {ioc.value for ioc in analyze(recorded["pypdf"]).iocs}
    assert {
        "update-check.example-host.example",
        "xn--bcher-kva.example",
        "https://gitlab.example.com/group/tool/-/raw/main/a.ps1",
        "http://198.51.100.7/a.php?id=-1",
        "CVE-2017-11882",
        "ops-team@example.org",
        "http://198.51.100.7/1/update-win.exe",
    } <= values


def test_a_soft_hyphen_after_a_hyphen_at_a_line_end_differs_on_purpose() -> None:
    # pdftotext -raw gives "--" here, which ends the URL; TTPrism deletes the soft hyphen instead, so
    # that the URL is joined across the line break.
    from_pypdf = analyze("Payload: http://198.51.100.7/KB-Auto-\u00ad\nwin.exe")
    from_pdftotext = analyze("Payload: http://198.51.100.7/KB-Auto--\nwin.exe")
    assert from_pypdf.iocs_of(IOCType.URL) == ["http://198.51.100.7/KB-Auto-win.exe"]
    assert from_pdftotext.iocs_of(IOCType.URL) == ["http://198.51.100.7/KB-Auto--"]


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="needs pdftotext (poppler-utils)")
def test_fresh_pypdf_and_pdftotext_texts_give_the_same_iocs(tmp_path: Path) -> None:
    pypdf = pytest.importorskip("pypdf")
    pdf = tmp_path / "soft-hyphens.pdf"
    pdf.write_bytes(build_pdf(LINES))
    from_pypdf = pypdf.PdfReader(str(pdf)).pages[0].extract_text()
    command = ["pdftotext", "-raw", "-enc", "UTF-8", str(pdf), "-"]
    raw = subprocess.run(command, capture_output=True, check=True).stdout.decode("utf-8")
    assert "\u00ad" in from_pypdf
    same_iocs(from_pypdf, raw)
