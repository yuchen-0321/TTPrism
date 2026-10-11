"""The whole real-report evaluation, run on a synthetic Traditional-Chinese set.

Before the held-out zh-TW reports are measured, every step of evaluate.py runs once on two synthetic
reports made like them: an encrypted PDF (owner password only) printed by Chromium, with a SHA-256
in a narrow table cell, full-width and CJK-bracket defanging, and a page whose WinAnsi font draws
hyphens with code 0xAD; and a Big5 web page with a table. The test checks that the review stops on
every warning, that nothing runs before a complete review is committed, and that the final numbers
are the ones the reviewed truth and the tool outputs give, counted here independently.

It needs pypdf, cryptography, iocextract, ioc-finder, pdftoppm, Chromium (on PATH, or CHROMIUM),
git, and a Python whose html.parser has the 2025 security fixes; it is skipped otherwise. Set
TTPRISM_SYNTHETIC_DIR to keep the set, its images and results in that directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from research_evaluate import evaluate
from test_pdf_soft_hyphens import build_pdf

CHROMIUM = os.environ.get("CHROMIUM") or next(
    (path for name in ("chromium", "chromium-browser", "google-chrome") if (path := shutil.which(name))),
    "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
)


def _missing() -> str | None:
    for module in ("pypdf", "cryptography", "iocextract", "ioc_finder"):
        try:
            __import__(module)
        except ImportError:
            return f"needs {module}"
    if shutil.which("pdftoppm") is None or shutil.which("git") is None:
        return "needs pdftoppm and git"
    if not Path(CHROMIUM).exists() or not hasattr(os, "geteuid"):
        return "needs Chromium (set CHROMIUM) on a POSIX system"
    if evaluate.html_parser_problems():
        return "needs a Python with the 2025 html.parser fixes"
    return None


pytestmark = pytest.mark.skipif(_missing() is not None, reason=str(_missing()))

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
HALVES = [SHA256[:32], SHA256[32:]]

TW01_PAGE = f"""<!doctype html><meta charset="utf-8">
<style>body{{font-family:"WenQuanYi Zen Hei",sans-serif;font-size:13px}}
td,th{{border:1px solid #000;padding:3px;vertical-align:top}}
.h{{font-family:"DejaVu Sans Mono",monospace;width:32ch;word-break:break-all}}</style>
<h1>樣本威脅報告（合成測試資料）</h1>
<p>本報告為測試用的合成資料，所有名稱與位址皆為保留用途。１．背景說明：２０２６年的測試。</p>
<h2>附錄：入侵指標</h2>
<table>
<tr><th>類型</th><th>指標</th></tr>
<tr><td>C2 網域</td><td>update-check【.】example.com</td></tr>
<tr><td>C2 位址</td><td>１９８．５１．１００．２３</td></tr>
<tr><td>備用位址</td><td>198【.】51【.】100【.】25</td></tr>
<tr><td>郵件</td><td>attacker［＠］mail．example．org</td></tr>
<tr><td>下載</td><td>hxxp://evil[.]example[.]net/a.exe</td></tr>
<tr><td>網域</td><td>c2.example.org</td></tr>
<tr><td>MD5</td><td>d41d8cd98f00b204e9800998ecf8427e</td></tr>
</table>
<p></p>
<table><tr><th>檔名</th><th>SHA-256</th></tr>
<tr><td>loader.dll</td><td class=h>{SHA256}</td></tr></table>
"""
# The second page: a WinAnsi font draws the hyphens with code 0xAD, which pypdf gives as U+00AD.
TW01_WINANSI = [
    b"Additional indicators",
    b"C2: beacon\\255relay.example.com",
    b"Relay: node\\255",
    b"sync.example.net",
    b"References",
]
TW02_PAGE = """<html><head><meta charset="big5"><title>樣本報告二</title></head><body>
<h1>樣本報告二（合成測試資料）</h1>
<p>說明見 http://a：本頁為 Big5 編碼。</p>
<h2>入侵指標</h2>
<table border=1>
<tr><th>類型</th><th>指標</th><th>說明</th></tr>
<tr><td>網域</td><td>evil〔.〕example.com</td><td>中繼站</td></tr>
<tr><td>位址</td><td>２０３．０．１１３．５</td><td>下載點</td></tr>
<tr><td>網址</td><td>http://203.0.113.9/x.php</td><td>回報</td></tr>
<tr><td>郵件</td><td>ops[at]example.org</td><td>釣魚寄件者</td></tr>
<tr><td>SHA1</td><td>da39a3ee5e6b4b0d3255bfef95601890afd80709</td><td>樣本</td></tr>
<tr><td>網域</td><td>files（.）example.net</td><td>備用</td></tr>
</table>
<h2>參考資料</h2>
<p>https://example.com/report</p>
</body></html>
"""
# The ground truth a reviewer reads off the pages, by writing class.
EXPECTED = {
    "tw01": {
        "plain": {
            ("domain", "c2.example.org"),
            ("domain", "beacon-relay.example.com"),
            ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
            ("sha256", SHA256),
        },
        "ascii-defang": {("url", "http://evil.example.net/a.exe"), ("domain", "evil.example.net")},
        "fullwidth-cjk-defang": {
            ("domain", "update-check.example.com"),
            ("ipv4", "198.51.100.23"),
            ("ipv4", "198.51.100.25"),
            ("email", "attacker@mail.example.org"),
        },
    },
    "tw02": {
        "plain": {("url", "http://203.0.113.9/x.php"), ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709")},
        "ascii-defang": {("email", "ops@example.org")},
        "fullwidth-cjk-defang": {
            ("domain", "evil.example.com"),
            ("domain", "files.example.net"),
            ("ipv4", "203.0.113.5"),
        },
    },
}
AMBIGUOUS = ["node-sync.example.net", "nodesync.example.net"]


def report_entry(report_id: str, fmt: str, start: str, end: str) -> dict[str, Any]:
    return {
        "id": report_id,
        "title": "synthetic",
        "publisher": "test",
        "published": "2026-10-11",
        "original_url": f"https://example.com/{report_id}",
        "url_source": "synthetic test data",
        "format": fmt,
        "appendix": {"start": start, "end": end},
        "retrieved": "2026-10-11T00:00:00Z",
        "final_url": f"https://example.com/{report_id}",
        "saved": {"kind": "server", "method": "made by the test", "tool": "test_research_pipeline.py"},
    }


def build_set(root: Path) -> Path:
    """Write the synthetic set under ``root``; return the manifest, committed in a git repository."""
    import pypdf

    pdf_dir = root / "eval-data" / "zh-tw" / "pdf"
    html_dir = root / "eval-data" / "zh-tw" / "html"
    pdf_dir.mkdir(parents=True)
    html_dir.mkdir(parents=True)
    work = root / "work"
    work.mkdir()
    (work / "tw01.html").write_text(TW01_PAGE, encoding="utf-8")
    printed = work / "tw01-printed.pdf"
    command = [CHROMIUM, "--headless", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={printed}"]
    if os.geteuid() == 0:
        command.append("--no-sandbox")
    subprocess.run([*command, (work / "tw01.html").as_uri()], check=True, capture_output=True, timeout=120)
    (work / "tw01-winansi.pdf").write_bytes(build_pdf(TW01_WINANSI))
    writer = pypdf.PdfWriter()
    writer.append(str(printed))
    writer.append(str(work / "tw01-winansi.pdf"))
    writer.encrypt(user_password="", owner_password="synthetic-owner", algorithm="AES-256")  # noqa: S106
    with (pdf_dir / "tw01.pdf").open("wb") as out:
        writer.write(out)
    (html_dir / "tw02.html").write_bytes(TW02_PAGE.encode("cp950"))
    repo = root / "repo"
    repo.mkdir()
    manifest = {
        "description": "synthetic zh-TW set",
        "fields": {},
        "text_conversion": {},
        "selection_rule": {"zh-tw": "the two synthetic reports of test_research_pipeline.py"},
        "sets": {
            "zh-tw": [
                report_entry("tw01", "pdf", "附錄：入侵指標", "References"),
                report_entry("tw02", "html", "入侵指標", "參考資料"),
            ]
        },
    }
    (repo / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", "utf-8")
    git(repo, "init", "-q")
    git(repo, "add", "manifest.json")
    git(repo, "commit", "-q", "-m", "selection rule")
    return repo / "manifest.json"


def git(repo: Path, *args: str) -> None:
    identity = ["-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"]
    executable = shutil.which("git") or "git"
    subprocess.run([executable, "-C", str(repo), *identity, *args], check=True, capture_output=True)


def fill_review(template: dict[str, Any], report_id: str) -> None:
    """What the reviewer writes after checking each line against the images."""
    template.update(
        reviewed_by="synthetic reviewer",
        reviewed_at="2026-10-11T00:00:00Z",
        pages_checked=list(template["images"]),
        checked_every_line=True,
    )
    cut = [w for w, warning in template["warnings"].items() if warning["kind"] in ("hex-cut", "hash-label")]
    wrapped = [w for w, warning in template["warnings"].items() if warning["kind"] == "name-cut"]
    for warning_id, warning in template["warnings"].items():
        if warning_id in cut + wrapped:
            warning.update(resolution="corrected", note="see the corrections")
        else:
            warning.update(resolution="confirmed", note="the page shows this value so")
    if report_id == "tw01":
        template["remove"] = [
            {"type": "md5", "value": half, "reason": "half of the SHA-256 in a narrow cell", "warnings": cut}
            for half in HALVES
        ] + [
            {
                "type": "domain",
                "value": "sync.example.net",
                "reason": "the end of a wrapped name",
                "warnings": wrapped,
            }
        ]
        template["add"] = [
            {
                "type": "sha256",
                "value": SHA256,
                "writing": SHA256,
                "class": "plain",
                "location": "pdf/tw01.pdf page 1 line 14",
                "reason": "one SHA-256 over two lines",
                "warnings": cut,
            },
        ]
        template["ambiguous"] = [
            {
                "type": "domain",
                "readings": AMBIGUOUS,
                "writing": "node- / sync.example.net",
                "location": "pdf/tw01.pdf page 2 line 3",
                "from_draft": False,
                "warnings": wrapped,
                "reason": "a hyphen at a line break: part of the name or not",
            },
        ]


def host(url: str) -> str:
    return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()


def independent_scores(results: dict[str, Any]) -> dict[str, dict[str, list[int]]]:
    """Recall by writing class for each tool, counted from the expected truth and the outputs."""
    scores: dict[str, dict[str, list[int]]] = {}
    for entry in results["reports"]:
        for tool, out in entry["outputs"].items():
            names = set(out["domain"]) | {
                host(u) for u in out["url"] if not host(u).replace(".", "").isdigit()
            }
            for klass, expected in EXPECTED[entry["id"]].items():
                counts = scores.setdefault(tool, {}).setdefault(klass, [0, 0])
                for kind, value in expected:
                    counts[0] += value in (names if kind == "domain" else set(out[kind]))
                    counts[1] += 1
    return scores


def test_the_synthetic_zh_tw_set_runs_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(os.environ.get("TTPRISM_SYNTHETIC_DIR") or tmp_path)
    if root != tmp_path and root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    manifest = build_set(root)
    repo = manifest.parent
    monkeypatch.setattr(evaluate, "DATA", root / "eval-data")
    monkeypatch.setattr(evaluate, "MANIFEST", manifest)
    monkeypatch.setattr(evaluate, "HERE", repo)
    monkeypatch.setattr(evaluate, "JUDGEMENTS", repo / "judgements.json")
    monkeypatch.setenv("CHROMIUM", CHROMIUM)

    def step(*argv: str) -> str:
        monkeypatch.setattr(sys, "argv", ["evaluate.py", *argv])
        evaluate.main()
        return capsys.readouterr().out

    # text: the encrypted PDF and the Big5 page.
    out = step("text", "zh-tw")
    assert "decrypted with the empty user password" in out
    conversion = json.loads((root / "eval-data/zh-tw/text/tw02.conversion.json").read_text(encoding="utf-8"))
    assert (conversion["decoding"]["encoding"], conversion["decoding"]["chosen_by"]) == (
        "cp950",
        "declared in meta",
    )
    text = (root / "eval-data/zh-tw/text/tw01.txt").read_text(encoding="utf-8")
    assert f"loader.dll {HALVES[0]}\n{HALVES[1]}" in text
    assert "beacon\u00adrelay.example.com" in text

    # defang: full-width and CJK writing in values, numbering and dates only in the text.
    step("defang", "zh-tw")
    defang = {
        r["id"]: r for r in json.loads((repo / "defang-zh-tw.json").read_text(encoding="utf-8"))["reports"]
    }
    assert defang["tw01"]["appendix"]["in_values"]["【.】"] == 4
    assert defang["tw01"]["full_text"]["all"]["．"] > defang["tw01"]["full_text"]["in_values"]["．"]
    assert defang["tw02"]["appendix"]["in_values"]["〔.〕"] == 1

    # truth: drafts, images and templates; nothing runs, and the review stops on every warning.
    out = step("truth", "zh-tw")
    drafts = {
        report_id: json.loads(
            (root / f"eval-data/zh-tw/truth/{report_id}.draft.json").read_text(encoding="utf-8")
        )
        for report_id in ("tw01", "tw02")
    }
    kinds = {rid: sorted(w["kind"] for w in d["warnings"]) for rid, d in drafts.items()}
    assert kinds == {
        "tw01": ["hash-label", "hash-label", "hex-cut", "name-cut"] + ["non-ascii"] * 5,
        "tw02": ["non-ascii"] * 3,
    }
    assert sorted(p.name for p in (root / "eval-data/zh-tw/truth/tw01").glob("*.png")) == [
        "1-page-0001.png",
        "1-page-0002.png",
    ]
    assert list((root / "eval-data/zh-tw/truth/tw02").glob("1-screenshot-*.png"))
    with pytest.raises(SystemExit, match="no reviewed ground truth"):
        step("run", "zh-tw", "after")
    with pytest.raises(SystemExit) as stopped:
        step("review", "zh-tw")
    for report_id, result in drafts.items():
        for warning in result["warnings"]:
            assert f"warnings.{warning['id']}: resolution must be" in str(stopped.value), (report_id, warning)

    # The review, checked, written into the manifest and committed.
    for report_id in ("tw01", "tw02"):
        path = root / f"eval-data/zh-tw/truth/{report_id}.review.json"
        template = json.loads(path.read_text(encoding="utf-8"))
        fill_review(template, report_id)
        path.write_text(json.dumps(template, ensure_ascii=False), encoding="utf-8")
    step("review", "zh-tw")
    with pytest.raises(SystemExit, match="not committed as it stands"):
        step("run", "zh-tw", "after")
    git(repo, "commit", "-q", "-am", "reviewed ground truth")

    # run, score (provisional), blinded judging, score (final).
    out = step("run", "zh-tw", "after")
    results = json.loads((repo / "results-zh-tw-after.json").read_text(encoding="utf-8"))
    errors = {entry["id"]: entry["errors"] for entry in results["reports"]}
    assert errors["tw01"] == {}
    assert set(errors["tw02"]) <= {"iocextract"}  # its ValueError on "http://a：" is recorded, not raised
    out = step("score", "zh-tw", "after")
    assert "PROVISIONAL" in out
    step("judge", "zh-tw", "after")
    sheet_path = root / "eval-data/zh-tw/judging/after.json"
    sheet = json.loads(sheet_path.read_text(encoding="utf-8"))
    for item in sheet["items"]:
        item.update(category="c", reason="not an indicator of the synthetic appendix")
    sheet_path.write_text(json.dumps(sheet, ensure_ascii=False), encoding="utf-8")
    step("judge", "zh-tw", "after", "--import")
    out = step("score", "zh-tw", "after")
    results = json.loads((repo / "results-zh-tw-after.json").read_text(encoding="utf-8"))
    assert results["status"] == "final"
    assert "PROVISIONAL" not in out

    # The numbers: the reviewed truth, and recall by writing class counted independently.
    truth_counts = {entry["id"]: entry["truth_classes"] for entry in results["reports"]}
    assert truth_counts == {
        rid: {klass: len(EXPECTED[rid][klass]) for klass in evaluate.CLASSES} for rid in ("tw01", "tw02")
    }
    expected = independent_scores(results)
    for tool, total in results["totals"].items():
        assert {k: v[:2] for k, v in total["recall_by_class"].items()} == expected[tool], tool
        overall = [sum(v[0] for v in expected[tool].values()), sum(v[1] for v in expected[tool].values())]
        by_type = total["recall"]
        assert [
            sum(v[0] for k, v in by_type.items() if k != "url-host"),
            sum(v[1] for k, v in by_type.items() if k != "url-host"),
        ] == overall
        precision = total["precision"]
        assert precision["a"] == precision["b"] == 0
        assert precision["truth"] + precision["c"] == precision["judged_total"]
    assert results["totals_by_format"].keys() == {"pdf", "html"}
    assert results["reports_using_fullwidth_cjk"] == ["tw01", "tw02"]
    left_out = {entry["id"]: entry["left_out"]["ambiguous"] for entry in results["reports"]}
    assert left_out == {"tw01": {"domain": 2}, "tw02": {}}


def test_screenshots_show_what_the_text_has(tmp_path: Path) -> None:
    def drawn(page: str, html: bool = True) -> list[tuple[int, int]]:
        if html:
            body, headers = evaluate.reviewable_page(page)
        else:
            body, headers = (
                page.encode("utf-8"),
                [{"name": "Content-Type", "value": "text/plain; charset=utf-8"}],
            )
        sizes = []
        for shot in evaluate.screenshots(CHROMIUM, body, headers, tmp_path / "page"):
            data = shot.read_bytes()
            sizes.append((int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")))
        return sizes

    rows = "".join(f"<p>row {i} r{i}.example.net</p>" for i in range(150))
    # The page's own styles are refused, so nothing it hides, clips or scrolls is left out; what the
    # browser's defaults hide (hidden attributes, closed <details>, <dialog>) is shown too.
    hiding = (
        "<style>.d-none{display:none!important}.fade{opacity:0}#m{height:120px;overflow:auto}"
        "body{position:fixed;top:0;bottom:0;overflow-y:auto}</style>"
    )
    for page in (
        f"{hiding}<div class=d-none>{rows}</div>",
        f"{hiding}<div style='display:none !important'>{rows}</div>",
        f"{hiding}<div class=fade>{rows}</div>",
        f"{hiding}<div id=m>{rows}</div>",
        f"<h2>IOCs</h2><div hidden>{rows}</div>",
        f"<details><summary>IOCs</summary>{rows}</details>",
        f"<dialog>{rows}</dialog>",
    ):
        assert len(drawn(page)) >= 2, page[:60]
    # <noscript>, which HtmlText drops, is not drawn although scripts are off.
    assert len(drawn(f"<p>a.example.com</p><noscript>{rows}</noscript>")) == 1
    # One long line is wrapped, so every screenshot stays as wide as the page.
    assert {width for width, _ in drawn("<pre style='overflow:auto'>" + "A" * 6000 + "</pre>")} == {1200}
    # A page that would leave itself, with scripts off, stays drawn; text with control bytes is shown.
    refresh = "<noscript><meta http-equiv=refresh content='0;url=http://other.example.com/'></noscript>"
    assert len(drawn(f"<html><head>{refresh}</head><body>{rows}</body></html>")) >= 2
    assert len(drawn("IOCs\x0b\nevil.example.com\x1a\n", html=False)) == 1
