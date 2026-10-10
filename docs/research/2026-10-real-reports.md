# IOC extraction on real Chinese-language reports (October 2026)

This note follows the synthetic check in [2026-10-existing-tools.md](2026-10-existing-tools.md). It
measures TTPrism, iocextract and ioc-finder on public TLP:CLEAR reports, with each report's own IOC
appendix as the ground truth.

**Status:** the Simplified-Chinese set (8 reports) was measured before and after fixing what it
showed. The Traditional-Chinese set (3–4 reports chosen by the maintainer) is held out: it will be
measured once, at the end, and has not been looked at during the fixes. TTPrism (`src/`) and the
evaluation script are frozen at FREEZE_COMMIT, the commit at which the "after" results below were
made; after it, only the Traditional-Chinese entries of the manifest (selection rule first, before
anyone looks at the files), the documentation and the results may change.

Everything needed to check the numbers is in [`2026-10-real-reports/`](2026-10-real-reports/):
the script, the manifest (original URLs, appendix markers, hand corrections of the ground truth,
each with a reason), the judgements of every extracted value outside the ground truth, and the
results with every tool's full output. PDFs, the extracted text and the ground-truth values are not
committed.

## 1. Reports

PDFs come from the CyberMonitor/APT_CyberCriminal_Campagin_Collections repository (partial clone,
sparse checkout of the PDFs only; no sample archive was checked out or unpacked). The URLs below are
the publishers' own; the manifest says how each was established, and the maintainer is checking
cn01, cn02, cn04 and cn05.

| ID | Publisher, date | Original URL | Appendix | Ground truth | Left out |
| --- | --- | --- | --- | --- | --- |
| cn01 | Tencent, 2018-04 | `s.tencent.com/research/report/471.html` | MD5s glued to file names in brackets; soft hyphens for every hyphen | 9 MD5, 6 domains, 3 IPv4 | |
| cn02 | 360, 2018-09 | `ti.360.net/uploads/2018/09/20/6f8a….pdf` | Plain lists; `hxxp` in the body | 84 MD5, 78 domains, 10 IPv4, 1 URL | |
| cn03 | 360, 2019-05 | `blogs.360.cn/post/analysis-of-APT-C-38.html` | Two-column MD5 table; hyphenated WHOIS table in the body | 29 MD5, 12 domains, 4 IPv4 | |
| cn04 | Tencent, 2019-11 | `s.tencent.com/research/report/836.html` | Plain lists | 77 MD5, 6 domains, 3 IPv4 | 1 masked |
| cn05 | Qi An Xin, 2020-09 | `ti.qianxin.com/uploads/2020/09/17/69da….pdf` | Plain lists; `[.]` in the body | 25 MD5, 11 domains, 9 URLs | |
| cn06 | Qi An Xin, 2020-10 | `mp.weixin.qq.com/s/omacDXAdio88a_f0Xwu-kg` | Domains wrapped inside narrow table cells | 4 MD5, 45 domains, 22 IPv4 | 8 ambiguous |
| cn07 | 360, 2020-10 | `blogs.360.cn/post/APT-C-44.html` | URLs defanged with `[.]` | 37 MD5, 3 domains, 3 URLs | |
| cn08 | Gcow, 2020-07 | `mp.weixin.qq.com/s/5mBqxf_v6G006EnjECoTHw` | Domains defanged with `[.]` | 9 MD5, 10 domains | |

The appendices list no SHA-1, SHA-256, IPv6 or e-mail values, so recall is reported for URLs,
domains, IPv4 and MD5 only.

## 2. Method

- **Input.** pypdf 6.20.0 turns each PDF into text, page headers and footers included; all tools
  read the same text. A web page would be decoded strictly and laid out by `HtmlText` in
  `evaluate.py` (standard-library `html.parser`; the text of the whole `<body>`, hidden content
  included, navigation and footer too; the rules are in its docstring and in the manifest's
  `text_conversion`), and its totals given separately as well; this set has none. `html.parser`
  before Python's 2025 security releases loses page content (3.11.4 drops everything after a comment
  ending in `--!>` up to the next `-->`, and raises on `<![ if … ]>`), so the script converts canary
  pages first and refuses such a Python. Versions: iocextract 1.16.1, ioc-finder 9.4.1; TTPrism at
  d53b3ed (baseline, Python 3.11.4) and FREEZE_COMMIT (after the fixes, Python 3.11.17; the first fix
  commit, 6d0012d, gave the same output, see section 4). The PDF text is the same on both Pythons
  (same SHA-256). The "after" results file lists every installed package, the Python version and
  the SHA-256 of the files that parse HTML; the baseline, made earlier, records only the tool
  versions and Python 3.11.4.
- **TTPrism settings.** *default* (the main numbers) and *raw* (`--include-reserved
  --no-default-allowlist`). Comparisons with the other tools use raw.
- **Ground truth.** The values in the appendix, found with plain line rules, then corrected by hand.
  In PDF text every soft hyphen is read as a hyphen first, as TTPrism reads it, and other invisible
  format characters are deleted (those that separate two names become spaces); the rules take only
  printable ASCII as part of a value (so a name right after Chinese text is found, and a URL ends at
  Chinese text or full-width punctuation), read `[.]` and `(.)` as dots and the common defangs of
  `://` and `@`, and find URLs, e-mail addresses, IPv4 addresses, domains and hashes. Rebuilt with
  these rules, the ground truth of all eight reports is unchanged: cn01's appendix has
  ten soft hyphens, all in file names and GUIDs, and no appendix lists an e-mail address. The
  corrections: the report's own address printed as a page header inside the appendix and a section
  heading read as a domain (`0x04.IOCs`) were removed; in cn06 a layout put a `-` at every wrap in
  the domain table, so `serveuser.-` + `com` was read as `serveuser.com` (a hyphen next to a dot
  cannot be part of a name) and `dynamic-` + `dns.net` kept its hyphen (cn02 lists that provider
  unwrapped). Eight cn06 entries wrap at a hyphen that may or may not belong to the name (`126-` +
  `maildownload…`); they are left out, like the masked `wiki.xxxx.com`, and a tool output equal to
  either reading counts neither way. A URL in the appendix adds its host to the domains.
- **Matching.** Domains lower-cased, trailing dot removed; URLs refanged with scheme and host
  lower-cased, scored as whole URLs and by host; MD5 case-insensitive. Before domain recall, each
  tool's domain output gets the hosts of its URL output (iocextract has no domain extractor, so its
  domains come only from URLs).
- **Precision.** Every distinct extracted value of the eight types that is not in the ground truth
  was judged from its context: **a** an indicator the report names outside the appendix, **b** a
  correct value that is not an indicator, **c** a wrong value. Strict precision is (truth + a) /
  judged, lenient is (truth + a + b) / judged. Values with a mask (`xxx`, `*`) are left out, as in
  the ground truth. **All 262 judgements were made by one person (the evaluator), without a second
  rater**; each has a one-line reason in `judgements.json`.

Judgement rules that affect the numbers: a reference, the publisher's own pages and legitimate
services that the malware uses (Kanbox cloud storage, dynamic DNS parent domains) are b; a
certificate thumbprint is a (it is a SHA-1 of the certificate and an indicator); an IPv4 address
that is the host of an appendix URL counts as listed; a defanged host that a tool reports as a URL
with an `http://` it invented (iocextract: `nrots[.]net` → `http://nrots.net`) is c, because the
report does not contain that URL. Counted as a and b instead, iocextract's strict and lenient
precision would be 0.820 and 0.922 rather than 0.798 and 0.896.

Examples:

| Category | Value | Report and context |
| --- | --- | --- |
| a | `fiesta.kozow.com` | cn05, "相关 C2: fiesta.kozow.com:4567" in the body |
| a | `http://180.150.227.24/do/index.php?id=ssss` | cn04, upload URL in the body (the address is in the appendix) |
| a | `153a7ea3a7acb476fd66d214e61e51bb35b4a24b` | cn05, thumbprint of the AsyncRAT server certificate |
| b | `technet.microsoft.com` | cn02, reference for a vulnerability |
| b | `serveusers.com` | cn06, dynamic DNS provider whose subdomains the attackers registered |
| b | `https://blogs.360.cn/post/APT-C-44.html` | cn07, the report's own address in every page header |
| c | `00b27593843dc41ac674ea5021879cf5` (MD5) | cn05, `SerialNumber:` of a certificate |
| c | `daters.com` | cn03, the second line of `androidup‐` / `daters.com` in a hyphenated WHOIS table |
| c | `http://nrots.net` | cn08 (iocextract), the defanged domain `nrots[.]net` with an invented scheme |

## 3. Results (Simplified Chinese, 8 reports)

Recall (found / in ground truth), all reports together:

| Tool | URL | URL host | Domain | IPv4 | MD5 |
| --- | --- | --- | --- | --- | --- |
| TTPrism default, before | 13/13 | 9/9 | 162/171 | 42/42 | 274/274 |
| TTPrism raw, before | 13/13 | 9/9 | 162/171 | 42/42 | 274/274 |
| **TTPrism default, after** | 13/13 | 9/9 | **169/171** | 42/42 | 274/274 |
| **TTPrism raw, after** | 13/13 | 9/9 | **169/171** | 42/42 | 274/274 |
| iocextract | 13/13 | 9/9 | 21/171 | 42/42 | 274/274 |
| ioc-finder | 13/13 | 9/9 | 162/171 | 42/42 | 272/274 |

Precision (distinct values; masked and ambiguous ones left out):

| Tool | In truth | a | b | c | Strict | Lenient | Masked |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TTPrism default, before | 493 | 62 | 97 | 32 | 0.811 | 0.953 | 22 |
| TTPrism raw, before | 493 | 62 | 107 | 33 | 0.799 | 0.953 | 22 |
| **TTPrism default, after** | 500 | 62 | 101 | **6** | **0.840** | **0.991** | 3 |
| **TTPrism raw, after** | 500 | 62 | 111 | **7** | **0.827** | **0.990** | 3 |
| iocextract | 331 | 36 | 45 | 48 | 0.798 | 0.896 | 4 |
| ioc-finder | 491 | 63 | 115 | 41 | 0.780 | 0.942 | 24 |

**Default filtering lost no recall**, before or after: every ground-truth value that raw found,
default found too. It removed 11 values, all b or c: four `cve.mitre.org` URLs and their two hosts,
`github.com` twice, `www.google.com`, `www.virustotal.com` and a VirusTotal URL that a line break
had cut.

Reading the numbers:

- With the same input, the three tools find the plain appendix values alike: every tool finds all
  IPv4 addresses and URLs. The differences are at the edges: ioc-finder misses two MD5s glued to
  a bracket (`…3FF3(HttpProv.dll)`, cn01); iocextract finds domains only inside URLs and turns
  `[.]` domains into invented URLs.
- Before the fixes, TTPrism raw had the same domain recall as ioc-finder (both missed the 9
  wrapped cn06 names) and fewer wrong values (33 against 41 for ioc-finder and 48 for iocextract).
  After them it finds 7 of the 9 and has 7 wrong values. The 7 more domains moved from "missed" to
  "in truth"; the remaining two are `dynamic-` wraps, whose hyphen TTPrism cannot tell from an
  inserted one.
- Strict precision is low for every tool because reports cite many references and legitimate
  services (b). Lenient precision, the share of values that are correct as written, is the better
  measure of extraction quality; strict precision is what an analyst gets if they import
  everything as indicators.
- These "after" numbers were made on the same eight reports the fixes were derived from, so they
  are optimistic. The held-out Traditional-Chinese set will show how much of the gain carries over.

**What this does not support:** the synthetic check found that full-width and CJK-bracket
defanging (`．`, `【.】`, `[。]`, `［＠］`) defeats both libraries. None of these eight reports uses
any of those forms; the only defanging in their text is ASCII `[.]` (24 times, in cn05, cn07 and
cn08) and one `hxxp` (cn02), which all three tools handle. In this sample the differences come from
PDF artifacts and noise, not from CJK defanging. Whether Traditional-Chinese reports use the
full-width forms is one thing the held-out set will show.

## 4. TTPrism issues found and what changed

Recorded from the baseline before any change; fixed in 6d0012d with unit tests and a 1 MB case in
`tests/test_redos.py` for every new pattern (report text costs 0.6–0.7 s/MB before and after). Two
of the rules were refined later (see below); the table describes them as they are now.

| Baseline issue | Count | Change |
| --- | --- | --- |
| Certificate serial numbers (`SerialNumber:` + 32 hex) read as MD5 (all three tools) | 3 c | Hex values right after a serial-number label (`serial`, `serial number`, `序列号`, `序列號`, `序號`, with or without a colon) are counted as `certificate_serial` |
| GUIDs whose hyphens the PDF converter wrote as soft hyphens read as MD5 | 2 c | Soft hyphens between the groups of a GUID become hyphens (now: every soft hyphen, see below) |
| Names wrapped at a hyphen next to a dot (`serveuser.-` / `com`) missed | 7 recall | Joined without the hyphen |
| URLs wrapped after one of their own hyphens (`KB-Auto-win-` / `update.exe`) cut | 6 c | Joined keeping the hyphen, when a URL on the line runs up to the hyphen (also over several lines) |
| The rest of a name after any other hyphen at a line end (`daters.com`, `dns.net`) | 14 c | Dropped as a fragment (`line_wrap_fragment`); the hyphen may or may not belong to the name |
| Masked names (`wiki.xxxx.com`, `mail.cass.xxxx.net`) reported | 19 masked | Names with a label of three or more `x` are dropped (`masked_name`) |
| Detection name `Backdoor.Win32.Ht` reported as a domain | 1 c | Names of the form type.platform.family are dropped (`detection_name`) |

Still wrong after the fixes (raw): four URLs cut at a line break that is not after a hyphen
(`…china.ht` / `ml`, `…Programm` / `able…`, a VirusTotal hash split in two, a WeChat ID), a URL
template cut at its placeholder (`?session=[8 位随机数字]`), `ail.com` from an e-mail address split
as `gm` / `ail.com`, and `n.qq.com` from a URL host split as `mp.weixi` / `n.qq.com`. A break without
a hyphen gives no sign that the line continues, so these are left as known limitations. Three URL
templates with `XXX` placeholders in their query are still reported (their hosts are real).

The new rules can be wrong in rare text: a URL that really ends in `-` at the end of a line is
joined with the next line, and a name at the start of a line after a line ending in a letter or
digit and `-` (`2019-` / `example.com`) is dropped as a fragment.

**Changes made before the freeze from reading the code, not from these data.** A first round
(6857503, then 6c655c8, 60a0d1f, a7d7e7b and 88bda72 after four rounds of adversarial review), a
second one after the maintainer's review of it (19952b5, then 7b985f0 after one more review round)
and a third after the maintainer's freeze check (91327ec and a2dc77a, then FREEZE_COMMIT after a
review round):

- **Every soft hyphen is a hyphen.** A PDF draws only visible characters, so a soft hyphen in text
  extracted from a PDF stands where the page shows a hyphen: pypdf gives U+00AD for the hyphen of
  code 0xAD in WinAnsi-encoded fonts, where pdftotext gives `-` (a one-page Helvetica PDF showing
  `update-check.example-host.com`, with the first hyphen written as code 0xAD: pypdf 6.20.0 gives
  `update\u00adcheck…`, pdftotext `update-check…`). The first round read them as hyphens only at
  line ends and between GUID groups and deleted the rest, so that page gave
  `updatecheck.example-host.com`, and `CVE\u00ad2017\u00ad11882` or `198.51.100.1\u00ad198.51.100.9`
  gave nothing at all. The second round read one between two letters or digits as `-`, which still
  gave `xn-bcher-kva.example` for `xn\u00ad\u00adbcher-kva.example`, `//raw/` for GitLab's
  `/\u00ad/raw/` and `?id=1` for `?id=\u00ad1`. Now every soft hyphen is read as `-`, one for one, so
  the pypdf text of such a PDF gives the same IOCs as its `pdftotext -raw` text (a test builds the
  PDF and compares both). At a line end, with up to 1,024 spaces or format characters before the
  break, it works exactly like `-` (before the first round it was deleted, so `update\u00ad` /
  `check-server.com` gave the wrong `check-server.com`); right after a hyphen at a line end it is
  deleted, since the first round made `KB-Auto-\u00ad` / `win.exe` into `KB-Auto--` (here
  `pdftotext -raw` gives `--`, the one intended difference). It is also deleted in a run of format
  characters with U+2063 or the end of a bidi embedding or isolate, and in a run of more than 64.
- **The warning goes the other way.** Text copied from a web page uses soft hyphens as invisible
  break hints (`&shy;`), which should be deleted. TTPrism warns when deleting every soft hyphen would
  change any value it reports, of any type, by extracting at most the first 8 Mi characters a second
  time in that reading, cut where no value can go on (a line end or a space in the last 64 Ki
  characters before that). In a longer text it finds only the values that deleting the soft hyphens
  would add, not those it would lose. The first round warned in the opposite case, and walked every
  extracted value of the whole text to count; values are now looked up, so the cost of the check is
  bounded by the 8 Mi characters it reads.
- **`序號` is a label with or without a colon again**, as in 6d0012d. The first round required a
  colon because `序號` also heads the row-number column of tables, but pypdf writes a table row by
  row, so that heading is followed by the other headings, not by a hash, and tables gave the same
  output at 31d5e41 and 8514df1. What the colon rule did change was a certificate field written
  without one (`序號 0e44…`), which became an MD5 again.
- **URL joins (first round).** A line ending in `<letter or digit>-` is joined with the next line as
  part of a URL only if a URL, as the extractor reads it, really runs up to the hyphen; before, any
  URL earlier on a line of Chinese text without spaces was enough. A URL wrapped after its own
  hyphens or at dots over several lines is joined at every break; while it is still in its host,
  only a line of host characters, or one going on to a port or path, carries it further.

None of these changed any scored output on the eight reports (6d0012d, 6c655c8, 60a0d1f, a7d7e7b,
88bda72, 19952b5, 7b985f0 and FREEZE_COMMIT give identical results; only the wording of cn01's
warning changed). cn01's converter wrote every hyphen as a soft
hyphen; reading them as hyphens changes none of its domains, URLs, addresses or hashes, but adds two
CVE IDs, which are not scored: `CVE-2017-11882`, and `CVE-2017-1188` from `CVE\u00ad2017\u00ad1188` /
`2`, broken without a hyphen. Deleting the soft hyphens would lose both and turn the two GUIDs in its
appendix into MD5s, so cn01 gets the warning, with a count of 2.

A differential test on 18,000 generated wrapped names and URLs (three seeds of 6,000; each value is
also read unwrapped, which gives the right answer) compares 7b985f0 with earlier commits:

| 7b985f0 against | Correct values gained | Lost | Wrong values added | Removed |
| --- | --- | --- | --- | --- |
| 6c655c8 | 3,057 | 0 | 348 | 2,391 |
| 31d5e41 | 2,117 | 73 | 174 | 1,450 |

The 73 correct values lost relative to 31d5e41 are lost on purpose: in every one, a URL ended
earlier on the line (`样本下载自http://a.example.com/x.exe，…`), and such a URL no longer joins the
next line. The wrong values added all come from breaks at a dot without a hyphen, which no rule can
join (README, Limitations), but this holds only for the cases this generator makes: the maintainer's
review, with another generator, found 45 of 597 added wrong values that did not. The version of this
paragraph in 2ef93cc, which reported this test at 88bda72, said that all 210 wrong values 88bda72
added relative to 6c655c8 (three seeds) came from dot breaks; 74 of them came instead from a hyphen
followed by a soft hyphen at a line end, read as `--`. That regression came in with 6857503, so
6c655c8 had it too, but 88bda72's new joins carried it into more values; 19952b5 fixed it. Most of
the correct values 88bda72 lost relative to 31d5e41 (282 of 299 on the first seed) came from the
same regression.

## 5. Limitations

- One person built the ground truth corrections and made every judgement; no inter-rater
  agreement was measured. The reasons are recorded so that each call can be checked.
- Recall counts only the appendix. Indicators named only in the body are credited in precision (a)
  but not missed in recall.
- Appendices have their own errors (cn02 lists `gaewaa.upgrinfo.com`, the body `gaewaaa`; cn05
  lists `he-moondelight.96.lt`, the body `the-moondelight.96.lt`); the ground truth follows the
  appendix.
- Eight reports from three vendors and one community team, 2018–2020; only these years had
  suitable Simplified-Chinese reports with IOC appendices in the collection. The candidates were
  picked by hand, not by a fixed criterion, and the screening missed one: Gcow's SideWinder report
  of 2020-01-01, which has a `[.]`-defanged IOC appendix, was never offered and was found only when
  the selection was written down (the manifest's `selection_rule` records all 19 candidates). The PDF text depends
  on pypdf and on how each PDF was made; another converter would give other artifacts.

## 6. Reproducing

`text` needs a Python with the 2025 `html.parser` security fixes, also for a set of PDFs only, and
refuses one without them (3.11.17 was used; 3.11.4 is refused). The selection rule of a set must be
committed before `text` runs.

```sh
uv venv -p 3.11.17 /tmp/eval
uv pip install -p /tmp/eval/bin/python -r docs/research/2026-10-real-reports/requirements.txt -e .
E=docs/research/2026-10-real-reports/evaluate.py
/tmp/eval/bin/python -I $E text zh-cn && /tmp/eval/bin/python -I $E truth zh-cn
/tmp/eval/bin/python -I $E run zh-cn after && /tmp/eval/bin/python -I $E score zh-cn after
```

The PDFs go in `eval-data/zh-cn/pdf/<id>.pdf` (web pages in `eval-data/<set>/html/<id>.html`); the
manifest lists each one's path and blob SHA-1 in the collection, and the results list the SHA-256 of
each source file and of its text.
