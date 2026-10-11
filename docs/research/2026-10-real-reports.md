# IOC extraction on real Chinese-language reports (October 2026)

This note follows the synthetic check in [2026-10-existing-tools.md](2026-10-existing-tools.md). It
measures TTPrism, iocextract and ioc-finder on public TLP:CLEAR reports, with each report's own IOC
appendix as the ground truth.

**Status:** the Simplified-Chinese set (8 reports) was measured before and after fixing what it
showed. The Traditional-Chinese set (3–4 reports chosen by the maintainer) is held out: it will be
measured once, at the end, and has not been looked at during the fixes. TTPrism (`src/`) is frozen
at 435bb97, the commit at which the "after" results below were made, and does not change again for
this evaluation. The evaluation tool was changed after 435bb97, before any Traditional-Chinese file
was added: its ground truth is now a draft that a reviewer checks line by line against the rendered
pages before any tool runs, and the whole procedure for the held-out set, down to how its results
will be read, is written down in section 6 in advance. The tool is frozen with that section; after
it, only the Traditional-Chinese entries of the manifest (selection rule first, before anyone looks
at the files), the reviewed ground truth, the judgements, the documentation and the results may
change.

Everything needed to check the numbers is in [`2026-10-real-reports/`](2026-10-real-reports/):
the script, the manifest (original URLs, appendix markers, the reviewed ground truth or, for zh-cn,
the hand corrections, each with a reason), the judgements of every extracted value outside the
ground truth, the results with every tool's full output, and the defang statistics. PDFs and the
extracted text are not committed.

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
  d53b3ed (baseline, Python 3.11.4) and 435bb97 (after the fixes, Python 3.11.17; the first fix
  commit, 6d0012d, gave the same output, see section 4). The PDF text is the same on both Pythons
  (same SHA-256). The "after" results file lists every installed package, the Python version and
  the SHA-256 of the files that parse HTML; the baseline, made earlier, records only the tool
  versions and Python 3.11.4.
- **TTPrism settings.** *default* (the main numbers) and *raw* (`--include-reserved
  --no-default-allowlist`). Comparisons with the other tools use raw.
- **Ground truth.** (The zh-cn procedure, kept for these results; the held-out set uses the draft and
  review of section 6.) The values in the appendix, found with plain line rules, then corrected by hand.
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
  either reading counts neither way. A URL in the appendix adds its host to the domains. These
  corrections are kept in the manifest as `legacy_truth_corrections`; the zh-cn results were made by
  evaluate.py as of 7eea575 and were not made again with the draft-and-review procedure. Run on the
  same eight appendices, the current draft rules give this ground truth exactly, except where the hand
  corrections applied, and each of those is either done by the rules or flagged for the reviewer:
  `0x04.IOCs` and the `serveuser.-` fragments are left out by the top-level-domain check, the
  page-header addresses get an `own-address` warning (10 occurrences in cn03, cn06, cn07 and cn08),
  and all 18 wrapped cn06 names (20 line breaks) get a `name-cut` warning.
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
full-width forms is one thing the held-out set will show. `defang` (section 6.3) counts the same:
no full-width or CJK writing occurs inside any value of the eight texts, and outside values only the
full-width colon of Chinese prose does, not even a full-width digit
([`defang-zh-cn.json`](2026-10-real-reports/defang-zh-cn.json)).

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
and a third after the maintainer's freeze check (91327ec and a2dc77a, then 435bb97 after a
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
88bda72, 19952b5, 7b985f0 and 435bb97 give identical results; only the wording of cn01's
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

## 6. The held-out Traditional-Chinese set: the procedure, fixed in advance

This section is committed before any Traditional-Chinese file is in the working directory; the commit
at which the first one is added is the freeze commit of the evaluation tool, and nothing below changes
after it.

### 6.1 Order of the steps

1. Commit the selection rule (`selection_rule` → `zh-tw` in the manifest).
2. Download the files, and write each report's manifest entry: its bibliographic fields (`title`,
   `publisher`, `published`, `original_url`, `url_source`), its source fields (`retrieved`,
   `final_url`, `saved`, charsets) and its appendix markers (`start`, and `end` or `end_of_text`),
   which every command checks.
3. `text`: PDFs with pypdf (one with only an owner password is decrypted with the empty user
   password), web pages decoded strictly and laid out by `HtmlText`. `text` prints where each
   appendix starts and ends; the markers are corrected until they are right, and are then fixed
   (the review covers them through the draft's SHA-256).
4. `defang`: count the writings (6.3).
5. `truth`, the review, `review`, and a commit of the manifest. The ground truth is fixed before any
   tool runs, by a reviewer who has not seen any tool's output: `review` refuses once the set has
   results, and `run` refuses unless every report's review is complete, committed as it stands and
   made against the draft that the current text and rules give.
6. `run`.
7. `judge`, the judging, `judge --import`.
8. `score`.

### 6.2 Ground truth: a draft, reviewed line by line

`truth` reads each line of the appendix: soft hyphens in PDF text as hyphens and other format
characters deleted (as for zh-cn), then the defang styles as the ASCII characters they stand for —
dot, at sign, colon and slash in ASCII, full-width or CJK brackets (`[.]` `(.)` `{.}` `[dot]`
`(dot)` `[at]` `{at}` `[@]` `[:]` `[://]` `[/]` `【.】` `〔.〕` `［.］` `[。]` `（.）` `［＠］`, with or
without spaces inside and around), the full-width dot and at sign (with or without spaces around),
the full-width colon, slash and hyphen, full-width letters and digits, and the hyphens U+2010,
U+2011, U+2212 and U+FE63 — and finds URLs, e-mail
addresses, IPv4 addresses, names and hashes in the ASCII text that results. A name's last label must
be a top-level domain of `iana-tlds.txt` (the IANA list of 2026-09-30, copied from the PyPI package
`tlds` 2026093003 because data.iana.org could not be reached; not TTPrism's list), which leaves out
file names such as `setup.msi`; a name under a top-level domain that is also a common file extension
(`.zip`, `.sh`, `.so`, `.py`, `.app` …) is left out with a warning. A URL ends at white space,
non-ASCII text, quotation marks, brackets, `<`, `>` and `&&`. One function gives the standard form of
a value for the ground truth and for every tool's output (scheme and host lower-cased, `hxxp` as
`http`); a URL it cannot parse is kept as it is and listed, never an exception.

For each report `truth` writes the draft, a review page that shows every line of the appendix with
the values read from it and its warnings beside images of the pages (pdftoppm for each PDF page the
appendix is on; headless Chromium screenshots of a web page, decoded as `text` decoded it, with
scripts off, every other request refused and `<meta http-equiv="refresh">` taken out). Since
`HtmlText` reads hidden content, the screenshots show it too: hidden elements, closed `<details>`
and boxes that scroll are laid out in the page. A report whose pages cannot be drawn is named, and
`review` refuses it until they are. The warnings:

| Warning | What the reviewer checks |
| --- | --- |
| `hex-cut` | hex digits at a line end and the next line's start that make a SHA-1 or SHA-256 together (not two MD5s under an MD5 label); a run of lines of 32 hex digits with no MD5 label (two of them may be the halves of a SHA-256); a piece of the length of no hash |
| `hash-label` | a hash whose length differs from the hash type named in the label above it |
| `name-cut` | a name ending at a line end in `.` or `-` before a line that starts with a name or with `.` or `-`, or a line starting with `.` or `-` after a name |
| `url-cut` | a URL that reaches the line end before a line that does not start with a value |
| `file-extension` | a name left out because its top-level domain is also a file extension |
| `url-unparseable` | a URL without a host in standard form |
| `non-ascii` | a value read from non-ASCII writing (full-width or CJK forms, Unicode or soft hyphens, deleted format characters), or a URL that stops right before non-ASCII letters |
| `masked` | a masked value, left out |
| `own-address` | a value at the report's own address, often a page header printed inside the appendix |
| `unread-defang` | a dot or at sign in a form the reading does not know, between ASCII letters or digits |

Line ends and starts are found past any white space, the no-break spaces pypdf gives included.

The reviewer checks every line against the images and fills in the template: who and when, the
images checked (every PDF page the appendix is on, and screenshots of each web page), that every line
was checked, and a resolution for every warning — `confirmed`, or `corrected` by an `add`, `remove` or
`ambiguous` entry that names it — each with a note; a resolution must be for the draft's own warning
of that number (its kind, line and message). Every added value is in standard form and of the shape
of its type, and records its writing as the page shows it, its writing class and where it stands; a
draft value whose writing, class or place is wrong is removed and added again. A `remove` entry that
matches no value of the draft is an error, and so is one that removes a name which a URL kept in
the truth has as its host (the URL would make it an indicator again). An `ambiguous` entry lists two
or more readings with the writing and place, and says whether a reading is a value of the draft
(`from_draft`): when it says so, at least one must be, and when it does not, none may be (its
readings are values the draft did not read, as for a name wrapped across lines; a typo in them is
not caught, as for an added value). A URL without a host cannot stay in the truth. `review` checks
all of this and writes the reviewed ground truth into the manifest (`truth_review`), where every
final value has its four records; `run` and `score` check it again, and `run` stops if earlier
results of the set were made with another review.

Writing classes: *plain*; *ASCII defang* (`[.]` `(.)` `{.}` `[dot]` a URL scheme written `hxxp`
or `fxp`, `[:]` `[://]` `[/]` `[@]` `[at]`); *full-width or CJK-bracket defang* (`【.】` `〔.〕` `［.］`
`[。]` `（.）` `．` `＠` `／` `：` `－`, full-width letters and digits). The spaces around a form do not
decide its class. Unicode hyphens and soft hyphens are plain. A value written several ways in the
appendix gets the class of its plainest writing, since a tool can find it from that one; a URL's
host is classed by how the host itself is written, as the plainest of its own entry and its writing
in each URL, and so is an address that is a URL's host and a value of its own.

### 6.3 What is measured

1. **The main question, how indicators are written.** `defang` counts each writing in the whole text
   and in the appendix of each report: ASCII (`[.]` `(.)` `[dot]` `hxxp` `[:]` `[@]` `[at]`, others)
   and full-width or CJK (`【.】` `〔.〕` `［.］` `[。]` `（.）` `．` `＠` `：` `／` `－`, full-width letters
   and digits, other bracket forms) — the same characters as the writing classes — each twice:
   everywhere, and only inside values the line rules find. Full-width digits, `１．` numbering and the
   full-width colon are common in Chinese body text, so only the second count says whether indicators
   are written that way. A report *uses* full-width or CJK-bracket writing when that count finds at
   least one such writing inside a value anywhere in its text, or when one of its reviewed
   ground-truth values is written only so (a form the rules do not read, added by the reviewer);
   `score` records both counts for each report.
2. **The tools.** Recall of each tool by writing class (plain, ASCII defang, full-width or
   CJK-bracket defang); overall recall (by type and by URL host) and precision (strict, lenient)
   computed as for zh-cn; totals for all reports and for PDFs and web pages separately. TTPrism raw
   is the one compared, default is reported as well. A tool that fails on a report is recorded with
   its error and has found nothing there.

### 6.4 How the results will be read

- Descriptively, without statistical tests: with 3–4 reports, each is a case.
- If no Traditional-Chinese report uses full-width or CJK-bracket writing, the README and this
  report will say: "None of the 11–12 real reports evaluated so far uses these writings; TTPrism's
  handling of them is supported only by synthetic tests." (README in Chinese: 「目前評估的 11–12
  份真實報告都沒有用到這些寫法；TTPrism 對它們的處理只有合成測試支持」.)
- If some do: "N of M use them", with each tool's recall in that class, and nothing inferred beyond
  these reports.

### 6.5 Excluding a report

Once the files are in, a report is excluded only for a technical reason: it has no IOC appendix after
all, its indicators are only in images, its file cannot be read, it is not in Traditional Chinese, or
it is not TLP:CLEAR. An excluded report goes to `skipped` with its reason. No report is excluded
because of its content or its results. It is replaced only before the review of the ground truth
starts, by the next report under the same selection rule.

### 6.6 Judging

All extracted values outside the ground truth, from all tools together, go on one sheet (`judge`),
without the names of the tools that found them and in a shuffled order; the evaluator judges each
(a, b or c, with a one-line reason). There is one rater, and no agreement between raters is
measured. While any value is unjudged, `score` marks every total as provisional. `judgements.json`
is checked (a wrong category, type or form is an error with its place) and its SHA-256 is recorded
in the results.

### 6.7 Checked on a synthetic set

`tests/test_research_pipeline.py` runs every step on two synthetic reports made like the held-out
ones: a PDF printed by Chromium and encrypted with only an owner password, with a SHA-256 that a
narrow table cell breaks into two 32-digit halves, full-width and CJK-bracket defanging, and a second
page whose WinAnsi font draws hyphens with code 0xAD (one inside a name, one at a line end); and a
Big5 web page with an indicator table. `review` stopped on all twelve warnings until each was
resolved (the split SHA-256 by its `hex-cut` and two `hash-label` warnings, the wrapped name by
`name-cut`), `run` refused before the review was committed, iocextract's `ValueError` on
`http://a：` in the web page was recorded as its error on that report while the run went on, `score`
was provisional until the blinded sheet was judged, and the recall of every tool by writing class
equals an independent count from the reviewed values and the outputs. A second test draws pages with
hidden content, a closed `<details>`, a box that scrolls, a `<meta http-equiv="refresh">` in
`<noscript>`, and a text attachment with control characters, and checks that all of it is drawn.
These are checks of the procedure, not results.

### 6.8 Known gaps, not fixed before the freeze

- Windows: rendering needs a POSIX system, and Git's `autocrlf` and the console encoding are not
  handled; the evaluation runs on Linux or macOS.
- The draft has no rule for IPv6 addresses; a reviewer adds them by hand.
- A name with a single asterisk (`evil.*.com`) is not found by the draft at all, as a value or as a
  masked one; URLs and tool outputs with one are treated as masked.
- IPv4 octets above 255 are not rejected; CIDR blocks and ranges are read as plain addresses.
- A cp950 page with an outdated `gb2312` `<meta>` decodes as GB 18030 without an error; `text`
  prints the encoding and declared charsets, and such a page needs a `charset_override`.
- A text attachment that is not UTF-8 stops `text` with Python's `UnicodeDecodeError`, which does not
  name the file.
- An ambiguous URL contributes no host, even when only its path is ambiguous (the reviewer can add
  the host as a name). Removing a name that is the host of a URL kept in the truth is refused by
  `review`, not silently undone.
- Results made by another evaluate.py stop `score` without saying what changed.

## 7. Reproducing

The zh-cn results were made by evaluate.py as of 7eea575, with the hand corrections now in
`legacy_truth_corrections`; reproduce them with that commit's `docs/research/2026-10-real-reports/`.
The current script makes the zh-cn text, defang statistics and ground-truth drafts, but `run` needs a
review, which zh-cn does not have.

The held-out set, in the order of section 6.1 (`text` needs a Python with the 2025 `html.parser`
security fixes, 3.11.17 was used; `truth` needs pdftoppm and Chromium on a POSIX system):

```sh
uv venv -p 3.11.17 /tmp/eval
uv pip install -p /tmp/eval/bin/python -r docs/research/2026-10-real-reports/requirements.txt -e .
E=docs/research/2026-10-real-reports/evaluate.py
# selection rule committed; files in eval-data/zh-tw/pdf/<id>.pdf or html/<id>.html;
# each report's manifest entry written (bibliographic and source fields, appendix markers)
/tmp/eval/bin/python -I $E text zh-tw
/tmp/eval/bin/python -I $E defang zh-tw
CHROMIUM=/path/to/chromium /tmp/eval/bin/python -I $E truth zh-tw
# review eval-data/zh-tw/truth/<id>.review.html against its images; fill in <id>.review.json
/tmp/eval/bin/python -I $E review zh-tw
git commit -m "Reviewed zh-TW ground truth" docs/research/2026-10-real-reports/manifest.json
/tmp/eval/bin/python -I $E run zh-tw heldout
/tmp/eval/bin/python -I $E judge zh-tw heldout     # judge eval-data/zh-tw/judging/heldout.json
/tmp/eval/bin/python -I $E judge zh-tw heldout --import
/tmp/eval/bin/python -I $E score zh-tw heldout
```

The source files go in `eval-data/<set>/pdf/<id>.pdf` or `eval-data/<set>/html/<id>.html`; the
results list the SHA-256 of each source file and of its text, and each step stops if what it was made
from changed.
