# IOC extraction on real Chinese-language reports (October 2026)

This note follows the synthetic check in [2026-10-existing-tools.md](2026-10-existing-tools.md). It
measures TTPrism, iocextract and ioc-finder on public TLP:CLEAR reports, with each report's own IOC
appendix as the ground truth.

**Status:** the Simplified-Chinese set (8 reports) was measured before and after fixing what it
showed. The Traditional-Chinese set (3–4 reports chosen by the maintainer) is held out: it will be
measured once, at the end, and has not been looked at during the fixes. TTPrism is frozen for it at
whatever commit is HEAD when its files arrive.

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
  read the same text. Versions: iocextract 1.16.1, ioc-finder 9.4.1, Python 3.11.4; TTPrism at
  d53b3ed (baseline) and 6c655c8 (after the fixes; the first fix commit, 6d0012d, gave the same
  output, see section 4).
- **TTPrism settings.** *default* (the main numbers) and *raw* (`--include-reserved
  --no-default-allowlist`). Comparisons with the other tools use raw.
- **Ground truth.** The values in the appendix, found with plain line rules, then corrected by
  hand: the report's own address printed as a page header inside the appendix and a section heading
  read as a domain (`0x04.IOCs`) were removed; in cn06 a layout put a `-` at every wrap in the
  domain table, so `serveuser.-` + `com` was read as `serveuser.com` (a hyphen next to a dot cannot
  be part of a name) and `dynamic-` + `dns.net` kept its hyphen (cn02 lists that provider
  unwrapped). Eight cn06 entries wrap at a hyphen that may or may not belong to the name
  (`126-` + `maildownload…`); they are left out, like the masked `wiki.xxxx.com`, and a tool output
  equal to either reading counts neither way. A URL in the appendix adds its host to the domains.
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
| Certificate serial numbers (`SerialNumber:` + 32 hex) read as MD5 (all three tools) | 3 c | Hex values right after a serial-number label (`serial`, `serial number`, `序列号`, `序列號`, `證書序號`, `憑證序號`, or a bare `序號` with a colon) are counted as `certificate_serial` |
| GUIDs whose hyphens the PDF converter wrote as soft hyphens read as MD5 | 2 c | Soft hyphens between the groups of a GUID become hyphens before format characters are deleted |
| Names wrapped at a hyphen next to a dot (`serveuser.-` / `com`) missed | 7 recall | Joined without the hyphen |
| URLs wrapped after one of their own hyphens (`KB-Auto-win-` / `update.exe`) cut | 6 c | Joined keeping the hyphen, when a URL on the line runs up to the hyphen |
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

**Changes made before the freeze from reading the code, not from these data** (6857503, then
6c655c8 after an adversarial review of it):

- A soft hyphen right before a line break, also with spaces, bidi controls or other format
  characters between, is read as `-`, so the line-break rules apply to it exactly as to `-`. It used
  to be deleted first, so `update\u00ad` / `check-server.com` gave the wrong `check-server.com`.
- Soft hyphens deleted between two ASCII letters or digits inside an extracted name, e-mail address
  or URL, defanged or not, now give a warning, because some converters (cn01's among them) write
  every hyphen as a soft hyphen and the value then loses its hyphens (`KB-Auto` read as `KBAuto`).
- A bare `序號` is a serial-number label only with a colon, since it also heads the row-number
  column of tables; `證書序號` and `憑證序號` need none.
- A line ending in `<letter or digit>-` is joined with the next line as part of a URL only if a URL
  really runs up to the hyphen; before, any URL earlier on a line of Chinese text without spaces was
  enough.

None of these changed any output on the eight reports (6d0012d and 6c655c8 give identical
results). cn01 has 46 soft hyphens inside lines, but none inside an extracted value, so it gives no
warning.

## 5. Limitations

- One person built the ground truth corrections and made every judgement; no inter-rater
  agreement was measured. The reasons are recorded so that each call can be checked.
- Recall counts only the appendix. Indicators named only in the body are credited in precision (a)
  but not missed in recall.
- Appendices have their own errors (cn02 lists `gaewaa.upgrinfo.com`, the body `gaewaaa`; cn05
  lists `he-moondelight.96.lt`, the body `the-moondelight.96.lt`); the ground truth follows the
  appendix.
- Eight reports from three vendors and one community team, 2018–2020; only these years had
  suitable Simplified-Chinese reports with IOC appendices in the collection. The PDF text depends
  on pypdf and on how each PDF was made; another converter would give other artifacts.

## 6. Reproducing

```sh
uv venv -p 3.11 /tmp/eval
uv pip install -p /tmp/eval/bin/python -r docs/research/2026-10-real-reports/requirements.txt -e .
E=docs/research/2026-10-real-reports/evaluate.py
/tmp/eval/bin/python -I $E text zh-cn && /tmp/eval/bin/python -I $E truth zh-cn
/tmp/eval/bin/python -I $E run zh-cn after && /tmp/eval/bin/python -I $E score zh-cn after
```

The PDFs go in `eval-data/zh-cn/pdf/<id>.pdf`; the manifest lists each one's path and blob SHA-1
in the collection, and the results list the SHA-256 of each PDF and of its text.
