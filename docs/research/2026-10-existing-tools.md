# Existing tools and the CJK defang gap (October 2026)

This note records the competitor check behind TTPrism's scope (planning document, section 2). It
is a **first, synthetic check**. It does not replace the planned test against ten public
Chinese-language threat reports, which is still to do (see "Next step").

## 1. Maintenance status (PyPI, checked 2026-10-08)

| Tool | Latest version | Last release | Notes |
| --- | --- | --- | --- |
| [iocextract](https://pypi.org/project/iocextract/) | 1.16.1 | 2023-09-22 | No release for three years; imports `requests` without declaring it |
| [ioc-finder](https://pypi.org/project/ioc-finder/) | 9.4.1 | 2026-06-17 | Actively maintained |

## 2. CJK and full-width defanging

Script: [`compare_existing_tools.py`](compare_existing_tools.py). Each input is one synthetic
sentence in the style of a Chinese-language report. Domains use `example.com` and IPs use
documentation ranges.

| Defang style | Example | iocextract 1.16.1 | ioc-finder 9.4.1 | TTPrism |
| --- | --- | --- | --- | --- |
| ASCII `[.]` | `update-check[.]example.com` | found (as `http://` URL) | found | found |
| Full-width dot `．` | `update-check．example．com` | missed | missed | found |
| `【.】` | `update-check【.】example.com` | missed | partial (`example.com`) | found |
| `[。]` | `update-check[。]example.com` | missed | partial | found |
| Full-width parens `（.）` | `update-check（.）example.com` | missed | partial | found |
| Domain glued to CJK text | `使用update-check.example.com作為` | missed | found | found |
| `hxxps` + `【.】` | `hxxps://cdn-update【.】example.com/a/stage2.bin` | truncated (`https://cdn-update`) | partial | found (URL and domain) |
| Full-width IP | `１９８．５１．１００．２３` | missed | missed | found |
| ASCII IP `[.]` | `198.51.100[.]23` | found | found | found |
| Full-width CVE | `ＣＶＥ－２０２３－２３３９７` | missed | missed | found |
| Email `［＠］` + `．` | `attacker［＠］mail-update．example．com` | missed | missed | found |

"Partial" means the tool returned only the part after the CJK bracket, which is a different (and
wrong) indicator.

**What this shows:** both libraries handle ASCII defanging but not the full-width and CJK-bracket
forms. A Chinese-language report that uses these forms will lose IOCs or, worse, yield truncated
ones. This supports the hypothesis in the planning document.

**What this does not show:** how often these forms actually appear in published reports. The
inputs were written to exercise each form, not sampled from real reports, and TTPrism was built
with these forms in mind.

## 3. Stale ATT&CK IDs in sandbox output

CAPE signatures carry their own ATT&CK technique lists. Of the 916 technique references in
[kevoreilly/community](https://github.com/kevoreilly/community) signatures (commit `af2e503`,
2026-10-08), checked against Enterprise ATT&CK 19.2:

| Status in ATT&CK 19.2 | References |
| --- | --- |
| Active | 700 |
| Revoked (e.g. `T1086` PowerShell → `T1059.001`, `T1045` → `T1027.002`, `T1089`) | 193 |
| Deprecated (`T1064` Scripting) | 20 |
| Not in Enterprise ATT&CK (mobile/ICS IDs) | 3 |

So about **23% of the TTP labels CAPE attaches are outdated**. ATT&CK 19 also renamed the
*Defense Evasion* tactic to *Stealth*, added *Defense Impairment*, and revoked `T1562.001`
(now `T1685`) and `T1070.001` (now `T1685.005`). TTPrism resolves revoked IDs through ATT&CK's
revocation history and reports the original ID alongside the current one.

## Next step

Run TTPrism, iocextract and ioc-finder on ten public (TLP:CLEAR) Chinese-language threat reports
and record, per report: the defang styles used, IOCs found by each tool, and false positives.
Candidate sources are reports published in Chinese by Taiwanese government CERTs and security
vendors. Only cite reports that may be redistributed, and record each report's URL rather than
committing its text.

Done for eight Simplified-Chinese reports in [2026-10-real-reports.md](2026-10-real-reports.md);
none of them uses the full-width or CJK-bracket forms above. Traditional-Chinese reports are next.
