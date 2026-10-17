**English** | [繁體中文](https://github.com/yuchen-0321/TTPrism/blob/main/README.zh-TW.md)

# TTPrism

[![PyPI](https://img.shields.io/pypi/v/ttprism)](https://pypi.org/project/ttprism/)
[![Python](https://img.shields.io/pypi/pyversions/ttprism)](https://pypi.org/project/ttprism/)
[![License](https://img.shields.io/github/license/yuchen-0321/TTPrism)](https://github.com/yuchen-0321/TTPrism/blob/main/LICENSE)
[![CI](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml/badge.svg)](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml)

**TTPrism splits a threat report or sandbox run into its IOCs and MITRE ATT&CK techniques**, the
way a prism splits light into a spectrum. It also reads the full-width and CJK-bracket defanging
of Chinese-language reports (`evil【.】com`, `１９８．５１．１００．２３`).

On the 12 real Chinese-language IOC lists evaluated so far, none of which uses full-width or
CJK-bracket defanging (so that handling is supported only by synthetic tests), TTPrism's measured
advantages were fewer wrong values and repairing values split across PDF lines, with the same
recall as ioc-finder; see [Evaluation](https://github.com/yuchen-0321/TTPrism#evaluation).

> **Status:** 0.1.0, the first release. Feedback and detection-quality reports are very
> welcome.

## Quick start

Python 3.11 or newer:

```sh
pip install ttprism
```

If you only want the command, `pipx install ttprism` puts it in its own environment.

Save this Chinese-language report excerpt, with mixed defang styles, as `report.txt`:

```text
C2 為 update-check【.】example 與 198.51.100[.]23，下載 hxxps://cdn.update-check［.］example/stage2.bin
攻擊者利用 ＣＶＥ－２０２３－２３３９７，並執行 PowerShell（T1086）。
```

```sh
$ ttprism extract report.txt -f csv --include-reserved
type,value,sources,detail
url,https://cdn.update-check.example/stage2.bin,text,
domain,cdn.update-check.example,text,
domain,update-check.example,text,
ipv4,198.51.100.23,text,
cve,CVE-2023-23397,text,
attack-technique,T1059.001,reported,PowerShell (reported as T1086)
```

`--include-reserved` is only needed because the example uses documentation addresses and the
reserved `.example` TLD. Without it they are filtered out like any other reserved value, and only
the CVE and the technique remain:

```sh
$ ttprism extract report.txt -f csv
type,value,sources,detail
cve,CVE-2023-23397,text,
attack-technique,T1059.001,reported,PowerShell (reported as T1086)
```

The outdated `T1086` is reported as the current `T1059.001`. Leave out `-f csv` for JSON, which
also counts what was filtered under `suppressed`.

## What it does and what it does not

- **Extracts IOCs** (URLs, domains, IPv4/IPv6, emails, MD5/SHA-1/SHA-256, CVE IDs) from report text
  and from CAPE sandbox reports, and **undoes defanging**: ASCII forms (`evil[.]com`, `hxxp://`) and
  full-width and CJK forms (`evil【.】com`, `evil．com`, `attacker［＠］mail．com`,
  `１９８．５１．１００．２３`), which English-oriented extractors missed in a
  [synthetic test](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-existing-tools.md).
  It also finds domains glued to Chinese text without a space, as ioc-finder does.
- **Maps sandbox behaviour to ATT&CK** with YAML rules for CAPE signatures, command lines, API call
  sequences and registry writes. It also **normalises outdated technique IDs**: about a quarter of
  the TTP labels in CAPE's signatures point at techniques ATT&CK has since revoked or deprecated.
- **Exports** JSON, CSV or a STIX 2.1 bundle.
- **Treats its input as hostile.** Regexes run in linear time, input size is capped, nothing is
  executed or fetched, and CSV output is safe to open in Excel. See the
  [threat model](https://github.com/yuchen-0321/TTPrism/blob/main/docs/threat-model.md).

What it does not do:

- **Only static analysis.** It never executes, unpacks or downloads samples, and never visits or
  resolves the indicators it finds.
- **No PDF reading.** Convert a PDF to text first (see [Turn a PDF report into an IOC CSV](https://github.com/yuchen-0321/TTPrism#turn-a-pdf-report-into-an-ioc-csv)).
- **CAPE is the only sandbox format so far.**
- **No techniques guessed from prose.** For text reports it records the technique IDs the author
  wrote.

| Input | How it is read |
| --- | --- |
| Plain text, Markdown | IOC extraction plus the ATT&CK technique IDs written in the text |
| PDF reports | Convert to text first (for example `pdftotext -raw report.pdf`); TTPrism does not parse PDFs. The [evaluation on real reports](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md) used pypdf (`page.extract_text()`), headers and footers included; converters differ in how they break lines and write hyphens |
| CAPE `report.json` | Detected automatically (input that looks like JSON but does not parse is analysed as text, with a warning); network, files, commands, API calls, registry, signatures |

Non-UTF-8 text (for example Big5 or GB18030) needs `--encoding big5`.

## Common tasks

### Turn a PDF report into an IOC CSV

For a PDF whose page reads:

```text
攻擊者從 hxxps://cdn.update-check[.]example/KB-Auto-win-
update.exe 下載第二階段酬載，C2 為 203.0.113[.]7。
樣本 SHA-256：8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05
```

convert it with `pdftotext -raw` (from poppler), then extract:

```sh
$ pdftotext -raw report.pdf report.txt
$ ttprism extract report.txt -f csv -o iocs.csv --include-reserved
$ cat iocs.csv
type,value,sources,detail
url,https://cdn.update-check.example/KB-Auto-win-update.exe,text,
domain,cdn.update-check.example,text,
ipv4,203.0.113.7,text,
sha256,8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05,text,
```

The URL broken after its own hyphen is joined again. Use `-raw`: pdftotext's default mode joins
a line ending in a hyphen to the next and drops the hyphen, which here gives
`/KB-Auto-winupdate.exe`. pypdf (`page.extract_text()`), which the evaluation used, works too.
How line breaks are joined, and where that goes wrong, is listed under
[Limitations](https://github.com/yuchen-0321/TTPrism#limitations).

### Defang the output to paste it into chat

```sh
$ ttprism extract report.txt -f csv --defang --include-reserved
type,value,sources,detail
url,hxxps[://]cdn[.]update-check[.]example/stage2.bin,text,
domain,cdn[.]update-check[.]example,text,
domain,update-check[.]example,text,
ipv4,198[.]51[.]100[.]23,text,
cve,CVE-2023-23397,text,
attack-technique,T1059.001,reported,PowerShell (reported as T1086)
```

`--defang` works for JSON and CSV. It changes the scheme, host and `@` only; URL paths are left as
they are.

### Turn a CAPE report into ATT&CK techniques and STIX

CAPE's `report.json` is detected automatically:

```sh
$ ttprism extract report.json -f csv --include-reserved
type,value,sources,detail
url,http://update-check.example/gate.php?id=1,cape:network.http,
url,http://update-check.example/p.ps1,cape:commands,
url,https://cdn.update-check.example/stage2.bin,cape:network.http,
domain,cdn.update-check.example,cape:network.dns;cape:network.http,
domain,update-check.example,cape:commands;cape:network.domains;cape:network.http,
ipv4,192.0.2.80,cape:network.domains,
ipv4,198.51.100.23,cape:network.domains;cape:network.hosts,
ipv4,203.0.113.5,cape:network.hosts,
ipv4,203.0.113.7,cape:network.dns,
md5,1b2062450bd3d9b1f41aadadae4f44f1,cape:dropped,
md5,5f89cef4c9ed3f109bc7c400d822e60e,cape:target,
sha1,a2eebf3d37a530f407d8907e869f880fa5346b29,cape:target,
sha1,fe077a501a66e0b4be2672b15928a38ae34068af,cape:dropped,
sha256,334486bd1343a3dd88c93f57d0b16f08d906bccb7cf084f1e545547defabb6dc,cape:dropped,
sha256,8ddcb559924bcba8d5497d45f66c01316bb77d5cf8618b9771e62166fdbbce05,cape:target,
attack-technique,T1027.002,reported;rule:cape.packer-known,Software Packing (reported as T1045)
attack-technique,T1053.005,rule:cmd.scheduled-task,Scheduled Task
attack-technique,T1055,reported,Process Injection
attack-technique,T1055.012,rule:cape.injection-runpe;rule:api.process-hollowing,Process Hollowing
attack-technique,T1059.001,rule:cmd.powershell,PowerShell
attack-technique,T1105,rule:api.download-to-file;rule:cmd.download,Ingress Tool Transfer
attack-technique,T1490,rule:cmd.inhibit-recovery,Inhibit System Recovery
attack-technique,T1497,reported,Virtualization/Sandbox Evasion
attack-technique,T1497.001,rule:cape.antivm,System Checks
attack-technique,T1547.001,rule:reg.run-keys,Registry Run Keys / Startup Folder
```

In the JSON output (`ttprism extract report.json --include-reserved`), each technique says why it
was assigned. Here a CAPE signature carried the revoked `T1045` and a TTPrism rule matched the same
signature:

```json
{
  "id": "T1027.002",
  "name": "Software Packing",
  "tactics": [
    "stealth"
  ],
  "status": "active",
  "reported": true,
  "rules": [
    "cape.packer-known"
  ],
  "confidence": "high",
  "evidence": [
    "CAPE signature packer_upx: T1045",
    "signature: packer_upx"
  ],
  "original_ids": [
    "T1045"
  ],
  "url": "https://attack.mitre.org/techniques/T1027/002/"
}
```

For a STIX 2.1 bundle, with an `indicator` per IOC, a `vulnerability` per CVE, an `attack-pattern`
per technique and a `grouping` that ties them together:

```sh
$ ttprism extract report.json -f stix -o bundle.json --include-reserved
```

### Use it as a Python library

```python
import ttprism

# include_reserved keeps documentation names such as *.example.com, filtered by default.
options = ttprism.AnalysisOptions(include_reserved=True)
result = ttprism.analyze_text("C2: c2【.】example.com, see T1071.001", options)
for ioc in result.iocs:
    print(ioc.type, ioc.value)          # domain c2.example.com
print(result.techniques[0].name)        # Web Protocols

result = ttprism.analyze_file("report.json")
bundle = ttprism.to_stix_bundle(result)
```

### Add your own allowlist and rules

An allowlist drops values you never want reported, such as your own organisation's names. It is
YAML with the keys `domains`, `url_hosts`, `ips` (addresses or CIDR ranges), `hashes` and
`emails`; `"name"` matches exactly and `"*.name"` matches the name and all its subdomains. An entry
under `domains` drops only the domain itself: URLs on that host are still reported unless the host
is also under `url_hosts`. The built-in list is
[`allowlist.yaml`](https://github.com/yuchen-0321/TTPrism/blob/main/src/ttprism/data/allowlist.yaml).

`my-allowlist.yaml`:

```yaml
domains:
  - "*.corp.example"
```

`incident.txt`:

```text
受害主機 hr.corp.example 連線至 update-check【.】example
```

```sh
$ ttprism extract incident.txt -f csv --include-reserved --allowlist my-allowlist.yaml
type,value,sources,detail
domain,update-check.example,text,
```

In the JSON output the dropped name is counted as `"suppressed": {"allowlisted": 1}`.

ATT&CK rules are YAML too; the format is in
[`rules/attack/README.md`](https://github.com/yuchen-0321/TTPrism/blob/main/rules/attack/README.md).
`my-rules.yaml`:

```yaml
attack_version: "19.2"

rules:
  - id: local.powershell-hidden-window
    technique: T1564.003
    confidence: medium
    description: PowerShell started with a hidden window.
    references:
      - https://attack.mitre.org/techniques/T1564/003/
    match:
      commands:
        - [powershell, -w hidden]
        - [powershell, -windowstyle hidden]
```

Check it against the bundled ATT&CK catalog, then use it alongside the built-in rules:

```sh
$ ttprism validate-rules my-rules.yaml
1 rules checked against ATT&CK 19.2: OK
$ ttprism extract report.json -f csv --include-reserved --rules my-rules.yaml
```

On the CAPE report above, this adds one row to the output:

```text
attack-technique,T1564.003,rule:local.powershell-hidden-window,Hidden Window
```

## Options

`ttprism extract [options] INPUT`, where `INPUT` is a file or `-` for standard input
(`cat report.txt | ttprism extract -`).

| Option | Effect |
| --- | --- |
| `-f json\|csv\|stix` | Output format (default `json`) |
| `-o FILE` | Write to a file instead of standard output |
| `--defang` | Defang IOC values in JSON/CSV output |
| `--include-reserved` | Keep private/documentation IPs and `example`/`test` domains |
| `--allowlist FILE` | Add an allowlist (repeatable); `--no-default-allowlist` disables the built-in one |
| `--rules PATH` | Add ATT&CK rule files or directories (repeatable); `--no-default-rules` disables the built-in rules |
| `--input-format auto\|text\|cape` | Override input detection |
| `--encoding NAME` | Input text encoding (default UTF-8; for example `big5`, `gb18030`) |
| `--max-size SIZE` | Refuse larger inputs (default `64m`) |
| `-q`, `--quiet` | Do not print warnings |

`ttprism validate-rules [PATH ...]` checks rule files against the bundled ATT&CK catalog (the
built-in rules when no path is given). `ttprism --version` prints the version.

## How ATT&CK mapping works

- **`reported`**: the input names the technique. A report cites `T1059.001`, or a CAPE signature
  carries its own TTP label.
- **`rules`**: a TTPrism rule matched observed behaviour. Rules live in
  [`rules/attack/`](https://github.com/yuchen-0321/TTPrism/blob/main/rules/attack/README.md) as YAML, so analysts can add and review them without
  Python. Each rule has a `confidence` and a public reference.
- **`original_ids`**: outdated IDs from the input that were resolved through ATT&CK's revocation
  history (`T1086` → `T1059.001`, `T1562.001` → `T1685`).

TTPrism does not guess techniques from report prose. The bundled catalog is Enterprise ATT&CK
**19.2**.

## Filtering

By default TTPrism drops (the name in brackets is the key under `suppressed`):

- **Reserved values** (`reserved`): private, loopback and documentation IP ranges, IPv6 addresses
  outside the global unicast block `2000::/3`, and `example.com`, `.test`, `.example`, `.invalid`,
  `.local` names.
- **Allowlisted values** (`allowlisted`): the root domains of large platforms (`google.com`, but not
  `drive.google.com` or URLs on it), sandbox background traffic, certificate revocation hosts,
  reference sites such as `attack.mitre.org`, and empty-file hashes. See
  [`allowlist.yaml`](https://github.com/yuchen-0321/TTPrism/blob/main/src/ttprism/data/allowlist.yaml).
- **File names that look like domains** (`filename_like_domain`): `payload.zip` or `setup.py`
  written without a URL.
- **Public suffixes** (`public_suffix`): `co.uk`, `com.tw` or `gov.tw` written without a URL (names
  under them, such as `evil.co.uk`, are kept).
- **Code identifiers** (`code_identifier`): COM and .NET names such as `WScript.Shell` or
  `System.Net.Security`.
- **Browser versions** (`version_like`): `Chrome/120.0.0.0` in a User-Agent string is not an IPv4
  address.
- **Certificate serial numbers** (`certificate_serial`): hex right after a serial-number label
  (`SerialNumber:`, `Serial Number`, `序列号`, `序號`, `憑證序號`, with or without a colon) has the
  length of a hash but is not one.
- **Masked names** (`masked_name`): names, e-mail addresses and URL hosts with a label of three or
  more `x` (`wiki.xxxx.com`), which reports use to hide the real value.
- **Antivirus detection names** (`detection_name`): `Backdoor.Win32.Ht` or `Trojan.MSIL.Bot`, whose
  family happens to be a TLD.
- **Fragments of names broken across lines** (`line_wrap_fragment`): the part of a name or e-mail
  address that starts a line when the line before ends in a letter or digit and a hyphen
  (`dynamic-` / `dns.net`), since that hyphen may or may not belong to the name. See Limitations.

Counts of what was dropped are reported under `suppressed`, so nothing disappears silently.

A CAPE report is also read only up to fixed limits, and what lies beyond them is counted under
`suppressed` too: at most 10,000 distinct API names, command lines, registry writes, signatures
and TTP labels each (`truncated_apis`, `truncated_commands`, `truncated_registry_writes`,
`truncated_signatures`, `truncated_ttps`), and command lines up to 8 Mi characters in total for
rule matching and for IOC search (`truncated_rule_commands`, `truncated_ioc_commands`, also named
in a warning).

## Limitations

- An ideographic full stop `。` is only treated as a dot inside brackets (`[。]`, `【。】`), since
  it also ends Chinese sentences.
- Internationalised domain names are recognised only in punycode (`xn--`) form. A name written
  with non-ASCII letters (an IDN or a homograph such as a Cyrillic `о`) is skipped rather than
  reported in truncated form.
- Alternative-root TLDs such as `.bit` and `.i2p` are not recognised; `.onion` is.
- A URL directly followed by `;command` (for example `wget http://x/a.sh;chmod`) keeps that
  suffix, because `;` is legal inside URLs.
- A defang marker with a space on one side only (`update [.]example[.]com`) reads as a word
  followed by a leading-dot name, giving `example.com`; write ` [.] ` with spaces on both sides
  or none.
- A single bidi mark between two name characters is removed as part of the name, so two IOCs
  separated only by such a mark (`198.51.100.7\u200f203.0.113.9`) are not split.
- A full-width colon `：` is read as `:`, so a URL directly followed by `：` and ASCII text
  (`.../a.exe：C2`) keeps that text; full-width `（），；！` do end a URL.
- ATT&CK command rules split a line at cmd.exe's `&`, `&&` and `||` only: PowerShell statements
  joined by `;` are matched as one command.
- `--defang` changes the scheme, host and `@` only; URL paths are left as they are.
- Names and URLs broken across lines (as PDF converters leave them) are joined only where the
  hyphen at the break cannot belong to them (`evil.-` / `com`, `evil-` / `.com`) or where a URL
  breaks after one of its own hyphens (`/KB-Auto-win-` / `update.exe`, over as many lines as it
  takes; while the URL is still in its host, only a line of letters, digits, dots and hyphens, or
  one that goes on to a port or path, carries it to a further line, so a URL that wraps again after
  a user name or password is cut there). This misjudges some cases:
  - a URL that really ends in `-` at the end of a line is joined with the start of the next line;
  - a hyphen that the converter added where it broke a URL is kept (`/download-` / `file.exe` gives
    `/download-file.exe` also when the URL is `/downloadfile.exe`), over as many lines as it takes;
  - a name at the start of a line after a line ending in a letter or digit and `-` (`2019-` /
    `evil.com`) is dropped as a fragment;
  - a URL broken at a hyphen in its password (`http://user:pa-` / `ss@evil.com/x`) is lost
    entirely: the first line ends in no URL and the second starts with a fragment.

  A break without a hyphen (`mp.weixi` / `n.qq.com`) gives no sign that the line continues, so such
  names and URLs are not joined, and the part on each line may be reported on its own.
- Every soft hyphen (U+00AD) is read as a hyphen, one for one (two make `--`): in text extracted
  from a PDF it stands where the page shows a hyphen (pypdf gives U+00AD for a hyphen drawn with
  code 0xAD in a WinAnsi-encoded font, where `pdftotext -raw` gives `-`, and both texts give the
  same IOCs except where a soft hyphen is deleted, below). At a line end, with at most 1,024 spaces
  or format characters between it and the break, it works exactly like `-`. It is deleted instead
  right after a hyphen at a line end (where `pdftotext -raw` gives `--`; a soft hyphen before it is
  still a hyphen), in a run of format characters with U+2063 or the end of a bidi embedding or
  isolate, and in a run of more than 64 format characters. Text copied from a web page uses soft
  hyphens as invisible break hints (`&shy;`) instead: there `KB-Auto` should read `KBAuto`, and a
  hash with one inside it is lost, while its pieces may be reported as shorter hashes (a SHA-256
  split in the middle as two MD5s). TTPrism warns when deleting every soft hyphen would change any
  value it reports; to find out, it extracts at most the first 8 Mi characters of such a text a
  second time, cut where no value can go on (a line end or a space in the last 64 Ki characters
  before that, or at 8 Mi if there is none). In a longer text it finds only values that deleting the
  soft hyphens would add, not those it would lose. pdftotext's default mode, unlike `-raw`, also
  joins a line ending in a hyphen to the next and drops the hyphen, which no reading of separate
  lines can repeat.
- CAPE is the only sandbox format so far.

## Evaluation

TTPrism was compared with iocextract and ioc-finder on public TLP:CLEAR Chinese-language reports,
using each report's own IOC list as the ground truth. The method, every number and every judgement
are in the
[research note](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md).

- **The reports.** Eight Simplified-Chinese reports with an IOC appendix (2018–2020), and four
  Traditional-Chinese reports with a real IOC list (the note's set 2). An earlier Traditional-Chinese
  set of four, chosen under a literal reading of "indicators", held only one real IOC list: two were
  lists of reference links and one had an English body.
- **CJK defanging is untested on real reports.** None of the 12 reports with a real IOC list writes
  indicators with full-width or CJK-bracket defanging; the only defanging in them is ASCII (`[.]`,
  one `hxxp`). TTPrism's handling of those writings is supported only by synthetic tests.
- **What was measured in TTPrism's favour:** fewer wrong values, and repairing names and URLs split
  across PDF lines.
  - On the Simplified-Chinese reports TTPrism found 7 of 9 domain names that a line break had split
    and that the other tools missed, and reported 7 wrong values against 41 for ioc-finder and 48 for
    iocextract. These numbers were made after fixes derived from the same eight reports, so they are
    optimistic.
  - On the Traditional-Chinese set 2, measured with TTPrism's code frozen before those reports were
    added, TTPrism reported no wrong value, ioc-finder one and iocextract 36. Set 2 was chosen after
    the earlier set had been measured, from candidates already looked at.
- **Otherwise recall is the same as ioc-finder's.** On set 2 both found 73 of 75 values
  (iocextract 71); the two missed by every tool are SHA-256 hashes that a table cell split over two
  lines. On the Simplified-Chinese reports, before the fixes, TTPrism and ioc-finder found the same
  domains (162 of 171; ioc-finder also missed two MD5 hashes glued to a bracket); the 7 more that
  TTPrism found after the fixes are the split names above.
- **Caveats.** The samples are small and the results descriptive. One rater, the evaluator (Claude,
  an AI assistant working for the maintainer), built the ground truths and judged every value
  outside them; no inter-rater agreement was measured.

## Security

TTPrism only parses input statically. It never executes, unpacks or downloads samples, and this
repository contains no malware. Test data uses reserved names, documentation IP ranges and hashes
of harmless strings. The evaluation results under `docs/research/` are different: they contain real
IOCs (malicious domains, URLs, IP addresses and hashes) quoted from public TLP:CLEAR reports, so
treat them as data and do not open or resolve them.

Found a vulnerability? Please report it privately; see [SECURITY.md](https://github.com/yuchen-0321/TTPrism/blob/main/SECURITY.md). False positives
and missed IOCs are not vulnerabilities; open a *Detection quality* issue instead.

## Contributing

See [CONTRIBUTING.md](https://github.com/yuchen-0321/TTPrism/blob/main/CONTRIBUTING.md). Please use
only TLP:CLEAR material.

- **ATT&CK rules need no Python.** They are YAML files in
  [`rules/attack/`](https://github.com/yuchen-0321/TTPrism/blob/main/rules/attack/README.md);
  `ttprism validate-rules` checks them.
- **Report detection problems.** A missed IOC, a value wrongly extracted, an unrecognised defang
  form or a wrong ATT&CK mapping goes in a
  [Detection quality](https://github.com/yuchen-0321/TTPrism/issues/new?template=detection_quality.yml)
  issue, with the smallest excerpt that shows it.
- **Code**: extraction, parsers, exporters, tests; the development setup and checks are in
  CONTRIBUTING.md.

## License

MIT; see [LICENSE](https://github.com/yuchen-0321/TTPrism/blob/main/LICENSE).

The bundled ATT&CK catalog is derived from MITRE ATT&CK®:
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. The TLD list comes
from IANA.
