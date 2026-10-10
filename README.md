# TTPrism

[![CI](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml/badge.svg)](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml)

**TTPrism splits a threat report or sandbox run into its IOCs and MITRE ATT&CK techniques**, the
way a prism splits light into a spectrum.

- **Extracts IOCs** (URLs, domains, IPv4/IPv6, emails, MD5/SHA-1/SHA-256, CVE IDs) from report text
  and from CAPE sandbox reports, and **undoes defanging**: ASCII forms (`evil[.]com`, `hxxp://`) and
  full-width and CJK forms (`evil【.】com`, `evil．com`, `attacker［＠］mail．com`,
  `１９８．５１．１００．２３`), which English-oriented extractors missed in a synthetic test. None of
  the eight real Simplified-Chinese reports [evaluated so far](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md) used the full-width or CJK
  forms; there TTPrism's measured advantages were repairing names and URLs split across PDF lines
  and reporting fewer wrong values (partly through fixes made on those same reports; a held-out
  Traditional-Chinese set is next).
- **Maps sandbox behaviour to ATT&CK** with YAML rules for CAPE signatures, command lines, API call
  sequences and registry writes. It also **normalises outdated technique IDs**: about a quarter of
  the TTP labels in CAPE's signatures point at techniques ATT&CK has since revoked.
- **Exports** JSON, CSV or a STIX 2.1 bundle.
- **Treats its input as hostile.** Regexes run in linear time, input size is capped, nothing is
  executed or fetched, and CSV output is safe to open in Excel. See the
  [threat model](https://github.com/yuchen-0321/TTPrism/blob/main/docs/threat-model.md).

> **Status:** pre-release (0.1.0.dev). The first PyPI release (v0.1) is planned. Feedback and
> detection-quality reports are very welcome.

## Install

Python 3.11 or newer:

```sh
pip install git+https://github.com/yuchen-0321/TTPrism.git
```

## Usage

```sh
ttprism extract report.md                        # JSON to stdout
ttprism extract report.md -f csv -o iocs.csv     # CSV file
ttprism extract cape/report.json -f stix         # STIX 2.1 bundle from a CAPE report
ttprism extract report.md --defang -f csv        # hxxps[://]evil[.]com, safe to paste in chat
cat report.txt | ttprism extract -               # read standard input
```

A Chinese-language report with mixed defang styles:

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

(`--include-reserved` is only needed here because the example uses documentation addresses and
the reserved `.example` TLD, which are filtered out by default.)

From a CAPE report, each technique says why it was assigned:

```json
{
  "id": "T1053.005",
  "name": "Scheduled Task",
  "reported": false,
  "rules": ["cmd.scheduled-task"],
  "confidence": "high",
  "evidence": ["command: s^c^h^t^a^s^k^s /create /tn upd /tr C:\\Users\\analyst\\upd.exe /sc minute"],
  "original_ids": []
}
```

### Inputs

| Input | How it is read |
| --- | --- |
| Plain text, Markdown | IOC extraction plus the ATT&CK technique IDs written in the text |
| PDF reports | Convert to text first (for example `pdftotext report.pdf`); TTPrism does not parse PDFs. The [evaluation on real reports](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md) used pypdf (`page.extract_text()`), headers and footers included; converters differ in how they break lines and write hyphens |
| CAPE `report.json` | Detected automatically (input that looks like JSON but does not parse is analysed as text, with a warning); network, files, commands, API calls, registry, signatures |

Non-UTF-8 text (for example Big5 or GB18030) needs `--encoding big5`.

### Options

| Option | Effect |
| --- | --- |
| `-f json\|csv\|stix` | Output format (default `json`) |
| `-o FILE` | Write to a file instead of standard output |
| `--defang` | Defang IOC values in JSON/CSV output |
| `--include-reserved` | Keep private/documentation IPs and `example`/`test` domains |
| `--allowlist FILE` | Add an allowlist (repeatable); `--no-default-allowlist` disables the built-in one |
| `--rules PATH` | Add ATT&CK rule files (repeatable); `--no-default-rules` disables the built-in rules |
| `--input-format auto\|text\|cape` | Override input detection |
| `--max-size SIZE` | Refuse larger inputs (default `64m`) |

`ttprism validate-rules [PATH ...]` checks rule files against the bundled ATT&CK catalog.

### As a library

```python
import ttprism

# include_reserved keeps documentation names such as *.example.com, filtered by default.
options = ttprism.AnalysisOptions(include_reserved=True)
result = ttprism.analyze_text("C2: c2【.】example.com, see T1071.001", options)
for ioc in result.iocs:
    print(ioc.type, ioc.value)          # domain c2.example.com
print(result.techniques[0].name)        # Web Protocols

result = ttprism.analyze_file("cape/report.json")
bundle = ttprism.to_stix_bundle(result)
```

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

## Security

TTPrism only parses input statically. It never executes, unpacks or downloads samples, and this
repository contains no malware. Test data uses reserved names, documentation IP ranges and hashes
of harmless strings. The evaluation results under `docs/research/` are different: they contain real
IOCs (malicious domains, URLs, IP addresses and hashes) quoted from public TLP:CLEAR reports, so
treat them as data and do not open or resolve them.

Found a vulnerability? Please report it privately; see [SECURITY.md](https://github.com/yuchen-0321/TTPrism/blob/main/SECURITY.md). False positives
and missed IOCs are not vulnerabilities; open a *Detection quality* issue instead.

## Contributing

See [CONTRIBUTING.md](https://github.com/yuchen-0321/TTPrism/blob/main/CONTRIBUTING.md). Rule contributions need no Python. Please use only
TLP:CLEAR material.

## 繁體中文簡介

TTPrism 從威脅報告與沙箱輸出中抽取 IOC，並把行為對應到 MITRE ATT&CK。除了 ASCII 的 defang 寫法，它也處理全形與中日韓括號寫法，例如 `【.】`、`．`、`［＠］`、全形數字，在合成測試中，既有的英文導向工具漏掉了這些寫法（見[研究紀錄](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-existing-tools.md)）；它也能抽出緊接中文字、沒有空白的網域，這點 ioc-finder 同樣做得到。不過目前評估的 8 份真實簡體中文報告都沒有用到全形或中日韓括號寫法；在這些報告上，TTPrism 量到的優勢是修復被 PDF 斷行切開的網域與 URL，以及抽出較少錯誤的值，其中一部分來自針對同一批報告所做的修正，保留不看的繁體中文報告尚待量測（見[真實報告評估](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-real-reports.md)）。ATT&CK 對應規則以 YAML 撰寫，分析師不必寫程式也能貢獻。安全漏洞請依 [SECURITY.md](https://github.com/yuchen-0321/TTPrism/blob/main/SECURITY.md) 私下回報；誤報、漏報請開公開 issue。

## License

MIT; see [LICENSE](https://github.com/yuchen-0321/TTPrism/blob/main/LICENSE).

The bundled ATT&CK catalog is derived from MITRE ATT&CK®:
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. The TLD list comes
from IANA.
