# TTPrism

[![CI](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml/badge.svg)](https://github.com/yuchen-0321/TTPrism/actions/workflows/ci.yml)

**TTPrism splits a threat report or sandbox run into its IOCs and MITRE ATT&CK techniques**, the
way a prism splits light into a spectrum.

- **Extracts IOCs** (URLs, domains, IPv4/IPv6, emails, MD5/SHA-1/SHA-256, CVE IDs) from report text
  and from CAPE sandbox reports, and **undoes defanging**, including the full-width and CJK forms
  common in Chinese-language reports (`evil【.】com`, `evil．com`, `attacker［＠］mail．com`,
  `１９８．５１．１００．２３`) that English-oriented extractors miss.
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
| PDF reports | Convert to text first (for example `pdftotext report.pdf`); TTPrism does not parse PDFs |
| CAPE `report.json` | Detected automatically; network, files, commands, API calls, registry, signatures |

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

By default TTPrism drops:

- **Reserved values**: private, loopback and documentation IP ranges, and `example.com`, `.test`,
  `.example`, `.invalid`, `.local` names.
- **Allowlisted values**: the root domains of large platforms (`google.com`, but not
  `drive.google.com` or URLs on it), sandbox background traffic, certificate revocation hosts,
  reference sites such as `attack.mitre.org`, and empty-file hashes. See
  [`allowlist.yaml`](https://github.com/yuchen-0321/TTPrism/blob/main/src/ttprism/data/allowlist.yaml).
- **File names that look like domains**: `payload.zip` or `setup.py` written without a URL.

Counts of what was dropped are reported under `suppressed`, so nothing disappears silently.

## Limitations

- An ideographic full stop `。` is only treated as a dot inside brackets (`[。]`, `【。】`), since
  it also ends Chinese sentences.
- Internationalised domain names are recognised only in punycode (`xn--`) form.
- CAPE is the only sandbox format so far.

## Security

TTPrism only parses input statically. It never executes, unpacks or downloads samples, and this
repository contains no malware. Test data uses reserved names, documentation IP ranges and hashes
of harmless strings.

Found a vulnerability? Please report it privately; see [SECURITY.md](https://github.com/yuchen-0321/TTPrism/blob/main/SECURITY.md). False positives
and missed IOCs are not vulnerabilities; open a *Detection quality* issue instead.

## Contributing

See [CONTRIBUTING.md](https://github.com/yuchen-0321/TTPrism/blob/main/CONTRIBUTING.md). Rule contributions need no Python. Please use only
TLP:CLEAR material.

## 繁體中文簡介

TTPrism 從威脅報告與沙箱輸出中抽取 IOC，並把行為對應到 MITRE ATT&CK。它特別處理中文報告常見的全形與中日韓括號 defang 寫法，例如 `【.】`、`．`、`［＠］`、全形數字，以及緊接中文字、沒有空白的網域。既有的英文導向工具常漏掉這些寫法，比較結果見[研究紀錄](https://github.com/yuchen-0321/TTPrism/blob/main/docs/research/2026-10-existing-tools.md)。ATT&CK 對應規則以 YAML 撰寫，分析師不必寫程式也能貢獻。安全漏洞請依 [SECURITY.md](https://github.com/yuchen-0321/TTPrism/blob/main/SECURITY.md) 私下回報；誤報、漏報請開公開 issue。

## License

MIT; see [LICENSE](https://github.com/yuchen-0321/TTPrism/blob/main/LICENSE).

The bundled ATT&CK catalog is derived from MITRE ATT&CK®:
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. The TLD list comes
from IANA.
