# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Security fixes are marked **Security** and link to
their advisory.

## [Unreleased]

### Added

- IOC extraction from report text and Markdown: URLs, domains, IPv4, IPv6, email addresses,
  MD5/SHA-1/SHA-256 hashes and CVE IDs, with TLD validation against the IANA list.
- URLs with `http(s)`, `ftp(s)`, `sftp`, `ws(s)`, `ldap(s)`, `rmi`, `iiop`, `dns`, `tcp`, `udp`,
  `smb`, `file`, `ssh`, `telnet`, `irc` and `rtsp` schemes; hosts in UNC paths (`\\host\share`),
  protocol-relative URLs and wildcard names (`*.evil.com`); URL lists joined by commas or quotes
  split into separate URLs; open-redirect targets and percent-encoded URLs inside a URL's query
  extracted as well, keeping the outer URL.
- Noise filters: file names that look like domains (`payload.zip`, `invoice.pdf.zip`) and COM /
  .NET identifiers (`WScript.Shell`, `System.IO`) are dropped and counted under `suppressed`;
  names glued to non-ASCII letters (IDNs, homographs) are skipped instead of truncated.
- Refanging of common and CJK defang styles: `[.]`, `(.)`, `[dot]`, `【.】`, `〔.〕`, `[。]`,
  ` [.] ` between labels, `[/]`, `[//]`, full-width characters (`．`, `［＠］`, `１９８．５１…`),
  `hxxp(s)`, `hxxp[s]`, `h[tt]p`, `[:]`, `[://]`, Unicode hyphens and minus signs, and zero-width,
  bidi and other format characters inserted by PDF converters. Only width variants, ligatures,
  hyphens and dot forms are folded (not full NFKC), so superscript footnotes and circled list
  numbers never merge into an IOC.
- `--defang` output for safe sharing.
- CAPE `report.json` parser: network IOCs, sample/dropped/payload hashes, URLs on executed
  command lines, signatures, API calls, written registry keys.
- ATT&CK mapping rules in YAML (`rules/attack/`, 111 rules) for CAPE signatures, command lines,
  API call sequences and registry writes, written against Enterprise ATT&CK 19.2, each with a
  confidence level and reference. Command phrases match on word boundaries (`_` counts as part of
  a word) in two views of each command line, quotes removed and quotes as spaces, so cmd.exe
  quote and caret obfuscation does not hide them. `exclude_commands` lets a rule ignore lines
  such as `net user ... /add` or `ipconfig /flushdns`.
- Normalisation of revoked ATT&CK IDs through the revocation history (for example `T1086` →
  `T1059.001`, `T1562.001` → `T1685`), for IDs in reports and in CAPE's own signature TTPs.
- Output as JSON, CSV and STIX 2.1 bundles (indicators, vulnerabilities, attack patterns).
- Default allowlist for platform root domains, sandbox background traffic, OCSP/CRL hosts and
  reference sites, plus custom allowlists; reserved and documentation values filtered by default.
- `ttprism validate-rules` for rule authors.
- Security hardening: linear-time regexes with a ReDoS test suite (56 pathological 1 MB inputs),
  chunked input reading with a size limit, JSON nesting limit, strict YAML schemas with aliases
  rejected, per-report caps on rule inputs, an indexed IP allowlist, atomic `-o` writes, CSV
  formula escaping, control/bidi-character sanitisation of all output and messages, explicit
  reserved-IP tables independent of the Python version, Hypothesis fuzz tests.
- Project governance: security policy with private vulnerability reporting, threat model,
  contributing guide, code of conduct, issue templates.
