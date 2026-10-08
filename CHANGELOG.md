# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Security fixes are marked **Security** and link to
their advisory.

## [Unreleased]

### Added

- IOC extraction from report text and Markdown: URLs, domains, IPv4, IPv6, email addresses,
  MD5/SHA-1/SHA-256 hashes and CVE IDs, with TLD validation against the IANA list.
- Refanging of common and CJK defang styles: `[.]`, `(.)`, `[dot]`, `【.】`, `〔.〕`, `[。]`,
  full-width characters (`．`, `［＠］`, `１９８．５１…`), `hxxp(s)`, `[:]`, `[://]`, zero-width
  characters inserted by PDF converters.
- `--defang` output for safe sharing.
- CAPE `report.json` parser: network IOCs, sample/dropped/payload hashes, URLs on executed
  command lines, signatures, API calls, written registry keys.
- ATT&CK mapping rules in YAML (`rules/attack/`, 106 rules) for CAPE signatures, command lines,
  API call sequences and registry writes, written against Enterprise ATT&CK 19.2, each with a
  confidence level and reference.
- Normalisation of revoked ATT&CK IDs through the revocation history (for example `T1086` →
  `T1059.001`, `T1562.001` → `T1685`), for IDs in reports and in CAPE's own signature TTPs.
- Output as JSON, CSV and STIX 2.1 bundles (indicators, vulnerabilities, attack patterns).
- Default allowlist for platform root domains, sandbox background traffic, OCSP/CRL hosts and
  reference sites, plus custom allowlists; reserved and documentation values filtered by default.
- `ttprism validate-rules` for rule authors.
- Security hardening: linear-time regexes with a ReDoS test suite, input size limit, JSON nesting
  limit, strict YAML schemas with `safe_load`, CSV formula escaping, control-character
  sanitisation, Hypothesis fuzz tests.
- Project governance: security policy with private vulnerability reporting, threat model,
  contributing guide, code of conduct, issue templates.
