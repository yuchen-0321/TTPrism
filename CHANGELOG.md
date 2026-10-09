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
  `smb`, `file`, `ssh`, `telnet`, `irc`, `rtsp`, `ssl`, `tls`, `smtp(s)`, `imap(s)`, `pop3(s)`,
  `socks`, `redis`, `mongodb`, `mysql`, `mssql`, `postgres(ql)`, `amqp(s)`, `mqtt(s)`, `rsync`,
  `git`, `svn`, `vnc` and `rdp` schemes, also with a prefix (`stratum+tcp`, `git+https`,
  `mongodb+srv`); integer, hex and octal IPv4 hosts (`http://3221225985/`); hosts in UNC paths
  (`\\host\share`, also WebDAV `\\host@SSL\...` and `file://host@SSL/...`, after a label colon and
  JSON-escaped), protocol-relative URLs and wildcard names (`*.evil.com`);
  URL lists joined by commas or quotes split into separate URLs; open-redirect targets and
  percent-encoded URLs inside a URL's query extracted as well, each query parameter on its own,
  keeping the outer URL.
- Noise filters: file names that look like domains (`payload.zip`, `setup.msi.zip`), COM /
  .NET identifiers (`WScript.Shell`, `System.Net.Security`), bare public suffixes (`co.uk`,
  `com.tw`) and browser versions (`Chrome/120.0.0.0`) are dropped and counted under
  `suppressed`; names glued to non-ASCII letters (IDNs, homographs) are skipped instead of
  truncated, but emoji and right-to-left letters next to a name are not glue. A label before an
  IPv6 address (`C2:2001:db8::1`, `IPv6:2001:db8::1`) is not taken as part of it. A literal `%`
  (`LIKE '%198.51.100.7%'`) is not read as a percent escape.
- Fixes from an evaluation on eight public Chinese-language reports
  (`docs/research/2026-10-real-reports.md`): certificate serial numbers labelled as such
  (`SerialNumber: 00B7...`, `序列号：`) and GUIDs whose hyphens a PDF converter wrote as soft
  hyphens are no longer read as hashes; names and URLs broken across PDF lines are joined where
  the hyphen at the break cannot be part of them (`evil.-` / `com`, `evil-` / `.com`) or is part of a
  URL (`/KB-Auto-win-` / `update.exe`), and otherwise the rest of a name on the next line is dropped
  as a fragment (`line_wrap_fragment`); masked names (`wiki.xxxx.com`) and antivirus detection
  names (`Backdoor.Win32.Ht`) are dropped (`masked_name`, `detection_name`). A soft hyphen at the
  end of a line, also before spaces or format characters, is read as a hyphen, so these line-break
  rules apply to it; soft hyphens deleted between two letters or digits inside an extracted name,
  e-mail address or URL, defanged or not (`KB\u00adAuto`, `up\u00addate[.]example[.]com`), give a
  warning, since some converters write every hyphen that way. A bare `序號` counts as a
  serial-number label only with a colon, since it also heads the row-number column of tables
  (`證書序號` and `憑證序號` need none). A line ending in a hyphen is joined with the next as part of a
  URL only when the URL really reaches the hyphen, not when a URL ended earlier on the line (Chinese
  text without spaces).
- Refanging of common and CJK defang styles: `[.]`, `(.)`, `[dot]`, `【.】`, `〔.〕`, `[。]`,
  the same markers with a space on each side (` [.] `, ` (at) `, ` {dot} `), `[/]`, `[//]`,
  full-width characters (`．`, `［＠］`, `１９８．５１…`), `hxxp`, `hxxp[s]`, `hxxp(s)`,
  `http(s)`, `h[tt]p`, `[:]`, `[://]`, Unicode hyphens, minus signs and spaces, `xn–` from
  typographers, and zero-width, bidi and other format characters inserted by PDF converters
  (bidi controls between two names separate them). Only width variants, ligatures, hyphens and
  dot forms are folded (not full NFKC), so superscript footnotes and circled list numbers never
  merge into an IOC, and full-width `（），；！` stay as they are, so they end a URL.
- `--defang` output for safe sharing.
- CAPE `report.json` parser: network IOCs, sample/dropped/payload hashes, URLs on executed
  command lines, signatures, API calls, written registry keys.
- ATT&CK mapping rules in YAML (`rules/attack/`, 111 rules) for CAPE signatures, command lines,
  API call sequences and registry writes, written against Enterprise ATT&CK 19.2, each with a
  confidence level and reference. Command phrases match on word boundaries (`_` counts as part of
  a word; switches such as `-enc` must be a word of their own) in two views of each command, quotes
  removed and quotes as spaces, with glued switches (`del/f/q`) split, so cmd.exe quote, caret and
  switch obfuscation does not hide them. Commands chained with `&`, `&&` or `||` are matched one by
  one, and `chained_commands` covers idioms that span them (`ping ... & del`). `exclude_commands`
  lets a rule ignore commands such as `net user ... /add` or `ipconfig /flushdns`, and `<arg>`
  stands for one argument (`net start <arg>`, `net share <arg>=`). Phrase lists are indexed by the
  word runs every match contains, so each command is tested only against lists that can match it.
- Normalisation of revoked ATT&CK IDs through the revocation history (for example `T1086` →
  `T1059.001`, `T1562.001` → `T1685`), for IDs in reports and in CAPE's own signature TTPs.
- Output as JSON, CSV and STIX 2.1 bundles (indicators, vulnerabilities, attack patterns).
- Default allowlist for platform root domains, sandbox background traffic, OCSP/CRL hosts and
  reference sites, plus custom allowlists; reserved and documentation values filtered by default.
- `ttprism validate-rules` for rule authors.
- Security hardening: linear-time regexes with a ReDoS test suite (pathological 1 MB inputs, cost per MB),
  chunked input reading with a size limit, JSON nesting limit, strict YAML schemas with aliases
  and duplicate keys rejected, per-report caps on rule inputs (IOC extraction and rule matching each
  see at most 8 Mi characters of CAPE command lines, with a warning past that), an indexed IP allowlist, atomic
  `-o` writes (in place where a new file cannot replace the old one), CSV formula escaping,
  control/bidi-character sanitisation of all output and messages, explicit
  reserved-IP tables independent of the Python version (IPv6 outside `2000::/3` is reserved),
  Hypothesis fuzz tests.
- Project governance: security policy with private vulnerability reporting, threat model,
  contributing guide, code of conduct, issue templates.
